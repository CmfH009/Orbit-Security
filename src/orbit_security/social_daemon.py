"""Orbit Security Autonomous Social Agent Daemon (social_daemon.py).

Implements the continuous 60-minute execution lifecycle with organic jitter,
pacing micro-delays, hardware governor awareness, and anti-bot quota enforcement.
Integrates FeedHarvester, RelevanceEngine, GroundTruthGate, and OrbitXDriver.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
from pathlib import Path
import random
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from orbit_security.circuit_breaker import BreakerState, SocialCircuitBreaker, TriggerType
from orbit_security.feed_harvester import FeedHarvester
from orbit_security.ground_truth_gate import GroundTruthGate
from orbit_security.models import DomainAuditResult
from orbit_security.quota_manager import SocialQuotaManager
from orbit_security.relevance_engine import (
    ActionDecision,
    ActionType,
    DiscoveredPost,
    RelevanceEngine,
)
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.social_state import SocialStateManager

logger = logging.getLogger(__name__)

# Ensure logging outputs cleanly
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [ORBIT-SOCIAL] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class SocialDaemon:
    """Master runner for the autonomous social outreach and intelligence pipeline."""

    ARCADE_URL = "https://cmfh009.github.io/Orbit-Security/"

    def __init__(
        self,
        nominal_interval_seconds: int = 3600,
        dry_run: bool = False,
        driver: Optional[Any] = None,
    ):
        self.nominal_interval = nominal_interval_seconds
        self.dry_run = dry_run
        self.running = False
        self.driver = driver

        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.state_file = self.base_dir / "data" / "social_daemon_state.json"

        # Initialize headless driver if none provided and not dry_run
        if self.driver is None and not self.dry_run:
            try:
                from orbit_security.x_driver import OrbitXDriver, DriverConfig
                config = DriverConfig(headless=True)
                self.driver = OrbitXDriver(config=config)
                self.driver.start()
                logger.info("Initialized Headless OrbitXDriver (zero-window background mode).")
            except Exception as e:
                logger.warning(f"Could not initialize headless OrbitXDriver: {e}")

        # Core subsystems
        self.state_manager = SocialStateManager()
        self.quota_manager = SocialQuotaManager(state_manager=self.state_manager)
        self.circuit_breaker = SocialCircuitBreaker(state_manager=self.state_manager)
        self.relevance_engine = RelevanceEngine(project_root=self.base_dir)
        self.ground_truth_gate = GroundTruthGate(max_audit_age_minutes=30)
        self.harvester = FeedHarvester(driver=self.driver, dry_run=self.dry_run)

    def _check_hardware_governor(self) -> bool:
        """Verifies host CPU and RAM status before initiating heavy operations."""
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            if cpu > 70.0:
                logger.warning(f"Host CPU elevated ({cpu}% > 70.0%). Pacing social daemon.")
                return False

            vm = psutil.virtual_memory()
            free_mb = vm.available / (1024 * 1024)
            if free_mb < 800.0:
                logger.warning(f"Host RAM constrained ({free_mb:.0f}MB < 800MB). Yielding cycle.")
                return False
        except Exception:
            pass
        return True

    def _save_daemon_heartbeat(self, status: str = "RUNNING"):
        """Saves current daemon status for supervisor monitoring."""
        st = {
            "pid": os.getpid(),
            "status": status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "circuit_state": self.circuit_breaker.state.value,
            "quotas": self.quota_manager.get_status_summary(),
        }
        tmp = self.state_file.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(st, f, indent=2)
            tmp.replace(self.state_file)
        except Exception:
            if tmp.exists():
                tmp.unlink()

    def _format_roast_reply(self, result: DomainAuditResult) -> str:
        """Builds an RFC-compliant roast reply <= 280 chars."""
        dmarc_line = "✉️ DMARC: Monitoring mode (RFC 7489 p=none)"
        for f in result.findings:
            if "p=reject" in f.title.lower() or "quarantine" in f.title.lower():
                dmarc_line = "✉️ DMARC: Enforced policy (Pass)"
                break
            elif "missing" in f.title.lower() and "dmarc" in f.title.lower():
                dmarc_line = "✉️ DMARC: Missing record (Spoofable)"
                break

        key_finding = "Zero dangling CNAME takeovers detected"
        for f in result.findings:
            if "takeover" in f.title.lower() or "expired" in f.title.lower():
                key_finding = f.title
                break

        reply = (
            f"🛡️ Orbit Roast: {result.domain}\n\n"
            f"📊 Score: {result.score}/100 (Grade: {result.grade})\n"
            f"{dmarc_line}\n"
            f"⚠️ Key: {key_finding[:40]}\n\n"
            f"Decode in our 16-bit arcade:\n"
            f"{self.ARCADE_URL}"
        )
        return reply[:280]

    def _execute_passive_scan(self, domain: str) -> Optional[DomainAuditResult]:
        """Runs a 5-second asynchronous passive scan for inbound roast requests."""
        try:
            scanner = OrbitSecurityScanner(timeout=5.0)
            result = asyncio.run(scanner.scan_domain(domain, use_crtsh=False))
            return result
        except Exception as e:
            logger.error(f"Error executing passive scan for {domain}: {e}")
            return None

    def execute_hourly_cycle(self) -> Dict[str, Any]:
        """Executes a single hourly cycle conforming to all anti-bot quotas."""
        cycle_start = time.time()
        logger.info("=== Starting Orbit Social Hourly Execution Cycle ===")
        self.quota_manager.reset_hourly_cycle()
        self._save_daemon_heartbeat("EXECUTING_CYCLE")

        # 1. Hardware Governor Check
        if not self._check_hardware_governor():
            logger.info("Hardware governor pacing: yielding cycle early.")
            return {"status": "PACED_BY_HARDWARE"}

        # 2. Circuit Breaker Check
        available, reason = self.circuit_breaker.is_available()
        if not available:
            logger.warning(f"Skipping cycle: Circuit Breaker active ({reason})")
            return {"status": "CIRCUIT_OPEN", "reason": reason}

        # 3. Time-of-Day Check
        multiplier = self.quota_manager.get_time_of_day_multiplier()
        if multiplier == 0.0:
            logger.info("Current window is DORMANT (quiet night period). Sleeping without mutations.")
            return {"status": "DORMANT_WINDOW"}

        # 4. Multi-Vector Post Harvesting
        candidates = self.harvester.harvest_hourly_candidates(max_candidates=20)
        logger.info(f"Processing {len(candidates)} discovered candidates this cycle.")

        actions_performed = 0

        # 5. Evaluate and Execute Candidates
        for post in candidates:
            # Check remaining quota
            if not self.quota_manager.get_status_summary():
                break

            # Calculate Relevance Score
            score = self.relevance_engine.calculate_score(post)
            if score.is_hard_dropped or score.total_score < 50:
                continue

            # Classify Recommended Action
            decision = self.relevance_engine.classify_action(post, score)
            action_name = decision.action.value

            if decision.action == ActionType.DROP:
                continue

            # Check quota for specific action
            if not self.quota_manager.can_perform(action_name):
                continue

            # Check deduplication in SQLite
            if self.state_manager.is_interacted(post.tweet_id, action_name):
                continue

            # Execute action workflow
            success = False
            content_snippet = post.text[:120]

            if decision.action == ActionType.LIKE:
                logger.info(f"Action Dispatch: LIKE on @{post.author_handle} (Tweet: {post.tweet_id}) | Score: {score.total_score}")
                if self.dry_run or not self.driver:
                    success = True
                else:
                    success = self.driver.like_tweet(f"https://x.com/{post.author_handle}/status/{post.tweet_id}")

            elif decision.action in (ActionType.REPOST, ActionType.QUOTE):
                logger.info(f"Action Dispatch: {action_name} on @{post.author_handle} (Tweet: {post.tweet_id}) | Score: {score.total_score}")
                if self.dry_run or not self.driver:
                    success = True
                else:
                    success = self.driver.repost_tweet(f"https://x.com/{post.author_handle}/status/{post.tweet_id}")

            elif decision.action == ActionType.REPLY:
                logger.info(f"Action Dispatch: REPLY to @{post.author_handle} (Tweet: {post.tweet_id})")

                # If inbound roast requested and domain found, execute passive scan
                if decision.scan_recommended and decision.target_domain:
                    # Validate against CVD: only roast if explicit inbound request
                    is_inbound = "roast my" in post.text.lower() or "check my" in post.text.lower() or "_arsoncode" in post.text.lower()
                    if not is_inbound:
                        logger.info(f"CVD Gate: Suppressing unsolicited public roast for domain {decision.target_domain}.")
                        continue

                    audit = self._execute_passive_scan(decision.target_domain)
                    if not audit:
                        continue

                    reply_text = self._format_roast_reply(audit)
                    verdict = self.ground_truth_gate.validate_inbound_roast(
                        domain=decision.target_domain,
                        reply_text=reply_text,
                        audit_result=audit,
                        is_explicit_request=is_inbound,
                    )

                    if not verdict.is_approved:
                        logger.warning(f"Ground-Truth Gate Rejected Reply: {verdict.rejection_reason}")
                        continue

                    content_snippet = reply_text
                    if self.dry_run or not self.driver:
                        success = True
                    else:
                        success = self.driver.reply_to_tweet(
                            f"https://x.com/{post.author_handle}/status/{post.tweet_id}",
                            reply_text,
                        )
                else:
                    # Educational reply without naming unverified third-party targets
                    edu_reply = (
                        f"@{post.author_handle} DNS drift post-launch is often the blind spot. "
                        f"Stale records pointing to canceled SaaS endpoints (Unbounce, S3, Webflow) "
                        f"remain unmonitored until hijacked. Continuous RFC 1035 & 8484 diffing is key."
                    )
                    content_snippet = edu_reply
                    if self.dry_run or not self.driver:
                        success = True
                    else:
                        success = self.driver.reply_to_tweet(
                            f"https://x.com/{post.author_handle}/status/{post.tweet_id}",
                            edu_reply,
                        )

            if success:
                self.state_manager.record_action(
                    tweet_id=post.tweet_id,
                    action_type=action_name,
                    author_handle=post.author_handle,
                    target_domain=decision.target_domain,
                    audit_score=score.total_score,
                    content_snippet=content_snippet,
                    status="SIMULATED" if self.dry_run else "SUCCESS",
                )
                self.quota_manager.record_hourly_action(action_name)
                actions_performed += 1

                # If in probe mode, record circuit recovery
                if self.circuit_breaker.state == BreakerState.HALF_OPEN:
                    self.circuit_breaker.record_probe_success()

                # Paced human-like micro-delay between actions
                micro_delay = random.uniform(45.0, 120.0) if not self.dry_run else 0.1
                logger.info(f"Pacing: sleeping {micro_delay:.1f}s before next interaction...")
                time.sleep(micro_delay)

        # 6. Export JSON snapshot & commit telemetry
        snapshot = self.state_manager.export_json_snapshot()
        duration = round(time.time() - cycle_start, 2)
        logger.info(
            f"=== Cycle Complete in {duration}s. Actions: {actions_performed} | "
            f"Daily Totals: {snapshot.get('today_metrics')} ==="
        )
        self._save_daemon_heartbeat("IDLE")

        return {
            "status": "COMPLETED",
            "actions_count": actions_performed,
            "duration_seconds": duration,
        }

    def publish_original_post(
        self,
        text: Optional[str] = None,
        media_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Publishes an original thought leadership post or educational breakdown."""
        # Default high-impact post if none provided
        if not text:
            text = (
                "How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:\n\n"
                "The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance catches them in 800ms. 🧵👇"
            )
            default_media = self.base_dir / "landing" / "assets" / "orbit_cats_pounce.jpg"
            if default_media.exists() and not media_path:
                media_path = str(default_media)

        # 1. Ground-Truth & CVD Gate Validation
        verdict = self.ground_truth_gate.validate_proactive_post(text)
        if not verdict.is_approved:
            logger.warning(f"Ground-Truth Gate Rejected Post: {verdict.rejection_reason}")
            return {"status": "REJECTED_BY_GATE", "reason": verdict.rejection_reason}

        # 2. Check Quota
        if not self.quota_manager.can_perform("POST"):
            logger.warning("Daily or hourly post quota reached.")
            return {"status": "QUOTA_EXCEEDED"}

        # 3. Execution
        post_id = f"post_{int(time.time())}"
        success = False
        if self.dry_run or not self.driver:
            logger.info(f"[DRY-RUN] Publishing original post: {text[:80]}...")
            success = True
        else:
            logger.info(f"Publishing live post via OrbitXDriver: {text[:80]}...")
            success = self.driver.post_tweet(text, media_path=media_path)

        if success:
            self.state_manager.record_action(
                tweet_id=post_id,
                action_type="POST",
                author_handle="_arsoncode",
                content_snippet=text[:120],
                status="SIMULATED" if self.dry_run else "SUCCESS",
            )
            self.quota_manager.record_hourly_action("POST")

        return {
            "status": "SUCCESS" if success else "FAILED",
            "post_id": post_id,
            "text": text,
            "media_path": media_path,
            "character_count": len(text),
            "dry_run": self.dry_run,
        }

    def compute_sleep_duration(self) -> float:
        """Calculates sleep interval with uniform jitter (-8 to +12 minutes)."""
        jitter = random.uniform(-480.0, 720.0)
        effective = max(1800.0, self.nominal_interval + jitter)
        return effective

    def run_loop(self):
        """Continuous 24/7 background execution loop."""
        self.running = True
        logger.info(
            f"Orbit Social Daemon started (Nominal Cadence: {self.nominal_interval}s, DryRun: {self.dry_run})"
        )

        def sig_handler(sig, frame):
            logger.info(f"Received signal {sig}. Terminating gracefully...")
            self.running = False

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        while self.running:
            try:
                self.execute_hourly_cycle()
            except Exception as e:
                logger.error(f"Error during hourly cycle execution: {e}", exc_info=True)
                self.circuit_breaker.trip(TriggerType.NETWORK, str(e))

            if not self.running:
                break

            sleep_s = self.compute_sleep_duration()
            next_run = datetime.datetime.now() + datetime.timedelta(seconds=sleep_s)
            logger.info(
                f"Next cycle scheduled in {sleep_s / 60:.1f} minutes (at {next_run.strftime('%H:%M:%S')}). Sleeping..."
            )

            # Responsive sleep in small increments to catch exit signals
            slept = 0.0
            while self.running and slept < sleep_s:
                time.sleep(min(2.0, sleep_s - slept))
                slept += 2.0

        self._save_daemon_heartbeat("STOPPED")
        if self.driver and hasattr(self.driver, "close"):
            try:
                self.driver.close()
            except Exception:
                pass
        logger.info("Orbit Social Daemon stopped cleanly.")
