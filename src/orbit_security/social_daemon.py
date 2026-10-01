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
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import random
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from orbit_security.circuit_breaker import BreakerState, SocialCircuitBreaker, TriggerType
from orbit_security.content_queue import ContentQueue
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
from orbit_security.smart_follow import SmartFollowEngine
from orbit_security.social_state import SocialStateManager

logger = logging.getLogger("orbit_security.social_daemon")

def setup_daemon_logging():
    """Sets up dual console and rotating file logging for social daemon."""
    log_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [ORBIT-SOCIAL] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root_log = logging.getLogger()
    root_log.setLevel(logging.INFO)

    # Local data log file
    data_log = Path(__file__).resolve().parent.parent.parent / "data" / "social_daemon.log"
    data_log.parent.mkdir(parents=True, exist_ok=True)
    if not any(getattr(h, "baseFilename", None) == str(data_log) for h in root_log.handlers):
        try:
            rfh = RotatingFileHandler(str(data_log), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
            rfh.setFormatter(log_formatter)
            root_log.addHandler(rfh)
        except Exception:
            pass

    # System log file
    sys_log = Path("A:/system/logs/orbit_social.log")
    if sys_log.parent.exists() and not any(getattr(h, "baseFilename", None) == str(sys_log) for h in root_log.handlers):
        try:
            srfh = RotatingFileHandler(str(sys_log), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
            srfh.setFormatter(log_formatter)
            root_log.addHandler(srfh)
        except Exception:
            pass

setup_daemon_logging()


class SocialDaemon:
    """Master runner for the autonomous social outreach and intelligence pipeline."""

    ARCADE_URL = "https://cmfh009.github.io/Orbit-Security/"

    def __init__(
        self,
        nominal_interval_seconds: int = 3600,
        dry_run: bool = False,
        driver: Optional[Any] = None,
        driver_mode: str = "auto",
    ):
        self.nominal_interval = nominal_interval_seconds
        self.dry_run = dry_run
        self.running = False
        self.driver = driver
        self.driver_mode = driver_mode.lower()

        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.state_file = self.base_dir / "data" / "social_daemon_state.json"

        # Initialize driver if none provided and not dry_run
        if self.driver is None and not self.dry_run:
            self._ensure_driver()

        # Core subsystems
        self.state_manager = SocialStateManager()
        self.quota_manager = SocialQuotaManager(state_manager=self.state_manager)
        self.circuit_breaker = SocialCircuitBreaker(state_manager=self.state_manager)
        self.relevance_engine = RelevanceEngine(project_root=self.base_dir)
        self.ground_truth_gate = GroundTruthGate(max_audit_age_minutes=30)
        self.content_queue = ContentQueue(project_root=self.base_dir)
        self.harvester = FeedHarvester(driver=self.driver, dry_run=self.dry_run)
        self.smart_follow = SmartFollowEngine(project_root=self.base_dir)

    def _ensure_driver(self) -> Optional[Any]:
        """Ensures an active, healthy browser driver is connected."""
        if self.dry_run:
            return None
        if self.driver is not None:
            if hasattr(self.driver, "is_authenticated") and self.driver.is_authenticated:
                return self.driver
            if hasattr(self.driver, "page") and self.driver.page and not self.driver.page.is_closed():
                return self.driver

        # 1. Prefer authenticated desktop window if mode is 'auto' or 'desktop'
        if self.driver_mode in ("auto", "desktop"):
            try:
                from orbit_security.desktop_x_bridge import DesktopAutomationDriver
                desktop_drv = DesktopAutomationDriver()
                if desktop_drv.is_available() or self.driver_mode == "desktop":
                    self.driver = desktop_drv
                    logger.info("Initialized DesktopAutomationDriver hooked to active Chrome window.")
                    if hasattr(self, "harvester") and self.harvester:
                        self.harvester.driver = self.driver
                    return self.driver
            except Exception as e:
                logger.debug(f"DesktopAutomationDriver initialization skipped: {e}")

        # 2. Headless OrbitXDriver (stealth Patchright)
        try:
            from orbit_security.x_driver import OrbitXDriver, DriverConfig
            config = DriverConfig(headless=True)
            drv = OrbitXDriver(config=config)
            drv.start()
            self.driver = drv
            logger.info(f"Initialized Headless OrbitXDriver (is_authenticated={drv.is_authenticated}).")
            if hasattr(self, "harvester") and self.harvester:
                self.harvester.driver = self.driver
            return self.driver
        except Exception as e:
            logger.warning(f"Could not initialize headless OrbitXDriver: {e}")
            self.driver = None
            return None

    def _check_hardware_governor(self) -> bool:
        """Verifies host CPU and RAM status before initiating heavy operations."""
        try:
            import psutil
            for _ in range(5):
                cpu = psutil.cpu_percent(interval=0.5)
                if cpu <= 88.0:
                    break
                time.sleep(2.0)
            else:
                logger.warning(f"Host CPU sustained elevated ({cpu}% > 88.0%). Pacing social daemon.")
                return False

            vm = psutil.virtual_memory()
            free_mb = vm.available / (1024 * 1024)
            if free_mb < 600.0:
                logger.warning(f"Host RAM constrained ({free_mb:.0f}MB < 600MB). Yielding cycle.")
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
            self._save_daemon_heartbeat("SLEEPING")
            return {"status": "DORMANT_WINDOW"}

        # Ensure driver is ready if not dry_run
        if not self.dry_run:
            self._ensure_driver()
            if not self.driver:
                logger.warning("No active browser driver available for social cycle. Yielding.")
                self._save_daemon_heartbeat("DRIVER_UNAVAILABLE")
                return {"status": "DRIVER_UNAVAILABLE"}

        actions_performed = 0

        # 4. Proactive Staged Content Publication (Hourly Original Post)
        if self.quota_manager.can_perform("POST"):
            queued_post = self.content_queue.get_next_queued_post(
                self.state_manager, allow_generative=True
            )
            if queued_post:
                logger.info(f"Dispatching queued staged post: [{queued_post['id']}] {queued_post['title']}")
                res = self.publish_original_post(
                    post_id=queued_post["id"],
                    text=queued_post["text"],
                    media_path=queued_post.get("media_path"),
                )
                if res.get("status") == "SUCCESS":
                    actions_performed += 1
                    # Organic delay after posting before harvesting
                    micro_delay = random.uniform(30.0, 60.0) if not self.dry_run else 0.1
                    logger.info(f"Pacing: sleeping {micro_delay:.1f}s after original post before harvesting...")
                    time.sleep(micro_delay)
            else:
                logger.info("ContentQueue: All staged posts currently marked as published.")
        else:
            logger.info("Hourly POST quota currently exhausted. Skipping proactive publication.")

        # 5. Multi-Vector Post Harvesting
        candidates = self.harvester.harvest_hourly_candidates(max_candidates=20)
        logger.info(f"Processing {len(candidates)} discovered candidates this cycle.")

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
                if self.dry_run:
                    success = True
                elif self.driver:
                    success = self.driver.like_tweet(f"https://x.com/{post.author_handle}/status/{post.tweet_id}")
                else:
                    success = False

            elif decision.action in (ActionType.REPOST, ActionType.QUOTE):
                logger.info(f"Action Dispatch: {action_name} on @{post.author_handle} (Tweet: {post.tweet_id}) | Score: {score.total_score}")
                if self.dry_run:
                    success = True
                elif self.driver:
                    success = self.driver.repost_tweet(f"https://x.com/{post.author_handle}/status/{post.tweet_id}")
                else:
                    success = False

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
                    if self.dry_run:
                        success = True
                    elif self.driver:
                        success = self.driver.reply_to_tweet(
                            f"https://x.com/{post.author_handle}/status/{post.tweet_id}",
                            reply_text,
                        )
                    else:
                        success = False
                else:
                    # Educational reply without naming unverified third-party targets
                    edu_reply = (
                        f"@{post.author_handle} DNS drift post-launch is often the blind spot. "
                        f"Stale records pointing to canceled SaaS endpoints (Unbounce, S3, Webflow) "
                        f"remain unmonitored until hijacked. Continuous RFC 1035 & 8484 diffing is key."
                    )
                    content_snippet = edu_reply
                    if self.dry_run:
                        success = True
                    elif self.driver:
                        success = self.driver.reply_to_tweet(
                            f"https://x.com/{post.author_handle}/status/{post.tweet_id}",
                            edu_reply,
                        )
                    else:
                        success = False

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

        # 6. Autonomous Smart Following Step (Agent 1: @OrbitScout)
        if self.quota_manager.can_perform("FOLLOW") and self.smart_follow.can_follow_today():
            target = self.smart_follow.select_seed_target()
            if target:
                handle = target["handle"]
                logger.info(
                    f"Action Dispatch: FOLLOW on @{handle} ({target.get('category')}) via @OrbitScout"
                )
                follow_success = False
                if self.dry_run:
                    follow_success = True
                elif self.driver and hasattr(self.driver, "follow_user"):
                    try:
                        follow_success = self.driver.follow_user(handle)
                    except Exception as e:
                        logger.warning(f"Driver follow failed for @{handle}: {e}")
                else:
                    follow_success = False

                if follow_success:
                    self.smart_follow.record_follow_success(
                        handle=handle,
                        category=target.get("category", "infosec"),
                        notes=f"Followed via @OrbitScout (Authority: {target.get('authority_weight')})",
                        discovered_via="seed",
                    )
                    self.quota_manager.record_hourly_action("FOLLOW")
                    self.state_manager.record_action(
                        tweet_id=f"follow_{handle}",
                        action_type="FOLLOW",
                        author_handle=handle,
                        status="SIMULATED" if self.dry_run else "SUCCESS",
                    )
                    actions_performed += 1

        # 7. Export JSON snapshot & commit telemetry
        snapshot = self.state_manager.export_json_snapshot()
        duration = round(time.time() - cycle_start, 2)
        logger.info(
            f"=== Cycle Complete in {duration}s. Actions: {actions_performed} | "
            f"Daily Totals: {snapshot.get('today_metrics')} ==="
        )
        self._save_daemon_heartbeat("SLEEPING")

        return {
            "status": "COMPLETED",
            "actions_count": actions_performed,
            "duration_seconds": duration,
        }

    def publish_original_post(
        self,
        post_id: Optional[str] = None,
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
        final_post_id = post_id or f"post_{int(time.time())}"
        success = False
        if self.dry_run:
            logger.info(f"[DRY-RUN] Publishing original post [{final_post_id}]: {text[:80]}...")
            success = True
        elif self.driver:
            logger.info(f"Publishing live post [{final_post_id}] via OrbitXDriver: {text[:80]}...")
            success = self.driver.post_tweet(text, media_path=media_path)
        else:
            logger.error(f"Cannot publish original post [{final_post_id}]: No active driver connected.")
            return {"status": "DRIVER_UNAVAILABLE"}

        if success:
            self.state_manager.record_action(
                tweet_id=final_post_id,
                action_type="POST",
                author_handle="_arsoncode",
                content_snippet=text[:120],
                status="SIMULATED" if self.dry_run else "SUCCESS",
            )
            self.quota_manager.record_hourly_action("POST")

        return {
            "status": "SUCCESS" if success else "FAILED",
            "post_id": final_post_id,
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
            cycle_result = {}
            try:
                cycle_result = self.execute_hourly_cycle()
            except Exception as e:
                logger.error(f"Error during hourly cycle execution: {e}", exc_info=True)
                self.circuit_breaker.trip(TriggerType.NETWORK, str(e))
                cycle_result = {"status": "ERROR"}

            if not self.running:
                break

            status = cycle_result.get("status") if isinstance(cycle_result, dict) else ""
            if status in ("PACED_BY_HARDWARE", "DRIVER_UNAVAILABLE"):
                sleep_s = 120.0
                logger.info(f"Cycle yielded ({status}). Retrying in 2.0 minutes...")
            else:
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
