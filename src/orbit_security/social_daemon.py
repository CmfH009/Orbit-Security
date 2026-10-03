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
        nominal_interval_seconds: int = 7200,
        dry_run: bool = False,
        driver: Optional[Any] = None,
        driver_mode: str = "headless",
        state_file: Optional[Union[str, Path]] = None,
        state_manager: Optional[SocialStateManager] = None,
    ):
        self.nominal_interval = nominal_interval_seconds
        self.dry_run = dry_run
        self.running = False
        self.driver = driver
        self.driver_mode = driver_mode.lower()

        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.is_custom_state = state_file is not None
        self.state_file = Path(state_file) if state_file else self.base_dir / "data" / "social_daemon_state.json"

        # Initialize driver if none provided and not dry_run
        if self.driver is None and not self.dry_run:
            self._ensure_driver()

        # Core subsystems
        self.state_manager = state_manager or SocialStateManager()
        self.quota_manager = SocialQuotaManager(state_manager=self.state_manager)
        self.circuit_breaker = SocialCircuitBreaker(state_manager=self.state_manager)
        self.relevance_engine = RelevanceEngine(project_root=self.base_dir)
        self.ground_truth_gate = GroundTruthGate(max_audit_age_minutes=30)
        self.content_queue = ContentQueue(project_root=self.base_dir)
        self.harvester = FeedHarvester(driver=self.driver, dry_run=self.dry_run)
        from orbit_security.social_lead_enricher import SocialLeadEnricher
        self.lead_enricher = SocialLeadEnricher(leads_file=self.base_dir / "data" / "social_leads.json")

    def close_driver(self):
        """Closes and releases active driver cleanly."""
        if self.driver is not None:
            if hasattr(self.driver, "close"):
                try:
                    self.driver.close()
                except Exception:
                    pass
            self.driver = None

    def _ensure_driver(self) -> Optional[Any]:
        """Ensures an active, healthy browser driver is connected."""
        if self.dry_run:
            return None

        # Verify existing driver liveness
        if self.driver is not None:
            is_healthy = False
            if hasattr(self.driver, "is_alive"):
                is_healthy = self.driver.is_alive()
            elif hasattr(self.driver, "is_available"):
                is_healthy = self.driver.is_available()
            elif hasattr(self.driver, "page") and self.driver.page and not self.driver.page.is_closed():
                try:
                    self.driver.page.evaluate("() => true")
                    is_healthy = True
                except Exception:
                    is_healthy = False

            if is_healthy:
                return self.driver
            else:
                logger.warning("Existing driver disconnected or target closed. Recycling driver.")
                self.close_driver()

        # 1. Default: Pure Headless Stealth Patchright via Multi-Adapter Proxy
        if self.driver_mode in ("headless", "auto"):
            try:
                from orbit_security.x_driver import OrbitXDriver, DriverConfig
                config = DriverConfig(
                    headless=True,
                    proxy={"server": "http://127.0.0.1:8989"},
                    use_desktop_driver=False,
                    desktop_fallback=False,
                )
                drv = OrbitXDriver(config=config)
                drv.start()
                if drv.is_authenticated:
                    self.driver = drv
                    logger.info("Initialized headless OrbitXDriver (stealth Patchright via proxy).")
                    if hasattr(self, "harvester") and self.harvester:
                        self.harvester.driver = self.driver
                    return self.driver
                else:
                    logger.warning("Headless OrbitXDriver started but authentication check was false.")
            except Exception as e:
                logger.warning(f"Could not initialize headless OrbitXDriver: {e}")

        # 2. Desktop driver only if explicitly requested via driver_mode='desktop'
        if self.driver_mode == "desktop":
            try:
                from orbit_security.desktop_x_bridge import DesktopAutomationDriver
                desktop_drv = DesktopAutomationDriver()
                if desktop_drv.is_available():
                    self.driver = desktop_drv
                    logger.info("Initialized DesktopAutomationDriver hooked to active Chrome window.")
                    if hasattr(self, "harvester") and self.harvester:
                        self.harvester.driver = self.driver
                    return self.driver
            except Exception as e:
                logger.debug(f"DesktopAutomationDriver initialization skipped: {e}")

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
    def execute_hourly_cycle(self) -> Dict[str, Any]:
        """Executes a single hourly cycle conforming to all anti-bot quotas."""
        cycle_start = time.time()
        logger.info("=== Starting Orbit Social Hourly Execution Cycle ===")

        # 0. Emergency Quarantine Check
        stop_file = self.state_file.parent / "EMERGENCY_STOP" if self.is_custom_state else self.base_dir / "data" / "EMERGENCY_STOP"
        if not self.dry_run and stop_file.exists() and not getattr(self, "force_cycle", False):
            logger.warning("EMERGENCY STOP ACTIVE: Account flagged on X. Aborting cycle immediately to protect account.")
            self.circuit_breaker.trip(TriggerType.AUTH, "Account flagged on X - manual review in progress")
            self._save_daemon_heartbeat("QUARANTINED_ACCOUNT_REVIEW")
            return {"status": "EMERGENCY_STOP", "reason": "Account flagged on X - manual review in progress"}

        self.quota_manager.reset_hourly_cycle()
        self._save_daemon_heartbeat("EXECUTING_CYCLE")

        # 1. Circuit Breaker Check
        available, reason = self.circuit_breaker.is_available()
        if not available:
            logger.warning(f"Skipping cycle: Circuit Breaker active ({reason})")
            return {"status": "CIRCUIT_OPEN", "reason": reason}

        # 2. Ensure driver is ready if not dry_run
        if not self.dry_run:
            self._ensure_driver()
            if not self.driver:
                logger.warning("No active browser driver available for social cycle. Yielding.")
                self._save_daemon_heartbeat("DRIVER_UNAVAILABLE")
                return {"status": "DRIVER_UNAVAILABLE"}

        # 3. Hardware Governor Check (skipped for dry-run or forced cycles)
        if not self.dry_run and not getattr(self, "force_cycle", False):
            if not self._check_hardware_governor():
                logger.info("Hardware governor pacing: yielding cycle early.")
                return {"status": "PACED_BY_HARDWARE"}

        # 4. Multiplier Check (Uniform 24/7 round-the-clock cadence)
        multiplier = self.quota_manager.get_time_of_day_multiplier()
        actions_performed = 0

        # 5. Proactive Staged Content Publication (Original Post)
        # Scaled back to twice a day with minimum inter-post spacing (e.g. morning/evening)
        if self.quota_manager.can_perform("POST", allow_dormant=True, ignore_spacing=getattr(self, "force_cycle", False)):
            queued_post = self.content_queue.get_next_queued_post(
                self.state_manager, allow_generative=True
            )
            if queued_post:
                m_type = queued_post.get("media_type", "media")
                m_name = Path(queued_post.get("media_path") or "").name
                logger.info(
                    f"Dispatching queued staged post: [{queued_post['id']}] {queued_post['title']} "
                    f"({m_type.upper()}: {m_name})"
                )
                res = self.publish_original_post(
                    post_id=queued_post["id"],
                    text=queued_post["text"],
                    media_path=queued_post.get("media_path"),
                    ignore_spacing=getattr(self, "force_cycle", False),
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
            logger.info("POST quota reached or spacing active (scaled to twice a day). Proceeding with continuous following & engagement.")

        # 6. Harvest Inbound Interactions & Lead Enrichment (Act II)
        if self.driver and hasattr(self.driver, "harvest_inbound_interactions"):
            try:
                inbound_interactions = self.driver.harvest_inbound_interactions(limit=10)
                if inbound_interactions:
                    logger.info(f"Discovered {len(inbound_interactions)} inbound interactions for lead qualification.")
                    asyncio.run(self.lead_enricher.scan_interactions(inbound_interactions))
            except Exception as e:
                logger.warning(f"Inbound lead enrichment sweep error: {e}")

        # 7. Multi-Vector Post Harvesting
        candidates = self.harvester.harvest_hourly_candidates(max_candidates=20)
        logger.info(f"Processing {len(candidates)} discovered candidates this cycle.")

        # 8. Evaluate and Execute Candidates
        for post in candidates:
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
                logger.debug(f"Automated commenting/replying disabled by policy. Skipping post {post.tweet_id}.")
                continue

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
        # Ensure browser/driver resources are released cleanly before entering long sleep
        self.close_driver()
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
        ignore_spacing: bool = False,
    ) -> Dict[str, Any]:
        """Publishes an original thought leadership post or educational breakdown with media."""
        # Default high-impact post if none provided
        if not text:
            text = (
                "How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:\n\n"
                "The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance catches them in 800ms. 🧵👇\n"
                "https://cmfh009.github.io/Orbit-Security/"
            )

        final_post_id = post_id or f"post_{int(time.time())}"

        # If media_path is None, autonomously synthesize or bind fresh alternating media
        if not media_path:
            last_info = (
                self.state_manager.get_last_post_media_info()
                if hasattr(self.state_manager, "get_last_post_media_info")
                else None
            )
            last_type = last_info.get("media_type") if last_info else None
            req_type = "video" if last_type == "image" else "image"
            recent_media = (
                self.state_manager.get_recent_media_paths(limit=15)
                if hasattr(self.state_manager, "get_recent_media_paths")
                else []
            )
            recent_media_names = {Path(p).name for p in recent_media}

            if req_type == "video":
                try:
                    card = self.content_queue.creative_engine.media_gen.generate_telemetry_radar_card()
                    vid = self.content_queue.creative_engine.video_gen.generate_video_short(
                        script_text=text[:120] if text else "Orbit Security perimeter scan complete.",
                        image_path=card,
                        title=f"auto_{final_post_id}",
                    )
                    media_path = str(vid)
                except Exception as e:
                    logger.error(f"Error synthesizing video fallback: {e}")
            else:
                try:
                    card = self.content_queue.creative_engine.media_gen.generate_dns_attack_diagram()
                    media_path = str(card)
                except Exception as e:
                    logger.error(f"Error synthesizing image fallback: {e}")

        # Detect media type from path
        ext = Path(media_path).suffix.lower() if media_path else ""
        media_type = "video" if ext in (".mp4", ".webm", ".mov", ".mkv") else "image"

        # 1. Ground-Truth & CVD Gate Validation
        verdict = self.ground_truth_gate.validate_proactive_post(text)
        if not verdict.is_approved:
            logger.warning(f"Ground-Truth Gate Rejected Post: {verdict.rejection_reason}")
            return {"status": "REJECTED_BY_GATE", "reason": verdict.rejection_reason}

        # 2. Driver Availability Guard
        if not self.dry_run and not self.driver:
            logger.error(f"Cannot publish original post [{final_post_id}]: No active driver connected.")
            return {"status": "DRIVER_UNAVAILABLE"}

        # 3. Check Quota (scaled to twice a day with inter-post spacing)
        allow_dormant = self.dry_run or getattr(self, "force_cycle", False)
        eff_ignore_spacing = ignore_spacing or self.dry_run or getattr(self, "force_cycle", False)
        if not self.quota_manager.can_perform("POST", allow_dormant=allow_dormant, ignore_spacing=eff_ignore_spacing):
            logger.warning("Daily post quota (2/day) or minimum inter-post spacing active.")
            return {"status": "QUOTA_EXCEEDED"}

        # 4. Execution
        success = False
        if self.dry_run:
            logger.info(
                f"[DRY-RUN] Publishing original post [{final_post_id}] ({media_type.upper()}: {Path(media_path or '').name}): {text[:80]}..."
            )
            success = True
        elif self.driver:
            logger.info(
                f"Publishing live post [{final_post_id}] via OrbitXDriver ({media_type.upper()}: {Path(media_path or '').name}): {text[:80]}..."
            )
            try:
                success = self.driver.post_tweet(text, media_path=media_path)
            except Exception as e:
                logger.error(f"Driver post_tweet raised exception: {e}")
                self.close_driver()
                self._ensure_driver()
                if self.driver:
                    try:
                        success = self.driver.post_tweet(text, media_path=media_path)
                    except Exception as e2:
                        logger.error(f"Retry post_tweet also failed: {e2}")
                        success = False
                else:
                    success = False
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
                metadata={
                    "media_path": str(media_path) if media_path else None,
                    "media_type": media_type,
                    "media_name": Path(media_path).name if media_path else None,
                },
            )
            self.quota_manager.record_hourly_action("POST")

        return {
            "status": "SUCCESS" if success else "FAILED",
            "post_id": final_post_id,
            "text": text,
            "media_path": media_path,
            "media_type": media_type,
            "character_count": len(text),
            "dry_run": self.dry_run,
        }

    def compute_sleep_duration(self) -> float:
        """Calculates sleep interval with uniform jitter (-7 to +8 minutes around nominal cadence)."""
        jitter = random.uniform(-420.0, 480.0)
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
                self.close_driver()
                cycle_result = {"status": "ERROR"}

            if not self.running:
                break

            status = cycle_result.get("status") if isinstance(cycle_result, dict) else ""
            if status == "ERROR":
                sleep_s = 300.0
                logger.info(f"Cycle resulted in error. Retrying in {sleep_s / 60:.1f} minutes after recycling driver...")
            elif status in ("PACED_BY_HARDWARE", "DRIVER_UNAVAILABLE"):
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

        self.close()

    def close(self):
        """Clean shutdown of browser context and daemon heartbeat."""
        self._save_daemon_heartbeat("STOPPED")
        if self.driver and hasattr(self.driver, "close"):
            try:
                self.driver.close()
            except Exception:
                pass
        self.driver = None
        logger.info("Orbit Social Daemon stopped cleanly.")
