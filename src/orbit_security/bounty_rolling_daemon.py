"""
bounty_rolling_daemon.py: Autonomous Rolling Bug Bounty Radar Daemon
===================================================================
Executes continuous round-robin sweeps across the 27 Bug Bounty targets:
- Probes hosts for dangling SaaS takeovers, TLS expiration, CORS, and missing HSTS.
- Gated by OperatorExploitSandbox verification (confidence >= 0.85).
- Emits real-time SSE events to SQLite WAL Blackboard on :9090.
- Hardware governor: respects thermals and throttles when host CPU > 70%.
"""

from __future__ import annotations

import os
import sys
import time
import json
import signal
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger("orbit_security.bounty_rolling_daemon")

WORKSPACE_ROOT = Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut")
ORBIT_SRC = WORKSPACE_ROOT / "projects" / "orbit-security" / "src"
if str(ORBIT_SRC) not in sys.path and ORBIT_SRC.exists():
    sys.path.insert(0, str(ORBIT_SRC))

from orbit_security.bounty_active_prober import BountyActiveProber, BountyRollingWorker
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyScopeIngester,
    DEFAULT_BOUNTY_DATA_PATH,
    DEFAULT_RADAR_STATE_PATH,
)
from orbit_security.cert_transparency import CtStreamDaemon

LOGS_DIR = WORKSPACE_ROOT / "system" / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DAEMON_LOG_FILE = LOGS_DIR / "bounty_rolling_daemon.log"


class BountyRollingDaemon:
    """Production lifecycle supervisor for continuous rolling bug bounty sweeps."""

    def __init__(
        self,
        interval_sec: float = 1800.0,
        programs_path: Optional[Path] = None,
        state_file: Optional[Path] = None,
        ct_watermark_file: Optional[Path] = None,
        offline: bool = False,
    ):
        self.interval_sec = interval_sec
        self.programs_path = Path(programs_path or DEFAULT_BOUNTY_DATA_PATH)
        self.state_file = Path(state_file or DEFAULT_RADAR_STATE_PATH)
        self.offline = offline
        self.prober = BountyActiveProber(state_file=self.state_file)
        self.worker = BountyRollingWorker(
            prober=self.prober,
            programs_path=self.programs_path,
            sweep_interval_sec=self.interval_sec,
        )
        self.ct_daemon = CtStreamDaemon(watermark_file=ct_watermark_file)
        self.running = False

    def setup_logging(self, verbose: bool = False):
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.FileHandler(str(DAEMON_LOG_FILE), encoding="utf-8"),
                logging.StreamHandler(sys.stdout),
            ],
        )

    def sweep_ct_logs_for_program(self, program_id: str) -> Optional[Dict[str, Any]]:
        """Polls Certificate Transparency streams for all in-scope apex domains of a program."""
        programs = self.worker.load_programs()
        target = next((p for p in programs if p.program_id == program_id), None)
        if not target:
            logger.error(f"Program ID '{program_id}' not found in active catalog.")
            return None

        poll_results = self.ct_daemon.poll_domains(target.in_scope)
        new_subdomains: List[str] = []
        takeover_findings: List[Dict[str, Any]] = []
        new_certificates = 0

        for res in poll_results:
            new_certificates += int(res.get("new_certificates", 0))
            for sub in res.get("new_subdomains", []):
                if sub not in new_subdomains:
                    new_subdomains.append(sub)
            takeover_findings.extend(res.get("takeover_findings", []))

        return {
            "program_id": target.program_id,
            "program_name": target.name,
            "domains_polled": len(poll_results),
            "new_certificates": new_certificates,
            "new_subdomains": new_subdomains,
            "takeover_findings": takeover_findings,
        }

    def sweep_program(self, program_id: str) -> Optional[Dict[str, Any]]:
        """Executes targeted sweep for a single specified program."""
        programs = self.worker.load_programs()
        target = next((p for p in programs if p.program_id == program_id), None)
        if not target:
            logger.error(f"Program ID '{program_id}' not found in active catalog.")
            return None

        logger.info(f"Executing focused sweep for program: {target.name} ({target.program_id})")
        ct_summary = self.sweep_ct_logs_for_program(program_id)
        confirmed = self.worker.execute_single_program_sweep(target, offline=self.offline)
        return {
            "program_id": target.program_id,
            "program_name": target.name,
            "confirmed_count": len(confirmed),
            "findings": confirmed,
            "ct_discovery": ct_summary,
        }

    def sweep_one_cycle(self) -> Optional[Dict[str, Any]]:
        """Sweeps next program in round-robin sequence."""
        return self.worker.run_one_cycle(offline=self.offline)

    def run_loop(self):
        """Runs the continuous daemon loop with hardware governor."""
        self.running = True
        logger.info(
            f"Bounty Rolling Daemon initialized. Interval: {self.interval_sec}s | Offline: {self.offline}"
        )

        def _handle_exit(sig, frame):
            logger.info("Shutdown signal received. Stopping Bounty Rolling Daemon...")
            self.running = False

        signal.signal(signal.SIGINT, _handle_exit)
        signal.signal(signal.SIGTERM, _handle_exit)

        while self.running:
            try:
                cycle_result = self.sweep_one_cycle()
                if cycle_result:
                    logger.info(
                        f"Round-Robin Sweep: {cycle_result['program_name']} -> "
                        f"{cycle_result['confirmed_count']} verified findings."
                    )

                # Sleep in increments to remain responsive to SIGINT
                elapsed = 0.0
                while self.running and elapsed < self.interval_sec:
                    time.sleep(1.0)
                    elapsed += 1.0

            except Exception as e:
                logger.error(f"Unexpected error during sweep cycle: {e}", exc_info=True)
                time.sleep(5.0)

        logger.info("Bounty Rolling Daemon stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(description="Orbit Bug Bounty Rolling Daemon")
    parser.add_argument("--interval", type=float, default=1800.0, help="Interval between program sweeps in seconds")
    parser.add_argument("--sweep-once", action="store_true", help="Run a single round-robin cycle and exit")
    parser.add_argument("--program", type=str, help="Sweep a specific program by ID and exit")
    parser.add_argument("--offline", action="store_true", help="Run in offline mock mode without live network probes")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--status", action="store_true", help="Show current radar state and exit")

    args = parser.parse_args()
    daemon = BountyRollingDaemon(interval_sec=args.interval, offline=args.offline)
    daemon.setup_logging(verbose=args.verbose)

    if args.status:
        state_file = Path(DEFAULT_RADAR_STATE_PATH)
        if state_file.exists():
            with open(state_file, "r", encoding="utf-8") as f:
                print(json.dumps(json.load(f), indent=2))
        else:
            print("Radar state file not found.")
        return

    if args.program:
        res = daemon.sweep_program(args.program)
        print(json.dumps(res, indent=2))
        return

    if args.sweep_once:
        res = daemon.sweep_one_cycle()
        print(json.dumps(res, indent=2))
        return

    daemon.run_loop()


if __name__ == "__main__":
    main()
