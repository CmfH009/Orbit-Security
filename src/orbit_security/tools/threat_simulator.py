#!/usr/bin/env python3
"""orbit_security.tools.threat_simulator: Offline Threat Simulation & Blackboard Replay Engine.
========================================================================================
Injects high-fidelity synthetic threat events into the SQLite WAL Blackboard:
- Validates real-time Server-Sent Events (SSE) reactivity on :9090.
- Stress-tests Cockpit HUD 3D Attack Surface Canvas and toast notifications.
- Supports high-concurrency burst mode (100+ events) and paced playback mode.
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orbit_security.threat_simulator")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Standardized Synthetic Attack Scenarios
SCENARIOS: Dict[str, Dict[str, Any]] = {
    "dangling_s3_takeover": {
        "topic": "perimeter",
        "event_type": "SUBDOMAIN_TAKEOVER_DETECTED",
        "source": "threat_simulator",
        "payload": {
            "domain": "staging.client-sim.agency",
            "cname": "client-sim-assets.s3.amazonaws.com",
            "service": "AWS S3",
            "confidence": 0.98,
            "simulated": True,
            "remediation_hint": "Claim s3 bucket client-sim-assets or remove orphaned CNAME.",
        },
    },
    "cisa_kev_weaponized": {
        "topic": "cve_radar",
        "event_type": "CISA_KEV_MATCH_DETECTED",
        "source": "threat_simulator",
        "payload": {
            "cve_id": "CVE-2024-21887",
            "product": "Connect Secure",
            "vendor": "Ivanti",
            "matched_header": "Server: Ivanti-Connect-Secure/9.1R18",
            "vulnerability_name": "Ivanti Connect Secure Command Injection",
            "due_date": "2024-01-22",
            "ransomware_flag": "Known",
            "domain": "vpn-gateway.client-sim.agency",
            "simulated": True,
        },
    },
    "tls_wildcard_expiry": {
        "topic": "perimeter",
        "event_type": "TLS_EXPIRATION_CRITICAL",
        "source": "threat_simulator",
        "payload": {
            "domain": "*.client-sim.agency",
            "issuer": "Let's Encrypt Authority X3",
            "days_remaining": 2,
            "simulated": True,
            "severity": "CRITICAL",
        },
    },
    "ssrf_attempt_blocked": {
        "topic": "security_guardrail",
        "event_type": "SSRF_ATTEMPT_BLOCKED",
        "source": "threat_simulator",
        "payload": {
            "target_host": "169.254.169.254",
            "source_scanner": "recon_prober",
            "status": "REJECTED_CLOUD_METADATA_IP",
            "simulated": True,
        },
    },
    "dmarc_spoofing_risk": {
        "topic": "perimeter",
        "event_type": "EMAIL_POSTURE_CRITICAL",
        "source": "threat_simulator",
        "payload": {
            "domain": "client-sim.agency",
            "dmarc_record": "v=DMARC1; p=none;",
            "risk": "Spoofing / Phishing impersonation allowed (policy is none)",
            "simulated": True,
        },
    },
    "ct_log_new_subdomain": {
        "topic": "threat_intel",
        "event_type": "CT_LOG_NEW_SUBDOMAIN",
        "source": "threat_simulator",
        "payload": {
            "subdomain": "shadow-api.client-sim.agency",
            "apex_domain": "client-sim.agency",
            "source_feed": "certificate_transparency",
            "issuer": "C=US, O=Let's Encrypt, CN=R3",
            "simulated": True,
        },
    },
    "epss_critical_fusion": {
        "topic": "cve_radar",
        "event_type": "CRITICAL_0DAY_CORRELATED",
        "source": "threat_simulator",
        "payload": {
            "cve_id": "CVE-2024-21887",
            "domain": "remote-access.client-sim.agency",
            "in_cisa_kev": True,
            "epss_score": 0.942,
            "threat_level": "CRITICAL_ACTUALLY_EXPLOITED_IN_WILD",
            "simulated": True,
        },
    },
}


class ThreatSimulator:
    """Injects high-fidelity synthetic threat events into the SQLite WAL Blackboard."""

    def __init__(self, blackboard: Optional[Any] = None, dry_run: bool = False):
        self.dry_run = dry_run
        self._blackboard = blackboard

    @property
    def blackboard(self) -> Any:
        if self._blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self._blackboard = get_blackboard()
        return self._blackboard

    def inject_scenario(self, scenario_id: str, extra_payload: Optional[Dict[str, Any]] = None) -> bool:
        """Injects a specific scenario into the Blackboard."""
        scenario = SCENARIOS.get(scenario_id)
        if not scenario:
            logger.error(f"Unknown scenario: '{scenario_id}'")
            return False

        payload = dict(scenario["payload"])
        if extra_payload:
            payload.update(extra_payload)
        payload["simulated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if self.dry_run:
            print(f"[DRY-RUN] Emitted {scenario['event_type']} ({scenario['topic']}) -> {payload.get('domain', 'N/A')}")
            return True

        self.blackboard.publish(
            event_type=scenario["event_type"],
            payload=payload,
            source=scenario["source"],
            topic=scenario["topic"],
        )
        return True

    def run_burst(self, count: int = 100) -> int:
        """Injects high-volume synthetic events rapidly to test SQLite WAL concurrency."""
        scenario_keys = list(SCENARIOS.keys())
        cycle_keys = itertools.cycle(scenario_keys)
        injected = 0

        print(f"[*] Starting burst simulation of {count} events...")
        start_t = time.perf_counter()

        for i in range(count):
            sc_key = next(cycle_keys)
            self.inject_scenario(sc_key, extra_payload={"burst_index": i})
            injected += 1

        elapsed = time.perf_counter() - start_t
        print(f"[✓] Burst complete: {injected} events injected in {elapsed:.3f}s ({injected / max(elapsed, 0.001):.1f} eps)")
        return injected

    def run_playback(self, count: int = 10, interval_sec: float = 2.0) -> int:
        """Injects spaced events for real-time visual inspection in Cockpit UI."""
        scenario_keys = list(SCENARIOS.keys())
        cycle_keys = itertools.cycle(scenario_keys)
        injected = 0

        print(f"[*] Starting playback simulation: {count} events @ {interval_sec}s interval...")
        for i in range(count):
            sc_key = next(cycle_keys)
            sc_info = SCENARIOS[sc_key]
            self.inject_scenario(sc_key, extra_payload={"playback_index": i})
            injected += 1
            print(f"  [{i + 1}/{count}] Emitted {sc_info['event_type']} ({sc_info['topic']})")
            if interval_sec > 0 and i < count - 1:
                time.sleep(interval_sec)

        print(f"[✓] Playback complete: {injected} events emitted.")
        return injected


def main() -> int:
    parser = argparse.ArgumentParser(description="Orbit Offline Threat Simulator & Replay Engine")
    parser.add_argument("--scenario", "-s", choices=list(SCENARIOS.keys()) + ["all"], default="all")
    parser.add_argument(
        "--burst",
        "-b",
        nargs="?",
        const=100,
        type=int,
        default=None,
        help="Inject N events at max speed for concurrency testing (default: 100)",
    )
    parser.add_argument(
        "--playback",
        "-p",
        nargs="?",
        const=10,
        type=float,
        default=None,
        help="Playback mode: event count or spacing interval in seconds",
    )
    parser.add_argument("--interval", "-i", type=float, default=1.5, help="Playback interval in seconds (default: 1.5)")
    parser.add_argument("--dry-run", action="store_true", help="Print simulated events without inserting into Blackboard")
    args = parser.parse_args()

    sim = ThreatSimulator(dry_run=args.dry_run)

    if args.burst is not None:
        sim.run_burst(count=args.burst)
        return 0

    if args.scenario != "all":
        sim.inject_scenario(args.scenario)
        print(f"[✓] Injected single scenario: {args.scenario}")
        return 0

    interval = args.interval
    count = 10
    if args.playback is not None:
        if args.playback <= 0:
            count = 5
        elif args.playback < 5.0 and not float(args.playback).is_integer():
            interval = float(args.playback)
            count = 10
        else:
            count = int(args.playback)

    sim.run_playback(count=count, interval_sec=interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
