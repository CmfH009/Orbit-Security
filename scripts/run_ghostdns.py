#!/usr/bin/env python3
"""scripts/run_ghostdns.py: GhostDNS Headless Scanner & Drift Sentinel CLI.

Usage:
    # Run full headless audit on a store domain
    python scripts/run_ghostdns.py --domain candykittens.co.uk

    # Capture authoritative DNS baseline for a domain
    python scripts/run_ghostdns.py --domain brand.com --snapshot

    # Check for silent DNS drift against saved baseline
    python scripts/run_ghostdns.py --domain brand.com --check-drift

    # List all enrolled GhostDNS targets and statuses
    python scripts/run_ghostdns.py --status

    # Register new store target on Store tier ($29/mo)
    python scripts/run_ghostdns.py --register --domain "newstore.com" --client "New Store DTC" --plan Store
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure local src/ is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.ghost_dns import GhostDNSManager


def main():
    parser = argparse.ArgumentParser(
        description="GhostDNS: Dedicated Dangling CNAME & DNS Drift Sentinel ($29/mo Store, $199/mo Agency)"
    )
    parser.add_argument("--domain", "-d", type=str, help="Target domain to scan or snapshot")
    parser.add_argument("--snapshot", action="store_true", help="Capture authoritative baseline snapshot")
    parser.add_argument("--check-drift", action="store_true", help="Check for silent DNS drift against baseline")
    parser.add_argument("--all", action="store_true", help="Run audit on all enrolled targets")
    parser.add_argument("--status", action="store_true", help="Display all enrolled targets and health grades")
    parser.add_argument("--register", action="store_true", help="Enroll a new target domain")
    parser.add_argument("--client", type=str, help="Client/Store name when registering")
    parser.add_argument("--plan", choices=["Store", "Agency"], default="Store", help="Subscription plan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    manager = GhostDNSManager()

    if args.register:
        if not args.domain:
            print("Error: --domain is required when using --register")
            sys.exit(1)
        client_name = args.client or args.domain
        t = manager.register_target(args.domain, client_name=client_name, plan=args.plan)
        baseline = manager.capture_baseline(args.domain)
        print(f"✓ Registered GhostDNS target: {t.domain} (Plan: {t.plan} ${29 if t.plan=='Store' else 199}/mo)")
        print(f"  • Authoritative baseline captured with {len(baseline.records)} record type(s).")
        return

    if args.status:
        targets = list(manager.targets.values())
        if args.json:
            print(json.dumps([t.__dict__ for t in targets], indent=2))
            return

        print("\n" + "=" * 70)
        print(" 👻 GHOSTDNS: MONITORED STORE & AGENCY PERIMETERS")
        print("=" * 70)
        print(f" Enrolled Targets: {len(targets)}")
        print(f" Authoritative Baselines: {len(manager.baselines)}")
        print("-" * 70)
        print(f" {'Domain':<26} {'Plan':<8} {'Score':<10} {'Grade':<8} {'Dangling':<10} {'Drift'}")
        print("-" * 70)
        for t in targets:
            print(
                f" {t.domain:<26} {t.plan:<8} {str(t.last_audit_score) + '/100':<10} {t.last_audit_grade:<8} "
                f"{str(t.dangling_cname_count) + ' CNAMEs':<10} {t.drift_anomalies_count} anomalies"
            )
        print("=" * 70 + "\n")
        return

    if args.snapshot:
        if not args.domain:
            print("Error: --domain is required when capturing snapshot")
            sys.exit(1)
        baseline = manager.capture_baseline(args.domain)
        print(f"✓ Captured baseline for {args.domain}:")
        for rtype, vals in baseline.records.items():
            print(f"  • {rtype:<6} -> {vals}")
        return

    if args.check_drift:
        if not args.domain:
            print("Error: --domain is required when checking drift")
            sys.exit(1)
        anomalies = manager.check_dns_drift(args.domain)
        if anomalies:
            print(f"⚠️  Detected {len(anomalies)} DNS drift anomaly(s) on {args.domain}:")
            for a in anomalies:
                print(f"  - [{a.severity.value}] {a.record_type}: {a.description}")
        else:
            print(f"✓ No DNS drift detected on {args.domain}. State matches authoritative baseline.")
        return

    targets_to_scan = []
    if args.all:
        targets_to_scan = [t.domain for t in manager.targets.values()]
    elif args.domain:
        targets_to_scan = [args.domain]
    else:
        parser.print_help()
        sys.exit(0)

    for domain in targets_to_scan:
        report = manager.execute_audit(domain)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print("\n" + "=" * 70)
            print(f" 👻 GHOSTDNS AUDIT REPORT: {domain.upper()}")
            print("=" * 70)
            print(f" Hygiene Score:      {report.score}/100 (Grade: {report.grade})")
            print(f" Vulnerability Flag: {'🔴 VULNERABLE' if report.is_vulnerable else '🟢 SECURE'}")
            print(f" Dangling CNAMEs:    {len(report.dangling_cnames)}")
            print(f" Drift Anomalies:    {len(report.drift_anomalies)}")
            if report.dangling_cnames:
                print("\nDangling SaaS Pointers:")
                for d in report.dangling_cnames:
                    print(f"  • {d.get('provider')}: CNAME points to {d.get('cname_target')} (Severity: {d.get('severity')})")
            if report.drift_anomalies:
                print("\nDrift Anomalies:")
                for a in report.drift_anomalies:
                    print(f"  • {a.get('record_type')}: {a.get('description')}")
            print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
