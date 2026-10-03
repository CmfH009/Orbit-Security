#!/usr/bin/env python3
"""scripts/run_bounty_radar.py: Automated Bug Bounty Radar & Takeover Sweeper (Act III).

Usage:
    # Run off-peak sweep (only executes if current time is 2:00 AM - 5:00 AM MST)
    python scripts/run_bounty_radar.py

    # Force sweep immediately across all programs
    python scripts/run_bounty_radar.py --now

    # Sweep specific program (e.g. Shopify or GitLab)
    python scripts/run_bounty_radar.py --program shopify --now

    # Ingest custom HackerOne scope export JSON
    python scripts/run_bounty_radar.py --ingest-h1 path/to/h1_scope.json

    # Inspect radar status and recent findings
    python scripts/run_bounty_radar.py --status
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

from orbit_security.bounty_radar import (
    BountyRadarSupervisor,
    BountyScopeIngester,
    BountyTakeoverSweeper,
    HackerOneDisclosureGenerator,
    OffPeakWindow,
)


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Automated Bug Bounty Radar & HackerOne Takeover Sweeper (Act III)"
    )
    parser.add_argument("--program", "-p", type=str, help="Specific program ID to sweep (e.g. 'shopify', 'gitlab')")
    parser.add_argument("--now", action="store_true", help="Force sweep immediately (override 2:00 AM - 5:00 AM MST off-peak window)")
    parser.add_argument("--max-targets", type=int, default=15, help="Max expanded subdomains per wildcard scope (default: 15)")
    parser.add_argument("--ingest-h1", type=str, help="Path to HackerOne JSON scope export to ingest")
    parser.add_argument("--ingest-bugcrowd", type=str, help="Path to Bugcrowd JSON scope export to ingest")
    parser.add_argument("--passive-ct", action="store_true", help="Passively query Certificate Transparency (crt.sh) logs for real subdomains")
    parser.add_argument("--output-dir", type=str, help="Directory to save generated HackerOne Markdown disclosures")
    parser.add_argument("--status", action="store_true", help="Display radar telemetry, programs, and recent findings")

    args = parser.parse_args()

    ingester = BountyScopeIngester()

    if args.ingest_h1:
        path = Path(args.ingest_h1)
        if not path.exists():
            print(f"Error: File not found: {path}")
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ingested = ingester.ingest_hackerone_scope(data)
        print(f"✓ Ingested {len(ingested)} program(s) from HackerOne scope: {[p.name for p in ingested]}")
        return

    if args.ingest_bugcrowd:
        path = Path(args.ingest_bugcrowd)
        if not path.exists():
            print(f"Error: File not found: {path}")
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ingested = ingester.ingest_bugcrowd_scope(data)
        print(f"✓ Ingested {len(ingested)} program(s) from Bugcrowd scope: {[p.name for p in ingested]}")
        return

    supervisor = BountyRadarSupervisor(ingester=ingester)

    if args.status:
        st = supervisor.state
        print("\n" + "=" * 70)
        print(" 🎯 ORBIT SECURITY: BUG BOUNTY RADAR STATUS")
        print("=" * 70)
        print(f" Last Sweep (UTC):            {st.get('last_sweep_utc') or 'Never'}")
        print(f" Total Sweeps Run:            {st.get('total_sweeps', 0)}")
        print(f" Total Vulnerabilities Found: {st.get('total_vulnerabilities_found', 0)}")
        print(f" Active Programs Enrolled:    {len(ingester.list_programs())}")
        print("\nPrograms:")
        for p in ingester.list_programs():
            print(f"  • {p.name:<20} ({p.platform.title()}) [{len(p.in_scope)} wildcard scopes] Max: ${p.max_bounty}")
        recent = st.get("recent_findings", [])
        if recent:
            print("\nRecent Findings:")
            for r in recent:
                print(f"  - [{r.get('severity')}] {r.get('target_domain')} ({r.get('flaw_type')} - {r.get('provider') or 'Mail'})")
        print("=" * 70 + "\n")
        return

    print("\n" + "=" * 70)
    print(" 🎯 ORBIT SECURITY: AUTOMATED BUG BOUNTY RADAR SWEEP")
    print("=" * 70)

    is_off_peak = OffPeakWindow.is_off_peak()
    print(f" Off-Peak Window (2:00 AM - 5:00 AM MST): {'🟢 IN WINDOW' if is_off_peak else '🟡 OUTSIDE WINDOW'}")

    res = supervisor.run_sweep(
        program_id=args.program,
        force_now=args.now,
        max_domains_per_program=args.max_targets,
        use_passive_ct=args.passive_ct,
        output_dir=Path(args.output_dir) if args.output_dir else None,
    )

    if res.get("status") == "SKIPPED_OUTSIDE_WINDOW":
        print(f"\n⚠️  {res.get('message')}")
        print("Tip: Run with --now to bypass the off-peak restriction.")
        return

    print(f"\n✓ Sweep Completed.")
    print(f"  • Programs Scanned:         {res.get('programs_scanned')}")
    print(f"  • Vulnerabilities Detected: {res.get('vulnerabilities_found')}")

    disclosed = res.get("disclosed_files", [])
    if disclosed:
        print(f"\n📄 Generated HackerOne Disclosures ({len(disclosed)}):")
        for f in disclosed:
            print(f"  - {f}")
    else:
        print("  • No new takeover or spoofing vulnerabilities detected in scanned scopes.")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    main()
