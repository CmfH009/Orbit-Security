#!/usr/bin/env python3
"""sync_bounty_scopes.py: Bug Bounty Scope Synchronization & Fleet Expansion CLI.

Synchronizes bug bounty wildcard targets and authorized program scopes from public feeds
(e.g. ProjectDiscovery Chaos, HackerOne JSON, Bugcrowd JSON) into Orbit Security's
bounty_programs.json with strict safety constraints (cash tier, out_of_scope enforcement, max fleet limit).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

# Ensure orbit_security package is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.bounty_radar import (
    BountyScopeIngester,
    DEFAULT_BOUNTY_DATA_PATH,
    DEFAULT_RADAR_STATE_PATH,
)


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Bug Bounty Scope Synchronization & Fleet Expansion CLI"
    )
    parser.add_argument(
        "--feed",
        type=str,
        default=None,
        help="Path or HTTP URL to scope feed JSON (Chaos, HackerOne, or Bugcrowd). If omitted, synchronizes and validates the enrolled fleet from data-path.",
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["chaos", "hackerone", "bugcrowd"],
        default="chaos",
        help="Feed schema format (default: chaos)",
    )
    parser.add_argument(
        "--all-tiers",
        action="store_true",
        help="Ingest points/swag programs in addition to cash bounties (default: cash-only)",
    )
    parser.add_argument(
        "--max-programs",
        type=int,
        default=25,
        help="Maximum programs to ingest from feed (default: 25)",
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default=str(DEFAULT_BOUNTY_DATA_PATH),
        help="Path to output bounty_programs.json",
    )
    parser.add_argument(
        "--state-path",
        type=str,
        default=str(DEFAULT_RADAR_STATE_PATH),
        help="Path to output bounty_radar_state.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate scopes without writing to disk",
    )

    args = parser.parse_args()

    print("==============================================================================")
    print(" 🛰️ ORBIT SECURITY: BUG BOUNTY SCOPE INGESTION & FLEET EXPANSION")
    print("==============================================================================")
    print(f" Source Feed:      {args.feed if args.feed else 'ENROLLED FLEET (Auto-Sync)'}")
    print(f" Feed Type:        {args.type.upper() if args.feed else 'CANONICAL FLEET'}")
    print(f" Cash Bounties:    {'ALL TIERS' if args.all_tiers else 'CASH ONLY'}")
    print(f" Max Ingest Limit: {args.max_programs}")
    print(f" Dry Run Mode:     {'YES (No disk writes)' if args.dry_run else 'NO (Persisting to disk)'}")
    print("------------------------------------------------------------------------------")

    ingester = BountyScopeIngester(data_path=Path(args.data_path))
    initial_count = len(ingester.programs)

    try:
        if args.feed:
            if args.dry_run:
                # Temporary in-memory ingester
                test_ingester = BountyScopeIngester(data_path=Path(args.data_path))
                # Monkey-patch save to no-op
                test_ingester.save = lambda: None
                ingested = test_ingester.sync_from_feed(
                    source_url_or_path=args.feed,
                    feed_type=args.type,
                    cash_only=not args.all_tiers,
                    max_programs=args.max_programs,
                )
                ingester = test_ingester
            else:
                ingested = ingester.sync_from_feed(
                    source_url_or_path=args.feed,
                    feed_type=args.type,
                    cash_only=not args.all_tiers,
                    max_programs=args.max_programs,
                )
            print(f"\n[+] Successfully ingested {len(ingested)} authorized programs from feed.")
        else:
            # Synchronize, validate and refresh current enrolled fleet
            ingested = list(ingester.programs.values())
            if not args.dry_run:
                ingester.save()
            print(f"\n[+] Synchronized and verified {len(ingested)} enrolled programs in fleet.")

        print(f"[+] Total Enrolled Fleet: {len(ingester.programs)} programs (was: {initial_count}).\n")

        print(f"{'PROGRAM ID':<18} {'PROGRAM NAME':<24} {'IN-SCOPE':<10} {'MAX BOUNTY':<12} {'TIER'}")
        print("-" * 78)
        for prog in ingested:
            in_scope_count = len(prog.in_scope)
            bounty_str = f"${prog.max_bounty:,}" if prog.max_bounty > 0 else "N/A"
            print(f"{prog.program_id:<18} {prog.name[:22]:<24} {in_scope_count:<10} {bounty_str:<12} {prog.bounty_tier.upper()}")
        print("-" * 78)

        # Synchronize and inspect radar telemetry state
        state_file = Path(args.state_path)
        if state_file.exists():
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state_data = json.load(f)
                active_ids = [p.program_id for p in ingester.programs.values() if getattr(p, "state", "active") == "active"]
                if not state_data.get("programs_scanned"):
                    state_data["programs_scanned"] = active_ids
                if not args.dry_run:
                    with open(state_file, "w", encoding="utf-8") as f:
                        json.dump(state_data, f, indent=2)
                print(f"[+] Radar telemetry state active: {state_data.get('total_sweeps', 0)} sweeps, "
                      f"{state_data.get('total_vulnerabilities_found', 0)} vulns, "
                      f"{len(active_ids)} active programs.")
            except Exception as se:
                print(f"[-] Warning: Failed to inspect radar state: {se}")
        else:
            active_ids = [p.program_id for p in ingester.programs.values() if getattr(p, "state", "active") == "active"]
            new_state = {
                "last_sweep_utc": None,
                "total_sweeps": 0,
                "total_vulnerabilities_found": 0,
                "programs_scanned": active_ids,
                "recent_findings": [],
            }
            if not args.dry_run:
                with open(state_file, "w", encoding="utf-8") as f:
                    json.dump(new_state, f, indent=2)
            print(f"[+] Initialized fresh radar telemetry state: {len(active_ids)} active programs.")

        if not args.dry_run:
            print(f"\n[+] Scopes saved to {args.data_path}")
            if state_file.exists():
                print(f"[+] Radar telemetry saved to {args.state_path}")

    except Exception as e:
        print(f"\n[-] Error synchronizing bounty scopes: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
