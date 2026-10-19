#!/usr/bin/env python3
r"""scripts/register_prospects_as_agencies.py

Auto-registers new agency prospects from data/new_prospects.json as Orbit
Security white-label retainer agencies, persisting to data/agency_retainers.json.

Usage:
    # Register all 54 prospects as Starter tier ($299/mo) agencies
    .venv\Scripts\python.exe scripts/register_prospects_as_agencies.py

    # Register only the first 3 (dry run: print plan, do not persist)
    .venv\Scripts\python.exe scripts/register_prospects_as_agencies.py --dry-run --limit 3

    # Register only agencies whose name contains "Digital" on the Scale tier
    .venv\Scripts\python.exe scripts/register_prospects_as_agencies.py --agency Digital --tier Scale
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure local src/ is on sys.path so `orbit_security` is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier  # noqa: E402

PROSPECTS_PATH = PROJECT_ROOT / "data" / "new_prospects.json"

TIER_PRICES = {
    RetainerTier.STARTER: 299,
    RetainerTier.SCALE: 499,
    RetainerTier.ENTERPRISE: 999,
}

TIER_CHOICES = [tier.value for tier in RetainerTier]  # ["Starter", "Scale", "Enterprise"]


def slug_from_domain(domain: str) -> str:
    """Derive an agency id slug from an agency domain (e.g. bluestout.com -> bluestout)."""
    return domain.strip().split(".")[0]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Orbit Security: Auto-register new prospect agencies as white-label retainers."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of prospects to register (default: all 54)",
    )
    parser.add_argument(
        "--agency",
        type=str,
        default=None,
        help="Only register agencies whose name contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--tier",
        choices=TIER_CHOICES,
        default="Starter",
        help="Retainer tier to assign (default: Starter)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the registration plan without registering or persisting",
    )
    args = parser.parse_args()

    tier = RetainerTier(args.tier)
    monthly_price = TIER_PRICES[tier]

    with open(PROSPECTS_PATH, "r", encoding="utf-8") as f:
        prospects = json.load(f)

    # Apply filters
    filtered = prospects
    if args.agency:
        needle = args.agency.lower()
        filtered = [p for p in filtered if needle in p["agency_name"].lower()]
    if args.limit is not None:
        filtered = filtered[: args.limit]

    manager = AgencyRetainerManager()  # loads/saves data/agency_retainers.json by default

    registered = 0
    failed = 0
    domains_added = 0

    for prospect in filtered:
        agency_name = prospect["agency_name"]
        agency_domain = prospect["agency_domain"]
        contact_email = prospect["contact_email"]
        portfolio_domains = prospect.get("portfolio_domains", [])
        agency_id = slug_from_domain(agency_domain)

        try:
            if args.dry_run:
                print(
                    f"[PLAN] Would register {agency_name} ({agency_id}) — "
                    f"{tier.value} ${monthly_price}/mo — {len(portfolio_domains)} client domains"
                )
                registered += 1
                domains_added += len(portfolio_domains)
                continue

            retainer = manager.register_agency(
                agency_id=agency_id,
                agency_name=agency_name,
                tier=tier,
                custom_domain=None,
                support_email=contact_email,
                website=f"https://{agency_domain}",
            )

            added = 0
            for domain in portfolio_domains:
                if manager.add_client_domain(agency_id, domain, client_name=domain):
                    added += 1

            domains_added += added
            registered += 1
            print(
                f"[✓] Registered {agency_name} ({agency_id}) — "
                f"{tier.value} ${monthly_price}/mo — {added} client domains"
            )
        except Exception as exc:  # one failure must not crash the batch
            failed += 1
            print(f"[✗] Failed to register {agency_name} ({agency_id}): {exc}")

    if args.dry_run:
        print(
            f"\nDry run complete: {registered} agencies would be registered, "
            f"{domains_added} client domains would be added."
        )
    else:
        manager.save()
        print(
            f"\nSummary: {registered} registered, {failed} failed, "
            f"{domains_added} client domains added."
        )


if __name__ == "__main__":
    main()
