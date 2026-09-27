#!/usr/bin/env python3
"""Orbit Security: Autonomous 48-Hour Bump / Follow-Up Campaign Engine.

Identifies dispatched agency campaigns that are eligible for a follow-up,
filters out bounces/replies, and dispatches or stages high-conversion Bump #1 emails.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

DATA_DIR = REPO_ROOT / "data"
DISPATCHED_CAMPAIGNS_PATH = DATA_DIR / "dispatched_campaigns.json"
PROSPECTS_PATH = DATA_DIR / "prospects.json"
FOLLOWUPS_LOG_PATH = DATA_DIR / "dispatched_followups.json"

# Known hard bounces / blocked SMTP destinations (contacted via X instead)
EXCLUDED_BOUNCE_DOMAINS = {
    "anatta.io",
    "fostr.online",
    "guidance.com",
}


def load_json_data(path: Path) -> Any:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_data(path: Path, data: Any):
    os.makedirs(path.parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_client_domain_for_agency(agency_domain: str, prospects: List[Dict[str, Any]]) -> str:
    for p in prospects:
        if p.get("agency_domain") == agency_domain:
            portfolios = p.get("portfolio_domains", [])
            if portfolios:
                return portfolios[0]
    return "your client builds"


def generate_bump_copy(agency_name: str, client_domain: str) -> Dict[str, str]:
    subject = f"Re: Co-branded perimeter hygiene audit for {client_domain}"
    body = (
        f"Hey {agency_name} team,\n\n"
        f"Quick bump on this — wanted to make sure the white-label perimeter audit for "
        f"{client_domain} didn't get buried over the weekend.\n\n"
        f"We also pushed our live 16-bit Fleet Command Center if your developers or account "
        f"leads want to test passive DoH lookups across your full client roster:\n"
        f"https://cmfh009.github.io/Orbit-Security/fleet.html\n\n"
        f"Happy to walk through any DMARC or DNS drift remediation steps, or configure automated "
        f"monthly reporting for your retainer care plans.\n\n"
        f"Best,\n"
        f"Carson Haynes\n"
        f"Founder, Orbit Security\n"
        f"carsonmail009@gmail.com\n"
        f"https://cmfh009.github.io/Orbit-Security/"
    )
    return {"subject": subject, "body": body}


def get_eligible_followups(
    dispatched: Dict[str, Any],
    prospects: List[Dict[str, Any]],
    followups_log: Dict[str, Any],
    min_hours: float = 36.0,
    cohort_index: Optional[int] = None,
) -> List[Dict[str, Any]]:
    now = datetime.now()
    eligible = []

    # Map prospect indices for cohort filtering (1-indexed cohorts of 10)
    prospect_order = [p.get("agency_domain") for p in prospects]

    for agency_domain, info in dispatched.items():
        # Exclude hard bounces
        if agency_domain in EXCLUDED_BOUNCE_DOMAINS:
            continue

        # Exclude already followed up
        if agency_domain in followups_log:
            continue

        # Cohort filtering if requested
        if cohort_index is not None:
            try:
                idx = prospect_order.index(agency_domain)
                item_cohort = (idx // 10) + 1 if idx < 30 else 5
                if item_cohort != cohort_index:
                    continue
            except ValueError:
                pass

        # Parse dispatch time
        disp_time_str = info.get("dispatched_at")
        if not disp_time_str:
            continue

        try:
            disp_dt = datetime.strptime(disp_time_str, "%Y-%m-%d %H:%M:%S")
            elapsed_hours = (now - disp_dt).total_seconds() / 3600.0
        except Exception:
            elapsed_hours = 999.0

        if elapsed_hours >= min_hours:
            client_domain = get_client_domain_for_agency(agency_domain, prospects)
            copy = generate_bump_copy(info.get("agency_name", "Agency"), client_domain)
            eligible.append({
                "agency_domain": agency_domain,
                "agency_name": info.get("agency_name"),
                "contact_email": info.get("contact_email"),
                "client_domain": client_domain,
                "dispatched_at": disp_time_str,
                "elapsed_hours": round(elapsed_hours, 1),
                "subject": copy["subject"],
                "body": copy["body"],
            })

    return eligible


def main():
    parser = argparse.ArgumentParser(description="Orbit Security: 48-Hour Bump Follow-Up Engine")
    parser.add_argument("--cohort", type=int, help="Filter by cohort number (1 to 5)")
    parser.add_argument("--min-hours", type=float, default=30.0, help="Minimum elapsed hours since initial dispatch (default: 30.0)")
    parser.add_argument("--limit", type=int, default=10, help="Max follow-up emails to process")
    parser.add_argument("--send", action="store_true", help="Dispatch live emails via SMTP")
    parser.add_argument("--export-eml", action="store_true", help="Export EML draft files for review")
    parser.add_argument("--dry-run", action="store_true", help="Print eligible follow-ups without sending")
    args = parser.parse_args()

    dispatched = load_json_data(DISPATCHED_CAMPAIGNS_PATH)
    prospects = load_json_data(PROSPECTS_PATH)
    followups_log = load_json_data(FOLLOWUPS_LOG_PATH)

    eligible = get_eligible_followups(
        dispatched=dispatched,
        prospects=prospects,
        followups_log=followups_log,
        min_hours=args.min_hours,
        cohort_index=args.cohort,
    )

    print("=" * 65)
    print("📬 ORBIT SECURITY: 48-HOUR BUMP FOLLOW-UP CAMPAIGN ENGINE")
    print(f"Total Dispatched in Registry: {len(dispatched)}")
    print(f"Already Followed Up: {len(followups_log)}")
    print(f"Minimum Elapsed Threshold: {args.min_hours}h")
    print(f"Eligible for Bump #1: {len(eligible)}")
    print("=" * 65)

    if not eligible:
        print("[ℹ] No campaigns currently meet the elapsed follow-up criteria.")
        return

    targets = eligible[: args.limit]
    print(f"\nProcessing {len(targets)} candidate(s):\n")

    dispatcher = EmailDispatcher()

    for idx, item in enumerate(targets, 1):
        print(f"[{idx}/{len(targets)}] {item['agency_name']} ({item['agency_domain']})")
        print(f"    To: {item['contact_email']}")
        print(f"    Client Anchor: {item['client_domain']}")
        print(f"    Elapsed: {item['elapsed_hours']} hours ago ({item['dispatched_at']})")
        print(f"    Subject: {item['subject']}")

        if args.export_eml:
            eml_dir = REPO_ROOT / "outbound_campaigns" / "followups"
            eml_path = eml_dir / f"bump1_{item['agency_domain']}.eml"
            dispatcher.export_eml(
                recipient_email=item["contact_email"],
                subject=item["subject"],
                body_text=item["body"],
                pdf_attachment_path=None,
                output_eml_path=str(eml_path),
            )
            print(f"    [✔] Exported EML: {eml_path.name}")

        if args.send:
            if not dispatcher.is_configured():
                print("    [!] SMTP not configured. Cannot send live.")
                continue
            try:
                dispatcher.send_email(
                    recipient_email=item["contact_email"],
                    subject=item["subject"],
                    body_text=item["body"],
                )
                followups_log[item["agency_domain"]] = {
                    "agency_name": item["agency_name"],
                    "contact_email": item["contact_email"],
                    "client_domain": item["client_domain"],
                    "followup_dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "bump_number": 1,
                    "status": "SENT",
                }
                save_json_data(FOLLOWUPS_LOG_PATH, followups_log)
                print("    [🚀] Live Bump #1 dispatched successfully!")
            except Exception as e:
                print(f"    [❌] Error sending follow-up: {e}")

        print("-" * 50)

    if not args.send and not args.export_eml:
        print("\n[ℹ] Ran in preview mode. Use --export-eml or --send to execute.")


if __name__ == "__main__":
    main()
