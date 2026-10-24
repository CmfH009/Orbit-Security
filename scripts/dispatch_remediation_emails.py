#!/usr/bin/env python3
"""scripts/dispatch_remediation_emails.py: Dispatch the 13 Rescued-Score Remediation Emails.

Reads staged .eml correction drafts from data/remediation/correction_emails/
and delivers them via EmailDispatcher (authenticated SMTP) to agency contacts.

Usage:
    # Dry-run: preview the 13 staged emails and target agencies without sending
    python scripts/dispatch_remediation_emails.py

    # Send a single test agency (e.g. Aligent)
    python scripts/dispatch_remediation_emails.py --agency Aligent --send

    # Send all 13 staged remediation emails with rate limiting
    python scripts/dispatch_remediation_emails.py --send-all
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

REMEDIATION_DIR = PROJECT_ROOT / "data" / "remediation"
MANIFEST_PATH = REMEDIATION_DIR / "remediation_manifest.json"
EMAILS_DIR = REMEDIATION_DIR / "correction_emails"


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found: {MANIFEST_PATH}")
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def save_manifest(manifest: dict) -> None:
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Orbit Security: Dispatch Rescued-Score Remediation Emails"
    )
    parser.add_argument(
        "--send-all",
        action="store_true",
        help="Deliver all 13 staged correction emails via SMTP",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Enable live sending (required with --agency)",
    )
    parser.add_argument(
        "--agency",
        type=str,
        help="Filter to a specific agency name (e.g. 'Aligent', 'Pixafy')",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of emails to dispatch (default: all)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=2.0,
        help="Seconds to wait between emails (default: 2.0s)",
    )

    args = parser.parse_args()
    manifest = load_manifest()
    affected = manifest.get("affected", [])

    # Filter to rescued audits only
    rescued = [a for a in affected if a.get("classification") == "rescued"]

    if args.agency:
        target_name = args.agency.lower()
        rescued = [a for a in rescued if target_name in a.get("agency_name", "").lower()]
        if not rescued:
            print(f"No rescued agency found matching '{args.agency}'")
            return 1

    if args.limit > 0:
        rescued = rescued[:args.limit]

    print("=" * 76)
    print(" 🛠️  ORBIT SECURITY: AUDIT REMEDIATION DISPATCHER")
    print("=" * 76)
    print(f" Targets Selected: {len(rescued)} rescued agency audits")
    print(f" Mode:             {'🚀 LIVE DISPATCH' if (args.send_all or args.send) else '🔍 DRY RUN (Preview Only)'}")
    print("=" * 76)

    dispatcher = EmailDispatcher()
    is_live = args.send_all or args.send

    if is_live and not dispatcher.is_configured():
        print("\n❌ Error: SMTP is not configured. Verify SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in .env")
        return 1

    success_count = 0
    fail_count = 0

    for idx, item in enumerate(rescued, 1):
        agency = item.get("agency_name", "Unknown")
        domain = item.get("client_domain", "Unknown")
        contact = item.get("contact_email", "N/A")
        old_pub = item.get("published", {})
        old_g = old_pub.get("grade", "?")
        old_s = old_pub.get("score", 0)
        new_corr = item.get("corrected", {})
        new_g = new_corr.get("grade", "?")
        new_s = new_corr.get("score", 0)
        delta = item.get("delta", 0)
        rel_eml_path = item.get("correction_email_path", "")
        eml_path = PROJECT_ROOT / rel_eml_path if rel_eml_path else None

        print(f"\n[{idx}/{len(rescued)}] {agency} -> {domain}")
        print(f"    Recipient:  {contact}")
        print(f"    Adjustment: {old_g} ({old_s}/100) -> {new_g} ({new_s}/100)  [+{delta} pts]")
        print(f"    EML Draft:  {rel_eml_path}")

        if not eml_path or not eml_path.exists():
            print(f"    ⚠️  Warning: EML file not found: {eml_path}")
            fail_count += 1
            continue

        if is_live:
            try:
                dispatcher.send_raw_eml(str(eml_path))
                item["dispatched_at"] = datetime.now(timezone.utc).isoformat()
                item["dispatch_status"] = "SENT"
                success_count += 1
                print(f"    ✓ Successfully dispatched correction note to {contact}")
                if idx < len(rescued):
                    time.sleep(args.sleep)
            except Exception as ex:
                item["dispatch_status"] = "FAILED"
                item["dispatch_error"] = str(ex)
                fail_count += 1
                print(f"    ❌ Dispatch failed: {ex}")
        else:
            print("    [DRY RUN] Would send raw EML over SMTP. Use --send-all to transmit.")

    if is_live:
        manifest["last_dispatch_run_utc"] = datetime.now(timezone.utc).isoformat()
        save_manifest(manifest)

    print("\n" + "=" * 76)
    if is_live:
        print(f" 🏁 Finished: {success_count} sent successfully, {fail_count} failed.")
    else:
        print(f" 💡 Dry run complete for {len(rescued)} agencies. Pass --send-all to execute live transmission.")
    print("=" * 76 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
