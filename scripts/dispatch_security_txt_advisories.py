#!/usr/bin/env python3
"""Orbit Security: RFC 9116 Security.txt & Responsible Disclosure Dispatcher.

Usage:
    # List all 121 staged advisories and their primary contacts
    python scripts/dispatch_security_txt_advisories.py --list

    # Preview an advisory for a specific target (dry-run)
    python scripts/dispatch_security_txt_advisories.py --target hhc247.org

    # Export .eml files for high-priority targets
    python scripts/dispatch_security_txt_advisories.py --severity MEDIUM --export-eml

    # Send coordinated responsible disclosure email via configured SMTP
    python scripts/dispatch_security_txt_advisories.py --target hhc247.org --send
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
from dotenv import load_dotenv
load_dotenv(REPO_ROOT / ".env")

SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

DATA_DIR = REPO_ROOT / "data"
DISCLOSURES_DIR = DATA_DIR / "disclosures"
REGISTRY_PATH = DATA_DIR / "security_txt_registry.json"
DISPATCH_LOG_PATH = DATA_DIR / "dispatched_security_advisories.json"
STAGED_EML_DIR = DISCLOSURES_DIR / "staged_advisories_eml"


def load_registry() -> List[Dict[str, Any]]:
    if not REGISTRY_PATH.exists():
        from scripts.audit_security_txt_disclosures import audit_disclosures
        audit_disclosures()
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("bundles", [])


def load_dispatch_log() -> Dict[str, Any]:
    if not DISPATCH_LOG_PATH.exists():
        return {}
    try:
        with open(DISPATCH_LOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_dispatch_log(log: Dict[str, Any]):
    os.makedirs(DISPATCH_LOG_PATH.parent, exist_ok=True)
    with open(DISPATCH_LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)


def get_advisory_text_for_bundle(bundle_name: str) -> Optional[str]:
    bundle_dir = DISCLOSURES_DIR / bundle_name
    advisory_path = bundle_dir / "security_txt_advisory.txt"
    if advisory_path.exists():
        return advisory_path.read_text(encoding="utf-8", errors="ignore")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Security.txt & Responsible Disclosure Dispatcher"
    )
    parser.add_argument("--list", action="store_true", help="List all staged advisories")
    parser.add_argument("--program", type=str, help="Filter by program ID or name")
    parser.add_argument("--severity", type=str, help="Filter by severity (HIGH, MEDIUM, LOW)")
    parser.add_argument("--target", type=str, help="Filter by exact or partial target domain")
    parser.add_argument("--limit", type=int, default=10, help="Max advisories to process (default: 10)")
    parser.add_argument("--export-eml", action="store_true", help="Export RFC 822 .eml files to disk")
    parser.add_argument("--send", action="store_true", help="Dispatch live disclosure email via SMTP")
    parser.add_argument("--dry-run", action="store_true", help="Print email preview without sending (default)")

    args = parser.parse_args()

    bundles = load_registry()
    dispatch_log = load_dispatch_log()

    # Filter
    filtered = []
    for b in bundles:
        if args.program and args.program.lower() not in b.get("program_id", "").lower() and args.program.lower() not in b.get("program_name", "").lower():
            continue
        if args.severity and args.severity.upper() != b.get("severity", "").upper():
            continue
        if args.target and args.target.lower() not in b.get("target_domain", "").lower():
            continue
        filtered.append(b)

    if args.list:
        print("=" * 80)
        print(f"🛰️ ORBIT SECURITY: SECURITY.TXT ADVISORY REGISTRY ({len(filtered)} staged)")
        print("=" * 80)
        print(f"{'Target Domain':<32} | {'Program':<18} | {'Sev':<6} | {'CVSS':<4} | {'Contact'}")
        print("-" * 80)
        for b in filtered[:50]:
            contact = b["contacts"][0] if b.get("contacts") else "N/A"
            disp = " [SENT]" if b["target_domain"] in dispatch_log else ""
            print(f"{b['target_domain']:<32} | {b['program_name'][:18]:<18} | {b['severity']:<6} | {b['cvss_score']:<4} | {contact}{disp}")
        if len(filtered) > 50:
            print(f"... and {len(filtered) - 50} more. Use --program or --target to filter.")
        return

    targets = filtered[: args.limit]
    if not targets:
        print("[ℹ] No advisories matched the specified criteria.")
        return

    print("=" * 80)
    print(f"🛰️ ORBIT SECURITY: RESPONSIBLE DISCLOSURE PREVIEW ({len(targets)} candidates)")
    print(f"Mode: {'LIVE SMTP DISPATCH' if args.send else ('EXPORT EML' if args.export_eml else 'DRY-RUN PREVIEW')}")
    print("=" * 80)

    dispatcher = EmailDispatcher()

    for idx, b in enumerate(targets, 1):
        target_domain = b["target_domain"]
        advisory_text = get_advisory_text_for_bundle(b["bundle_name"])
        if not advisory_text:
            print(f"[{idx}] {target_domain}: Missing advisory text.")
            continue

        lines = advisory_text.splitlines()
        subject = next((l.replace("Subject:", "").strip() for l in lines if l.startswith("Subject:")), f"Responsible Disclosure: {target_domain}")
        to_email = b["contacts"][0] if b.get("contacts") else f"security@{target_domain}"
        zip_path = b.get("zip_path")

        print(f"\n[{idx}/{len(targets)}] Target: {target_domain} ({b['program_name']})")
        print(f"    Recipient: {to_email}")
        print(f"    Subject:   {subject}")
        print(f"    Severity:  {b['severity']} (CVSS {b['cvss_score']}) | CWE: {b['cwe_id']}")
        print(f"    Evidence Bundle: {Path(zip_path).name if zip_path else 'N/A'}")

        if args.export_eml:
            STAGED_EML_DIR.mkdir(parents=True, exist_ok=True)
            clean_dom = target_domain.replace(".", "_")
            eml_file = STAGED_EML_DIR / f"disclosure_{b['program_id']}_{clean_dom}.eml"
            dispatcher.export_eml(
                recipient_email=to_email,
                subject=subject,
                body_text=advisory_text,
                pdf_attachment_path=None,
                output_eml_path=str(eml_file),
            )
            print(f"    [✔] Exported EML: {eml_file.name}")

        if args.send:
            if not dispatcher.is_configured():
                print("    [!] SMTP not configured. Cannot send live.")
                continue

            # Check if already sent
            if target_domain in dispatch_log:
                print(f"    [ℹ] Advisory for {target_domain} already dispatched on {dispatch_log[target_domain]['sent_at']}. Skipping duplicate.")
                continue

            try:
                dispatcher.send_email(
                    recipient_email=to_email,
                    subject=subject,
                    body_text=advisory_text,
                )
                dispatch_log[target_domain] = {
                    "program_id": b["program_id"],
                    "program_name": b["program_name"],
                    "recipient": to_email,
                    "subject": subject,
                    "severity": b["severity"],
                    "cvss_score": b["cvss_score"],
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                    "bundle_name": b["bundle_name"],
                    "status": "DISPATCHED",
                }
                save_dispatch_log(dispatch_log)
                print(f"    [🚀] Live security advisory successfully dispatched to {to_email}!")
                time.sleep(2.0)
            except Exception as send_err:
                print(f"    [❌] Error sending advisory: {send_err}")

        # Show brief excerpt in dry-run
        if not args.send and not args.export_eml:
            print("    --- Advisory Summary ---")
            for body_line in lines[10:18]:
                print(f"    {body_line}")
            print("    ------------------------")

    print("\n" + "=" * 80)
    if not args.send and not args.export_eml:
        print("[ℹ] Ran in dry-run mode. Use --export-eml to create EML files or --send to dispatch.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
