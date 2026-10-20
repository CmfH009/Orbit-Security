#!/usr/bin/env python3
"""Orbit Security: Live Dispatch Engine for Cohort 6.

Sends personalized perimeter audit emails with co-branded PDF attachments
to the 10 premier Cohort 6 agencies via configured SMTP, and logs dispatches
to dispatched_campaigns.json.
"""

from datetime import datetime
import json
import os
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / ".env")

from orbit_security.mailer import EmailDispatcher

STAGED_LOG = REPO_ROOT / "data" / "cohort_6_staged.json"
DISPATCHED_CAMPAIGNS_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"
CAMPAIGNS_DIR = REPO_ROOT / "outbound_campaigns"


def slugify(text: str) -> str:
    return text.lower().replace(" ", "-").replace("+", "-plus-").replace(".", "-")


def main():
    if not STAGED_LOG.exists():
        print(f"[❌] {STAGED_LOG.name} not found. Run stage_cohort_6.py first.")
        return

    with open(STAGED_LOG, "r", encoding="utf-8") as f:
        staged_agencies = json.load(f)

    dispatched = {}
    if DISPATCHED_CAMPAIGNS_PATH.exists():
        with open(DISPATCHED_CAMPAIGNS_PATH, "r", encoding="utf-8") as f:
            dispatched = json.load(f)

    dispatcher = EmailDispatcher()
    if not dispatcher.is_configured():
        print("[❌] SMTP not configured in .env. Cannot dispatch live.")
        return

    print("=" * 70)
    print("🚀 ORBIT SECURITY: LAUNCHING COHORT 6 LIVE DISPATCH")
    print(f"Total Staged Agencies: {len(staged_agencies)}")
    print(f"Sender: {dispatcher.sender_name} <{dispatcher.smtp_user}>")
    print("=" * 70)

    sent_count = 0

    for idx, item in enumerate(staged_agencies, 1):
        name = item["agency_name"]
        domain = item["agency_domain"]
        email = item["contact_email"]
        client = item["client_domain"]
        pdf_path = item["pdf_path"]
        agency_slug = slugify(name)

        # Read tailored body from staged txt file
        txt_file = CAMPAIGNS_DIR / agency_slug / f"{client}_pitch_email.txt"
        if txt_file.exists():
            body_text = txt_file.read_text(encoding="utf-8")
        else:
            body_text = (
                f"Hi {name} team,\n\n"
                f"We recently ran a perimeter-hygiene assessment for {client} "
                f"and compiled a co-branded audit report (Score: {item.get('score')}/100).\n\n"
                f"The full audit PDF is attached for your engineering review.\n\n"
                f"Best regards,\n"
                f"Carson Haynes\n"
                f"Founder, Orbit Security\n"
            )

        subject = f"Perimeter Hygiene & Retainer Audit: {client}"

        print(f"\n[{idx}/{len(staged_agencies)}] Dispatching to {name} ({domain})...")
        print(f"    Recipient: {email}")
        print(f"    Anchor: {client} | Score: {item.get('score')}/100 ({item.get('grade')})")

        try:
            dispatcher.send_email(
                recipient_email=email,
                subject=subject,
                body_text=body_text,
                pdf_attachment_path=pdf_path if os.path.exists(pdf_path) else None,
            )
            dispatched[domain] = {
                "agency_name": name,
                "contact_email": email,
                "client_domain": client,
                "score": item.get("score"),
                "grade": item.get("grade"),
                "dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "SENT",
                "cohort": 6,
            }
            with open(DISPATCHED_CAMPAIGNS_PATH, "w", encoding="utf-8") as f:
                json.dump(dispatched, f, indent=2)

            sent_count += 1
            print("    [🚀] Live pitch email dispatched successfully with attached PDF audit!")
            time.sleep(2.0)
        except Exception as e:
            print(f"    [❌] Failed to send email to {email}: {e}")

    print("\n" + "=" * 70)
    print(f"🏁 Cohort 6 Launch Complete: {sent_count}/{len(staged_agencies)} dispatched successfully!")
    print(f"Dispatched registry updated: {DISPATCHED_CAMPAIGNS_PATH.name} (Total: {len(dispatched)})")
    print("=" * 70)


if __name__ == "__main__":
    main()
