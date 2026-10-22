#!/usr/bin/env python3
"""Orbit Security: Recover & Re-Dispatch 8 Bounced Cohort 7 & 8 High-Value Agencies.

Updates verified inbound contact addresses (from website contact/privacy/footer scraping
and MX validation) and re-dispatches their co-branded PDF perimeter audits via Gmail SMTP.
"""

from datetime import datetime
import json
import os
from pathlib import Path
import sys
import time
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

DISPATCHED_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"
BOUNCED_PATH = REPO_ROOT / "data" / "bounced_agencies.json"
PROSPECTS_PATH = REPO_ROOT / "data" / "prospects.json"
COHORT_7_STAGED = REPO_ROOT / "data" / "cohort_7_staged.json"
COHORT_8_STAGED = REPO_ROOT / "data" / "cohort_8_staged.json"
AUDITS_DIR = REPO_ROOT / "data" / "generated_audits"
CAMPAIGNS_DIR = REPO_ROOT / "outbound_campaigns"

RECOVERY_TARGETS = [
    {
        "agency_name": "Astound Commerce",
        "agency_domain": "astoundcommerce.com",
        "old_email": "contact@astoundcommerce.com",
        "new_email": "privacy@astounddigital.com",
        "cc_email": "marketing@astounddigital.com",
        "client_domain": "underarmour.com",
        "slug": "astound-commerce",
        "cohort": 7,
        "verification_note": "Rebranded to Astound Digital (astounddigital.com); privacy@astounddigital.com scraped from /privacy-policy",
    },
    {
        "agency_name": "Scandiweb",
        "agency_domain": "scandiweb.com",
        "old_email": "hello@scandiweb.com",
        "new_email": "info@scandiweb.com",
        "client_domain": "puma.com",
        "slug": "scandiweb",
        "cohort": 7,
        "verification_note": "Scraped mailto:info@scandiweb.com from scandiweb.com homepage & privacy policy",
    },
    {
        "agency_name": "BORN Group",
        "agency_domain": "borngroup.com",
        "old_email": "info@borngroup.com",
        "new_email": "privacy@borngroup.com",
        "client_domain": "dita.com",
        "slug": "born-group",
        "cohort": 7,
        "verification_note": "Decoded Cloudflare data-cfemail on borngroup.com/privacy/ (privacy@borngroup.com)",
    },
    {
        "agency_name": "The Stable",
        "agency_domain": "thestable.com",
        "old_email": "hello@thestable.com",
        "new_email": "info@thestable.com",
        "client_domain": "ring.com",
        "slug": "the-stable",
        "cohort": 7,
        "verification_note": "Verified corporate directory contact info@thestable.com (Proofpoint MX)",
    },
    {
        "agency_name": "Tryzens",
        "agency_domain": "tryzens.com",
        "old_email": "info@tryzens.com",
        "new_email": "hello@tryzens.com",
        "client_domain": "sweatybetty.com",
        "slug": "tryzens",
        "cohort": 8,
        "verification_note": "Scraped hello@tryzens.com and partnerships@tryzens.com from tryzens.com/contact-us/",
    },
    {
        "agency_name": "Series Eight",
        "agency_domain": "serieseight.com",
        "old_email": "hello@serieseight.com",
        "new_email": "info@serieseight.com",
        "client_domain": "oatly.com",
        "slug": "series-eight",
        "cohort": 8,
        "verification_note": "Scraped info@serieseight.com from serieseight.com/contact and footer",
    },
    {
        "agency_name": "By Association Only",
        "agency_domain": "byassociationonly.com",
        "old_email": "hello@byassociationonly.com",
        "new_email": "enquiries@bao.agency",
        "client_domain": "astridandmiyu.com",
        "slug": "by-association-only",
        "cohort": 8,
        "verification_note": "Scraped enquiries@bao.agency and info@bao.agency from byassociationonly.com/contact",
    },
    {
        "agency_name": "Elogic Commerce",
        "agency_domain": "elogic.co",
        "old_email": "info@elogic.co",
        "new_email": "office@elogic.co",
        "client_domain": "whirlpool.com",
        "slug": "elogic-commerce",
        "cohort": 8,
        "verification_note": "Scraped office@elogic.co from elogic.co/contacts/ and header/footer",
    },
]


def main():
    dispatcher = EmailDispatcher()
    if not dispatcher.is_configured():
        print("[!] SMTP not configured in .env")
        sys.exit(1)

    dispatched = json.loads(DISPATCHED_PATH.read_text(encoding="utf-8"))
    bounced = json.loads(BOUNCED_PATH.read_text(encoding="utf-8"))
    prospects = json.loads(PROSPECTS_PATH.read_text(encoding="utf-8"))

    print("=" * 72)
    print("🔄 ORBIT SECURITY: RECOVERING 8 BOUNCED COHORT 7 & 8 AGENCIES")
    print("=" * 72)

    recovered_count = 0

    for idx, item in enumerate(RECOVERY_TARGETS, 1):
        name = item["agency_name"]
        domain = item["agency_domain"]
        new_email = item["new_email"]
        client = item["client_domain"]
        slug = item["slug"]

        pdf_path = AUDITS_DIR / slug / f"{client}_audit.pdf"
        txt_path = CAMPAIGNS_DIR / slug / f"{client}_pitch_email.txt"
        eml_path = CAMPAIGNS_DIR / slug / f"{client}_pitch_email.eml"

        if not pdf_path.exists():
            print(f"[!] Missing PDF for {name}: {pdf_path}")
            continue

        body_text = txt_path.read_text(encoding="utf-8")
        subject = f"Perimeter Hygiene & Retainer Audit: {client}"

        # Re-export EML with updated recipient
        dispatcher.export_eml(
            recipient_email=new_email,
            subject=subject,
            body_text=body_text,
            pdf_attachment_path=str(pdf_path),
            output_eml_path=str(eml_path),
        )

        print(f"\n[{idx}/{len(RECOVERY_TARGETS)}] Re-dispatching {name} ({domain})")
        print(f"    Old (Bounced): {item['old_email']} -> New (Verified): {new_email}")
        print(f"    Verification : {item['verification_note']}")
        print(f"    Attachment   : {pdf_path.name}")

        try:
            dispatcher.send_email(
                recipient_email=new_email,
                subject=subject,
                body_text=body_text,
                pdf_attachment_path=str(pdf_path),
            )
            # Also send to secondary marketing@astounddigital.com if Astound
            if item.get("cc_email"):
                time.sleep(1.5)
                dispatcher.send_email(
                    recipient_email=item["cc_email"],
                    subject=subject,
                    body_text=body_text,
                    pdf_attachment_path=str(pdf_path),
                )
                print(f"    [✔] Also dispatched to secondary contact: {item['cc_email']}")

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if domain in dispatched:
                dispatched[domain]["contact_email"] = new_email
                dispatched[domain]["previous_bounced_email"] = item["old_email"]
                dispatched[domain]["dispatched_at"] = now_str
                dispatched[domain]["status"] = "SENT"
                dispatched[domain]["recovered"] = True
                dispatched[domain].pop("bounced_at", None)
                dispatched[domain].pop("bounce_reason", None)

            if domain in bounced:
                bounced.pop(domain, None)

            for p in prospects:
                if p.get("agency_domain") == domain:
                    p["contact_email"] = new_email

            recovered_count += 1
            print(f"    [🚀] Successfully re-dispatched audit to {new_email}!")
            time.sleep(2.0)
        except Exception as e:
            print(f"    [❌] Error re-dispatching to {new_email}: {e}")

    DISPATCHED_PATH.write_text(json.dumps(dispatched, indent=2), encoding="utf-8")
    BOUNCED_PATH.write_text(json.dumps(bounced, indent=2), encoding="utf-8")
    PROSPECTS_PATH.write_text(json.dumps(prospects, indent=2), encoding="utf-8")

    # Update cohort_7_staged.json and cohort_8_staged.json
    for staged_file in (COHORT_7_STAGED, COHORT_8_STAGED):
        if staged_file.exists():
            staged_data = json.loads(staged_file.read_text(encoding="utf-8"))
            for entry in staged_data:
                for rt in RECOVERY_TARGETS:
                    if entry.get("agency_domain") == rt["agency_domain"]:
                        entry["contact_email"] = rt["new_email"]
                        entry["status"] = "SENT"
            staged_file.write_text(json.dumps(staged_data, indent=2), encoding="utf-8")

    print("\n" + "=" * 72)
    print(f"🏁 Recovery complete! {recovered_count}/{len(RECOVERY_TARGETS)} agencies re-dispatched.")
    print(f"Remaining unrecovered bounces in ledger: {len(bounced)}")
    print("=" * 72)


if __name__ == "__main__":
    main()
