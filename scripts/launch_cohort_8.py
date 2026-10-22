#!/usr/bin/env python3
"""Orbit Security: Autonomous Cohort 8 Staging & Live Dispatch Engine.

Appends 10 fresh Cohort 8 agencies, scans their flagship client perimeters,
generates co-branded PDF/Markdown audit reports, stages .eml drafts, and
dispatches live personalized outreach emails via configured Gmail SMTP.
"""

import asyncio
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
from orbit_security.models import AgencyBranding
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner
from scripts.append_cohort_8 import COHORT_8, main as append_main

AUDITS_DIR = REPO_ROOT / "data" / "generated_audits"
CAMPAIGNS_DIR = REPO_ROOT / "outbound_campaigns"
STAGED_LOG = REPO_ROOT / "data" / "cohort_8_staged.json"
MATRIX_FILE = REPO_ROOT / "data" / "cohort_8_matrix.md"
DISPATCHED_CAMPAIGNS_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"


def slugify(text: str) -> str:
    return text.lower().replace(" ", "-").replace("+", "-plus-").replace(".", "-")


async def stage_and_send_agency(
    scanner: OrbitSecurityScanner,
    dispatcher: EmailDispatcher,
    agency: dict,
    dispatched: dict,
) -> dict:
    agency_name = agency["agency_name"]
    agency_domain = agency["agency_domain"]
    contact_email = agency["contact_email"]
    client_domain = agency["portfolio_domains"][0]
    hook = agency.get("personalization_hook", "")
    agency_slug = slugify(agency_name)

    agency_audit_dir = AUDITS_DIR / agency_slug
    agency_audit_dir.mkdir(parents=True, exist_ok=True)
    campaign_dir = CAMPAIGNS_DIR / agency_slug
    campaign_dir.mkdir(parents=True, exist_ok=True)

    branding = AgencyBranding(
        agency_name=agency_name,
        support_email=contact_email,
        website=f"https://{agency_domain}",
    )

    print(f"\n[*] Scanning perimeter for {client_domain} (on behalf of {agency_name})...")
    result = await scanner.scan_domain(client_domain, agency_branding=branding)

    pdf_path = agency_audit_dir / f"{client_domain}_audit.pdf"
    md_path = agency_audit_dir / f"{client_domain}_audit.md"
    ReportGenerator.generate_pdf(result, str(pdf_path))
    md_content = ReportGenerator.generate_markdown(result)
    md_path.write_text(md_content, encoding="utf-8")

    subject = f"Perimeter Hygiene & Retainer Audit: {client_domain}"
    body = (
        f"Hi {agency_name} team,\n\n"
        f"{hook}\n\n"
        f"We recently performed an automated external hygiene pass across top D2C perimeters and "
        f"compiled a co-branded audit report for {client_domain} (Score: {result.score}/100, Grade: {result.grade}).\n\n"
        f"Key observations:\n"
        f"- Total Findings: {len(result.findings)}\n"
        f"- Critical/High Risks: {len([f for f in result.findings if f.severity.value in ('CRITICAL', 'HIGH')])}\n\n"
        f"The full cryptographic PDF audit is attached for your engineering review. We run Orbit Security "
        f"to give premier eCommerce development agencies white-label retainer protection ($59/mo), enabling "
        f"continuous DNS drift monitoring, DMARC spoof defense, and monthly executive security badges for your clients.\n\n"
        f"You can also test our 16-bit passive lookup engine on our live Fleet Command Center:\n"
        f"https://cmfh009.github.io/Orbit-Security/fleet.html\n\n"
        f"Best regards,\n"
        f"Carson Haynes\n"
        f"Founder, Orbit Security\n"
        f"carsonmail009@gmail.com\n"
        f"https://cmfh009.github.io/Orbit-Security/"
    )

    txt_path = campaign_dir / f"{client_domain}_pitch_email.txt"
    txt_path.write_text(body, encoding="utf-8")

    eml_path = campaign_dir / f"{client_domain}_pitch_email.eml"
    dispatcher.export_eml(
        recipient_email=contact_email,
        subject=subject,
        body_text=body,
        pdf_attachment_path=str(pdf_path),
        output_eml_path=str(eml_path),
    )

    print(f"    [✔] Score: {result.score}/100 ({result.grade}) | Findings: {len(result.findings)}")
    print(f"    [✔] Generated PDF: {pdf_path.name}")

    status = "STAGED"
    if dispatcher.is_configured():
        try:
            dispatcher.send_email(
                recipient_email=contact_email,
                subject=subject,
                body_text=body,
                pdf_attachment_path=str(pdf_path),
            )
            status = "SENT"
            dispatched[agency_domain] = {
                "agency_name": agency_name,
                "contact_email": contact_email,
                "client_domain": client_domain,
                "score": result.score,
                "grade": result.grade,
                "dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "SENT",
                "cohort": 8,
            }
            with open(DISPATCHED_CAMPAIGNS_PATH, "w", encoding="utf-8") as f:
                json.dump(dispatched, f, indent=2)
            print(f"    [🚀] Live email + PDF audit dispatched to {contact_email}!")
            await asyncio.sleep(2.0)
        except Exception as e:
            print(f"    [❌] Failed to send email to {contact_email}: {e}")

    return {
        "agency_name": agency_name,
        "agency_domain": agency_domain,
        "contact_email": contact_email,
        "client_domain": client_domain,
        "score": result.score,
        "grade": result.grade,
        "findings_count": len(result.findings),
        "critical_high_count": len([f for f in result.findings if f.severity.value in ('CRITICAL', 'HIGH')]),
        "pdf_path": str(pdf_path),
        "eml_path": str(eml_path),
        "status": status,
        "staged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


async def main():
    append_main()
    dispatched = {}
    if DISPATCHED_CAMPAIGNS_PATH.exists():
        with open(DISPATCHED_CAMPAIGNS_PATH, "r", encoding="utf-8") as f:
            dispatched = json.load(f)

    scanner = OrbitSecurityScanner()
    dispatcher = EmailDispatcher()
    records = []

    print("=" * 70)
    print("🚀 ORBIT SECURITY: COHORT 8 STAGING & LIVE DISPATCH")
    print(f"Target Agencies: {len(COHORT_8)}")
    print("=" * 70)

    for idx, agency in enumerate(COHORT_8, 1):
        print(f"\n[{idx}/{len(COHORT_8)}] Processing {agency['agency_name']} ({agency['agency_domain']})...")
        rec = await stage_and_send_agency(scanner, dispatcher, agency, dispatched)
        records.append(rec)

    with open(STAGED_LOG, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print("\n" + "=" * 70)
    print(f"🏁 Cohort 8 complete! Total agencies in ledger: {len(dispatched)}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
