#!/usr/bin/env python3
"""Orbit Security: Autonomous Cohort 7 Staging Engine.

Scans client perimeters for 10 premier Cohort 7 agencies, generates
co-branded PDF/Markdown audit reports, stages personalized pitch
emails and .eml drafts ready for 1-click review or dispatch, and outputs
both cohort_7_staged.json and cohort_7_matrix.md.
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
# Explicitly load local .env
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
from scripts.append_cohort_7 import COHORT_7

AUDITS_DIR = REPO_ROOT / "data" / "generated_audits"
CAMPAIGNS_DIR = REPO_ROOT / "outbound_campaigns"
STAGED_LOG = REPO_ROOT / "data" / "cohort_7_staged.json"
MATRIX_FILE = REPO_ROOT / "data" / "cohort_7_matrix.md"


def slugify(text: str) -> str:
    return text.lower().replace(" ", "-").replace("+", "-plus-").replace(".", "-")


async def stage_agency(scanner: OrbitSecurityScanner, dispatcher: EmailDispatcher, agency: dict) -> dict:
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
        website=f"https://{agency_domain}"
    )

    print(f"\n[*] Scanning perimeter for {client_domain} (on behalf of {agency_name})...")
    result = await scanner.scan_domain(client_domain, agency_branding=branding)

    pdf_path = agency_audit_dir / f"{client_domain}_audit.pdf"
    md_path = agency_audit_dir / f"{client_domain}_audit.md"
    ReportGenerator.generate_pdf(result, str(pdf_path))
    md_content = ReportGenerator.generate_markdown(result)
    md_path.write_text(md_content, encoding="utf-8")

    # Generate tailored pitch copy
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
        output_eml_path=str(eml_path)
    )

    print(f"    [✔] Score: {result.score}/100 ({result.grade}) | Findings: {len(result.findings)}")
    print(f"    [✔] Generated PDF: {pdf_path.name}")
    print(f"    [✔] Staged EML: {eml_path.name}")

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
        "staged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def generate_matrix(staged_records: list) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = [
        "# Cohort 7: Outbound Outreach & Perimeter Hygiene Matrix",
        f"**Generated:** {timestamp} | **Total Staged Targets:** {len(staged_records)}",
        "",
        "| # | Agency | Contact Email | Client Anchor | Score | Grade | Critical/High | Status | PDF Audit | Staged Draft |",
        "|---|--------|---------------|---------------|-------|-------|---------------|--------|-----------|--------------|"
    ]

    for idx, rec in enumerate(staged_records, 1):
        agency = f"**{rec['agency_name']}** (`{rec['agency_domain']}`)"
        email = f"`{rec['contact_email']}`"
        client = f"`{rec['client_domain']}`"
        score = f"**{rec['score']}/100**"
        grade = f"`{rec['grade']}`"
        vulns = f"{rec['critical_high_count']} / {rec['findings_count']}"
        status = "🟢 `STAGED_READY`"
        pdf_name = Path(rec['pdf_path']).name
        eml_name = Path(rec['eml_path']).name
        md.append(f"| {idx} | {agency} | {email} | {client} | {score} | {grade} | {vulns} | {status} | `{pdf_name}` | `{eml_name}` |")

    md.extend([
        "",
        "### Retainer Value Proposition:",
        "- **White-label Protection**: Continuous DNS drift monitoring and automated DMARC/SPF/DKIM spoof defense for retainer clients at $59/mo.",
        "- **Fleet Command Center**: Live 16-bit passive telemetry portal at `https://cmfh009.github.io/Orbit-Security/fleet.html`.",
        "- **Zero Interruption**: Fully passive DoH / CT reconnaissance with zero payload delivery or active network exploitation.",
        "",
        "### Next Action:",
        "- Review staged `.eml` drafts in `outbound_campaigns/` or trigger live dispatch via `scripts/run_followup_campaign.py`."
    ])

    return "\n".join(md)


async def main():
    print("=" * 70)
    print("🚀 ORBIT SECURITY: COHORT 7 STAGING & PERIMETER RECONNAISSANCE")
    print(f"Target Agencies: {len(COHORT_7)}")
    print("=" * 70)

    scanner = OrbitSecurityScanner()
    dispatcher = EmailDispatcher()
    staged_records = []

    for idx, agency in enumerate(COHORT_7, 1):
        print(f"\n[{idx}/{len(COHORT_7)}] Preparing {agency['agency_name']} ({agency['agency_domain']})...")
        try:
            record = await stage_agency(scanner, dispatcher, agency)
            staged_records.append(record)
        except Exception as e:
            print(f"    [❌] Error staging {agency['agency_name']}: {e}")
        await asyncio.sleep(0.5)

    with open(STAGED_LOG, "w", encoding="utf-8") as f:
        json.dump(staged_records, f, indent=2)

    matrix_content = generate_matrix(staged_records)
    MATRIX_FILE.write_text(matrix_content, encoding="utf-8")

    print("\n" + "=" * 70)
    print(f"🏁 Successfully staged {len(staged_records)} Cohort 7 agencies!")
    print(f"Manifest written to: {STAGED_LOG.name}")
    print(f"Matrix written to: {MATRIX_FILE.name}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
