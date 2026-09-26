import argparse
import asyncio
import os
import sys
from typing import List

from orbit_security.mailer import EmailDispatcher
from orbit_security.models import AgencyBranding
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner
from dotenv import load_dotenv

load_dotenv()



TARGET_DOMAINS = [
    "example.com",
    "httpbin.org",
]


async def prospect_domain(
    domain: str,
    output_dir: str,
    recipient_email: str = "founder@agency-lead.com",
    send_live: bool = False
):
    os.makedirs(output_dir, exist_ok=True)
    scanner = OrbitSecurityScanner()
    branding = AgencyBranding(
        agency_name=os.getenv("DEFAULT_AGENCY_NAME", "Orbit Security Partner"),
        support_email=os.getenv("DEFAULT_AGENCY_EMAIL", "carsonmail009@gmail.com"),
        website=os.getenv("DEFAULT_AGENCY_WEBSITE", "https://cmfh009.github.io/orbit-security")
    )

    print(f"\n[*] Scanning perimeter for {domain} (including Certificate Transparency logs)...")
    result = await scanner.scan_domain(domain, agency_branding=branding, use_crtsh=True)

    # Output paths
    safe_name = domain.replace(".", "_")
    pdf_path = os.path.join(output_dir, f"{safe_name}_security_audit.pdf")
    md_path = os.path.join(output_dir, f"{safe_name}_security_audit.md")
    email_path = os.path.join(output_dir, f"{safe_name}_pitch_email.txt")
    eml_path = os.path.join(output_dir, f"{safe_name}_pitch_email.eml")

    ReportGenerator.generate_pdf(result, pdf_path)
    ReportGenerator.generate_markdown(result)

    crit_or_high = [f for f in result.findings if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")]

    pitch_lines = [
        f"Hi there,",
        "",
        f"I came across your agency and was admiring your portfolio work.",
        "",
        f"Our automated perimeter scanner ran a routine non-intrusive hygiene check on {domain} and flagged {len(result.findings)} items (Score: {result.score}/100, Grade: {result.grade}).",
        "",
        "Key perimeter findings:",
    ]

    if crit_or_high:
        for f in crit_or_high[:3]:
            pitch_lines.append(f"- [{f.severity.value}] {f.title}: {f.description}")
    else:
        pitch_lines.append("- Perimeter is currently clean, but lacks automated monthly regression monitoring.")

    pitch_lines.extend([
        "",
        f"I've attached the full white-labeled PDF report for your records.",
        "",
        "We built Orbit Security so agencies can automatically generate these co-branded PDF audits every month for all your client domains to justify your $150-$300/mo website maintenance retainers without burning engineer hours.",
        "",
        "Would you be open to a quick look at how your agency can run this across your entire client roster?",
        "",
        "Best regards,",
        f"{branding.agency_name} Operations",
        f"{branding.website}",
    ])

    body_text = "\n".join(pitch_lines)
    subject = f"Security notice regarding {domain} (and a tool for your agency retainers)"

    with open(email_path, "w", encoding="utf-8") as f:
        f.write(f"Subject: {subject}\n\n{body_text}")

    dispatcher = EmailDispatcher()
    dispatcher.export_eml(
        recipient_email=recipient_email,
        subject=subject,
        body_text=body_text,
        pdf_attachment_path=pdf_path,
        output_eml_path=eml_path
    )

    print(f"[+] Audit completed for {domain}:")
    print(f"    - Score: {result.score} ({result.grade})")
    print(f"    - Subdomains Probed: {len(result.subdomains_scanned)}")
    print(f"    - PDF Report: {pdf_path}")
    print(f"    - Click-to-Send .EML Draft: {eml_path}")

    if send_live:
        if dispatcher.is_configured():
            dispatcher.send_email(
                recipient_email=recipient_email,
                subject=subject,
                body_text=body_text,
                pdf_attachment_path=pdf_path
            )
            print(f"    [✔] Live email dispatched via SMTP to {recipient_email}!")
        else:
            print(f"    [!] SMTP not configured in .env. Draft saved to {eml_path} for manual review.")


async def main():
    parser = argparse.ArgumentParser(description="Orbit Security Prospector")
    parser.add_argument("--send", action="store_true", help="Send live emails via SMTP (requires .env)")
    parser.add_argument("--recipient", default="founder@targetagency.com", help="Target email address")
    args = parser.parse_args()

    out_dir = os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns")
    for d in TARGET_DOMAINS:
        await prospect_domain(d, out_dir, recipient_email=args.recipient, send_live=args.send)


if __name__ == "__main__":
    asyncio.run(main())
