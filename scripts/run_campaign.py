import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from orbit_security.mailer import EmailDispatcher
from orbit_security.models import AgencyBranding
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner
from dotenv import load_dotenv

load_dotenv()


# Personalized hooks connecting Carson's engineering perspective to each agency's unique focus
AGENCY_PERSONALIZATION = {
    "charleagency.com": (
        "We've been following your team's e-commerce builds, particularly how you craft clean Shopify Plus experiences for brands like Candy Kittens."
    ),
    "wholegraindigital.com": (
        "As developers who care deeply about lean, efficient, zero-bloat architecture, we have long respected Wholegrain Digital's pioneering leadership in sustainable, low-carbon web design."
    ),
    "steadfastcollective.com": (
        "We came across your agency and were genuinely impressed by your work supporting developer ecosystems and open-source infrastructure—especially seeing your footprint with Adoptium/OpenJDK."
    ),
    "tinyfrog.com": (
        "We know Tiny Frog is renowned for specialized WordPress care plans, particularly for high-trust professional firms like Define Financial where compliance, client privacy, and brand trust are non-negotiable."
    ),
    "electriceye.io": (
        "We're big fans of your team's pragmatic approach to scaling high-volume Shopify Plus brands (like Giordano's)."
    ),
    "commandc.com": (
        "We've been following Command C's technical craftsmanship on high-catalog e-commerce architectures like Eden Brothers."
    ),
    "blubolt.com": (
        "We were admiring blubolt's work crafting seamless digital shopping experiences for heritage brands like Snowdonia Cheese."
    ),
    "underwaterpistol.com": (
        "We've been following Underwaterpistol's design-forward DTC builds like Brew Tea Company."
    ),
    "matchboxdesigngroup.com": (
        "We were admiring Matchbox's creative digital work, especially the clean experience on Blueprint Coffee."
    ),
    "mooveagency.com": (
        "We have immense respect for Moove's enterprise WordPress work supporting mission-driven platforms like CharityJob."
    ),
}


async def process_prospect(prospect: dict, output_root: str, send_live: bool = False):
    agency_name = prospect["agency_name"]
    agency_domain = prospect["agency_domain"]
    contact_email = prospect["contact_email"]
    portfolio_domains = prospect.get("portfolio_domains", [])

    target_domain = portfolio_domains[0] if portfolio_domains else agency_domain
    out_dir = os.path.join(output_root, agency_domain.replace(".", "_"))
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n=======================================================")
    print(f"[*] Processing Agency: {agency_name} ({agency_domain})")
    print(f"    - Recipient: {contact_email}")
    print(f"    - Target Portfolio Domain: {target_domain}")

    branding = AgencyBranding(
        agency_name=agency_name,
        support_email="carsonmail009@gmail.com",
        website=f"https://{agency_domain}"
    )

    safe_target = target_domain.replace(".", "_")
    pdf_path = os.path.join(out_dir, f"{safe_target}_security_audit.pdf")

    # If already scanned, reuse or re-scan quickly
    scanner = OrbitSecurityScanner(timeout=6.0)
    result = await scanner.scan_domain(target_domain, agency_branding=branding, use_crtsh=False)

    ReportGenerator.generate_pdf(result, pdf_path)
    ReportGenerator.generate_markdown(result)

    email_path = os.path.join(out_dir, "pitch_email.txt")
    eml_path = os.path.join(out_dir, "pitch_email.eml")

    # If a tailored, critic-approved pitch_email.txt already exists, preserve and use it!
    if os.path.exists(email_path):
        with open(email_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        lines = raw_content.splitlines()
        if lines and lines[0].startswith("Subject: "):
            subject = lines[0][len("Subject: "):].strip()
            body_text = "\n".join(lines[1:]).strip()
        else:
            subject = f"{target_domain} hygiene check / white-label retainer reports for {agency_name}"
            body_text = raw_content.strip()
    else:
        crit_or_high = [f for f in result.findings if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")]

        personal_hook = prospect.get("personalization_hook") or AGENCY_PERSONALIZATION.get(
            agency_domain,
            f"We've been admiring your agency's client craftsmanship on {target_domain}."
        )

        pitch_lines = [
            f"Hi {agency_name} team,",
            "",
            f"I'm Carson, software engineer and founder of Orbit Security. {personal_hook}",
            "",
            f"I ran a baseline external hygiene check on {target_domain} (Score: {result.score}/100, Grade: {result.grade}).",
            "",
        ]

        if crit_or_high:
            pitch_lines.append("Key perimeter observations:")
            for f in crit_or_high[:2]:
                pitch_lines.append(f"- [{f.severity.value}] {f.title}: {f.description}")
        else:
            pitch_lines.append(f"Perimeter is clean (100/100). Like most high-caliber builds, non-technical stakeholders often take this baseline for granted.")

        pitch_lines.extend([
            "",
            f"I've attached a sample co-branded audit PDF for {target_domain}.",
            "",
            "We built Orbit Security so agencies can automatically generate these white-label PDF audits every month for all client domains—giving clients tangible proof of work to defend $150-$350/mo maintenance retainers without pulling senior developers away from billable work.",
            "",
            "Open to taking a quick look at a sample audit co-branded for your agency?",
            "",
            "Best,",
            "Carson",
            "Founder & Software Engineer, Orbit Security",
            "https://cmfh009.github.io/Orbit-Security/",
        ])

        body_text = "\n".join(pitch_lines)
        subject = f"{target_domain} perimeter check / white-label retainer reports for {agency_name}"

        with open(email_path, "w", encoding="utf-8") as f:
            f.write(f"Subject: {subject}\n\n{body_text}")


    dispatcher = EmailDispatcher()
    dispatcher.export_eml(
        recipient_email=contact_email,
        subject=subject,
        body_text=body_text,
        pdf_attachment_path=pdf_path,
        output_eml_path=eml_path
    )

    print(f"[+] Tailored Campaign for {agency_name}:")
    print(f"    - Recipient: {contact_email}")
    print(f"    - Audited: {target_domain} (Score: {result.score}/100, Grade: {result.grade})")
    print(f"    - PDF Audit Attached: {pdf_path}")

    if send_live:
        if dispatcher.is_configured():
            dispatcher.send_email(
                recipient_email=contact_email,
                subject=subject,
                body_text=body_text,
                pdf_attachment_path=pdf_path
            )
            print(f"    [✔] Live email successfully dispatched via Gmail SMTP to {contact_email}!")
            return True
        else:
            print(f"    [!] SMTP not configured in .env. Draft saved to {eml_path}.")
            return False
    return False


def load_dispatched_state(file_path: str) -> dict:
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_dispatched_state(file_path: str, state: dict):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


async def main():
    parser = argparse.ArgumentParser(description="Run Orbit Security Prospecting Campaign")
    parser.add_argument("--send", action="store_true", help="Send live emails via SMTP")
    parser.add_argument("--start", type=int, default=0, help="Starting index in prospects list (default: 0)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of prospects to process")
    parser.add_argument("--force", action="store_true", help="Force re-dispatch even if already sent")
    args = parser.parse_args()

    prospects_file = os.path.join(os.path.dirname(__file__), "..", "data", "prospects.json")
    dispatched_file = os.path.join(os.path.dirname(__file__), "..", "data", "dispatched_campaigns.json")
    dispatched_state = load_dispatched_state(dispatched_file)

    with open(prospects_file, "r", encoding="utf-8") as f:
        prospects = json.load(f)

    out_root = os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns")

    selected = prospects[args.start : args.start + args.limit]
    print(f"[*] Starting personalized campaign run for {len(selected)} agencies (offset {args.start})...")

    import datetime
    for p in selected:
        agency_domain = p.get("agency_domain", "")
        contact_email = p.get("contact_email", "")

        if args.send and not args.force and agency_domain in dispatched_state:
            prev = dispatched_state[agency_domain]
            print(f"[*] [SKIP] {agency_domain} ({contact_email}) already dispatched on {prev.get('dispatched_at')}. (Use --force to override)")
            continue

        try:
            sent = await process_prospect(p, out_root, send_live=args.send)
            if sent:
                dispatched_state[agency_domain] = {
                    "agency_name": p.get("agency_name"),
                    "contact_email": contact_email,
                    "dispatched_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "SENT"
                }
                save_dispatched_state(dispatched_file, dispatched_state)
                # Gentle 4.0s delay between sends to adhere to good mail reputation
                await asyncio.sleep(4.0)
        except Exception as e:
            print(f"[!] Error processing {p.get('agency_name')}: {e}")

    print("\n[✔] All campaigns processed and dispatched!")


if __name__ == "__main__":
    asyncio.run(main())
