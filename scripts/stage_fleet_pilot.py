"""scripts/stage_fleet_pilot.py: Generates and manages high-converting, partner-first outreach drafts
for the White-Label Agency Fleet Studio (fleet.html) based on marketing/agency_fleet_outreach.md.
Stores output in private ignored storage: data/outreach_fleet_pilot/.

Usage:
    # Staging only: generate pitch_email.txt and pitch_email.eml for all 10 agencies
    python scripts/stage_fleet_pilot.py

    # Dry-run dispatch inspection
    python scripts/stage_fleet_pilot.py --dry-run

    # Live dispatch to a single agency
    python scripts/stage_fleet_pilot.py --agency 10up --send

    # Live dispatch to all 10 agencies
    python scripts/stage_fleet_pilot.py --send-all
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

OUTPUT_DIR = REPO_ROOT / "data" / "outreach_fleet_pilot"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PILOT_AGENCIES = [
    {
        "id": "10up",
        "name": "10up",
        "domain": "10up.com",
        "contact_email": "sales@10up.com",
        "focus": "Enterprise WordPress VIP & Publishing",
        "contact_title": "Director of Technology / Partner",
        "angle": "Enterprise retainer defense and multi-site DNS drift monitoring"
    },
    {
        "id": "alley_interactive",
        "name": "Alley Interactive",
        "domain": "alley.com",
        "contact_email": "info@alley.com",
        "focus": "High-Traffic News & Media Publishers",
        "contact_title": "VP of Engineering",
        "angle": "Publishing perimeter hygiene & dangling SaaS subdomains"
    },
    {
        "id": "avex_designs",
        "name": "Avex Designs",
        "domain": "avexdesigns.com",
        "contact_email": "hello@avexdesigns.com",
        "focus": "Shopify Plus Fashion & Lifestyle",
        "contact_title": "Founder & Technical Director",
        "angle": "eCommerce monthly maintenance care-plan retainer upsells"
    },
    {
        "id": "anatta",
        "name": "Anatta",
        "domain": "anatta.io",
        "contact_email": "hello@anatta.io",
        "focus": "High-Growth Shopify Plus Brands",
        "contact_title": "Head of Engineering",
        "angle": "Continuous perimeter hygiene during seasonal campaign spin-ups"
    },
    {
        "id": "ask_phill",
        "name": "Ask Phill",
        "domain": "askphill.com",
        "contact_email": "hello@askphill.com",
        "focus": "Headless Shopify & Next.js Commerce",
        "contact_title": "CTO / Lead Architect",
        "angle": "Modern headless edge perimeter & API gateway monitoring"
    },
    {
        "id": "absolute_web",
        "name": "Absolute Web",
        "domain": "absoluteweb.com",
        "contact_email": "info@absoluteweb.com",
        "focus": "eCommerce (Magento & Shopify Plus)",
        "contact_title": "VP of Technology",
        "angle": "Automated branded security hygiene PDFs for retainer reporting"
    },
    {
        "id": "active_theory",
        "name": "Active Theory",
        "domain": "activetheory.net",
        "contact_email": "contact@activetheory.net",
        "focus": "Creative WebGL & Immersive Experiences",
        "contact_title": "Technical Director",
        "angle": "Event & promotional microsite DNS drift protection"
    },
    {
        "id": "akqa",
        "name": "AKQA",
        "domain": "akqa.com",
        "contact_email": "contact@akqa.com",
        "focus": "Global Experience Architecture",
        "contact_title": "Technology Director",
        "angle": "Enterprise multi-domain fleet perimeter command"
    },
    {
        "id": "august_ash",
        "name": "August Ash",
        "domain": "augustash.com",
        "contact_email": "info@augustash.com",
        "focus": "Mid-Market CMS & Web Care Plans",
        "contact_title": "Director of Client Services",
        "angle": "Turnkey security value-add for $250-$500/mo care plans"
    },
    {
        "id": "astound_commerce",
        "name": "Astound Commerce",
        "domain": "astoundcommerce.com",
        "contact_email": "privacy@astounddigital.com",
        "focus": "Global Omnichannel Commerce",
        "contact_title": "Solutions Architect / Director",
        "angle": "Fleet-wide DMARC enforcement and subdomain takeover defense"
    }
]


def generate_pilot_drafts(dispatcher: EmailDispatcher | None = None) -> dict:
    if dispatcher is None:
        dispatcher = EmailDispatcher()

    manifest = {
        "batch_id": "fleet_pilot_01",
        "strategy": "White-Label Fleet Retainer (fleet.html)",
        "count": len(PILOT_AGENCIES),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agencies": []
    }

    for agency in PILOT_AGENCIES:
        agency_dir = OUTPUT_DIR / agency["id"]
        agency_dir.mkdir(parents=True, exist_ok=True)

        subject = f"White-label security audits for {agency['name']}'s client portfolio"
        body = f"""Hi {agency['name']} team,

Noticed {agency['name']} manages complex web builds across your {agency['focus']} client roster.

A recurring headache for digital studios is client DNS drift post-launch—marketing teams spin up unmonitored subdomains or third-party SaaS services that eventually expire into dangling records.

We built the Orbit Fleet Studio (https://cmfh009.github.io/Orbit-Security/fleet.html) specifically for agencies:
1. Multi-Client Perimeter Sentinel: Monitor your entire client fleet in one lightweight HUD.
2. 100% Passive DoH Telemetry: Zero active scans or intrusive probes against client infrastructure.
3. Branded Client PDFs: Export 1-click executive hygiene certificates under {agency['name']}'s brand to include in your monthly maintenance retainers.

Would you be open to testing a complimentary 10-domain agency dashboard for {agency['name']} to see if it fits your client care plans?

Best regards,

Carson Haynes
Founder & Systems Architect, Orbit Security
https://cmfh009.github.io/Orbit-Security/
"""

        txt_path = agency_dir / "pitch_email.txt"
        txt_path.write_text(f"Subject: {subject}\n\n{body}", encoding="utf-8")

        eml_path = agency_dir / "pitch_email.eml"
        dispatcher.export_eml(
            recipient_email=agency["contact_email"],
            subject=subject,
            body_text=body,
            pdf_attachment_path=None,
            output_eml_path=str(eml_path),
        )

        agency_entry = {
            "id": agency["id"],
            "name": agency["name"],
            "domain": agency["domain"],
            "contact_email": agency["contact_email"],
            "focus": agency["focus"],
            "contact_title": agency["contact_title"],
            "subject": subject,
            "draft_file": str(txt_path.relative_to(REPO_ROOT)),
            "eml_file": str(eml_path.relative_to(REPO_ROOT)),
            "dispatch_status": "STAGED",
        }
        manifest["agencies"].append(agency_entry)

    manifest_path = OUTPUT_DIR / "pilot_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Partner-First Agency Fleet Outreach Generator & Dispatcher"
    )
    parser.add_argument("--send-all", action="store_true", help="Send all 10 staged pilot emails via SMTP")
    parser.add_argument("--send", action="store_true", help="Live send (use with --agency)")
    parser.add_argument("--agency", type=str, help="Target specific agency ID (e.g. '10up', 'avex_designs')")
    parser.add_argument("--dry-run", action="store_true", help="Preview staged drafts and recipients without sending")
    parser.add_argument("--sleep", type=float, default=2.5, help="Seconds between sends (default: 2.5s)")

    args = parser.parse_args()

    dispatcher = EmailDispatcher()
    manifest = generate_pilot_drafts(dispatcher=dispatcher)

    is_live = args.send_all or args.send
    agencies = manifest["agencies"]

    if args.agency:
        target = args.agency.lower()
        agencies = [a for a in agencies if target in a["id"].lower() or target in a["name"].lower()]
        if not agencies:
            print(f"No agency found matching '{args.agency}'")
            return 1

    print("=" * 76)
    print(" 🚀 ORBIT SECURITY: PARTNER-FIRST AGENCY FLEET PILOT")
    print("=" * 76)
    print(f" Targets Staged:  {len(agencies)} agencies")
    print(f" Mode:            {'🚀 LIVE DISPATCH' if is_live else '🔍 STAGED & PREVIEW (Dry Run)'}")
    print(f" EML Directory:   {OUTPUT_DIR}")
    print("=" * 76)

    if is_live and not dispatcher.is_configured():
        print("❌ Error: SMTP is not configured in .env. Cannot perform live transmission.")
        return 1

    success = 0
    failed = 0

    for idx, a in enumerate(agencies, 1):
        print(f"\n[{idx}/{len(agencies)}] {a['name']} ({a['domain']})")
        print(f"    Recipient:  {a['contact_email']} [{a['contact_title']}]")
        print(f"    Focus:      {a['focus']}")
        print(f"    Draft EML:  {a['eml_file']}")

        if is_live:
            try:
                eml_abs = REPO_ROOT / a["eml_file"]
                dispatcher.send_raw_eml(str(eml_abs))
                a["dispatch_status"] = "SENT"
                a["dispatched_at"] = datetime.now(timezone.utc).isoformat()
                success += 1
                print(f"    ✓ Dispatched to {a['contact_email']}")
                if idx < len(agencies):
                    time.sleep(args.sleep)
            except Exception as ex:
                a["dispatch_status"] = "FAILED"
                a["dispatch_error"] = str(ex)
                failed += 1
                print(f"    ❌ Dispatch failed: {ex}")
        else:
            print("    [STAGED] .eml ready on disk. Pass --send-all to transmit via SMTP.")

    if is_live:
        manifest_path = OUTPUT_DIR / "pilot_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print("\n" + "=" * 76)
        print(f" 🏁 Transmission finished: {success} sent, {failed} failed.")
        print("=" * 76 + "\n")
    else:
        print("\n" + "=" * 76)
        print(f" ✓ All {len(agencies)} .eml drafts and text files staged in {OUTPUT_DIR}")
        print("=" * 76 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
