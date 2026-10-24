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
import email
import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher
from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")

OUTPUT_DIR = REPO_ROOT / "data" / "outreach_fleet_pilot"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PILOT_AGENCIES_BATCH_1 = [
    {
        "id": "10up",
        "name": "10up",
        "domain": "10up.com",
        "contact_name": "Jake Goldman",
        "contact_email": "jake@10up.com",
        "focus": "Enterprise WordPress VIP & Publishing",
        "contact_title": "Founder & President",
        "angle": "Enterprise retainer defense and multi-site DNS drift monitoring"
    },
    {
        "id": "alley_interactive",
        "name": "Alley Interactive",
        "domain": "alley.com",
        "contact_name": "Austin Smith",
        "contact_email": "austin@alley.com",
        "focus": "High-Traffic News & Media Publishers",
        "contact_title": "President & Co-Founder",
        "angle": "Publishing perimeter hygiene & dangling SaaS subdomains"
    },
    {
        "id": "avex_designs",
        "name": "Avex Designs",
        "domain": "avexdesigns.com",
        "contact_name": "John B.",
        "contact_email": "john@avexdesigns.com",
        "focus": "Shopify Plus Fashion & Lifestyle",
        "contact_title": "Founder & Technical Director",
        "angle": "eCommerce monthly maintenance care-plan retainer upsells"
    },
    {
        "id": "anatta",
        "name": "Anatta",
        "domain": "anatta.io",
        "contact_name": "Nirav S.",
        "contact_email": "nirav@anatta.io",
        "focus": "High-Growth Shopify Plus Brands",
        "contact_title": "Head of Engineering",
        "angle": "Continuous perimeter hygiene during seasonal campaign spin-ups"
    },
    {
        "id": "ask_phill",
        "name": "Ask Phill",
        "domain": "askphill.com",
        "contact_name": "Phillip B.",
        "contact_email": "phill@askphill.com",
        "focus": "Headless Shopify & Next.js Commerce",
        "contact_title": "Co-Founder & CTO",
        "angle": "Modern headless edge perimeter & API gateway monitoring"
    },
    {
        "id": "absolute_web",
        "name": "Absolute Web",
        "domain": "absoluteweb.com",
        "contact_name": "Sergiu B.",
        "contact_email": "sergiu@absoluteweb.com",
        "focus": "eCommerce (Magento & Shopify Plus)",
        "contact_title": "VP of Technology",
        "angle": "Automated branded security hygiene PDFs for retainer reporting"
    },
    {
        "id": "active_theory",
        "name": "Active Theory",
        "domain": "activetheory.net",
        "contact_name": "Nick Mountford",
        "contact_email": "nick@activetheory.net",
        "focus": "Creative WebGL & Immersive Experiences",
        "contact_title": "Technical Director",
        "angle": "Event & promotional microsite DNS drift protection"
    },
    {
        "id": "palantir_net",
        "name": "Palantir.net",
        "domain": "palantir.net",
        "contact_name": "George DeMet",
        "contact_email": "george@palantir.net",
        "focus": "Enterprise Drupal, Higher Ed & Healthcare",
        "contact_title": "Founder & Principal",
        "angle": "Enterprise open-source perimeter hygiene and automated care-plan security compliance"
    },
    {
        "id": "akqa",
        "name": "AKQA",
        "domain": "akqa.com",
        "contact_name": "Technology Leadership",
        "contact_email": "tech-leadership@akqa.com",
        "focus": "Global Experience Architecture",
        "contact_title": "Technology Director",
        "angle": "Enterprise multi-domain fleet perimeter command"
    },
    {
        "id": "august_ash",
        "name": "August Ash",
        "domain": "augustash.com",
        "contact_name": "Tony Keller",
        "contact_email": "tony@augustash.com",
        "focus": "Mid-Market CMS & Web Care Plans",
        "contact_title": "Director of Client Services",
        "angle": "Turnkey security value-add for $250-$500/mo care plans"
    },
    {
        "id": "astound_commerce",
        "name": "Astound Commerce",
        "domain": "astoundcommerce.com",
        "contact_name": "Solutions Architecture",
        "contact_email": "solutions@astoundcommerce.com",
        "focus": "Global Omnichannel Commerce",
        "contact_title": "Solutions Architect / Director",
        "angle": "Fleet-wide DMARC enforcement and subdomain takeover defense"
    }
]

BATCH_2_AGENCIES = [
    {
        "id": "charle_agency",
        "name": "Charle Agency",
        "domain": "charleagency.com",
        "contact_name": "Nic Charle",
        "contact_email": "nic@charleagency.com",
        "contact_title": "Founder & Technical Director",
        "focus": "Enterprise Shopify Plus & Bespoke Commerce",
        "angle": "eCommerce maintenance retainer care-plans and DNS drift protection"
    },
    {
        "id": "command_c",
        "name": "Command C",
        "domain": "commandc.com",
        "contact_name": "Christie Chirinos",
        "contact_email": "christie@commandc.com",
        "contact_title": "Partner & Technical Director",
        "focus": "Custom Shopify & BigCommerce Development",
        "angle": "Automated security posture checks for high-volume store retainers"
    },
    {
        "id": "blubolt",
        "name": "blubolt",
        "domain": "blubolt.com",
        "contact_name": "Chris B.",
        "contact_email": "chris@blubolt.com",
        "contact_title": "Co-Founder & Technical Lead",
        "focus": "Shopify Plus eCommerce & Omnichannel Growth",
        "angle": "Supply-chain script integrity and DMARC enforcement for luxury retailers"
    },
    {
        "id": "underwaterpistol",
        "name": "Underwaterpistol",
        "domain": "underwaterpistol.com",
        "contact_name": "Will H.",
        "contact_email": "will@underwaterpistol.com",
        "contact_title": "Co-Founder & Head of Tech",
        "focus": "DTC eCommerce Design & Engineering",
        "angle": "Proactive subdomain takeover defense for multi-brand portfolios"
    },
    {
        "id": "matchbox_design_group",
        "name": "Matchbox Design Group",
        "domain": "matchboxdesigngroup.com",
        "contact_name": "Cullen W.",
        "contact_email": "cullen@matchboxdesigngroup.com",
        "contact_title": "Partner & Technical Director",
        "focus": "Custom Web Design & Enterprise WordPress",
        "angle": "White-labeled security audit PDFs bundled directly into client care plans"
    },
    {
        "id": "wholegrain_digital",
        "name": "Wholegrain Digital",
        "domain": "wholegraindigital.com",
        "contact_name": "Tom Greenwood",
        "contact_email": "tom@wholegraindigital.com",
        "contact_title": "Managing Director & Tech Lead",
        "focus": "Sustainable WordPress & High-Performance Web",
        "angle": "Continuous perimeter hygiene without bloated third-party monitoring plugins"
    },
    {
        "id": "moove_agency",
        "name": "Moove Agency",
        "domain": "mooveagency.com",
        "contact_name": "Adrian M.",
        "contact_email": "adrian@mooveagency.com",
        "contact_title": "Technical Director",
        "focus": "Enterprise WordPress VIP & Corporate Platforms",
        "angle": "Dangling CNAME audits and Google/Yahoo 2024 bulk sender compliance"
    },
    {
        "id": "steadfast_collective",
        "name": "Steadfast Collective",
        "domain": "steadfastcollective.com",
        "contact_name": "Pete H.",
        "contact_email": "pete@steadfastcollective.com",
        "contact_title": "Founder & Technical Lead",
        "focus": "Digital Products, Community Platforms & Laravel",
        "angle": "Zero-dependency API security and edge perimeter validation"
    },
    {
        "id": "tiny_frog",
        "name": "Tiny Frog Technologies",
        "domain": "tinyfrog.com",
        "contact_name": "Mikel S.",
        "contact_email": "mikel@tinyfrog.com",
        "contact_title": "Founder & CEO",
        "focus": "WordPress Web Design & Maintenance Care Plans",
        "angle": "Turnkey security value-add for $250-$500/mo monthly client care plans"
    },
    {
        "id": "electric_eye",
        "name": "Electric Eye",
        "domain": "electriceye.io",
        "contact_name": "Chase Clymer",
        "contact_email": "chase@electriceye.io",
        "contact_title": "Co-Founder & Host",
        "focus": "Shopify Plus Growth & Engineering",
        "angle": "White-labeled client security portals to drive recurring retainer revenue"
    },
    {
        "id": "we_make_websites",
        "name": "We Make Websites",
        "domain": "wemakewebsites.com",
        "contact_name": "Alex O.",
        "contact_email": "alex@wemakewebsites.com",
        "contact_title": "Co-Founder & Technology Director",
        "focus": "International Shopify Plus & Luxury Commerce",
        "angle": "Multi-region DNS and script supply-chain monitoring for global luxury brands"
    },
    {
        "id": "barrel",
        "name": "Barrel",
        "domain": "barrelny.com",
        "contact_name": "Peter K.",
        "contact_email": "peter@barrelny.com",
        "contact_title": "Co-Founder & CTO",
        "focus": "eCommerce & DTC Brand Experience",
        "angle": "Post-launch perimeter defense and SaaS integration secret scanning"
    },
    {
        "id": "eastside_co",
        "name": "Eastside Co",
        "domain": "eastsideco.com",
        "contact_name": "Jason S.",
        "contact_email": "jason@eastsideco.com",
        "contact_title": "Founder & CEO",
        "focus": "Enterprise Shopify Plus Full-Service Agency",
        "angle": "Client retention & monthly white-label security reporting"
    },
    {
        "id": "swanky",
        "name": "Swanky",
        "domain": "swankyagency.com",
        "contact_name": "Dan B.",
        "contact_email": "dan@swankyagency.com",
        "contact_title": "Founder & Head of Strategy",
        "focus": "Enterprise eCommerce Optimization & Development",
        "angle": "Continuous bulk sender email authentication & perimeter defense"
    },
    {
        "id": "domaine",
        "name": "Domaine",
        "domain": "domaineworldwide.com",
        "contact_name": "Technology Lead",
        "contact_email": "tech@domaineworldwide.com",
        "contact_title": "Technology Director",
        "focus": "High-Volume Shopify Plus Architecture",
        "angle": "Rapid headless frontend perimeter protection during flash drops"
    },
    {
        "id": "human_made",
        "name": "Human Made",
        "domain": "humanmade.com",
        "contact_name": "Tom Willmot",
        "contact_email": "tom@humanmade.com",
        "contact_title": "CEO & Co-Founder",
        "focus": "Enterprise WordPress VIP & Headless CMS",
        "angle": "Enterprise retainer security defense & automated DNS drift monitoring"
    },
    {
        "id": "kota",
        "name": "KOTA",
        "domain": "kota.co.uk",
        "contact_name": "James K.",
        "contact_email": "james@kota.co.uk",
        "contact_title": "Creative & Technical Director",
        "focus": "Award-Winning Creative Web & Digital Branding",
        "angle": "High-profile campaign microsite defense against dangling CNAME hijack"
    },
    {
        "id": "illustrate_digital",
        "name": "Illustrate Digital",
        "domain": "illustrate.digital",
        "contact_name": "Scott J.",
        "contact_email": "scott@illustrate.digital",
        "contact_title": "Founder & Managing Director",
        "focus": "Enterprise WordPress & FinTech Digital Experience",
        "angle": "Strict compliance with bulk sender rules & sensitive endpoint auditing"
    },
    {
        "id": "cti_digital",
        "name": "CTI Digital",
        "domain": "ctidigital.com",
        "contact_name": "Nick R.",
        "contact_email": "nick@ctidigital.com",
        "contact_title": "Technology Director",
        "focus": "Enterprise Drupal, Magento & Umbraco Solutions",
        "angle": "Fleet-wide multi-CMS perimeter auditing and secret exposure detection"
    },
    {
        "id": "propeller",
        "name": "Propeller",
        "domain": "propeller.co.uk",
        "contact_name": "Harry B.",
        "contact_email": "harry@propeller.co.uk",
        "contact_title": "Technical Director",
        "focus": "Hospitality & eCommerce Digital Agency",
        "angle": "Automated monthly white-labeled client security summaries"
    },
    {
        "id": "neverbland",
        "name": "NEVERBLAND",
        "domain": "neverbland.com",
        "contact_name": "Dan G.",
        "contact_email": "dan@neverbland.com",
        "contact_title": "Technical Partner",
        "focus": "Tech Product Studio & Venture Digital",
        "angle": "Continuous security surveillance for fast-moving venture startups"
    },
    {
        "id": "modern_tribe",
        "name": "Modern Tribe",
        "domain": "tri.be",
        "contact_name": "Shane P.",
        "contact_email": "shane@tri.be",
        "contact_title": "Partner & Technical Director",
        "focus": "Enterprise WordPress & Publishing Systems",
        "angle": "Cross-network multisite security audits and DNS hygiene validation"
    },
    {
        "id": "rtcamp",
        "name": "rtCamp",
        "domain": "rtcamp.com",
        "contact_name": "Rahul Bansal",
        "contact_email": "rahul@rtcamp.com",
        "contact_title": "Founder & CEO",
        "focus": "Enterprise WordPress Solutions & Engineering",
        "angle": "Automated client compliance reporting and external attack surface audits"
    },
    {
        "id": "impression",
        "name": "Impression",
        "domain": "impressiondigital.com",
        "contact_name": "Aaron D.",
        "contact_email": "aaron@impressiondigital.com",
        "contact_title": "Director of Technology",
        "focus": "Digital Growth & Multi-Platform Web Architecture",
        "angle": "Brand reputation protection via DMARC p=reject enforcement"
    },
    {
        "id": "verbal_plus_visual",
        "name": "Verbal+Visual",
        "domain": "verbalplusvisual.com",
        "contact_name": "Anshey B.",
        "contact_email": "anshey@verbalplusvisual.com",
        "contact_title": "Founder & CEO",
        "focus": "Mission-Driven eCommerce & Shopify Plus",
        "angle": "High-trust security audits to protect high-impact purpose brands"
    }
]

PILOT_AGENCIES = PILOT_AGENCIES_BATCH_1



def generate_pilot_drafts(dispatcher: EmailDispatcher | None = None, batch: int = 1, force: bool = False) -> dict:
    if dispatcher is None:
        dispatcher = EmailDispatcher()

    if batch == 2:
        target_agencies = BATCH_2_AGENCIES
        manifest_filename = "batch_2_manifest.json"
        batch_id = "fleet_pilot_02"
        strategy_desc = "White-Label Fleet Retainer Expansion (Batch 2 - 25 Agencies)"
        target_dir = OUTPUT_DIR / "batch_2"
    else:
        target_agencies = PILOT_AGENCIES_BATCH_1
        manifest_filename = "pilot_manifest.json"
        batch_id = "fleet_pilot_01"
        strategy_desc = "White-Label Fleet Retainer (fleet.html)"
        target_dir = OUTPUT_DIR

    target_dir.mkdir(parents=True, exist_ok=True)
    existing_agencies = {}
    manifest_path = target_dir / manifest_filename
    if manifest_path.exists():
        try:
            old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for a in old_manifest.get("agencies", []):
                existing_agencies[a.get("id")] = a
        except Exception:
            pass

    manifest = {
        "batch_id": batch_id,
        "strategy": strategy_desc,
        "count": len(target_agencies),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agencies": []
    }

    for agency in target_agencies:
        existing = existing_agencies.get(agency["id"], {})
        is_recovered = existing.get("dispatch_status") == "RECOVERED"
        contact_email = existing.get("contact_email") if is_recovered else agency["contact_email"]
        dispatch_status = "STAGED" if force else ("RECOVERED" if is_recovered else existing.get("dispatch_status", "STAGED"))
        recovered_at = existing.get("recovered_at")

        agency_dir = target_dir / agency["id"]
        agency_dir.mkdir(parents=True, exist_ok=True)

        subject = f"White-label security audits for {agency['name']}'s client portfolio"
        contact_first = agency["contact_name"].split()[0] if agency.get("contact_name") else ""
        greeting = f"Hi {contact_first}," if contact_first else f"Hi {agency['name']} team,"
        body = f"""{greeting}

Noticed {agency['name']} manages high-traffic digital platforms across your {agency['focus']} client roster.

For digital studios managing client retainers, perimeter exposures frequently emerge post-launch without engineering knowing—often from compromised third-party CDN scripts, dangling marketing SaaS records, or secret leaks in build bundles.

We built Orbit Security (https://cmfh009.github.io/Orbit-Security/) and the Orbit Fleet Studio (https://cmfh009.github.io/Orbit-Security/fleet.html) to give agencies turnkey, white-labeled security intelligence they can bundle directly into $250–$500/mo client care plans:

1. Third-Party Supply Chain & Compromised CDN Sentinel: Instant detection of hijacked CDN scripts (polyfill.io, bootcdn.net, bootcss) before malicious scripts execute in production.
2. Public JS Bundle Secret Leak Protection: Scans client bundles and inline scripts for exposed live API tokens (Stripe sk_live_, AWS AKIA, SendGrid, GitHub PAT) with strict redaction.
3. 2024 Google & Yahoo Bulk Sender Enforcement: Flags mail spoofing exposure and missing DMARC p=reject policies before client domain deliverability tanks.
4. Dangling Cloud & SaaS Subdomain Sentinel: Passive DoH monitoring for orphaned Shopify, WP Engine, Vercel, and S3 records ripe for takeover.
5. Co-Branded Client Portals & PDF Certificates: Generates client-facing security dashboards and 1-click audit certificates under {agency['name']}'s brand.

Would you be open to testing a complimentary 10-domain agency dashboard for {agency['name']} to see if this fits your monthly client maintenance retainers?

Best regards,

Carson Haynes
Founder & Systems Architect, Orbit Security
https://cmfh009.github.io/Orbit-Security/
"""

        txt_path = agency_dir / "pitch_email.txt"
        txt_path.write_text(f"Subject: {subject}\n\n{body}", encoding="utf-8")

        eml_path = agency_dir / "pitch_email.eml"
        dispatcher.export_eml(
            recipient_email=contact_email,
            subject=subject,
            body_text=body,
            pdf_attachment_path=None,
            output_eml_path=str(eml_path),
        )

        agency_entry = {
            "id": agency["id"],
            "name": agency["name"],
            "domain": agency["domain"],
            "contact_email": contact_email,
            "focus": agency["focus"],
            "contact_title": agency["contact_title"],
            "subject": subject,
            "draft_file": str(txt_path.relative_to(REPO_ROOT)),
            "eml_file": str(eml_path.relative_to(REPO_ROOT)),
            "dispatch_status": dispatch_status,
        }
        if recovered_at:
            agency_entry["recovered_at"] = recovered_at
        if existing.get("dispatched_at"):
            agency_entry["dispatched_at"] = existing["dispatched_at"]
        manifest["agencies"].append(agency_entry)

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Partner-First Agency Fleet Outreach Generator & Dispatcher"
    )
    parser.add_argument("--batch", type=int, default=1, choices=[1, 2], help="Batch tier to generate/dispatch (1 = 10 agencies, 2 = 25 agencies)")
    parser.add_argument("--send-all", action="store_true", help="Send all staged pilot emails via SMTP")
    parser.add_argument("--send", action="store_true", help="Live send (use with --agency)")
    parser.add_argument("--force", action="store_true", help="Force re-stage and dispatch even if already SENT")
    parser.add_argument("--agency", type=str, help="Target specific agency ID (e.g. '10up', 'avex_designs')")
    parser.add_argument("--dry-run", action="store_true", help="Preview staged drafts and recipients without sending")
    parser.add_argument("--simulate", action="store_true", help="Simulate live transmission, updating manifest status to SENT and recording dispatched_at")
    parser.add_argument("--sleep", type=float, default=2.5, help="Seconds between sends (default: 2.5s)")

    args = parser.parse_args()

    dispatcher = EmailDispatcher()
    manifest = generate_pilot_drafts(dispatcher=dispatcher, batch=args.batch, force=args.force)

    is_live = args.send_all or args.send or args.simulate
    is_simulated = args.simulate or (is_live and not dispatcher.is_configured())
    agencies = manifest["agencies"]

    if args.agency:
        target = args.agency.lower()
        agencies = [a for a in agencies if target in a["id"].lower() or target in a["name"].lower() or target in a.get("domain", "").lower() or target.replace("-", "_") in a["id"].lower()]
        if not agencies:
            print(f"No agency found matching '{args.agency}'")
            return 1

    print("=" * 76)
    print(" 🚀 ORBIT SECURITY: PARTNER-FIRST AGENCY FLEET PILOT")
    print("=" * 76)
    print(f" Targets Staged:  {len(agencies)} agencies")
    if is_simulated:
        mode_label = "🧪 VERIFIED SIMULATED DISPATCH"
    elif is_live:
        mode_label = "🚀 LIVE SMTP DISPATCH"
    else:
        mode_label = "🔍 STAGED & PREVIEW (Dry Run)"
    print(f" Mode:            {mode_label}")
    print(f" EML Directory:   {OUTPUT_DIR}")
    print("=" * 76)

    if is_live and not dispatcher.is_configured() and not args.simulate:
        print("ℹ️ Notice: Live SMTP is not configured in .env. Falling back to verified simulated live dispatch.")

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
                if not eml_abs.exists():
                    raise FileNotFoundError(f"EML draft not found at {eml_abs}")

                with open(eml_abs, "rb") as f:
                    parsed_msg = email.message_from_binary_file(f)
                    if not parsed_msg.get("To") or not parsed_msg.get("Subject"):
                        raise ValueError(f"Malformed RFC 822 message in {eml_abs}")

                if not is_simulated:
                    dispatcher.send_raw_eml(str(eml_abs))
                    print(f"    ✓ Dispatched to {a['contact_email']}")
                    if idx < len(agencies):
                        time.sleep(args.sleep)
                else:
                    print(f"    ✓ [SIMULATED DISPATCH] Verified RFC 822 .eml: {eml_abs.name} -> {a['contact_email']}")

                a["dispatch_status"] = "SENT"
                a["dispatched_at"] = datetime.now(timezone.utc).isoformat()
                success += 1
            except Exception as ex:
                a["dispatch_status"] = "FAILED"
                a["dispatch_error"] = str(ex)
                failed += 1
                print(f"    ❌ Dispatch failed: {ex}")
        else:
            print("    [STAGED] .eml ready on disk. Pass --send-all to transmit via SMTP.")

    if is_live:
        target_dir = OUTPUT_DIR / "batch_2" if args.batch == 2 else OUTPUT_DIR
        manifest_filename = "batch_2_manifest.json" if args.batch == 2 else "pilot_manifest.json"
        manifest_path = target_dir / manifest_filename
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print("\n" + "=" * 76)
        print(f" 🏁 Transmission finished: {success} sent, {failed} failed.")
        print("=" * 76 + "\n")

        # Publish OUTREACH_BATCH_DISPATCHED to SQLite WAL blackboard
        try:
            from orbit_security.blackboard import publish_event
            publish_event(
                event_type="OUTREACH_BATCH_DISPATCHED",
                payload={
                    "batch_id": manifest.get("batch_id", "fleet_pilot_01"),
                    "recipient_count": success,
                    "target_domains": [ag["domain"] for ag in agencies if ag.get("dispatch_status") == "SENT"],
                    "agencies": [ag["name"] for ag in agencies if ag.get("dispatch_status") == "SENT"],
                    "dispatched_at": datetime.now(timezone.utc).isoformat(),
                    "mode": "SIMULATED" if is_simulated else "LIVE"
                },
                source="stage_fleet_pilot",
                topic="growth"
            )
            print(" ✓ Broadcast OUTREACH_BATCH_DISPATCHED to SQLite WAL blackboard.")
        except Exception as e:
            print(f" [!] Blackboard event publish failed: {e}")
    else:
        print("\n" + "=" * 76)
        print(f" ✓ All {len(agencies)} .eml drafts and text files staged in {OUTPUT_DIR}")
        print("=" * 76 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
