"""scripts/stage_fleet_pilot.py: Generates high-converting, partner-first outreach drafts
for the White-Label Agency Fleet Studio (fleet.html) based on marketing/agency_fleet_outreach.md.
Stores output in private ignored storage: data/outreach_fleet_pilot/.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "data" / "outreach_fleet_pilot"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PILOT_AGENCIES = [
    {
        "id": "10up",
        "name": "10up",
        "domain": "10up.com",
        "focus": "Enterprise WordPress VIP & Publishing",
        "contact_title": "Director of Technology / Partner",
        "angle": "Enterprise retainer defense and multi-site DNS drift monitoring"
    },
    {
        "id": "alley_interactive",
        "name": "Alley Interactive",
        "domain": "alley.com",
        "focus": "High-Traffic News & Media Publishers",
        "contact_title": "VP of Engineering",
        "angle": "Publishing perimeter hygiene & dangling SaaS subdomains"
    },
    {
        "id": "avex_designs",
        "name": "Avex Designs",
        "domain": "avexdesigns.com",
        "focus": "Shopify Plus Fashion & Lifestyle",
        "contact_title": "Founder & Technical Director",
        "angle": "eCommerce monthly maintenance care-plan retainer upsells"
    },
    {
        "id": "anatta",
        "name": "Anatta",
        "domain": "anatta.io",
        "focus": "High-Growth Shopify Plus Brands",
        "contact_title": "Head of Engineering",
        "angle": "Continuous perimeter hygiene during seasonal campaign spin-ups"
    },
    {
        "id": "ask_phill",
        "name": "Ask Phill",
        "domain": "askphill.com",
        "focus": "Headless Shopify & Next.js Commerce",
        "contact_title": "CTO / Lead Architect",
        "angle": "Modern headless edge perimeter & API gateway monitoring"
    },
    {
        "id": "absolute_web",
        "name": "Absolute Web",
        "domain": "absoluteweb.com",
        "focus": "eCommerce (Magento & Shopify Plus)",
        "contact_title": "VP of Technology",
        "angle": "Automated branded security hygiene PDFs for retainer reporting"
    },
    {
        "id": "active_theory",
        "name": "Active Theory",
        "domain": "activetheory.net",
        "focus": "Creative WebGL & Immersive Experiences",
        "contact_title": "Technical Director",
        "angle": "Event & promotional microsite DNS drift protection"
    },
    {
        "id": "akqa",
        "name": "AKQA",
        "domain": "akqa.com",
        "focus": "Global Experience Architecture",
        "contact_title": "Technology Director",
        "angle": "Enterprise multi-domain fleet perimeter command"
    },
    {
        "id": "august_ash",
        "name": "August Ash",
        "domain": "augustash.com",
        "focus": "Mid-Market CMS & Web Care Plans",
        "contact_title": "Director of Client Services",
        "angle": "Turnkey security value-add for $250-$500/mo care plans"
    },
    {
        "id": "astound_commerce",
        "name": "Astound Commerce",
        "domain": "astoundcommerce.com",
        "focus": "Global Omnichannel Commerce",
        "contact_title": "Solutions Architect / Director",
        "angle": "Fleet-wide DMARC enforcement and subdomain takeover defense"
    }
]

def generate_pilot_drafts():
    manifest = {
        "batch_id": "fleet_pilot_01",
        "strategy": "White-Label Fleet Retainer (fleet.html)",
        "count": len(PILOT_AGENCIES),
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

        agency_entry = {
            "id": agency["id"],
            "name": agency["name"],
            "domain": agency["domain"],
            "focus": agency["focus"],
            "contact_title": agency["contact_title"],
            "subject": subject,
            "draft_file": str(txt_path.relative_to(REPO_ROOT))
        }
        manifest["agencies"].append(agency_entry)

    manifest_path = OUTPUT_DIR / "pilot_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Successfully generated {len(PILOT_AGENCIES)} pilot drafts in {OUTPUT_DIR}")
    return manifest

if __name__ == "__main__":
    generate_pilot_drafts()
