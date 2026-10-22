#!/usr/bin/env python3
"""Orbit Security: Append and Register Cohort 10 Prospects (WordPress VIP, Laravel, Drupal & Enterprise Commerce Agencies)."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_FILE = REPO_ROOT / "data" / "prospects.json"

COHORT_10 = [
    {
        "agency_name": "Human Made",
        "agency_domain": "humanmade.com",
        "contact_email": "hello@humanmade.com",
        "portfolio_domains": ["techcrunch.com", "usa.gov"],
        "personalization_hook": "We admire Human Made's enterprise WordPress VIP architecture and high-scale Altis DXP engineering for global media and enterprise platforms."
    },
    {
        "agency_name": "WebDevStudios",
        "agency_domain": "webdevstudios.com",
        "contact_email": "contact@webdevstudios.com",
        "portfolio_domains": ["campbells.com", "nba.com"],
        "personalization_hook": "We follow WebDevStudios' bespoke enterprise WordPress VIP builds and complex headless CMS migrations for iconic consumer brands."
    },
    {
        "agency_name": "rtCamp",
        "agency_domain": "rtcamp.com",
        "contact_email": "hello@rtcamp.com",
        "portfolio_domains": ["aljazeera.com", " Coxautoinc.com".strip().lower()],
        "personalization_hook": "We respect rtCamp's global WordPress VIP Gold engineering, PHP/Composer performance hardening, and enterprise digital publishing pipelines."
    },
    {
        "agency_name": "Tighten",
        "agency_domain": "tighten.com",
        "contact_email": "hello@tighten.com",
        "portfolio_domains": ["laravel.com", "genentech.com"],
        "personalization_hook": "We admire Tighten's premier Laravel and PHP application engineering, Composer supply-chain stewardship, and enterprise web architecture."
    },
    {
        "agency_name": "Lullabot",
        "agency_domain": "lullabot.com",
        "contact_email": "hello@lullabot.com",
        "portfolio_domains": ["grammy.com", "ibm.com"],
        "personalization_hook": "We track Lullabot's enterprise Drupal engineering and high-traffic PHP digital experiences for major media and public-sector leaders."
    },
    {
        "agency_name": "Four Kitchens",
        "agency_domain": "fourkitchens.com",
        "contact_email": "hello@fourkitchens.com",
        "portfolio_domains": ["nbc.com", "stanford.edu"],
        "personalization_hook": "We respect Four Kitchens' enterprise Drupal & WordPress architecture and high-scale publishing systems for leading research and media organizations."
    },
    {
        "agency_name": "Palantir.net",
        "agency_domain": "palantir.net",
        "contact_email": "info@palantir.net",
        "portfolio_domains": ["uchicago.edu", "ahrq.gov"],
        "personalization_hook": "We admire Palantir.net's open-source Drupal stewardship and complex digital platform builds for healthcare, higher education, and enterprise brands."
    },
    {
        "agency_name": "Alley Interactive",
        "agency_domain": "alley.com",
        "contact_email": "info@alley.com",
        "portfolio_domains": ["kff.org", "brookings.edu"],
        "personalization_hook": "We follow Alley Interactive's enterprise WordPress VIP and modern PHP engineering for high-traffic research institutions and global newsrooms."
    },
    {
        "agency_name": "Fixel",
        "agency_domain": "fixel.com",
        "contact_email": "hello@fixel.com",
        "portfolio_domains": ["beardbrand.com", "roguefitness.com"],
        "personalization_hook": "We admire Fixel's high-craft digital product design, custom WordPress/Shopify builds, and brand perimeter execution."
    },
    {
        "agency_name": "Dekode",
        "agency_domain": "dekode.no",
        "contact_email": "hei@dekode.no",
        "portfolio_domains": ["reddbarna.no", "oblinor.no"],
        "personalization_hook": "We respect Dekode's status as a leading European WordPress VIP agency building high-trust digital platforms."
    }
]


def main():
    if not PROSPECTS_FILE.exists():
        print(f"Error: {PROSPECTS_FILE} not found.")
        return

    with open(PROSPECTS_FILE, "r", encoding="utf-8") as f:
        prospects = json.load(f)

    existing_domains = {p.get("agency_domain") for p in prospects}
    added = 0

    for item in COHORT_10:
        if item["agency_domain"] not in existing_domains:
            prospects.append(item)
            existing_domains.add(item["agency_domain"])
            added += 1

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"[✔] Appended {added} new Cohort 10 agencies to prospects.json (Total: {len(prospects)})")


if __name__ == "__main__":
    main()
