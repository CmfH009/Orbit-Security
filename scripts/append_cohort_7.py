#!/usr/bin/env python3
"""Orbit Security: Append and Register Cohort 7 Prospects.

Adds 10 premier, uncontacted global digital commerce and Shopify Plus agencies
into prospects.json with authentic client anchors and personalization hooks.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_FILE = REPO_ROOT / "data" / "prospects.json"

COHORT_7 = [
    {
        "agency_name": "Astound Commerce",
        "agency_domain": "astoundcommerce.com",
        "contact_email": "contact@astoundcommerce.com",
        "portfolio_domains": ["underarmour.com", "crocs.com"],
        "personalization_hook": "We've long respected Astound Commerce's global enterprise scale and headless architecture implementations for iconic retail flagships like Under Armour."
    },
    {
        "agency_name": "Scandiweb",
        "agency_domain": "scandiweb.com",
        "contact_email": "hello@scandiweb.com",
        "portfolio_domains": ["puma.com", "buff.com"],
        "personalization_hook": "We admire Scandiweb's pioneering work in progressive web apps and headless commerce optimization for global market leaders like Puma."
    },
    {
        "agency_name": "MindArc",
        "agency_domain": "mindarc.com.au",
        "contact_email": "hello@mindarc.com.au",
        "portfolio_domains": ["stylerunner.com", "bevilles.com.au"],
        "personalization_hook": "We track MindArc's premier Shopify Plus and headless design architecture across Australian retail leaders like Stylerunner."
    },
    {
        "agency_name": "Redstage",
        "agency_domain": "redstage.com",
        "contact_email": "info@redstage.com",
        "portfolio_domains": ["citgo.com", "arrow.com"],
        "personalization_hook": "We follow Redstage's enterprise B2B and D2C commerce engineering and robust migration patterns for major international retail brands."
    },
    {
        "agency_name": "Praella",
        "agency_domain": "praella.com",
        "contact_email": "hello@praella.com",
        "portfolio_domains": ["aloyoga.com", "chubbiesshorts.com"],
        "personalization_hook": "We admire Praella's technical focus on high-velocity Shopify Plus scaling and custom application engineering for fast-growing lifestyle brands."
    },
    {
        "agency_name": "Pixafy",
        "agency_domain": "pixafy.com",
        "contact_email": "info@pixafy.com",
        "portfolio_domains": ["yamaha.com", "bobsfurniture.com"],
        "personalization_hook": "We follow Pixafy's enterprise digital commerce engineering and custom ERP integration work for mission-critical retail platforms."
    },
    {
        "agency_name": "BORN Group",
        "agency_domain": "borngroup.com",
        "contact_email": "info@borngroup.com",
        "portfolio_domains": ["dita.com", "tagheuer.com"],
        "personalization_hook": "We have immense respect for BORN Group's award-winning brand experience design and luxury commerce flagships for prestige brands like DITA Eyewear."
    },
    {
        "agency_name": "Bluestone98",
        "agency_domain": "bluestone98.com",
        "contact_email": "hello@bluestone98.com",
        "portfolio_domains": ["superdry.com", "loake.com"],
        "personalization_hook": "We admire Bluestone98's technical craftsmanship in high-conversion Shopify Plus builds and bespoke UI systems for heritage British brands."
    },
    {
        "agency_name": "BeMeir",
        "agency_domain": "bemeir.com",
        "contact_email": "info@bemeir.com",
        "portfolio_domains": ["nestle.com", "fender.com"],
        "personalization_hook": "We respect BeMeir's deep open-source engineering expertise, enterprise security diligence, and headless architecture implementations."
    },
    {
        "agency_name": "The Stable",
        "agency_domain": "thestable.com",
        "contact_email": "hello@thestable.com",
        "portfolio_domains": ["ring.com", "quip.com"],
        "personalization_hook": "We follow The Stable's full-service commerce agency leadership and omnichannel scaling for pioneering consumer brands."
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

    for item in COHORT_7:
        if item["agency_domain"] not in existing_domains:
            prospects.append(item)
            existing_domains.add(item["agency_domain"])
            added += 1

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"[✔] Appended {added} new Cohort 7 prospects to {PROSPECTS_FILE.name} (Total: {len(prospects)})")

if __name__ == "__main__":
    main()
