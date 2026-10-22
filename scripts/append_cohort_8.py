#!/usr/bin/env python3
"""Orbit Security: Append and Register Cohort 8 Prospects.

Adds 10 premier, uncontacted global digital commerce and Shopify Plus agencies
into prospects.json with authentic client anchors and personalization hooks.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_FILE = REPO_ROOT / "data" / "prospects.json"

COHORT_8 = [
    {
        "agency_name": "Tryzens",
        "agency_domain": "tryzens.com",
        "contact_email": "info@tryzens.com",
        "portfolio_domains": ["sweatybetty.com", "cottonon.com"],
        "personalization_hook": "We admire Tryzens' international digital commerce engineering and omnichannel scaling for global retail flagships like Sweaty Betty."
    },
    {
        "agency_name": "Kensium",
        "agency_domain": "kensium.com",
        "contact_email": "info@kensium.com",
        "portfolio_domains": ["backcountry.com", "culinarydepotinc.com"],
        "personalization_hook": "We follow Kensium's deep expertise in complex ERP-to-commerce integrations and high-volume enterprise architecture for retailers like Backcountry."
    },
    {
        "agency_name": "Ziffity",
        "agency_domain": "ziffity.com",
        "contact_email": "contactus@ziffity.com",
        "portfolio_domains": ["bergdorfgoodman.com", "orientexpress.com"],
        "personalization_hook": "We respect Ziffity's full-stack digital commerce engineering, cloud infrastructure management, and headless implementations."
    },
    {
        "agency_name": "Series Eight",
        "agency_domain": "serieseight.com",
        "contact_email": "hello@serieseight.com",
        "portfolio_domains": ["oatly.com", "polaroid.com"],
        "personalization_hook": "We admire Series Eight's design-led headless commerce builds and bespoke digital experiences for iconic consumer brands like Polaroid."
    },
    {
        "agency_name": "Kubix Media",
        "agency_domain": "kubixmedia.co.uk",
        "contact_email": "hello@kubixmedia.co.uk",
        "portfolio_domains": ["simbasleep.com", "tefal.co.uk"],
        "personalization_hook": "We've long respected Kubix Media as an award-winning UK Shopify Plus agency powering high-converting storefronts like Simba Sleep and Tefal."
    },
    {
        "agency_name": "Mote",
        "agency_domain": "mote.agency",
        "contact_email": "hello@mote.agency",
        "portfolio_domains": ["skims.com", "glossier.com"],
        "personalization_hook": "We admire Mote's bespoke design-engineering craftsmanship and high-traffic Shopify Plus architectures for category-defining brands like SKIMS."
    },
    {
        "agency_name": "By Association Only",
        "agency_domain": "byassociationonly.com",
        "contact_email": "hello@byassociationonly.com",
        "portfolio_domains": ["astridandmiyu.com", "loupcharmant.com"],
        "personalization_hook": "We follow By Association Only's luxury Shopify Plus builds and refined headless storefronts for prestige international fashion brands."
    },
    {
        "agency_name": "Latori",
        "agency_domain": "latori.com",
        "contact_email": "info@latori.com",
        "portfolio_domains": ["sennheiser.com", "birkenstock.com"],
        "personalization_hook": "We respect Latori's position as a premier European Shopify Plus partner engineering complex enterprise storefronts for global icons like Sennheiser."
    },
    {
        "agency_name": "247 Commerce",
        "agency_domain": "247commerce.co.uk",
        "contact_email": "hello@247commerce.co.uk",
        "portfolio_domains": ["whittard.co.uk", "hackett.com"],
        "personalization_hook": "We track 247 Commerce's enterprise headless commerce and marketplace integration architecture for heritage British brands like Whittard."
    },
    {
        "agency_name": "Elogic Commerce",
        "agency_domain": "elogic.co",
        "contact_email": "info@elogic.co",
        "portfolio_domains": ["whirlpool.com", "hp.com"],
        "personalization_hook": "We admire Elogic Commerce's specialized B2B and D2C commerce engineering and high-availability store infrastructure."
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

    for item in COHORT_8:
        if item["agency_domain"] not in existing_domains:
            prospects.append(item)
            existing_domains.add(item["agency_domain"])
            added += 1

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"[✔] Appended {added} new Cohort 8 prospects to {PROSPECTS_FILE.name} (Total: {len(prospects)})")


if __name__ == "__main__":
    main()
