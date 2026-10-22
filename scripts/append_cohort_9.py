#!/usr/bin/env python3
"""Orbit Security: Append and Register Cohort 9 Prospects.

Adds 10 premier, uncontacted global digital commerce and Shopify Plus agencies
into prospects.json with verified MX/published contact emails and authentic client anchors.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_FILE = REPO_ROOT / "data" / "prospects.json"

COHORT_9 = [
    {
        "agency_name": "Rainy City Agency",
        "agency_domain": "rainycityagency.com",
        "contact_email": "hello@rainycityagency.com",
        "portfolio_domains": ["dartscorner.co.uk", "cernucci.com"],
        "personalization_hook": "We admire Rainy City Agency's high-converting Shopify Plus migrations and bespoke storefront engineering for fast-scaling retail brands like Darts Corner and Cernucci."
    },
    {
        "agency_name": "DYODE",
        "agency_domain": "dyode.com",
        "contact_email": "hello@dyode.com",
        "portfolio_domains": ["agjeans.com", "dita.com"],
        "personalization_hook": "We follow DYODE's enterprise Shopify Plus architecture and custom omnichannel commerce builds for luxury fashion flagships like AG Jeans."
    },
    {
        "agency_name": "Codal",
        "agency_domain": "codal.com",
        "contact_email": "go@codal.com",
        "portfolio_domains": ["thermos.com", "glassybaby.com"],
        "personalization_hook": "We respect Codal's enterprise Shopify Platinum engineering and complex platform migrations for iconic consumer brands like Thermos and glassybaby."
    },
    {
        "agency_name": "Grebban",
        "agency_domain": "grebban.com",
        "contact_email": "hello@grebban.com",
        "portfolio_domains": ["bjornborg.com", "jlindeberg.com"],
        "personalization_hook": "We admire Grebban's design-led headless commerce architecture and global digital flagship stores for Scandinavian fashion leaders like Björn Borg and J.Lindeberg."
    },
    {
        "agency_name": "Process Creative",
        "agency_domain": "processcreative.com.au",
        "contact_email": "enquiries@processcreative.com.au",
        "portfolio_domains": ["bondisands.com.au", "cocofloss.com"],
        "personalization_hook": "We track Process Creative's international Shopify Plus builds and high-velocity D2C commerce experiences for category leaders like Bondi Sands and Cocofloss."
    },
    {
        "agency_name": "Convert Digital",
        "agency_domain": "convertdigital.com.au",
        "contact_email": "enquiries@convertdigital.com.au",
        "portfolio_domains": ["2xu.com", "boody.com.au"],
        "personalization_hook": "We respect Convert Digital's composable commerce engineering and high-traffic Shopify Plus storefronts for premier retail brands like 2XU and Boody."
    },
    {
        "agency_name": "Aligent",
        "agency_domain": "aligent.com.au",
        "contact_email": "contact@aligent.com.au",
        "portfolio_domains": ["theathletesfoot.com.au", "rockwear.com.au"],
        "personalization_hook": "We follow Aligent's complex enterprise commerce integrations and headless omnichannel architecture for major retail flagships like The Athlete's Foot and Rockwear."
    },
    {
        "agency_name": "StudioForty9",
        "agency_domain": "studioforty9.com",
        "contact_email": "info@studioforty9.com",
        "portfolio_domains": ["elverys.ie", "mcelhinneys.com"],
        "personalization_hook": "We admire StudioForty9's enterprise eCommerce transformations and high-scale omnichannel retail engineering for leading brands like Intersport Elverys and McElhinneys."
    },
    {
        "agency_name": "Wondersauce",
        "agency_domain": "wondersauce.com",
        "contact_email": "hello@wondersauce.com",
        "portfolio_domains": ["crunchlabs.com", "sixpenny.com"],
        "personalization_hook": "We admire Wondersauce's bespoke digital commerce engineering and subscription platform scaling for modern flagship brands like CrunchLabs and Sixpenny."
    },
    {
        "agency_name": "Fluid Commerce",
        "agency_domain": "fluidcommerce.co.uk",
        "contact_email": "hello@fluidcommerce.co.uk",
        "portfolio_domains": ["augustinusbader.com", "cartwrightandbutler.co.uk"],
        "personalization_hook": "We respect Fluid Commerce's award-winning eCommerce engineering and high-performance storefront builds for luxury retail brands like Augustinus Bader and Cartwright & Butler."
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

    for item in COHORT_9:
        if item["agency_domain"] not in existing_domains:
            prospects.append(item)
            existing_domains.add(item["agency_domain"])
            added += 1

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"[✔] Appended {added} new Cohort 9 prospects to {PROSPECTS_FILE.name} (Total: {len(prospects)})")


if __name__ == "__main__":
    main()
