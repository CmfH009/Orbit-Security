#!/usr/bin/env python3
"""Orbit Security: Append and Stage Cohort 6 Prospects.

Adds 10 premier, uncontacted Shopify Plus and headless eCommerce design/dev
agencies into prospects.json with authentic client anchors and personalization hooks.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_FILE = REPO_ROOT / "data" / "prospects.json"

COHORT_6 = [
    {
        "agency_name": "Roswell NYC",
        "agency_domain": "roswellnyc.com",
        "contact_email": "contact@roswellnyc.com",
        "portfolio_domains": ["ruggable.com", "adinasjewels.com"],
        "personalization_hook": "We've long admired Roswell's D2C engineering excellence, especially the frictionless headless Shopify architecture powering Ruggable."
    },
    {
        "agency_name": "Zehner",
        "agency_domain": "zehnergroup.com",
        "contact_email": "hello@zehnergroup.com",
        "portfolio_domains": ["stampd.com", "blendsus.com"],
        "personalization_hook": "We have immense respect for Zehner's digital flagship executions and elevated lifestyle brand architecture for Stampd."
    },
    {
        "agency_name": "Vervaunt",
        "agency_domain": "vervaunt.com",
        "contact_email": "hello@vervaunt.com",
        "portfolio_domains": ["gymshark.com", "pandora.net"],
        "personalization_hook": "We admire Vervaunt's premier e-commerce consultancy and high-performance infrastructure consulting for market leaders like Gymshark."
    },
    {
        "agency_name": "Velstar",
        "agency_domain": "velstar.co.uk",
        "contact_email": "hello@velstar.co.uk",
        "portfolio_domains": ["castore.com", "frenchconnection.com"],
        "personalization_hook": "We follow Velstar's robust Shopify Plus enterprise builds, particularly your omnichannel scaling work for Castore."
    },
    {
        "agency_name": "Superco",
        "agency_domain": "superco.net",
        "contact_email": "hello@superco.net",
        "portfolio_domains": ["sohohome.com", "spoke-london.com"],
        "personalization_hook": "We've tracked Superco's bespoke luxury commerce experiences and conversion optimization behind Soho Home."
    },
    {
        "agency_name": "Novatize",
        "agency_domain": "novatize.com",
        "contact_email": "info@novatize.com",
        "portfolio_domains": ["kanuk.com", "laura.ca"],
        "personalization_hook": "We respect Novatize's full-funnel digital commerce implementations and robust catalog management for heritage brands like Kanuk."
    },
    {
        "agency_name": "Ether Creative",
        "agency_domain": "ethercreative.co.uk",
        "contact_email": "hello@ethercreative.co.uk",
        "portfolio_domains": ["churchs.com", "bensherman.co.uk"],
        "personalization_hook": "We love Ether's focus on bespoke British luxury design systems and headless commerce builds for Church's footwear."
    },
    {
        "agency_name": "Pinpoint",
        "agency_domain": "pinpointdesigns.co.uk",
        "contact_email": "hello@pinpointdesigns.co.uk",
        "portfolio_domains": ["bramblecrest.com", "smiggle.co.uk"],
        "personalization_hook": "We admire Pinpoint's technical rigor and custom ERP/eCommerce integration patterns for Bramblecrest."
    },
    {
        "agency_name": "Metacake",
        "agency_domain": "metacake.com",
        "contact_email": "hello@metacake.com",
        "portfolio_domains": ["groovelife.com", "tonyrobbins.com"],
        "personalization_hook": "We've admired Metacake's growth marketing engineering and resilient high-volume Shopify setups for Groove Life."
    },
    {
        "agency_name": "Blue Thirst",
        "agency_domain": "bluethirst.co.uk",
        "contact_email": "info@bluethirst.co.uk",
        "portfolio_domains": ["bathstore.com", "purecollection.com"],
        "personalization_hook": "We follow Blue Thirst's data-led digital growth and high-converting checkout experiences across UK retail."
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

    for item in COHORT_6:
        if item["agency_domain"] not in existing_domains:
            prospects.append(item)
            existing_domains.add(item["agency_domain"])
            added += 1
            print(f"[+] Added: {item['agency_name']} ({item['agency_domain']})")
        else:
            print(f"[-] Already present: {item['agency_domain']}")

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"\n[✔] Successfully appended {added} prospects to {PROSPECTS_FILE.name}.")
    print(f"[✔] Total registry now stands at {len(prospects)} prospects.")


if __name__ == "__main__":
    main()
