#!/usr/bin/env python3
"""Runner script for X Profile Bio Scraper & Lead Enrichment (run_lead_enrichment.py).

Usage:
    python scripts/run_lead_enrichment.py --harvest
    python scripts/run_lead_enrichment.py --handle some_user --domain example.com
    python scripts/run_lead_enrichment.py --list
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from orbit_security.desktop_x_bridge import DesktopAutomationDriver
from orbit_security.social_lead_enricher import (
    BioUrlExtractor,
    SocialLeadEnricher,
    UserProfile,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [LEAD-ENRICH] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_lead_enrichment")


def list_leads(enricher: SocialLeadEnricher):
    leads = enricher.load_leads()
    print(f"\n=== Orbit Security Qualified Social Leads ({len(leads)}) ===")
    if not leads:
        print("No leads recorded yet in data/social_leads.json.")
        return

    for l in leads:
        flag = "🚨 TAKEOVER" if l.get("has_critical_takeover") else "✉️ DMARC VULN"
        print(f"\n• Lead ID: {l.get('lead_id')} [{flag}]")
        print(f"  Handle: @{l.get('handle')} ({l.get('name')})")
        print(f"  Target Domain: {l.get('target_domain')} (Score: {l.get('score')}/100, Grade: {l.get('grade')})")
        print(f"  Interaction: {l.get('interaction_type')} | Status: {l.get('status')}")
        print(f"  Findings: {', '.join(l.get('findings_summary', []))}")
        print("  Drafted DM:")
        print(f"    \"{l.get('drafted_dm')}\"")


async def main_async():
    parser = argparse.ArgumentParser(description="Orbit Social Bio Scraper & Lead Enrichment")
    parser.add_argument("--handle", type=str, help="Twitter/X handle to enrich")
    parser.add_argument("--domain", type=str, help="Domain override for evaluation")
    parser.add_argument("--bio", type=str, default="", help="Profile bio text")
    parser.add_argument("--harvest", action="store_true", help="Harvest inbound interactions from desktop X window")
    parser.add_argument("--list", action="store_true", help="List recorded qualified leads")
    parser.add_argument("--mock", action="store_true", help="Force mock automation driver")
    args = parser.parse_args()

    enricher = SocialLeadEnricher()

    if args.list:
        list_leads(enricher)
        return

    if args.handle:
        domain = args.domain or BioUrlExtractor.clean_domain(args.domain or "")
        profile = UserProfile(
            handle=args.handle.replace("@", ""),
            name=args.handle.replace("@", "").title(),
            bio=args.bio or f"Founder @ {domain}" if domain else args.bio,
            bio_url=f"https://{domain}" if domain else None,
            interaction_type="manual_probe",
        )
        logger.info(f"Enriching individual profile @{profile.handle}...")
        lead = await enricher.enrich_profile(profile)
        if lead:
            logger.info(f"✓ High-impact lead qualified! Stored in data/social_leads.json.")
            print(f"\n[DRAFTED DM FOR @{lead.handle}]:\n{lead.drafted_dm}\n")
        else:
            logger.info("Target did not exhibit critical takeover or DMARC vulnerability.")
        return

    if args.harvest or True:
        # Default run: harvest inbound interactions via desktop bridge
        driver = DesktopAutomationDriver(mock_mode=args.mock)
        interactions = driver.harvest_inbound_interactions(limit=10)
        logger.info(f"Discovered {len(interactions)} inbound interactions from desktop session.")

        leads = await enricher.scan_interactions(interactions)
        logger.info(f"Enrichment sweep complete: {len(leads)} qualified leads recorded.")
        list_leads(enricher)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
