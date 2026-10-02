#!/usr/bin/env python3
"""scripts/generate_agency_portal.py: Generates co-branded security portals for agency retainers.

Usage:
    # Generate portal for Eastside Co
    python scripts/generate_agency_portal.py --agency "Eastside Co"

    # Generate portals for all enrolled agencies
    python scripts/generate_agency_portal.py --all

    # Register a new agency on the Scale tier ($499/mo) with a custom domain
    python scripts/generate_agency_portal.py --new-agency "KOTA" --tier Scale --domain "security.kota.co.uk" --support "ops@kota.co.uk"

    # Add a client domain to an agency
    python scripts/generate_agency_portal.py --agency "eastside-co" --add-client "newclient.com" --client-name "New Client Ltd"
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Ensure local src/ is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.agency_retainer import (
    AgencyPortalRenderer,
    AgencyRetainer,
    AgencyRetainerManager,
    RetainerTier,
)


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Agency White-Label Retainer Portal Generator ($299 - $499/mo)"
    )
    parser.add_argument("--agency", "-a", type=str, help="Agency ID or name to generate portal for")
    parser.add_argument("--all", action="store_true", help="Generate portals for all registered agencies")
    parser.add_argument("--tier", choices=["Starter", "Scale", "Enterprise"], default="Scale", help="Retainer Tier")
    parser.add_argument("--domain", type=str, help="Custom branded portal domain (e.g. security.agency.com)")
    parser.add_argument("--support", type=str, help="Support email for the agency")
    parser.add_argument("--new-agency", type=str, help="Register and create a new agency with the given name")
    parser.add_argument("--add-client", type=str, help="Add a client domain to the target agency")
    parser.add_argument("--client-name", type=str, help="Human-readable name for the client domain")
    parser.add_argument("--output-dir", type=str, help="Custom output directory for generated portals")

    args = parser.parse_args()

    manager = AgencyRetainerManager()

    if args.new_agency:
        tier_enum = RetainerTier(args.tier)
        agency_slug = args.new_agency.lower().replace(" ", "-").replace(".", "")
        retainer = manager.register_agency(
            agency_id=agency_slug,
            agency_name=args.new_agency,
            tier=tier_enum,
            custom_domain=args.domain,
            support_email=args.support,
        )
        print(f"✓ Registered new agency: {retainer.agency_name} (ID: {retainer.agency_id}, Tier: {retainer.tier.value} ${retainer.monthly_price}/mo)")
        docs_p, land_p = AgencyPortalRenderer.save_portal(retainer, output_dir=Path(args.output_dir) if args.output_dir else None)
        print(f"  • Generated Docs Portal: {docs_p}")
        if land_p:
            print(f"  • Generated Landing Portal: {land_p}")
        return

    if args.add_client:
        if not args.agency:
            print("Error: Must specify --agency when using --add-client")
            sys.exit(1)
        target_id = args.agency.lower().replace(" ", "-")
        try:
            added = manager.add_client_domain(
                agency_id=target_id,
                domain=args.add_client,
                client_name=args.client_name,
            )
            if added:
                print(f"✓ Added client domain '{args.add_client}' to agency '{target_id}'.")
            else:
                print(f"ℹ Domain '{args.add_client}' is already registered under agency '{target_id}'.")
        except Exception as e:
            print(f"Error adding client domain: {e}")
            sys.exit(1)

    agencies_to_render = []
    if args.all or (not args.agency and not args.new_agency and not args.add_client):
        agencies_to_render = manager.list_agencies()
    elif args.agency:
        target_slug = args.agency.lower().replace(" ", "-")
        # Match by ID or name
        found = manager.get_agency(target_slug)
        if not found:
            for a in manager.list_agencies():
                if a.agency_name.lower() == args.agency.lower():
                    found = a
                    break
        if not found:
            print(f"Error: Agency '{args.agency}' not found. Available agencies: {[a.agency_id for a in manager.list_agencies()]}")
            sys.exit(1)
        agencies_to_render = [found]

    print("\n" + "=" * 70)
    print(" 🚀 ORBIT SECURITY: WHITE-LABEL AGENCY PORTAL GENERATOR")
    print("=" * 70)

    for agency in agencies_to_render:
        docs_path, landing_path = AgencyPortalRenderer.save_portal(
            agency, output_dir=Path(args.output_dir) if args.output_dir else None
        )
        print(f"\n🏢 Agency: {agency.agency_name} (ID: {agency.agency_id})")
        print(f"   Tier: {agency.tier.value} (${agency.monthly_price}/mo) | Portal: {agency.custom_domain or 'Standard'}")
        print(f"   Managed Domains: {len(agency.client_domains)}")
        print(f"   📄 Docs Portal: {docs_path}")
        if landing_path:
            print(f"   🌐 Landing Portal: {landing_path}")

    print("\n" + "=" * 70)
    print(f"✓ Successfully generated {len(agencies_to_render)} agency security portal(s).")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
