#!/usr/bin/env python3
"""Orbit Security: $10 Meta Ad Campaign Staging Engine.

Prepares, audits, and stages the $10 Meta Test Flight campaign targeting
Shopify Plus and web agencies per the tactical blueprint.
"""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
CREATIVE_ASSET_PATH = REPO_ROOT / "landing" / "assets" / "orbit_cats_pounce.jpg"

CAMPAIGN_CONFIG = {
    "campaign_name": "Orbit Security - Agency Retainer Test Flight v1",
    "objective": "Traffic",
    "optimization_goal": "Landing Page Views",
    "total_budget_usd": 10.00,
    "daily_budget_usd": 2.50,
    "duration_days": 4,
    "bidding_strategy": "Highest Volume (Lowest Cost)",
    "destination_base": "https://cmfh009.github.io/Orbit-Security/",
}

TARGETING_CONFIG = {
    "locations": ["United States", "United Kingdom", "Canada"],
    "age_min": 25,
    "age_max": 54,
    "languages": ["English (All)"],
    "interests": [
        "Shopify Plus",
        "Web design",
        "Web development",
        "WordPress",
        "Cybersecurity",
    ],
    "job_titles": [
        "Founder",
        "Co-Founder",
        "Managing Director",
        "Creative Director",
        "Lead Developer",
        "Chief Technology Officer",
        "Agency Owner",
    ],
    "placements": ["Facebook Feed", "Instagram Feed"],
}

AD_VARIANTS = {
    "variant_1": {
        "name": "The Retainer Multiplier",
        "recommended": True,
        "headline": "Automate Agency Security Retainers",
        "description": "White-label audit PDFs in 10 seconds",
        "call_to_action": "Learn More",
        "url": (
            "https://cmfh009.github.io/Orbit-Security/"
            "?utm_source=meta&utm_medium=feed&utm_campaign=retainer_multiplier&utm_content=astro_pounce"
        ),
        "primary_text": (
            "How do top Shopify Plus & WordPress agencies justify $250/mo client maintenance "
            "retainers without burning engineering hours?\n\n"
            "They run automated monthly perimeter hygiene checks.\n\n"
            "Orbit Security scans your client roster in seconds—detecting misconfigured DNS records, "
            "exposed staging subdomains, missing DMARC security, and expiring SSL certificates—and "
            "generates co-branded, white-label client PDF reports.\n\n"
            "Run a free audit on your client domains today:"
        ),
    },
    "variant_2": {
        "name": "The Sentinel Guardian",
        "recommended": False,
        "headline": "Perimeter Defense for Web Agencies",
        "description": "Protect builds & export audit reports",
        "call_to_action": "Learn More",
        "url": (
            "https://cmfh009.github.io/Orbit-Security/"
            "?utm_source=meta&utm_medium=feed&utm_campaign=sentinel_guardian&utm_content=astro_pounce"
        ),
        "primary_text": (
            "Meet the perimetric sentinels guarding agency digital builds. 🛡️🐾\n\n"
            "A single exposed staging subdomain or dangling DNS record can compromise an entire client portfolio. "
            "Orbit Security provides continuous automated perimeter reconnaissance, vulnerability grading, and "
            "instant white-label client PDF reporting for digital agencies.\n\n"
            "Protect your agency's reputation before threat actors discover your client blindspots."
        ),
    },
}


def format_ad_copy(variant_key: str) -> str:
    variant = AD_VARIANTS[variant_key]
    return (
        f"=== {variant['name']} ({'RECOMMENDED' if variant.get('recommended') else 'ALTERNATIVE'}) ===\n\n"
        f"Primary Text:\n{variant['primary_text']}\n\n"
        f"Headline: {variant['headline']}\n"
        f"Description: {variant['description']}\n"
        f"Call to Action: {variant['call_to_action']}\n"
        f"Website URL: {variant['url']}\n"
    )


def verify_campaign() -> bool:
    print("=" * 65)
    print("🚀 ORBIT SECURITY: $10 META AD TEST FLIGHT AUDIT")
    print("=" * 65)

    asset_ok = CREATIVE_ASSET_PATH.exists()
    asset_size_kb = round(CREATIVE_ASSET_PATH.stat().st_size / 1024, 1) if asset_ok else 0
    img_dim_ok = False
    if asset_ok:
        try:
            with Image.open(CREATIVE_ASSET_PATH) as img:
                w, h = img.size
                img_dim_ok = (w == 1024 and h == 1024)
                print(f"Creative Asset: {CREATIVE_ASSET_PATH.name} ({w}x{h}, {asset_size_kb} KB) [{'PASS' if img_dim_ok else 'FAIL'}]")
        except Exception as e:
            print(f"Creative Asset Error: {e} [FAIL]")
    else:
        print(f"Creative Asset Missing: {CREATIVE_ASSET_PATH} [FAIL]")

    total = CAMPAIGN_CONFIG["total_budget_usd"]
    daily = CAMPAIGN_CONFIG["daily_budget_usd"]
    days = CAMPAIGN_CONFIG["duration_days"]
    math_ok = (daily * days == total)
    print(f"Pacing: ${daily:.2f}/day x {days} days = ${total:.2f} total [{'PASS' if math_ok else 'FAIL'}]")
    print(f"Objective: {CAMPAIGN_CONFIG['objective']} -> {CAMPAIGN_CONFIG['optimization_goal']} [PASS]")

    # Check variants
    v_ok = True
    for key, v in AD_VARIANTS.items():
        h_len = len(v["headline"])
        d_len = len(v["description"])
        h_pass = h_len <= 40
        d_pass = d_len <= 45
        has_utm = "utm_source=meta" in v["url"]
        print(f"{v['name']}: Headline {h_len}/40 [{'PASS' if h_pass else 'FAIL'}], Desc {d_len}/45 [{'PASS' if d_pass else 'FAIL'}], UTM [{'PASS' if has_utm else 'FAIL'}]")
        if not (h_pass and d_pass and has_utm):
            v_ok = False

    passed = asset_ok and img_dim_ok and math_ok and v_ok
    print("=" * 65)
    print(f"OVERALL STAGING STATUS: [{'READY FOR FLIGHT' if passed else 'AUDIT FAILED'}]")
    print("=" * 65)
    return passed


def copy_variant_to_clipboard(variant_key: str) -> bool:
    try:
        import pyperclip
        text = format_ad_copy(variant_key)
        pyperclip.copy(text)
        print(f"[✔] Successfully copied {AD_VARIANTS[variant_key]['name']} copy to Windows clipboard!")
        print("    -> Open Meta Ads Manager (https://adsmanager.facebook.com/) and paste into Ad creation.")
        print(f"    -> Attach creative image: {CREATIVE_ASSET_PATH}")
        return True
    except ImportError:
        print("[!] pyperclip not installed. Run: pip install pyperclip", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Orbit Security: Stage $10 Meta Ad Campaign")
    parser.add_argument("--verify", action="store_true", help="Run validation audit on all assets & copy")
    parser.add_argument("--preview", action="store_true", help="Print complete ad package and targeting instructions")
    parser.add_argument("--copy-variant1", action="store_true", help="Copy Variant 1 (The Retainer Multiplier) to clipboard")
    parser.add_argument("--copy-variant2", action="store_true", help="Copy Variant 2 (The Sentinel Guardian) to clipboard")
    parser.add_argument("--export-json", action="store_true", help="Output full campaign configuration as JSON")
    args = parser.parse_args()

    if args.export_json:
        data = {
            "campaign": CAMPAIGN_CONFIG,
            "targeting": TARGETING_CONFIG,
            "creative_asset": str(CREATIVE_ASSET_PATH),
            "variants": AD_VARIANTS,
        }
        print(json.dumps(data, indent=2))
        return

    if args.copy_variant1:
        verify_campaign()
        copy_variant_to_clipboard("variant_1")
        return

    if args.copy_variant2:
        verify_campaign()
        copy_variant_to_clipboard("variant_2")
        return

    if args.preview:
        verify_campaign()
        print("\n" + format_ad_copy("variant_1"))
        print("\n" + format_ad_copy("variant_2"))
        print("TARGETING PARAMETERS:")
        print(f"- Locations: {', '.join(TARGETING_CONFIG['locations'])}")
        print(f"- Age: {TARGETING_CONFIG['age_min']} - {TARGETING_CONFIG['age_max']}")
        print(f"- Interests: {', '.join(TARGETING_CONFIG['interests'])}")
        print(f"- Job Titles: {', '.join(TARGETING_CONFIG['job_titles'])}")
        print(f"- Placements: {', '.join(TARGETING_CONFIG['placements'])}")
        return

    # Default action
    verify_campaign()
    print("\nRun with --copy-variant1 or --copy-variant2 to copy ad copy to clipboard.")
    print("Run with --preview to see complete targeting parameters and copy text.")


if __name__ == "__main__":
    main()
