#!/usr/bin/env python3
"""Orbit Security: X Ads Test Flight Staging Engine.

Prepares, audits, and stages a micro-budget X (Twitter) Ads campaign
targeting Shopify Plus developers and agency CTOs via follower lookalikes.
"""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
X_CREATIVE_ASSET_PATH = REPO_ROOT / "landing" / "assets" / "orbit_cats_pounce.jpg"

X_CAMPAIGN_CONFIG = {
    "campaign_name": "Orbit Security - Agency Retainer X Test Flight v1",
    "objective": "Website Traffic",
    "total_budget_usd": 10.00,
    "daily_budget_usd": 2.50,
    "duration_days": 4,
    "pacing": "Standard",
    "destination_base": "https://cmfh009.github.io/Orbit-Security/",
}

X_TARGETING_CONFIG = {
    "follower_lookalikes": [
        "@ShopifyDevs",
        "@Shopify",
        "@troyhunt",
        "@dhh",
        "@levelsio",
        "@t3dotgg",
    ],
    "keywords": [
        "Shopify Plus",
        "client retainer",
        "DMARC",
        "subdomain takeover",
        "DNS drift",
        "web agency",
    ],
    "locations": ["United States", "United Kingdom", "Canada"],
    "languages": ["English"],
    "placements": ["Home timeline", "Profiles", "Search results"],
}

AD_1_URL = "https://cmfh009.github.io/Orbit-Security/?utm_source=x&utm_medium=promoted_tweet&utm_campaign=retainer"
AD_2_URL = "https://cmfh009.github.io/Orbit-Security/?utm_source=x&utm_medium=promoted_tweet&utm_campaign=sentinel"

X_AD_VARIANTS = {
    "variant_1": {
        "name": "The Agency Retainer Multiplier",
        "recommended": True,
        "url": AD_1_URL,
        "tweet_text": (
            "How top Shopify Plus agencies justify $250/mo maintenance retainers:\n\n"
            "Orbit Security scans client DNS, DMARC & SSL to export white-label audit PDFs in 10s.\n\n"
            f"Free audit:\n{AD_1_URL}"
        ),
    },
    "variant_2": {
        "name": "The Astro-Cat Sentinel",
        "recommended": False,
        "url": AD_2_URL,
        "tweet_text": (
            "Meet the perimetric sentinels guarding web builds. 🛡️🐾\n\n"
            "Passive scans for dangling DNS, missing DMARC & SSL drift. "
            "Instant white-label client PDF audits.\n\n"
            f"Audit free:\n{AD_2_URL}"
        ),
    },
}


def format_x_ad_copy(variant_key: str) -> str:
    variant = X_AD_VARIANTS[variant_key]
    status = "RECOMMENDED" if variant.get("recommended") else "ALTERNATIVE"
    return (
        f"=== {variant['name']} ({status}) ===\n\n"
        f"Promoted Tweet Text ({len(variant['tweet_text'])}/280 chars):\n"
        f"{variant['tweet_text']}\n\n"
        f"Destination URL: {variant['url']}\n"
    )


def verify_x_campaign() -> bool:
    print("=" * 65)
    print("🐦 ORBIT SECURITY: $10 X (TWITTER) AD TEST FLIGHT AUDIT")
    print("=" * 65)

    asset_ok = X_CREATIVE_ASSET_PATH.exists()
    asset_size_kb = round(X_CREATIVE_ASSET_PATH.stat().st_size / 1024, 1) if asset_ok else 0
    img_dim_ok = False
    if asset_ok:
        try:
            with Image.open(X_CREATIVE_ASSET_PATH) as img:
                w, h = img.size
                img_dim_ok = (w == 1024 and h == 1024)
                print(f"Creative Asset: {X_CREATIVE_ASSET_PATH.name} ({w}x{h}, {asset_size_kb} KB) [{'PASS' if img_dim_ok else 'FAIL'}]")
        except Exception as e:
            print(f"Creative Asset Error: {e} [FAIL]")
    else:
        print(f"Creative Asset Missing: {X_CREATIVE_ASSET_PATH} [FAIL]")

    total = X_CAMPAIGN_CONFIG["total_budget_usd"]
    daily = X_CAMPAIGN_CONFIG["daily_budget_usd"]
    days = X_CAMPAIGN_CONFIG["duration_days"]
    math_ok = (daily * days == total)
    print(f"Pacing: ${daily:.2f}/day x {days} days = ${total:.2f} total [{'PASS' if math_ok else 'FAIL'}]")
    print(f"Objective: {X_CAMPAIGN_CONFIG['objective']} ({X_CAMPAIGN_CONFIG['pacing']} Pacing) [PASS]")

    v_ok = True
    for key, v in X_AD_VARIANTS.items():
        t_len = len(v["tweet_text"])
        t_pass = t_len <= 280
        has_utm = "utm_source=x" in v["url"] and "utm_medium=promoted_tweet" in v["url"]
        print(f"{v['name']}: Text {t_len}/280 [{'PASS' if t_pass else 'FAIL'}], UTM [{'PASS' if has_utm else 'FAIL'}]")
        if not (t_pass and has_utm):
            v_ok = False

    passed = asset_ok and img_dim_ok and math_ok and v_ok
    print("=" * 65)
    print(f"OVERALL X STAGING STATUS: [{'READY FOR FLIGHT' if passed else 'AUDIT FAILED'}]")
    print("=" * 65)
    return passed


def copy_x_variant_to_clipboard(variant_key: str) -> bool:
    try:
        import pyperclip
        variant = X_AD_VARIANTS[variant_key]
        pyperclip.copy(variant["tweet_text"])
        print(f"[✔] Successfully copied {variant['name']} tweet to Windows clipboard!")
        print("    -> Open X Ads (https://ads.x.com/) or Tweet Composer.")
        print("    -> Paste text and attach image: " + str(X_CREATIVE_ASSET_PATH))
        return True
    except ImportError:
        print("[!] pyperclip not installed. Run: pip install pyperclip", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Orbit Security: Stage $10 X (Twitter) Ad Campaign")
    parser.add_argument("--verify", action="store_true", help="Run validation audit on all assets & copy")
    parser.add_argument("--preview", action="store_true", help="Print complete X ad package and targeting instructions")
    parser.add_argument("--copy-variant1", action="store_true", help="Copy Variant 1 (Agency Retainer) to clipboard")
    parser.add_argument("--copy-variant2", action="store_true", help="Copy Variant 2 (Astro-Cat Sentinel) to clipboard")
    parser.add_argument("--export-json", action="store_true", help="Output full campaign configuration as JSON")
    args = parser.parse_args()

    if args.export_json:
        data = {
            "campaign": X_CAMPAIGN_CONFIG,
            "targeting": X_TARGETING_CONFIG,
            "creative_asset": str(X_CREATIVE_ASSET_PATH),
            "variants": X_AD_VARIANTS,
        }
        print(json.dumps(data, indent=2))
        return

    if args.copy_variant1:
        verify_x_campaign()
        copy_x_variant_to_clipboard("variant_1")
        return

    if args.copy_variant2:
        verify_x_campaign()
        copy_x_variant_to_clipboard("variant_2")
        return

    if args.preview:
        verify_x_campaign()
        print("\n" + format_x_ad_copy("variant_1"))
        print("\n" + format_x_ad_copy("variant_2"))
        print("X ADS TARGETING MATRIX:")
        print(f"- Follower Lookalikes: {', '.join(X_TARGETING_CONFIG['follower_lookalikes'])}")
        print(f"- Keywords: {', '.join(X_TARGETING_CONFIG['keywords'])}")
        print(f"- Locations: {', '.join(X_TARGETING_CONFIG['locations'])}")
        print(f"- Placements: {', '.join(X_TARGETING_CONFIG['placements'])}")
        return

    verify_x_campaign()
    print("\nRun with --copy-variant1 or --copy-variant2 to copy Promoted Tweet text to clipboard.")
    print("Run with --preview to view full targeting matrix and Promoted Tweet copies.")


if __name__ == "__main__":
    main()
