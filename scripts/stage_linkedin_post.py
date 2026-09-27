#!/usr/bin/env python3
"""Orbit Security: LinkedIn Founder & Systems Architect Launch Stager.

Prepares, formats, verifies, and stages Carson Haynes' long-form LinkedIn
founder post with 1-click clipboard copying and visual asset verification.
"""

import argparse
import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
BANNER_ASSET_PATH = REPO_ROOT / "landing" / "assets" / "orbit_ad_banner.jpg"

LINKEDIN_POST_BODY = """Most web agencies build extraordinary digital experiences.

They spend months perfecting UX, tuning Core Web Vitals, and writing clean, scalable code.

Then comes launch day. Champagne pops. Everyone celebrates. 🥂

And then... 6 months pass.

A developer forgets an old staging subdomain.
A third-party DNS record gets left pointing to an abandoned cloud bucket or retired SaaS landing page.
DMARC email authentication silently drifts back to p=none.

Nobody notices until a malicious actor claims the dangling DNS or a client's deliverability tanks. And when that happens, the client doesn't blame the cloud hosting vendor.

They call the agency.

With autonomous AI crawlers and automated bots now representing over 51% of all web traffic, perimeter drift is no longer an edge case—it is constantly probed.

I spent the past several months architecting a solution to this exact problem: Orbit Security.

Orbit Security is an autonomous perimeter hygiene and white-label reporting sentinel built exclusively for digital web and eCommerce agencies.

Here is how we built it:
1. 100% Non-Intrusive: Zero code to install, zero access tokens required, strictly RFC-compliant passive surveillance.
2. Gamified Layman Explanations: Our built-in "Simple Cat" layman decoder translates cryptic acronyms (DMARC, HSTS, DKIM) into 5-year-old analogies and concrete 2-minute fixes that non-technical clients actually understand.
3. Built to Defend Agency Retainers: Our partners package automated monthly PDF audits directly into their care plans, turning passive security into an extra $150–$350/mo retainer per client without burning senior developer hours.

We just pushed our live platform, 16-bit cyber arcade horizon terminal, and agency Fleet Command Center:
👉 https://cmfh009.github.io/Orbit-Security/fleet.html

If you run a web or Shopify agency and want me to run a complimentary, zero-obligation perimeter audit on one of your flagship client builds, drop a comment below or send me a DM.

#WebDevelopment #ShopifyPlus #CyberSecurity #AgencyGrowth #B2BSaaS #SystemsArchitecture #WordPressVIP"""


def verify_post() -> bool:
    char_count = len(LINKEDIN_POST_BODY)
    word_count = len(LINKEDIN_POST_BODY.split())
    # LinkedIn post character limit is 3,000 characters
    is_valid_len = char_count <= 3000
    banner_exists = BANNER_ASSET_PATH.exists()
    banner_size_kb = round(BANNER_ASSET_PATH.stat().st_size / 1024, 1) if banner_exists else 0

    print("=" * 65)
    print("💼 ORBIT SECURITY: LINKEDIN LAUNCH POST AUDIT")
    print(f"Author: Carson Haynes (Founder & Systems Architect)")
    print(f"Character Count: {char_count} / 3,000 [{'PASS' if is_valid_len else 'FAIL'}]")
    print(f"Word Count: {word_count} words")
    print(f"16:9 Banner Asset: {BANNER_ASSET_PATH.name} ({banner_size_kb} KB) [{'PASS' if banner_exists else 'FAIL'}]")
    print(f"Destination Feed: https://www.linkedin.com/feed/")
    print(f"Profile: https://www.linkedin.com/in/carson-haynes-1902b743a/")
    print("=" * 65)
    return is_valid_len and banner_exists


def copy_to_clipboard() -> bool:
    try:
        import pyperclip
        pyperclip.copy(LINKEDIN_POST_BODY)
        print("[✔] Successfully copied full post body to Windows clipboard!")
        print("    -> Open LinkedIn (https://www.linkedin.com/feed/) and press Ctrl+V.")
        print(f"    -> Attach banner image: {BANNER_ASSET_PATH}")
        return True
    except ImportError:
        print("[!] pyperclip not installed. Run: pip install pyperclip", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Orbit Security: Stage LinkedIn Founder Post")
    parser.add_argument("--preview", action="store_true", help="Print formatted post text")
    parser.add_argument("--copy", action="store_true", help="Copy post body to Windows clipboard")
    parser.add_argument("--verify", action="store_true", help="Run character and asset audit")
    args = parser.parse_args()

    if args.verify:
        success = verify_post()
        if not success:
            sys.exit(1)
        return

    if args.copy:
        verify_post()
        copy_to_clipboard()
        return

    if args.preview:
        print("\n" + "=" * 65)
        print("LINKEDIN POST PREVIEW:")
        print("=" * 65 + "\n")
        print(LINKEDIN_POST_BODY)
        print("\n" + "=" * 65)
        return

    # Default action: verify and preview
    verify_post()
    print("\nRun with --copy to copy text to clipboard, or --preview to view full text.")


if __name__ == "__main__":
    main()
