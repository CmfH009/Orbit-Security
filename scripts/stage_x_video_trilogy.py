#!/usr/bin/env python3
"""
Orbit Security: Master X (Twitter) Video Trilogy Staging & Dispatch Engine
Orchestrates the 3-part viral video campaign for @_arsoncode on X:
- Post 1: Astro-Cat Gameplay Showcase (Zero-G Sentinel)
- Post 2: Full Feature & Animation Showcase Montage (Command Deck)
- Post 3: The $250/mo Retainer Exploit (Agency Teardown)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TRILOGY_POSTS = [
    {
        "id": "post_1",
        "num": 1,
        "title": "Astro-Cat Gameplay Showcase",
        "hook_type": "The Builder Rebellion",
        "video_path": Path(r"C:\Users\purav\Downloads\orbit_astro_cat_gameplay_x.mp4"),
        "cdn_url": "https://cmfh009.github.io/Orbit-Security/assets/orbit_astro_cat_gameplay_x.mp4",
        "target_audience": "Tech Twitter, Indie Hackers, Dev Founders",
        "tweet_text": (
            "Most cybersecurity landing pages are boring corporate templates with stock photos of padlocks.\n\n"
            "We built an interactive zero-gravity astronaut cat with orbital thrusters and laser cannons instead. 🛡️🐾\n\n"
            "Play with him live & run a free client DNS audit:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        )
    },
    {
        "id": "post_2",
        "num": 2,
        "title": "Full Feature & Animation Montage",
        "hook_type": "The Command Deck",
        "video_path": Path(r"C:\Users\purav\Downloads\orbit_montage_master.mp4"),
        "cdn_url": "https://cmfh009.github.io/Orbit-Security/assets/orbit_montage_master.mp4",
        "target_audience": "Web Designers, Frontend Engineers, Tech Leads",
        "tweet_text": (
            "We ditched the corporate playbook for Orbit Security.\n\n"
            "Here's the full command deck:\n"
            "• Sub-second RFC 8484 DNS radar\n"
            "• Dangling CNAME takeover diagnostics\n"
            "• Passive fleet portfolio telemetry\n"
            "• Zero-G Astro-Cat with laser cannons 🚀🐱\n\n"
            "Audit your edge:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        )
    },
    {
        "id": "post_3",
        "num": 3,
        "title": "The $250/mo Retainer Exploit",
        "hook_type": "Agency Retainer Masterclass",
        "video_path": Path(r"C:\Users\purav\Downloads\orbit_teardown_master.mp4"),
        "cdn_url": "https://cmfh009.github.io/Orbit-Security/assets/orbit_teardown_master.mp4",
        "target_audience": "Shopify Plus Agencies, Web Design Agencies, Agency CTOs",
        "tweet_text": (
            "How web agencies justify $250/mo retainers without writing code:\n\n"
            "1. Scan client domain (10s passive DoH)\n"
            "2. Spot dangling CNAMEs & spoofable DNS\n"
            "3. Astro-Cat zaps the threat 👾💥\n"
            "4. Export white-label executive audit PDF\n\n"
            "Run a free scan:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        )
    }
]

def twitter_v3_char_count(text: str):
    url_regex = re.compile(r'https?://[^\s]+')
    urls = url_regex.findall(text)
    text_without_urls = url_regex.sub('', text)

    weighted_units = len(urls) * 23 * 100
    for char in text_without_urls:
        cp = ord(char)
        if (0 <= cp <= 4351) or (8192 <= cp <= 8205) or (8208 <= cp <= 8223) or (8242 <= cp <= 8247):
            weighted_units += 100
        else:
            weighted_units += 200

    weighted_count = weighted_units // 100
    return weighted_count, len(text), len(urls)


def audit_trilogy():
    print("=" * 70)
    print("🚀 ORBIT SECURITY: X VIDEO TRILOGY PRE-FLIGHT AUDIT")
    print("=" * 70)
    all_ok = True

    for p in TRILOGY_POSTS:
        print(f"\n[{p['num']}/3] {p['title']} ({p['hook_type']})")
        print(f"Target: {p['target_audience']}")
        
        # Check video asset
        v_exists = p['video_path'].exists()
        v_size_mb = round(p['video_path'].stat().st_size / (1024 * 1024), 2) if v_exists else 0
        v_status = "PASS" if (v_exists and v_size_mb < 512) else "FAIL"
        print(f"  • Video: {p['video_path'].name} ({v_size_mb} MB) [{v_status}]")
        if not v_exists:
            all_ok = False

        # Check twitter char count
        chars, raw_len, urls = twitter_v3_char_count(p['tweet_text'])
        c_status = "PASS" if chars <= 280 else "FAIL"
        print(f"  • Copy Length: {chars}/280 weighted chars (raw: {raw_len}, urls: {urls}) [{c_status}]")
        if chars > 280:
            all_ok = False

    print("\n" + "=" * 70)
    print(f"TRILOGY STATUS: {'READY FOR DISPATCH' if all_ok else 'VERIFICATION FAILED'}")
    print("=" * 70)
    return all_ok


def copy_post_to_clipboard(post_num: int):
    try:
        import pyperclip
        post = next((p for p in TRILOGY_POSTS if p["num"] == post_num), None)
        if not post:
            print(f"Error: Post {post_num} not found!", file=sys.stderr)
            return False
        pyperclip.copy(post["tweet_text"])
        print(f"\n[✔] Successfully copied Post {post_num} ({post['title']}) to clipboard!")
        print(f"    • Target Video: {post['video_path']}")
        print(f"    • Simply drag the video from Downloads into X post composer, then press Ctrl+V.")
        return True
    except ImportError:
        print("pyperclip not installed", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Orbit Security: X Video Trilogy Staging")
    parser.add_argument("--audit", action="store_true", help="Run validation audit across all 3 videos and copy")
    parser.add_argument("--copy", type=int, choices=[1, 2, 3], help="Copy post 1, 2, or 3 text to clipboard")
    parser.add_argument("--export-json", action="store_true", help="Export campaign definition to JSON")
    args = parser.parse_args()

    if args.export_json:
        data = [{
            "id": p["id"],
            "title": p["title"],
            "video_path": str(p["video_path"]),
            "cdn_url": p["cdn_url"],
            "tweet_text": p["tweet_text"]
        } for p in TRILOGY_POSTS]
        print(json.dumps(data, indent=2))
        return

    if args.copy:
        copy_post_to_clipboard(args.copy)
        return

    audit_trilogy()

if __name__ == "__main__":
    main()
