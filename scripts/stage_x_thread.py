#!/usr/bin/env python3
"""
Orbit Security (@_arsoncode) — X Thread Staging & Character Validator
Architect: Carson Haynes & Antigravity
Target: 7-Part Technical Dangling CNAME Master Thread for X / Twitter
"""

import sys
import os
import re
import argparse
from typing import Dict, List, Optional, Tuple

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None


# Official Twitter text character counting algorithm (Twitter-text v3 specification)
def twitter_v3_char_count(text: str) -> Tuple[int, int, int]:
    """
    Computes Twitter character count according to Twitter text specification:
    - URLs (http:// or https://) count as exactly 23 characters (t.co standard).
    - Code points [0..4351], [8192..8205], [8208..8223], [8242..8247] count as 1 character.
    - Emojis, CJK, and other higher Unicode symbols count as 2 characters.
    Returns: (weighted_char_count, raw_string_length, url_count)
    """
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


TWEETS: List[Dict[str, Optional[str]]] = [
    {
        "num": 1,
        "title": "Tweet 1: The Hook",
        "description": "How an abandoned $15/mo Unbounce landing page compromises a $50M Shopify Plus brand.",
        "attachment": r"A:\projects\orbit-security\docs\assets\fleet_arena_preview.png",
        "text": """How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:

The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance catches them in 800ms. 🧵👇"""
    },
    {
        "num": 2,
        "title": "Tweet 2: The Setup",
        "description": "How agencies spin up promo/store/docs subdomains, cancel plans, and leave DNS pointing.",
        "attachment": None,
        "text": """Web & Shopify agencies launch dozens of promo subdomains every year:
• promo.brand.com ➔ Unbounce
• store.brand.com ➔ Shopify
• docs.brand.com ➔ AWS S3 / GitHub Pages

The seasonal campaign ends. The agency cancels the SaaS plan.

But nobody touches the DNS manager."""
    },
    {
        "num": 3,
        "title": "Tweet 3: The Vulnerability",
        "description": "DNS record dangling, edge returns 404 open invitation.",
        "attachment": None,
        "text": """The DNS record still points:
`promo.brand.com CNAME unbouncepages.com`

When anyone visits the URL, Unbounce’s edge returns:
"The requested URL was not found on this server."

To an attacker running automated reconnaissance, that 404 is an open invitation."""
    },
    {
        "num": 4,
        "title": "Tweet 4: The Exploit",
        "description": "Attacker registers trial on vendor, gains HTTPS, Let's Encrypt SSL, cookie access.",
        "attachment": None,
        "text": """A malicious actor registers a $15 trial on the vendor and claims promo.brand.com.

Suddenly, they gain:
1. Complete HTTPS delivery under brand.com
2. Cookie access across parent domain scopes
3. Valid Let's Encrypt SSL certificates
4. Flawless credential harvesting legitimacy"""
    },
    {
        "num": 5,
        "title": "Tweet 5: The Solution & Automation",
        "description": "orbit-recon clientbrand.com --remediate open-source CLI.",
        "attachment": None,
        "text": """You don't need a $20k enterprise audit to stop this.

Orbit packages detection heuristics into an open-source CLI:

`pip install orbit-security`
`orbit-recon clientbrand.com --remediate`

Resolves DNS pointers, audits RFC 7489 DMARC, and checks 30+ SaaS takeover signatures."""
    },
    {
        "num": 6,
        "title": "Tweet 6: The Agency Retainer Moat",
        "description": "$250/mo care plans with white-label client PDF audits.",
        "attachment": None,
        "text": """For web & eCommerce agencies:

Running this audit monthly turns a hidden liability into a high-margin $250/mo "Care Plan Retainer".

Orbit generates automated white-label client PDF audits with your agency logo—giving clients tangible proof of proactive perimeter hygiene."""
    },
    {
        "num": 7,
        "title": "Tweet 7: The Call to Action",
        "description": "CTA to 16-bit cyber arcade DoH scanner and GitHub repository.",
        "attachment": None,
        "text": """Want to see your perimeter hygiene score?

1. Test our zero-server DoH terminal in your browser (16-bit cyber arcade & Simple Cat decoder):
https://cmfh009.github.io/Orbit-Security/

2. Or drop your domain below for an instant audit.

GitHub: https://github.com/CmfH009/Orbit-Security"""
    }
]


def copy_tweet_to_clipboard(num: int) -> bool:
    """Copies tweet number `num` (1-indexed) to clipboard."""
    if not (1 <= num <= len(TWEETS)):
        print(f"[!] Error: Invalid tweet index {num}. Must be 1 to {len(TWEETS)}.")
        return False

    tweet = TWEETS[num - 1]
    if not HAS_PYPERCLIP:
        print("[!] pyperclip library is not installed. Unable to copy to clipboard.")
        return False

    try:
        pyperclip.copy(tweet["text"])
        return True
    except Exception as err:
        print(f"[!] Clipboard error: {err}")
        return False


def verify_thread() -> bool:
    """Verifies character limits for all tweets and prints the audit report."""
    all_pass = True
    results = []

    for item in TWEETS:
        count, raw_len, url_count = twitter_v3_char_count(item["text"])
        passed = count <= 280
        buffer = 280 - count
        if not passed:
            all_pass = False
        results.append({
            "num": item["num"],
            "title": item["title"],
            "count": count,
            "raw": raw_len,
            "urls": url_count,
            "buffer": buffer,
            "passed": passed,
            "attachment": item.get("attachment")
        })

    if HAS_RICH and console:
        table = Table(title="Orbit Security — 7-Part Master Thread Audit (Twitter v3 Rules)", show_header=True, header_style="bold cyan")
        table.add_column("#", justify="center", style="bold yellow", width=4)
        table.add_column("Title / Focus", style="bold white", width=30)
        table.add_column("Count (v3)", justify="center", width=12)
        table.add_column("Raw Len", justify="center", width=9)
        table.add_column("URLs", justify="center", width=6)
        table.add_column("Buffer", justify="center", width=10)
        table.add_column("Status", justify="center", width=12)

        for r in results:
            status_style = "bold green" if r["passed"] else "bold red"
            status_str = "PASS" if r["passed"] else "FAIL"
            buffer_str = f"+{r['buffer']}" if r["buffer"] >= 0 else str(r["buffer"])
            table.add_row(
                str(r["num"]),
                r["title"],
                f"{r['count']}/280",
                str(r["raw"]),
                str(r["urls"]),
                buffer_str,
                f"[{status_style}]{status_str}[/{status_style}]"
            )

        console.print(table)
        overall_color = "bold green" if all_pass else "bold red"
        console.print(f"[{overall_color}]Verdict: {'ALL 7 TWEETS COMPLY (<= 280 CHARS)' if all_pass else 'SOME TWEETS EXCEED 280 CHARACTERS'}[/{overall_color}]\n")
    else:
        print("=" * 82)
        print("Orbit Security — 7-Part Master Thread Audit (Twitter v3 Rules)")
        print("=" * 82)
        print(f"{'#':<3} | {'Title':<30} | {'Count':<10} | {'Raw':<7} | {'URLs':<5} | {'Buffer':<8} | {'Status':<8}")
        print("-" * 82)
        for r in results:
            status_str = "PASS" if r["passed"] else "FAIL"
            buffer_str = f"+{r['buffer']}" if r["buffer"] >= 0 else str(r["buffer"])
            print(f"{r['num']:<3} | {r['title']:<30} | {r['count']}/280    | {r['raw']:<7} | {r['urls']:<5} | {buffer_str:<8} | {status_str:<8}")
        print("-" * 82)
        print(f"Verdict: {'ALL 7 TWEETS COMPLY (<= 280 CHARS)' if all_pass else 'SOME TWEETS EXCEED 280 CHARACTERS'}\n")

    return all_pass


def display_tweet(num: int, show_copy_prompt: bool = False):
    """Displays a single formatted tweet."""
    if not (1 <= num <= len(TWEETS)):
        print(f"[!] Error: Invalid tweet index {num}.")
        return

    tweet = TWEETS[num - 1]
    count, raw_len, url_count = twitter_v3_char_count(tweet["text"])
    buffer = 280 - count
    attachment = tweet.get("attachment")
    attachment_info = f"📸 Attached Asset: {attachment}" if attachment else "📸 Attached Asset: None"

    if HAS_RICH and console:
        header = f"[bold cyan]{tweet['title']}[/bold cyan] ({count}/280 chars | Buffer: +{buffer} | URLs: {url_count})"
        content = f"{tweet['text']}\n\n[dim]{attachment_info}[/dim]"
        border_style = "green" if count <= 280 else "red"
        panel = Panel(content, title=header, border_style=border_style, expand=False)
        console.print(panel)
    else:
        print("=" * 70)
        print(f"{tweet['title']} ({count}/280 chars | Buffer: +{buffer} | URLs: {url_count})")
        print("-" * 70)
        print(tweet["text"])
        print("-" * 70)
        print(attachment_info)
        print("=" * 70)

    if show_copy_prompt:
        if HAS_PYPERCLIP:
            ans = input("Copy this tweet to clipboard? [y/N]: ").strip().lower()
            if ans == 'y':
                if copy_tweet_to_clipboard(num):
                    if HAS_RICH and console:
                        console.print(f"[bold green]✔ Tweet {num} copied to clipboard![/bold green]")
                    else:
                        print(f"✔ Tweet {num} copied to clipboard!")


def display_all_tweets():
    """Displays all 7 tweets sequentially."""
    for item in TWEETS:
        display_tweet(item["num"], show_copy_prompt=False)
        print()


def interactive_menu():
    """Runs interactive CLI loop for browsing and staging tweets."""
    while True:
        if HAS_RICH and console:
            console.print("\n[bold cyan]=== Orbit Security Thread Staging Console (@_arsoncode) ===[/bold cyan]")
            console.print("[1-7] View / Copy Tweet N")
            console.print("[A]   Display All 7 Tweets")
            console.print("[V]   Run Strict Character Count Verification")
            console.print("[C]   Quick-Copy Tweet (Prompt for #)")
            console.print("[Q]   Exit")
        else:
            print("\n=== Orbit Security Thread Staging Console (@_arsoncode) ===")
            print("[1-7] View / Copy Tweet N")
            print("[A]   Display All 7 Tweets")
            print("[V]   Run Strict Character Count Verification")
            print("[C]   Quick-Copy Tweet (Prompt for #)")
            print("[Q]   Exit")

        try:
            choice = input("\nEnter selection: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice == 'Q':
            print("Exiting thread staging console.")
            break
        elif choice == 'A':
            display_all_tweets()
        elif choice == 'V':
            verify_thread()
        elif choice == 'C':
            t_num = input("Enter tweet number to copy (1-7): ").strip()
            if t_num.isdigit() and 1 <= int(t_num) <= 7:
                if copy_tweet_to_clipboard(int(t_num)):
                    if HAS_RICH and console:
                        console.print(f"[bold green]✔ Tweet {t_num} copied to clipboard![/bold green]")
                    else:
                        print(f"✔ Tweet {t_num} copied to clipboard!")
            else:
                print("[!] Invalid tweet number.")
        elif choice.isdigit() and 1 <= int(choice) <= 7:
            display_tweet(int(choice), show_copy_prompt=True)
        else:
            print("[!] Invalid option. Please choose 1-7, A, V, C, or Q.")


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security (@_arsoncode) — X Thread Staging & Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--verify", "-v", action="store_true", help="Run character limit verification table")
    parser.add_argument("--all", "-a", action="store_true", help="Display all 7 staged tweets")
    parser.add_argument("--show", "-s", type=int, choices=range(1, 8), help="Display tweet N (1-7)")
    parser.add_argument("--copy", "-c", type=int, choices=range(1, 8), help="Copy tweet N (1-7) directly to clipboard")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive CLI staging menu")

    args = parser.parse_args()

    if args.verify:
        passed = verify_thread()
        sys.exit(0 if passed else 1)
    elif args.all:
        display_all_tweets()
    elif args.show:
        display_tweet(args.show, show_copy_prompt=False)
    elif args.copy:
        if copy_tweet_to_clipboard(args.copy):
            if HAS_RICH and console:
                console.print(f"[bold green]✔ Tweet {args.copy} copied to clipboard![/bold green]")
            else:
                print(f"✔ Tweet {args.copy} copied to clipboard!")
        else:
            sys.exit(1)
    elif args.interactive or sys.stdin.isatty():
        interactive_menu()
    else:
        # Default non-interactive behavior: verify and print all
        verify_thread()
        display_all_tweets()


if __name__ == "__main__":
    main()
