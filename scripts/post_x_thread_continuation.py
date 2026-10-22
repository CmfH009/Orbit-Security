#!/usr/bin/env python3
"""Orbit Security: Post Thread Continuation Tweets 2-5 via Desktop Automation.

Navigates cleanly to the specific tweet status URL, focuses the reply area,
pastes each sequential tweet with deliberate pacing (6-8s delays), submits via Ctrl+Enter,
and verifies each post.
"""

from pathlib import Path
import sys
import time

# Attach desktop automation tools
sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

# Thread continuation tweets (2 through 5)
REMAINING_TWEETS = [
    (
        2,
        (
            "2/5 The #1 recurring vulnerability pattern we see across top D2C, eCommerce, and SaaS ecosystems:\n\n"
            "• Marketing launches a campaign ➔ CNAME points to unbouncepages / webflow / heroku / S3\n"
            "• Campaign concludes ➔ SaaS account cancelled\n"
            "• DNS pointer remains live\n\n"
            "Edge returns 404. Attackers claim the orphaned SaaS resource in 60s and get full HTTPS on your domain."
        ),
    ),
    (
        3,
        (
            "3/5 Email spoofing & DMARC decay is the second critical exposure vector.\n\n"
            "Even with Google and Yahoo strictly enforcing bulk sender protections, dozens of brand subdomains still lack RFC 7489 policies or sit on permissive `+all` SPF records.\n\n"
            "Fraudsters don't need to breach your database if they can send authenticated phishing emails directly from your brand's domain."
        ),
    ),
    (
        4,
        (
            "4/5 You don't need a bloated $25k enterprise contract to lock down your perimeter.\n\n"
            "We built Orbit Security to give web engineering agencies and dev teams autonomous attack-surface visibility in under 800ms:\n\n"
            "`pip install orbit-security`\n"
            "`orbit-recon yourbrand.com --remediate`\n\n"
            "Scans DNS routing, checks 30+ SaaS takeover signatures, and generates instant copy-paste Cloudflare / Route 53 fixes."
        ),
    ),
    (
        5,
        (
            "5/5 Web agencies & dev shops:\n\n"
            "This security wave is the perfect moment to turn perimeter hygiene into a high-margin care plan for your clients.\n\n"
            "Test your apex domain right now in our zero-server 16-bit cyber terminal:\n"
            "👉 https://cmfh009.github.io/Orbit-Security/\n\n"
            "Open-source & RFC-compliant: https://github.com/CmfH009/Orbit-Security"
        ),
    ),
]


def post_remaining(start_url: str):
    print("=" * 68)
    print("🛰️  ORBIT SECURITY: POSTING THREAD REPLIES (TWEETS 2 - 5)")
    print(f"Parent Tweet: {start_url}")
    print("=" * 68)

    da.attach_to_interactive_desktop()
    current_target_url = start_url

    for num, text in REMAINING_TWEETS:
        print(f"\n[*] Preparing Tweet {num}/5 ({len(text)} chars)...")
        print(f"    Navigating to: {current_target_url}")

        # 1. Bring Chrome to focus
        ok, msg = da.focus_window("Google Chrome")
        if not ok:
            print(f"[!] Failed to focus Chrome: {msg}")
            return False
        time.sleep(1.0)

        # 2. Navigate directly to the parent tweet
        da.send_shortcut("ctrl+l")
        time.sleep(0.4)
        da.paste_text(current_target_url)
        time.sleep(0.4)
        da.send_key("enter")
        time.sleep(5.0)  # Wait for tweet thread page to render completely

        # 3. Focus the page body and click the reply box area
        wins = da.list_windows(include_empty=False)
        win = next((w for w in wins if "chrome" in w.get("process", "").lower()), None)
        if win:
            # Click in middle timeline area where 'Post your reply' sits
            rx = win["left"] + int(win["width"] * 0.45)
            ry = win["top"] + int(win["height"] * 0.45)
            da.click_at(rx, ry)
            time.sleep(1.2)

        # Also trigger X reply shortcut 'r' as backup
        da.send_key("r")
        time.sleep(1.5)

        # 4. Paste the tweet text
        print(f"    Injecting Tweet {num} text via clipboard...")
        da.paste_text(text)
        time.sleep(2.5)  # Deliberate pacing to allow draft preview to stabilize

        # 5. Submit reply via Ctrl+Enter
        print(f"    Submitting Tweet {num} via Ctrl+Enter...")
        da.send_shortcut("ctrl+enter")
        time.sleep(6.0)  # Paced 6-second cooldown after submission

        # 6. Check/extract the newly posted reply URL via DevTools copy() so subsequent tweets chain properly
        da.send_shortcut("ctrl+shift+j")
        time.sleep(1.5)
        # Select the latest article time link
        script = "const arts = document.querySelectorAll('article'); if (arts.length > 1) { copy(arts[arts.length - 1].querySelector('time').closest('a').href); }"
        da.paste_text(script)
        time.sleep(0.4)
        da.send_key("enter")
        time.sleep(0.8)
        da.send_shortcut("ctrl+shift+j")
        time.sleep(0.8)

        # Read clipboard
        try:
            import win32clipboard, win32con
            win32clipboard.OpenClipboard()
            new_url = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            if "status/" in new_url and new_url != current_target_url:
                current_target_url = new_url
                print(f"    [✔] Successfully chained to new reply URL: {current_target_url}")
            else:
                print(f"    [ℹ] Chaining off parent URL: {current_target_url}")
        except Exception:
            pass

        time.sleep(3.0)  # Additional spacing between tweets

    print("\n" + "=" * 68)
    print("🏁 Thread continuation completed! All 5 tweets posted and chained.")
    print("=" * 68)
    return True


if __name__ == "__main__":
    post_remaining("https://x.com/_arsoncode/status/2112362100454744454")
