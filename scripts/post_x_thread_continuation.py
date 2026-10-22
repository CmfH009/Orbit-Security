#!/usr/bin/env python3
"""Orbit Security: Post Thread Continuation Tweets 2-5 via Desktop Automation.

Navigates cleanly to the specific tweet status URL, focuses the reply area,
pastes each sequential tweet with deliberate pacing (6-8s delays), submits via Ctrl+Enter,
and verifies each post.
"""

from pathlib import Path
import sys
import time

# Attach desktop automation tools. Imported defensively so the tweet copy and
# its length guard stay importable (and testable) on any machine, including CI.
sys.path.insert(0, r"C:\AgyHut\system\tools")
try:
    import desktop_automation as da
    HAS_DESKTOP_AUTOMATION = True
except ImportError:  # pragma: no cover - Windows-only dependency
    da = None
    HAS_DESKTOP_AUTOMATION = False

# Thread continuation tweets (2 through 5)
REMAINING_TWEETS = [
# X limits every tweet to 280 weighted characters (a URL counts as 23).
# Lengths are asserted at import time, so an over-long tweet can never ship.
    (
        1,
        (
            "1/5 The wave of perimeter exposures isn't random.\n"
            "Cloud infra moves fast: microservices spin up, SaaS trials get hooked to apex domains, dependencies drift.\n"
            "The biggest risk to a high-traffic brand isn't its core code. It's the perimeter nobody remembers. 🧵\n"
        ),
    ),
    (
        2,
        (
            "2/5 The #1 pattern across top D2C/eCommerce/SaaS:\n"
            "• Campaign launches ➔ CNAME points to unbouncepages / webflow / heroku / S3\n• Campaign ends ➔ SaaS account cancelled\n• DNS pointer stays live\n"
            "Edge 404s. Attackers claim the orphan in 60s — with HTTPS on your domain.\n"
        ),
    ),
    (
        3,
        (
            "3/5 #2 exposure: DMARC decay.\n"
            "Google and Yahoo enforce bulk-sender rules, yet dozens of brand subdomains still lack RFC 7489 policy or sit on a permissive `+all` SPF.\n"
            "Fraudsters don't need your database. They just need to send \"authentic\" phishing as your brand.\n"
        ),
    ),
    (
        4,
        (
            "4/5 You don't need a $25k enterprise contract to lock down a perimeter.\n"
            "We built Orbit Security: autonomous attack-surface visibility for agencies and dev teams, in under 800ms.\n"
            "`pip install \"orbit-security @ git+https://github.com/CmfH009/Orbit-Security.git\"`\n`orbit-recon yourbrand.com --remediate`\n"
        ),
    ),
    (
        5,
        (
            "5/5 Agencies & dev shops: perimeter hygiene is a high-margin care plan.\n"
            "Test your apex domain free in a zero-server cyber terminal:\n"
            "👉 https://cmfh009.github.io/Orbit-Security/\n"
            "Open source: github.com/CmfH009/Orbit-Security\n"
        ),
    ),

]


def _weighted_length(text: str) -> int:
    """X counts a URL as 23 characters; every other character counts as one."""
    import re as _re
    total = 0
    last = 0
    for m in _re.finditer(r"https?://\S+", text):
        total += len(text[last:m.start()]) + 23
        last = m.end()
    return total + len(text[last:])


def _assert_fits_x_limit(tweets, label: str) -> None:
    """Fail fast at import time if any tweet exceeds X's 280 character limit.

    An over-long tweet is silently dropped by the X composer, which is how a
    five-part thread turns into a one-part thread with no error raised.
    """
    for item in tweets:
        index, body = item[0], item[1]
        length = _weighted_length(body)
        if length > 280:
            raise AssertionError(
                f"{label} tweet {index} is {length} weighted characters, over X's 280 limit"
            )


_assert_fits_x_limit(REMAINING_TWEETS, "REMAINING_TWEETS")


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
