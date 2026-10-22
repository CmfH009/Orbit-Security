#!/usr/bin/env python3
"""Orbit Security: "Boast & Roast" X Post via Desktop Automation."""

import os
import sys
import time
import win32gui
import win32con
import win32api

sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

ARTIFACT_DIR = r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9"

# Must be <= 280 characters (URL counts as 23 chars on X)
BOAST_ROAST_POST = (
    "Agencies charge $50k for a build then leave promo.client.com dangling on Unbounce & DMARC on p=none 💀\n\n"
    "Enterprise vendors want $25k/yr to check DNS. We built a zero-server attack simulator, PDF flipbook & $74k/yr ROI calculator free:\n"
    "https://cmfh009.github.io/Orbit-Security/#simulate"
)

da.attach_to_interactive_desktop()

def focus_main_chrome():
    wins = da.list_windows(include_empty=False)
    for w in wins:
        if "chrome.exe" in w["process"].lower() and w["width"] > 1000:
            hwnd = w["hwnd"]
            try:
                win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
                da.user32.AllowSetForegroundWindow(-1)
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            return hwnd
    return None

def press_enter():
    win32api.keybd_event(0x0D, 0x1C, 0, 0)
    time.sleep(0.15)
    win32api.keybd_event(0x0D, 0x1C, win32con.KEYEVENTF_KEYUP, 0)

def main():
    print(f"[*] Raw char count: {len(BOAST_ROAST_POST)} chars (X-weighted: ~254/280)")
    focus_main_chrome()
    time.sleep(1.0)

    # Click Tab 1 (Home / X) at x=65, y=18
    da.click_at(65, 18)
    time.sleep(2.0)

    # Navigate to x.com/compose/post
    da.click_at(350, 56)
    time.sleep(0.6)
    da.send_shortcut("ctrl+a")
    time.sleep(0.5)
    da.paste_text("https://x.com/compose/post")
    time.sleep(1.0)
    press_enter()

    print("[*] Waiting 8 seconds for X compose modal to load...")
    time.sleep(8.0)

    # Paste the Boast & Roast post
    print("[*] Pasting Boast & Roast copy...")
    da.paste_text(BOAST_ROAST_POST)
    time.sleep(3.5)

    da.capture_desktop(os.path.join(ARTIFACT_DIR, "x_boast_roast_preview.png"))

    # Submit via Ctrl+Enter
    print("[*] Submitting via Ctrl+Enter...")
    da.send_shortcut("ctrl+enter")
    time.sleep(7.0)

    # Navigate to profile to verify it is live
    da.click_at(350, 56)
    time.sleep(0.6)
    da.send_shortcut("ctrl+a")
    time.sleep(0.5)
    da.paste_text("https://x.com/_arsoncode")
    time.sleep(1.0)
    press_enter()
    time.sleep(7.0)

    da.capture_desktop(os.path.join(ARTIFACT_DIR, "x_boast_roast_live.png"))
    print("[+] Captured x_boast_roast_live.png")

if __name__ == "__main__":
    main()
