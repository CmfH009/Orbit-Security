#!/usr/bin/env python3
"""Orbit Security: Dismiss 'Leave site?' via Esc, paste caption first, attach MP4, and post to X."""

import os
import sys
import time
import win32gui
import win32con
import win32api

sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

ARTIFACT_DIR = r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9"
VIDEO_PATH = os.path.join(ARTIFACT_DIR, "orbit_boast_roast_2026.mp4")

VIDEO_POST_TEXT = (
    "404 Dangling CNAMEs vs. Active Perimeter Defense 🛡️🐱\n\n"
    "Watch how an abandoned Unbounce/S3 subdomain gets hijacked in 60s—and how agencies turn passive RFC-8484 telemetry into +$74k/yr in white-label retainers:\n"
    "https://cmfh009.github.io/Orbit-Security/#simulate"
)

da.attach_to_interactive_desktop()

def press_enter():
    win32api.keybd_event(0x0D, 0x1C, 0, 0)
    time.sleep(0.15)
    win32api.keybd_event(0x0D, 0x1C, win32con.KEYEVENTF_KEYUP, 0)

def find_file_dialog():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            cls = win32gui.GetClassName(hwnd)
            title = win32gui.GetWindowText(hwnd)
            if cls == "#32770" or "open" in title.lower():
                found.append((hwnd, title, cls))
        return True
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

def main():
    assert os.path.exists(VIDEO_PATH), f"Missing video: {VIDEO_PATH}"
    # 1. Dismiss "Leave site?" dialog: press Enter (or Space) on "Leave" if we want a clean slate,
    # OR let's press Esc to stay on the current modal!
    # Wait: if we press Esc to stay on the current modal where the video is ALREADY uploaded ("orbit_boast_roast_2026.mp4: Ready"),
    # let's see how many Tabs it takes to reach "Post" or "What's happening?"!
    # Actually, if we press Enter on "Leave", it navigates to x.com/_arsoncode cleanly with zero leftover state,
    # and then we can open https://x.com/compose/post, paste the text FIRST (when focus is 100% guaranteed inside "What's happening?"),
    # and then press Tab to reach the Media Upload icon!
    # Let's verify how many Tabs from "What's happening?" (after pasting text) reaches the Media Upload icon:
    # In x_video_step1_text.png, below the text box is:
    # 1. Remove card 'X' button (inside the link preview card) OR the link preview card itself
    # Wait: why guess Tab count after pasting text when we can check where focus is right now?
    # Right now in x_video_post_live.png:
    # Tab 1 is "Home / X" (which has the compose modal with the video uploaded and "Leave site?" prompt).
    # Tab 2 is "x.com/compose/post/tags" (which opened when Ctrl+Enter hit "Tag people").
    # First, let's close Tab 2 or press Esc on "Leave site?"!
    print("[*] Pressing Esc to cancel 'Leave site?' prompt...")
    da.send_key("esc")
    time.sleep(1.5)

    # Check window title to see which tab is active
    title = win32gui.GetWindowText(2229558)
    print(f"[*] Active Chrome title: {title}")

    # Let's capture a quick screenshot to see exact state after Esc
    da.capture_desktop(os.path.join(ARTIFACT_DIR, "x_after_esc.png"))
    print("[+] Captured x_after_esc.png")

if __name__ == "__main__":
    main()
