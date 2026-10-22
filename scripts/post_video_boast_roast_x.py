#!/usr/bin/env python3
"""Orbit Security: Pure Keyboard X Video Upload & Post Engine (@_arsoncode)."""

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
    dlg = find_file_dialog()
    if not dlg:
        print("[*] Opening File Open dialog via Ctrl+L -> compose/post -> Tab x2 -> Enter...")
        da.focus_window("chrome.exe")
        time.sleep(1.0)
        da.send_shortcut("ctrl+l")
        time.sleep(0.8)
        da.paste_text("https://x.com/compose/post")
        time.sleep(0.8)
        press_enter()
        time.sleep(8.5)
        da.send_key("tab")
        time.sleep(0.5)
        da.send_key("tab")
        time.sleep(0.8)
        press_enter()
        time.sleep(2.5)
        dlg = find_file_dialog()

    print(f"[+] File Open dialog active: {dlg}")
    # Ensure File name box is focused and paste VIDEO_PATH
    da.send_shortcut("alt+n")
    time.sleep(0.6)
    da.paste_text(VIDEO_PATH)
    time.sleep(1.2)
    press_enter()

    print("[*] Waiting 15 seconds for MP4 video upload & processing in X compose modal...")
    time.sleep(15.0)

    da.capture_desktop(os.path.join(ARTIFACT_DIR, "x_video_uploaded_state.png"))
    print("[+] Captured x_video_uploaded_state.png")

if __name__ == "__main__":
    main()
