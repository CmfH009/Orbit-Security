#!/usr/bin/env python3
"""Orbit Security: Scroll down @_arsoncode profile to see the newly posted tweet."""

import os
import sys
import time
import win32gui
import win32con
import win32api

sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

ARTIFACT_DIR = r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9"

da.attach_to_interactive_desktop()

for w in da.list_windows(include_empty=False):
    if "chrome.exe" in w["process"].lower() and w["width"] > 1000:
        win32gui.ShowWindow(w["hwnd"], win32con.SW_SHOW)
        da.user32.AllowSetForegroundWindow(-1)
        win32gui.SetForegroundWindow(w["hwnd"])
        break

time.sleep(1.0)
da.click_at(500, 500)
time.sleep(0.5)
# Press Page Down once to scroll past the pinned post
win32api.keybd_event(0x22, 0x51, 0, 0)
time.sleep(0.15)
win32api.keybd_event(0x22, 0x51, win32con.KEYEVENTF_KEYUP, 0)
time.sleep(2.5)

da.capture_desktop(os.path.join(ARTIFACT_DIR, "x_profile_scrolled.png"))
print("[+] Captured x_profile_scrolled.png")
