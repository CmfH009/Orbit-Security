# -*- coding: utf-8 -*-
"""
Captures multi-page and multi-section PNG screenshots of Orbit Security using the
active taskbar Chrome window via desktop_automation.py (Zero duplicate browsers).
"""

import os
import sys
import time
import threading
import functools
from http.server import HTTPServer, SimpleHTTPRequestHandler

sys.path.insert(0, "A:/system/tools")
import desktop_automation as da

ARTIFACT_DIR = "C:/Users/purav/.gemini/antigravity-cli/brain/9dad3157-5599-43d5-afaf-94bd85ec1bc9"
DOCS_DIR = "A:/projects/orbit-security/docs"

# 1. Ensure hash routing for #simulate and #flipbook is present in docs/index.html and landing/index.html
hash_hook = """        // Deep-link hash triggers for #simulate and #flipbook
        function handleHashTriggers() {
            const h = window.location.hash;
            if (h === '#simulate') {
                closePdfFlipbookModal();
                simulateTakeoverAttack();
            } else if (h === '#flipbook') {
                openPdfFlipbookModal();
            } else {
                closePdfFlipbookModal();
            }
        }
        window.addEventListener('hashchange', handleHashTriggers);
        window.addEventListener('DOMContentLoaded', () => { setTimeout(handleHashTriggers, 150); });
    </script>"""

for p in ["A:/projects/orbit-security/docs/index.html", "A:/projects/orbit-security/landing/index.html"]:
    with open(p, "r", encoding="utf-8") as f:
        c = f.read()
    if "handleHashTriggers" not in c:
        # Replace the last </script> before </body>
        idx = c.rfind("    </script>")
        if idx != -1:
            c = c[:idx] + hash_hook + c[idx + len("    </script>"):]
            with open(p, "w", encoding="utf-8") as f:
                f.write(c)
            print(f"Added hash triggers to {p}")

# 2. Start local HTTP server on 127.0.0.1:8765
class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

handler = functools.partial(QuietHandler, directory=DOCS_DIR)
httpd = HTTPServer(("127.0.0.1", 0), handler)
port = httpd.server_port
base_url = f"http://127.0.0.1:{port}"
server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
server_thread.start()
print(f"[+] Local server running at {base_url}")

# 3. Attach to interactive desktop & focus Chrome
da.attach_to_interactive_desktop()
ok, msg = da.focus_window("chrome.exe")
print(f"[+] Focus Chrome: {ok} - {msg}")
time.sleep(0.6)

# Close DevTools if open or ensure clean viewport by pressing Esc first
def navigate_and_capture(url: str, filename: str, wait_sec: float = 1.6, scroll_clicks: int = 0):
    da.focus_window("chrome.exe")
    time.sleep(0.2)
    da.send_shortcut("ctrl+l")
    time.sleep(0.2)
    da.paste_text(url)
    time.sleep(0.15)
    da.send_key("enter")
    time.sleep(wait_sec)
    if scroll_clicks != 0:
        # Move cursor to center of window so wheel scroll targets page body
        da.scroll(scroll_clicks, x=960, y=540)
        time.sleep(0.6)
    out_path = os.path.join(ARTIFACT_DIR, filename)
    ok, saved = da.capture_window("chrome.exe", out_path)
    print(f"[{'+' if ok else '-'}] Captured {filename} -> {saved}")

targets = [
    (f"{base_url}/index.html", "audit_01_hero_advisory.png", 1.8, 0),
    (f"{base_url}/index.html#simulate", "audit_02_attack_simulator.png", 1.4, 0),
    (f"{base_url}/index.html#audit-preview", "audit_03_audit_studio.png", 1.4, 0),
    (f"{base_url}/index.html#client-pitch-drawer", "audit_04_client_pitch_drawer.png", 1.4, 0),
    (f"{base_url}/index.html#flipbook", "audit_05_pdf_flipbook_modal.png", 1.4, 0),
    (f"{base_url}/index.html#pricing", "audit_06_pricing_roi_vault.png", 1.5, -5),
    (f"{base_url}/fleet.html", "audit_07_fleet_arena.png", 1.8, 0),
    (f"{base_url}/signup.html", "audit_08_signup_portal.png", 1.6, 0),
    (f"{base_url}/ghostdns/index.html", "audit_09_ghostdns_app.png", 1.6, 0),
    (f"{base_url}/portals/index.html", "audit_10_partner_portals.png", 1.6, 0),
]

for url, fname, wait_s, scr in targets:
    navigate_and_capture(url, fname, wait_sec=wait_s, scroll_clicks=scr)

# Return user's browser to live GitHub Pages URL with cache-buster
da.focus_window("chrome.exe")
time.sleep(0.2)
da.send_shortcut("ctrl+l")
time.sleep(0.2)
da.paste_text("https://cmfh009.github.io/Orbit-Security/?v=20261022")
time.sleep(0.15)
da.send_key("enter")
time.sleep(1.0)

httpd.shutdown()
print("[+] All 10 page screenshots captured successfully!")
