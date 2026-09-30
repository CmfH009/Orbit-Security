import http.server
import socketserver
import threading
import time
from pathlib import Path
from patchright.sync_api import sync_playwright

PORT = 8899
DOCS_DIR = Path(__file__).parent.parent / "docs"

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DOCS_DIR), **kwargs)

    def log_message(self, format, *args):
        pass  # Quiet logging

def run_headless_audit():
    httpd = socketserver.TCPServer(("", PORT), QuietHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] Local test HTTP server running at http://localhost:{PORT}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            console_logs = []
            page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))

            print("[*] Navigating to http://localhost:8899/index.html...")
            page.goto(f"http://localhost:{PORT}/index.html", wait_until="networkidle")

            target_input = page.locator("#targetDomain")
            assert target_input.is_visible(), "Target domain input not found"

            print("[*] Setting scan target to cmfh009.github.io...")
            target_input.fill("cmfh009.github.io")

            print("[*] Triggering radar scan...")
            page.click("#scanBtn")

            # Wait for auditHUD to appear and populate
            page.wait_for_selector("#auditHUD:not(.hidden)", timeout=15000)
            page.wait_for_selector("#auditHUD .font-pixel", timeout=15000)

            # Give DoH animation a moment to settle
            time.sleep(1.5)

            # Extract details
            grade_el = page.locator("#auditHUD .font-pixel").first
            grade = grade_el.inner_text().strip()

            hud_text = page.locator("#auditHUD").inner_text()
            print("\n=== EXTRACTED SCAN HUD RESULTS ===")
            print(hud_text)
            print("==================================\n")

            print(f"Extracted Grade: {grade}")
            assert grade in ("A+", "A"), f"Expected Grade A or A+, got: {grade}"

            assert "100" in hud_text or "95" in hud_text, "Expected score 95-100 in HUD"
            assert "HARDENED" in hud_text, "Expected HARDENED perimeter status"
            assert "PASS" in hud_text, "Expected PASS badges"

            # Check raw telemetry if rendered
            tab_raw = page.locator("#tabBtn-raw")
            if tab_raw.is_visible():
                tab_raw.click()
                time.sleep(0.5)
                raw_json = page.locator("#rawTelemetryJson").inner_text()
                print("Raw Telemetry JSON excerpt:")
                print(raw_json[:300])

            print("[✓] Headless browser empirical verification PASSED with Grade A+!")
            browser.close()
    finally:
        httpd.shutdown()

if __name__ == "__main__":
    run_headless_audit()
