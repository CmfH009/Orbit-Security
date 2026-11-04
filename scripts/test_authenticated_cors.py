"""
test_authenticated_cors.py
Utility script to test whether an authenticated endpoint on MercadoLibre or Xiaomi
leaks private user session data when queried cross-origin with user cookies.
"""
import sys
import requests
import argparse

def test_cors(url: str, cookie_header: str = "", auth_header: str = ""):
    headers = {
        "Origin": "https://evil.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    if cookie_header:
        headers["Cookie"] = cookie_header
    if auth_header:
        headers["Authorization"] = auth_header

    print(f"[*] Testing target: {url}")
    print(f"[*] Origin: https://evil.com")
    if cookie_header:
        print("[*] Included Cookie header: [PRESENT]")
    if auth_header:
        print("[*] Included Authorization header: [PRESENT]")

    r = requests.get(url, headers=headers, verify=False, timeout=10)
    print(f"[+] Status Code: {r.status_code}")
    print(f"[+] Access-Control-Allow-Origin: {r.headers.get('Access-Control-Allow-Origin')}")
    print(f"[+] Access-Control-Allow-Credentials: {r.headers.get('Access-Control-Allow-Credentials')}")
    print(f"[+] Content-Type: {r.headers.get('Content-Type')}")
    print(f"[+] Content-Length: {len(r.content)}")

    # Check for sensitive indicators in body
    body_text = r.text.lower()
    sensitive_keywords = ["email", "user_id", "userid", "address", "phone", "token", "balance", "order", "card", "name"]
    found_keywords = [kw for kw in sensitive_keywords if kw in body_text]

    print("\n--- Body Analysis ---")
    if found_keywords:
        print(f"[!] POTENTIAL SENSITIVE DATA DETECTED: {found_keywords}")
    else:
        print("[i] No obvious sensitive keywords found in response body.")

    print("\n--- Response Body Preview (First 400 chars) ---")
    print(r.text[:400])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test authenticated CORS reflection")
    parser.add_argument("url", help="Target URL (e.g. https://buyingflow.mercadolibre.com.mx/api/user)")
    parser.add_argument("--cookie", default="", help="Cookie string from logged in browser session")
    parser.add_argument("--auth", default="", help="Bearer token or Authorization header")
    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    test_cors(args.url, args.cookie, args.auth)
