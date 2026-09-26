"""Orbit Security Custom Domain & DNS Automation.

Configures:
1. docs/CNAME for GitHub Pages
2. Calls GitHub Pages REST API to bind the domain and request SSL
3. Verifies DNS propagation for A and CNAME records
"""

import argparse
import os
import socket
import sys
import httpx
from dotenv import load_dotenv

load_dotenv()

GITHUB_PAGES_IPS = [
    "185.199.108.153",
    "185.199.109.153",
    "185.199.110.153",
    "185.199.111.153"
]


def print_dns_guide(domain: str):
    print(f"\n=======================================================")
    print(f" 🌐 DNS CONFIGURATION GUIDE FOR: {domain}")
    print(f"=======================================================")
    print("Add the following records to your DNS provider (Cloudflare, Namecheap, GoDaddy):")
    print("\n[Record Type: A] (Apex / Root Domain: @)")
    for ip in GITHUB_PAGES_IPS:
        print(f"  Type: A     | Name: @   | Value: {ip} | TTL: Auto/300")
    print(f"\n[Record Type: CNAME] (Subdomain: www)")
    print(f"  Type: CNAME | Name: www | Value: cmfh009.github.io | TTL: Auto/300")
    print("=======================================================\n")


def configure_domain(domain: str, verify_dns: bool = True):
    domain = domain.strip().lower()
    cname_path = os.path.join(os.path.dirname(__file__), "..", "docs", "CNAME")

    # 1. Write CNAME
    with open(cname_path, "w", encoding="utf-8") as f:
        f.write(domain + "\n")
    print(f"[✔] Configured CNAME file: {cname_path} -> {domain}")

    # 2. DNS Verification if requested
    if verify_dns:
        print(f"[*] Checking DNS resolution for {domain}...")
        try:
            resolved_ips = socket.gethostbyname_ex(domain)[2]
            print(f"    Resolved IPs: {resolved_ips}")
            matches = set(resolved_ips).intersection(set(GITHUB_PAGES_IPS))
            if matches:
                print(f"    [✔] Successfully resolving to GitHub Pages ({len(matches)} matching IPs)!")
            else:
                print(f"    [!] Domain does not yet resolve to GitHub Pages IPs. DNS may still be propagating.")
        except Exception as e:
            print(f"    [!] DNS lookup failed ({e}). Records may not have propagated yet.")

    # 3. Call GitHub API to bind custom domain
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = "https://api.github.com/repos/CmfH009/Orbit-Security/pages"
        payload = {"cname": domain}
        try:
            r = httpx.put(url, headers=headers, json=payload, timeout=10.0)
            if r.status_code in (200, 204):
                print(f"[✔] GitHub Pages API updated: Custom domain bound to {domain}")
            else:
                print(f"[!] GitHub API response ({r.status_code}): {r.text}")
        except Exception as e:
            print(f"[!] GitHub API call error: {e}")

    print_dns_guide(domain)


def main():
    parser = argparse.ArgumentParser(description="Configure custom domain for Orbit Security")
    parser.add_argument("domain", nargs="?", default="orbitsecurity.ai", help="Domain to configure (e.g. orbitsecurity.ai)")
    parser.add_argument("--no-verify", action="store_true", help="Skip DNS lookup check")
    args = parser.parse_args()

    configure_domain(args.domain, verify_dns=not args.no_verify)


if __name__ == "__main__":
    main()
