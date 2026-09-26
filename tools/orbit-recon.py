#!/usr/bin/env python3
"""
Orbit Recon (orbit-recon.py)
Autonomous Attack Surface, DNS Hygiene & Perimeter Reconnaissance CLI
Part of the Orbit Security Intelligence Suite (https://cmfh009.github.io/Orbit-Security/)
"""

import sys
import argparse
import json
import socket
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
  ___       _     _ _     ____                      
 / _ \\ _ __| |__ (_) |_  |  _ \\ ___  ___ ___  _ __  
| | | | '__| '_ \\| | __| | |_) / _ \\/ __/ _ \\| '_ \\ 
| |_| | |  | |_) | | |_  |  _ <  __/ (_| (_) | | | |
 \\___/|_|  |_.__/|_|\\__| |_| \\_\\___|\\___\\___/|_| |_|
{DIM}  Autonomous Perimeter Hygiene & Attack Surface Scout{RESET}
"""

SAAS_SIGNATURES = [
    {
        "name": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website", ".s3."],
        "patterns": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    {
        "name": "GitHub Pages",
        "cname": ["github.io"],
        "patterns": ["There isn't a GitHub Pages site here", "For root URLs"]
    },
    {
        "name": "CloudFront",
        "cname": ["cloudfront.net"],
        "patterns": ["Bad request.", "ERROR: The request could not be satisfied"]
    },
    {
        "name": "Heroku",
        "cname": ["herokudns.com", "herokuapp.com"],
        "patterns": ["No such app", "Heroku | No such app"]
    },
    {
        "name": "Shopify",
        "cname": ["myshopify.com"],
        "patterns": ["Sorry, this shop is currently unavailable"]
    },
    {
        "name": "Webflow",
        "cname": ["proxy.webflow.com", "webflow.io"],
        "patterns": ["The page you are looking for doesn't exist"]
    },
    {
        "name": "Unbounce",
        "cname": ["unbouncepages.com"],
        "patterns": ["The requested URL was not found on this server"]
    }
]

SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref: refs/heads/"),
    ("/.env", "DB_PASSWORD"),
    ("/.env.local", "API_KEY"),
    ("/wp-config.php.bak", "DB_NAME"),
    ("/.DS_Store", "\x00\x00\x00\x01Bud1")
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Enforces encrypted HTTPS connections (HSTS)"),
    ("Content-Security-Policy", "Prevents XSS, data injection, and malicious frames"),
    ("X-Frame-Options", "Mitigates Clickjacking attacks"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing exploits"),
    ("Referrer-Policy", "Controls referrer leakage to external origins"),
    ("Permissions-Policy", "Restricts camera, microphone, and geolocation APIs")
]


def resolve_dns(domain: str) -> Dict[str, Any]:
    res = {
        "cname": None,
        "a_records": [],
        "mx_records": [],
        "dangling_risk": False,
        "matched_service": None
    }
    
    if HAS_DNS:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        try:
            answers = resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                res["cname"] = str(rdata.target).rstrip('.')
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                res["a_records"].append(str(rdata))
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, 'MX')
            for rdata in answers:
                res["mx_records"].append(str(rdata.exchange).rstrip('.'))
        except Exception:
            pass
    else:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            res["a_records"] = ips
        except Exception:
            pass

    if res["cname"]:
        cname_lower = res["cname"].lower()
        for saas in SAAS_SIGNATURES:
            if any(p in cname_lower for p in saas["cname"]):
                res["matched_service"] = saas["name"]
                if not res["a_records"]:
                    res["dangling_risk"] = True
                break

    return res


def check_headers_and_exposures(domain: str) -> Dict[str, Any]:
    url = f"https://{domain}"
    report = {
        "status_code": None,
        "headers_found": {},
        "missing_headers": [],
        "exposures": []
    }

    headers_dict = {}
    try:
        if HAS_HTTPX:
            with httpx.Client(timeout=5.0, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                report["status_code"] = resp.status_code
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                
                for path, signature in SENSITIVE_PATHS:
                    try:
                        probe = client.get(f"https://{domain}{path}")
                        if probe.status_code == 200 and signature in probe.text:
                            report["exposures"].append({"path": path, "status": 200, "verified": True})
                    except Exception:
                        pass
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Orbit-Recon/1.0"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                report["status_code"] = resp.status
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        report["error"] = str(e)

    for h_name, h_desc in SECURITY_HEADERS:
        val = headers_dict.get(h_name.lower())
        if val:
            report["headers_found"][h_name] = val
        else:
            report["missing_headers"].append({"header": h_name, "description": h_desc})

    return report


def calculate_score(dns_data: Dict[str, Any], web_data: Dict[str, Any]) -> int:
    score = 100
    if dns_data.get("dangling_risk"):
        score -= 40
    if web_data.get("exposures"):
        score -= 30 * len(web_data["exposures"])
    
    missing_count = len(web_data.get("missing_headers", []))
    score -= missing_count * 8
    
    return max(0, min(100, score))


def run_recon(target: str, json_output: bool = False):
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
    
    dns_res = resolve_dns(domain)
    web_res = check_headers_and_exposures(domain)
    score = calculate_score(dns_res, web_res)

    results = {
        "target": domain,
        "score": score,
        "dns": dns_res,
        "perimeter": web_res
    }

    if json_output:
        print(json.dumps(results, indent=2))
        return

    print(BANNER)
    print(f"{BOLD}Target:{RESET} {domain}")
    
    score_color = GREEN if score >= 85 else (YELLOW if score >= 60 else RED)
    print(f"{BOLD}Hygiene Score:{RESET} {score_color}{score}/100{RESET}\n")

    print(f"{CYAN}{BOLD}--- [1] DNS & Perimeter Routing ---{RESET}")
    print(f"  A Records   : {', '.join(dns_res['a_records']) or 'None detected'}")
    print(f"  CNAME Target: {dns_res['cname'] or 'Direct A/AAAA'}")
    if dns_res.get("matched_service"):
        print(f"  Service     : {dns_res['matched_service']}")
    if dns_res.get("dangling_risk"):
        print(f"  {RED}{BOLD}[!] CRITICAL: Dangling CNAME detected! Potential Subdomain Takeover.{RESET}")
    else:
        print(f"  {GREEN}[✓] Subdomain routing stable.{RESET}")

    print(f"\n{CYAN}{BOLD}--- [2] HTTP Security Headers ---{RESET}")
    for h, v in web_res.get("headers_found", {}).items():
        print(f"  {GREEN}[PASS]{RESET} {BOLD}{h}:{RESET} {DIM}{v[:45]}...{RESET}" if len(v) > 45 else f"  {GREEN}[PASS]{RESET} {BOLD}{h}:{RESET} {DIM}{v}{RESET}")
    for m in web_res.get("missing_headers", []):
        print(f"  {YELLOW}[WARN]{RESET} Missing {BOLD}{m['header']}{RESET} — {m['description']}")

    print(f"\n{CYAN}{BOLD}--- [3] Public Endpoint Exposures ---{RESET}")
    if web_res.get("exposures"):
        for exp in web_res["exposures"]:
            print(f"  {RED}[CRITICAL EXPOSURE]{RESET} Publicly accessible {exp['path']}")
    else:
        print(f"  {GREEN}[✓] Zero sensitive config files (.git, .env) publicly exposed.{RESET}")

    print(f"\n{DIM}Generated by Orbit Security — Continuous Zero-Drift Perimeter Sentinel{RESET}")
    print(f"{DIM}Learn more & automated reporting: https://cmfh009.github.io/Orbit-Security/{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Orbit Recon — Autonomous External Perimeter Reconnaissance")
    parser.add_argument("target", help="Target domain (e.g. agency.com or client.agency.com)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    run_recon(args.target, args.json)


if __name__ == "__main__":
    main()
