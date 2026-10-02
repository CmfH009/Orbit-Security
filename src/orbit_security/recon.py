#!/usr/bin/env python3
"""Orbit Recon (orbit_security.recon)

Autonomous Attack Surface, DNS Hygiene & Perimeter Reconnaissance Engine & CLI.
Part of the Orbit Security Intelligence Suite (https://cmfh009.github.io/Orbit-Security/).
"""

import argparse
import json
import socket
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


try:
    import dns.resolver
    from orbit_security.dns_cache import get_orbit_sync_resolver

    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    import urllib.request

    HAS_HTTPX = False

from orbit_security.scanner import is_safe_host
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES
from orbit_security.remediation import DnsRemediationGenerator

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

SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref: refs/heads/"),
    ("/.git/config", "[core]"),
    ("/.env", "DB_PASSWORD"),
    ("/.env.local", "API_KEY"),
    ("/wp-config.php.bak", "DB_NAME"),
    ("/wp-config.php.old", "DB_NAME"),
    ("/phpinfo.php", "phpinfo()"),
    ("/.DS_Store", "\x00\x00\x00\x01Bud1"),
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Enforces encrypted HTTPS connections (HSTS)"),
    ("Content-Security-Policy", "Prevents XSS, data injection, and malicious frames"),
    ("X-Frame-Options", "Mitigates Clickjacking attacks"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing exploits"),
    ("Referrer-Policy", "Controls referrer leakage to external origins"),
    ("Permissions-Policy", "Restricts camera, microphone, and geolocation APIs"),
    ("Cross-Origin-Opener-Policy", "Isolates browsing contexts against Spectre/XS-Leaks"),
]


def resolve_dns(domain: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "cname": None,
        "a_records": [],
        "mx_records": [],
        "dmarc_record": None,
        "bimi_record": None,
        "mta_sts_record": None,
        "caa_records": [],
        "dangling_risk": False,
        "matched_service": None,
        "remediation": None,
    }

    if not is_safe_host(domain):
        res["error"] = "Target domain resolves to private, loopback, or cloud metadata address (SSRF blocked)."
        return res

    if HAS_DNS:
        resolver = get_orbit_sync_resolver(timeout=4.0)

        try:
            answers = resolver.resolve(domain, "CNAME")
            for rdata in answers:
                res["cname"] = str(rdata.target).rstrip(".")
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                res["a_records"].append(str(rdata))
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                res["mx_records"].append(str(rdata.exchange).rstrip("."))
        except Exception:
            pass

        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                res["dmarc_record"] = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                break
        except Exception:
            pass

        labels = domain.split(".")
        is_sub = len(labels) > 2
        org_domain = ".".join(labels[-2:]) if is_sub else domain
        is_static = any(domain.endswith(s) for s in [".github.io", ".pages.dev", ".vercel.app", ".netlify.app", ".gitlab.io"])

        if not res.get("dmarc_record") and is_sub:
            try:
                org_answers = resolver.resolve(f"_dmarc.{org_domain}", "TXT")
                for rdata in org_answers:
                    res["dmarc_record"] = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    break
            except Exception:
                pass

        if not res.get("dmarc_record") and (is_static or not res["mx_records"]):
            if is_sub:
                try:
                    org_txt = resolver.resolve(org_domain, "TXT")
                    for rdata in org_txt:
                        t = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                        if t.startswith("v=spf1") and ("-all" in t or "~all" in t):
                            res["dmarc_record"] = f"Protected: RFC 7505 Non-Sending Host (Isolated via {org_domain} -all)"
                            break
                except Exception:
                    pass
            if not res.get("dmarc_record") and is_static:
                res["dmarc_record"] = "Protected: RFC 7505 Non-Sending Host"

        try:
            answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
            for rdata in answers:
                res["bimi_record"] = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                break
        except Exception:
            pass

        try:
            answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
            for rdata in answers:
                res["mta_sts_record"] = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                break
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "CAA")
            for rdata in answers:
                res["caa_records"].append(str(rdata))
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
        for saas in SAAS_TAKEOVER_SIGNATURES:
            if any(pattern in cname_lower for pattern in saas.cname_patterns):
                res["matched_service"] = saas.name
                res["remediation"] = saas.remediation
                if not res["a_records"]:
                    res["dangling_risk"] = True
                break

    return res


def check_headers_and_exposures(domain: str) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "status_code": None,
        "headers_found": {},
        "missing_headers": [],
        "exposures": [],
    }

    if not is_safe_host(domain):
        report["error"] = "Target domain resolves to private, loopback, or cloud metadata address (SSRF blocked)."
        for h_name, h_desc in SECURITY_HEADERS:
            report["missing_headers"].append({"header": h_name, "description": h_desc})
        return report

    url = f"https://{domain}"
    headers_dict = {}

    try:
        if HAS_HTTPX:
            with httpx.Client(timeout=6.0, follow_redirects=True, verify=False) as client:
                try:
                    resp = client.get(url)
                    report["status_code"] = resp.status_code
                    headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                except Exception as e:
                    report["error"] = str(e)

                for path, signature in SENSITIVE_PATHS:
                    try:
                        probe_url = f"https://{domain}{path}"
                        probe = client.get(probe_url)
                        if probe.status_code == 200:
                            content_type = probe.headers.get("content-type", "").lower()
                            # SPA Guard: Skip client-side HTML fallbacks
                            if "text/html" in content_type and not path.endswith((".html", ".htm")):
                                continue
                            body = probe.text[: 256 * 1024]
                            stripped = body.strip().lower()
                            if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
                                continue

                            if signature in body:
                                report["exposures"].append({"path": path, "status": 200, "verified": True})
                    except Exception:
                        pass
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Orbit-Recon/1.0"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
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


def calculate_score(dns_data: Dict[str, Any], web_data: Dict[str, Any], domain: str = "") -> int:
    score = 100
    if dns_data.get("dangling_risk"):
        score -= 40
    if web_data.get("exposures"):
        score -= 30 * len(web_data["exposures"])

    is_static = any(domain.endswith(s) for s in [".github.io", ".pages.dev", ".vercel.app", ".netlify.app", ".gitlab.io"])
    missing_count = len(web_data.get("missing_headers", []))
    if is_static:
        score -= min(missing_count * 1, 5)
    else:
        score -= missing_count * 8

    return max(0, min(100, score))


def build_remediation_plan(domain: str, dns_res: Dict[str, Any], web_res: Dict[str, Any]) -> Dict[str, Any]:
    """Generates actionable DNS records, Terraform HCL, and server configs to fix detected vulnerabilities."""
    plan: Dict[str, Any] = {
        "domain": domain,
        "items": [],
        "has_actions": False,
    }

    # 1. Dangling CNAME Takeover
    if dns_res.get("dangling_risk"):
        matched_service = dns_res.get("matched_service", "Unknown SaaS")
        cname = dns_res.get("cname", "unknown")
        takeover_info = DnsRemediationGenerator.generate_takeover_remediation(
            subdomain=domain,
            saas_provider=matched_service,
            cname_target=cname,
        )
        plan["items"].append({
            "type": "takeover",
            "title": f"Dangling CNAME Takeover ({matched_service})",
            "details": takeover_info,
        })
        plan["has_actions"] = True

    # 2. Missing DMARC
    if not dns_res.get("dmarc_record"):
        dmarc_snippets = DnsRemediationGenerator.generate_dmarc_fix(
            domain=domain,
            policy="quarantine",
            report_email=f"dmarc@{domain}",
        )
        cf_snippet = next((s for s in dmarc_snippets if s.provider == "Cloudflare"), dmarc_snippets[0])
        plan["items"].append({
            "type": "dmarc",
            "title": "Missing DMARC Email Anti-Spoofing Record",
            "provider": "Cloudflare",
            "dns_record": {
                "type": "TXT",
                "host": "_dmarc",
                "value": cf_snippet.record_value.strip('"'),
            },
            "terraform": cf_snippet.terraform_hcl,
        })
        plan["has_actions"] = True

    # 3. Missing Security Headers
    missing_headers = web_res.get("missing_headers", [])
    if missing_headers:
        nginx_lines = []
        for mh in missing_headers:
            h_name = mh["header"]
            if h_name == "Strict-Transport-Security":
                nginx_lines.append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')
            elif h_name == "X-Content-Type-Options":
                nginx_lines.append('add_header X-Content-Type-Options "nosniff" always;')
            elif h_name == "X-Frame-Options":
                nginx_lines.append('add_header X-Frame-Options "SAMEORIGIN" always;')
            elif h_name == "Referrer-Policy":
                nginx_lines.append('add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
            elif h_name == "Content-Security-Policy":
                nginx_lines.append("add_header Content-Security-Policy \"default-src 'self' https: data: 'unsafe-inline';\" always;")

        plan["items"].append({
            "type": "headers",
            "title": f"Missing {len(missing_headers)} Recommended HTTP Security Headers",
            "nginx_config": "\n".join(nginx_lines),
        })
        plan["has_actions"] = True

    return plan


def run_recon(target: str, json_output: bool = False, remediate: bool = False) -> Dict[str, Any]:
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].strip()

    dns_res = resolve_dns(domain)
    web_res = check_headers_and_exposures(domain)
    score = calculate_score(dns_res, web_res, domain=domain)

    results = {
        "target": domain,
        "score": score,
        "dns": dns_res,
        "perimeter": web_res,
    }

    if remediate:
        results["remediation"] = build_remediation_plan(domain, dns_res, web_res)

    if json_output:
        print(json.dumps(results, indent=2))
        return results

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
        if dns_res.get("remediation"):
            print(f"  {YELLOW}Remediation : {dns_res['remediation']}{RESET}")
    else:
        print(f"  {GREEN}[✓] Subdomain routing stable.{RESET}")

    caa_count = len(dns_res.get("caa_records", []))
    if caa_count > 0:
        print(f"  CAA Policy  : {GREEN}[PASS]{RESET} {caa_count} record(s) configured")
    else:
        print(f"  CAA Policy  : {YELLOW}[WARN]{RESET} Missing DNS CAA record (RFC 8659)")

    is_static = any(domain.endswith(s) for s in [".github.io", ".pages.dev", ".vercel.app", ".netlify.app", ".gitlab.io"])
    print(f"\n{CYAN}{BOLD}--- [2] Email & Phishing Defense ---{RESET}")
    dmarc_str = f"{GREEN}[PASS]{RESET} {dns_res['dmarc_record'][:35]}..." if dns_res.get("dmarc_record") else f"{RED}[FAIL]{RESET} Missing DMARC"
    bimi_str = (
        f"{GREEN}[PASS]{RESET} Active"
        if dns_res.get("bimi_record")
        else (f"{GREEN}[PASS]{RESET} N/A (Static Web Host — No Mail)" if (is_static or not dns_res.get("mx_records")) else f"{YELLOW}[OPPORTUNITY]{RESET} Missing BIMI Brand Logo")
    )
    mta_sts_str = (
        f"{GREEN}[PASS]{RESET} Enforced"
        if dns_res.get("mta_sts_record")
        else (f"{GREEN}[PASS]{RESET} N/A (Static Web Host — No MTA)" if (is_static or not dns_res.get("mx_records")) else f"{YELLOW}[WARN]{RESET} Missing MTA-STS Encryption")
    )
    print(f"  DMARC Policy: {dmarc_str}")
    print(f"  BIMI Trust  : {bimi_str}")
    print(f"  MTA-STS TLS : {mta_sts_str}")

    print(f"\n{CYAN}{BOLD}--- [3] HTTP Security Headers ---{RESET}")
    for h, v in web_res.get("headers_found", {}).items():
        val_str = f"{v[:45]}..." if len(v) > 45 else v
        print(f"  {GREEN}[PASS]{RESET} {BOLD}{h}:{RESET} {DIM}{val_str}{RESET}")
    for m in web_res.get("missing_headers", []):
        print(f"  {YELLOW}[WARN]{RESET} Missing {BOLD}{m['header']}{RESET} — {m['description']}")

    print(f"\n{CYAN}{BOLD}--- [4] Public Endpoint Exposures ---{RESET}")
    if web_res.get("exposures"):
        for exp in web_res["exposures"]:
            print(f"  {RED}[CRITICAL EXPOSURE]{RESET} Publicly accessible {exp['path']}")
    else:
        print(f"  {GREEN}[✓] Zero sensitive config files (.git, .env) publicly exposed.{RESET}")

    if remediate:
        rem_plan = results.get("remediation", {})
        print(f"\n{CYAN}{BOLD}--- [5] Automated Remediation & IaC Snippets ---{RESET}")
        if not rem_plan.get("has_actions"):
            print(f"  {GREEN}[✓] Perimeter pristine. No DNS or header remediation needed.{RESET}")
        else:
            for item in rem_plan.get("items", []):
                print(f"\n  {YELLOW}{BOLD}[ACTION: {item['title']}]{RESET}")
                if item["type"] == "takeover":
                    print(f"  {RED}Immediate Action:{RESET} {item['details']['action_immediate']}")
                    print(f"  {DIM}Decommission    :{RESET} {item['details']['option_decommission']}")
                    print(f"  {DIM}Verify command  :{RESET} {item['details']['cli_verification']}")
                elif item["type"] == "dmarc":
                    print(f"  {BOLD}Cloudflare DNS Record:{RESET}")
                    print(f"    Type: {item['dns_record']['type']} | Host: {item['dns_record']['host']} | Value: {item['dns_record']['value']}")
                    print(f"  {BOLD}Terraform HCL:{RESET}")
                    for line in item["terraform"].split("\n"):
                        print(f"    {DIM}{line}{RESET}")
                elif item["type"] == "headers":
                    print(f"  {BOLD}Nginx Server Configuration Snippet:{RESET}")
                    for line in item["nginx_config"].split("\n"):
                        print(f"    {DIM}{line}{RESET}")

    print(f"\n{DIM}Generated by Orbit Security — Continuous Zero-Drift Perimeter Sentinel{RESET}")
    print(f"{DIM}Learn more & automated reporting: https://cmfh009.github.io/Orbit-Security/{RESET}\n")

    return results


def run_bulk_recon(
    targets: List[str],
    json_output: bool = False,
    markdown_path: Optional[str] = None,
    fail_on_critical: bool = False,
    remediate: bool = False,
) -> List[Dict[str, Any]]:
    """Runs reconnaissance across multiple target domains concurrently/sequentially."""
    results = []
    has_critical_failure = False

    if not json_output:
        print(BANNER)
        print(f"{BOLD}Executing Bulk Perimeter Audit across {len(targets)} domains...{RESET}\n")

    for target in targets:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
        if not domain or domain.startswith("#"):
            continue

        dns_res = resolve_dns(domain)
        web_res = check_headers_and_exposures(domain)
        score = calculate_score(dns_res, web_res, domain=domain)

        has_takeover = bool(dns_res.get("dangling_risk"))
        has_exposure = bool(web_res.get("exposures"))
        if has_takeover or has_exposure:
            has_critical_failure = True

        res = {
            "target": domain,
            "score": score,
            "dns": dns_res,
            "perimeter": web_res,
            "has_takeover": has_takeover,
            "has_exposure": has_exposure,
        }
        if remediate:
            res["remediation"] = build_remediation_plan(domain, dns_res, web_res)
        results.append(res)

        if not json_output:
            score_color = GREEN if score >= 85 else (YELLOW if score >= 60 else RED)
            crit_badge = f" {RED}{BOLD}[CRITICAL DRIFT]{RESET}" if (has_takeover or has_exposure) else ""
            print(f"  • {BOLD}{domain:30}{RESET} Score: {score_color}{score:3}/100{RESET}{crit_badge}")

    if markdown_path:
        md_lines = [
            "# Orbit Security: Bulk Perimeter Audit Matrix",
            f"**Audit Timestamp:** {socket.gethostname()} | **Total Targets:** {len(results)}\n",
            "| Target Domain | Score | Routing / CNAME | Security Headers | Critical Exposures |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in results:
            cname = r["dns"].get("cname") or "Apex Direct"
            if r["has_takeover"]:
                cname = f"🚨 **Dangling CNAME ({r['dns'].get('matched_service', 'SaaS')})**"
            h_count = f"{len(r['perimeter'].get('headers_found', {}))}/{len(SECURITY_HEADERS)}"
            exp_text = f"🚨 {len(r['perimeter']['exposures'])} exposed" if r["has_exposure"] else "Clean"
            md_lines.append(f"| `{r['target']}` | **{r['score']}/100** | {cname} | {h_count} | {exp_text} |")

        md_content = "\n".join(md_lines) + "\n"
        with open(markdown_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        if not json_output:
            print(f"\n{GREEN}[✓] Markdown Audit Matrix exported to:{RESET} {markdown_path}")

    if json_output:
        print(json.dumps(results, indent=2))

    if fail_on_critical and has_critical_failure:
        print(f"\n{RED}{BOLD}[!] CI/CD Failure: Critical vulnerabilities (takeover or exposed secrets) detected.{RESET}")
        sys.exit(1)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Recon — Autonomous External Perimeter Reconnaissance"
    )
    parser.add_argument("target", nargs="?", default=None, help="Target domain (e.g. agency.com or client.agency.com)")
    parser.add_argument("--targets-file", "-f", help="Text file with domains to scan (one per line)")
    parser.add_argument("--markdown", "-m", help="Path to export Markdown fleet matrix")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with code 1 if critical takeover or secret exposure detected (CI/CD sentinel mode)",
    )
    parser.add_argument(
        "--remediate",
        "-r",
        action="store_true",
        help="Generate ready-to-paste DNS records, Terraform HCL, and server remediation snippets",
    )
    args = parser.parse_args()

    if args.targets_file:
        with open(args.targets_file, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        run_bulk_recon(
            targets=domains,
            json_output=args.json,
            markdown_path=args.markdown,
            fail_on_critical=args.fail_on_critical,
            remediate=args.remediate,
        )
    elif args.target:
        if args.markdown:
            run_bulk_recon(
                targets=[args.target],
                json_output=args.json,
                markdown_path=args.markdown,
                fail_on_critical=args.fail_on_critical,
                remediate=args.remediate,
            )
        else:
            res = run_recon(args.target, json_output=args.json, remediate=args.remediate)
            if args.fail_on_critical:
                has_takeover = bool(res["dns"].get("dangling_risk"))
                has_exposure = bool(res["perimeter"].get("exposures"))
                if has_takeover or has_exposure:
                    print(f"{RED}{BOLD}[!] CI/CD Failure: Critical posture risk detected.{RESET}")
                    sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

