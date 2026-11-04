"""Automated JavaScript asset crawler and CORS API endpoint miner.

Extracts script references from target hosts, parses internal API routes,
and tests candidate routes for credentialed CORS reflection.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mine_cors_endpoints")

# Targets confirmed with dynamic CORS reflection
DEFAULT_TARGETS = [
    "https://buyingflow.mercadolibre.com.mx",
    "https://buyingflow.mercadolibre.com.co",
    "https://buyingflow.mercadolibre.com.pe",
    "https://xiaomiyoupin.com",
    "https://youpin.cn",
    "https://airstarfinance.net",
]

ENDPOINT_REGEX = re.compile(
    r"""(?:"|')(\/(?:api|v[0-9]+|users?|account|checkout|cart|order|billing|wallet|profile|auth|session|bff)\/[a-zA-Z0-9_\-\/\?&=%]+)(?:"|')""",
    re.IGNORECASE,
)

SCRIPT_SRC_REGEX = re.compile(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.IGNORECASE)

EXCLUDED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf"}
SENSITIVE_KEYWORDS = ["email", "user_id", "userid", "address", "phone", "token", "balance", "order", "card", "name", "account"]

def extract_script_urls(html: str, base_url: str) -> List[str]:
    """Finds all script src attributes and resolves them to absolute URLs."""
    raw_srcs = SCRIPT_SRC_REGEX.findall(html)
    urls = []
    for src in raw_srcs:
        full_url = urljoin(base_url, src)
        urls.append(full_url)
    return sorted(list(set(urls)))

def extract_api_endpoints(js_code: str) -> Set[str]:
    """Parses JavaScript content to extract candidate internal REST/API endpoints."""
    matches = ENDPOINT_REGEX.findall(js_code)
    valid_endpoints = set()
    for m in matches:
        # Strip query parameters for normalization
        path = m.split("?")[0].strip()
        ext = os.path.splitext(path)[1].lower()
        if ext in EXCLUDED_EXTENSIONS:
            continue
        if len(path) > 2:
            valid_endpoints.add(path)
    return valid_endpoints

def evaluate_cors_response(status_code: int, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    """Evaluates whether an HTTP response indicates vulnerable credentialed CORS reflection."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    allow_origin = headers_lower.get("access-control-allow-origin", "")
    allow_creds = headers_lower.get("access-control-allow-credentials", "").lower() == "true"
    
    reflected = allow_origin == "https://evil.com"
    credentials = allow_creds

    body_lower = body.lower()
    found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in body_lower]
    
    is_high_value = bool(reflected and credentials and (status_code in [200, 201] or found_keywords))

    return {
        "status_code": status_code,
        "reflected": reflected,
        "credentials": credentials,
        "allow_origin": allow_origin,
        "sensitive_keywords": sorted(found_keywords),
        "is_high_value": is_high_value,
        "body_preview": body[:300] if body else "",
    }

def probe_endpoint_cors(url: str, session: requests.Session) -> Dict[str, Any]:
    """Sends a cross-origin probe with credentials flag to test for CORS misconfiguration."""
    headers = {
        "Origin": "https://evil.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    try:
        resp = session.get(url, headers=headers, timeout=8, verify=False, allow_redirects=False)
        return evaluate_cors_response(resp.status_code, dict(resp.headers), resp.text)
    except Exception as e:
        return {
            "status_code": 0,
            "error": str(e),
            "reflected": False,
            "credentials": False,
            "allow_origin": "",
            "sensitive_keywords": [],
            "is_high_value": False,
            "body_preview": "",
        }

def crawl_and_mine(targets: List[str], output_path: Path) -> List[Dict[str, Any]]:
    """Crawls targets, parses JS scripts, tests discovered endpoints, and writes results."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })
    
    all_findings = []
    for target in targets:
        logger.info(f"[*] Crawling target root: {target}")
        try:
            r = session.get(target, timeout=10, verify=False)
            if r.status_code >= 400:
                logger.warning(f"[-] Target {target} returned status {r.status_code}")
                continue
        except Exception as e:
            logger.error(f"[!] Error fetching {target}: {e}")
            continue

        scripts = extract_script_urls(r.text, target)
        logger.info(f"[+] Found {len(scripts)} scripts on {target}")

        discovered_endpoints: Set[str] = set()
        for script_url in scripts[:15]:  # Bound scan to top 15 bundles
            try:
                js_resp = session.get(script_url, timeout=10, verify=False)
                if js_resp.status_code == 200:
                    endpoints = extract_api_endpoints(js_resp.text)
                    discovered_endpoints.update(endpoints)
            except Exception as e:
                logger.debug(f"Failed to fetch script {script_url}: {e}")

        logger.info(f"[+] Discovered {len(discovered_endpoints)} unique API endpoints for {target}")

        for endpoint in discovered_endpoints:
            full_url = urljoin(target, endpoint)
            eval_result = probe_endpoint_cors(full_url, session)
            finding = {
                "base_target": target,
                "endpoint": endpoint,
                "full_url": full_url,
                **eval_result,
            }
            all_findings.append(finding)
            if eval_result.get("is_high_value"):
                logger.info(f"[🔥 HIGH IMPACT CORS] {full_url} -> Creds: {eval_result['credentials']} | Keywords: {eval_result['sensitive_keywords']}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)

    logger.info(f"[✔] Mining complete. Saved {len(all_findings)} endpoint evaluations to {output_path}")
    return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mine internal API routes and test CORS reflection")
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS, help="Target root URLs")
    parser.add_argument("--out", default="data/hackerone_staging/cors_endpoint_matrix.json", help="Output JSON path")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    out_file = project_root / args.out
    crawl_and_mine(args.targets, out_file)
