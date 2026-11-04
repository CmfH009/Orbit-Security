"""CLI script to crawl target hosts, download JavaScript bundles, and extract hardcoded secrets."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests
import urllib3

from orbit_security.tools.secret_harvester import SecretHarvester
from scripts.mine_cors_endpoints import extract_script_urls, DEFAULT_TARGETS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mine_js_secrets")


def harvest_target_secrets(targets: List[str], output_path: Path) -> List[Dict[str, Any]]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })
    harvester = SecretHarvester()
    all_findings: List[Dict[str, Any]] = []

    for target in targets:
        logger.info(f"[*] Crawling target for JS bundles: {target}")
        try:
            r = session.get(target, timeout=10, verify=False)
            if r.status_code >= 400:
                continue
        except Exception as e:
            logger.error(f"[!] Error fetching {target}: {e}")
            continue

        scripts = extract_script_urls(r.text, target)
        logger.info(f"[+] Found {len(scripts)} scripts on {target}")

        for script_url in scripts[:20]:
            try:
                js_resp = session.get(script_url, timeout=10, verify=False)
                if js_resp.status_code == 200:
                    matches = harvester.scan_text(js_resp.text)
                    for m in matches:
                        finding = {
                            "target": target,
                            "script_url": script_url,
                            **m.to_dict(),
                        }
                        all_findings.append(finding)
                        logger.warning(f"[🔥 SECRET FOUND] {target} -> {m.pattern_name}: {m.redacted_value}")
            except Exception as e:
                logger.debug(f"Failed to fetch script {script_url}: {e}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)

    logger.info(f"[✔] Secret harvesting complete. Staged {len(all_findings)} matches to {output_path}")
    return all_findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mine secrets from client JavaScript bundles")
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS, help="Target URLs to crawl")
    parser.add_argument("--out", default="data/hackerone_staging/js_leaked_secrets.json", help="Output JSON path")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    harvest_target_secrets(args.targets, project_root / args.out)
