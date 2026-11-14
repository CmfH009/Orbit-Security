"""CLI script to crawl target hosts, download JavaScript bundles, and extract hardcoded secrets."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import urllib3

from orbit_security.bounty_active_prober import (
    classify_js_secret_fp_reason,
    filter_and_deduplicate_js_secrets,
)
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyScopeIngester,
    DEFAULT_BOUNTY_DATA_PATH,
)
from orbit_security.egress_guard import (
    EgressViolationError,
    create_guarded_requests_session,
)
from orbit_security.scanner import PublicHostOnlyRoE
from orbit_security.tools.secret_harvester import SecretHarvester
from scripts.mine_cors_endpoints import extract_script_urls, DEFAULT_TARGETS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mine_js_secrets")


def resolve_targets_from_programs(
    programs: List[BountyProgram],
    max_targets_per_program: int = 4,
) -> List[str]:
    """Resolves primary HTTPS web endpoints for in-scope wildcards and direct domains."""
    targets: List[str] = []
    seen: Set[str] = set()

    for prog in programs:
        out_of_scope_clean = {s.strip().lower().lstrip("*.") for s in prog.out_of_scope}
        prog_targets = 0

        for scope in prog.in_scope:
            clean = scope.strip().lower()
            if not clean:
                continue

            if clean.startswith("*."):
                apex = clean.replace("*.", "").strip(".")
                if apex in out_of_scope_clean:
                    continue

                candidates = [f"https://{apex}", f"https://www.{apex}"]
                for cand in candidates:
                    if cand not in seen and prog_targets < max_targets_per_program:
                        targets.append(cand)
                        seen.add(cand)
                        prog_targets += 1
            else:
                if clean in out_of_scope_clean:
                    continue
                cand = f"https://{clean}"
                if cand not in seen and prog_targets < max_targets_per_program:
                    targets.append(cand)
                    seen.add(cand)
                    prog_targets += 1

    return targets


def _write_json_lf(output_path: Path, data: List[Dict[str, Any]]) -> None:
    """Persist JSON output strictly with Unix LF line endings."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(data, indent=2) + "\n").replace("\r\n", "\n")
    output_path.write_bytes(payload.encode("utf-8"))


def refilter_staged_js_secrets(output_path: Path) -> List[Dict[str, Any]]:
    """Re-apply JS secret FP filtering and (script_url, matched_value) deduplication to a staged JSON file."""
    existing_findings: List[Dict[str, Any]] = []
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    existing_findings = loaded
        except Exception:
            existing_findings = []

    filtered = filter_and_deduplicate_js_secrets(existing_findings)
    _write_json_lf(output_path, filtered)
    return filtered


def harvest_target_secrets(
    targets: List[str],
    output_path: Path,
    max_scripts_per_target: int = 15,
) -> List[Dict[str, Any]]:
    session = create_guarded_requests_session(roe_engine=PublicHostOnlyRoE())
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })
    harvester = SecretHarvester()
    all_findings: List[Dict[str, Any]] = []

    for target in targets:
        logger.info(f"[*] Crawling target for JS bundles: {target}")
        try:
            r = session.get(target, timeout=8, verify=False)
            if r.status_code >= 400:
                continue
        except EgressViolationError as e:
            logger.warning(f"[!] RoE egress blocked {target}: {e}")
            continue
        except Exception as e:
            logger.debug(f"[!] Error fetching {target}: {e}")
            continue

        scripts = extract_script_urls(r.text, target)
        logger.info(f"[+] Found {len(scripts)} scripts on {target}")

        for script_url in scripts[:max_scripts_per_target]:
            try:
                js_resp = session.get(script_url, timeout=8, verify=False)
                if js_resp.status_code == 200:
                    matches = harvester.scan_text(js_resp.text)
                    for m in matches:
                        fp_reason = classify_js_secret_fp_reason(
                            pattern_name=m.pattern_name,
                            matched_value=m.matched_value,
                            context_snippet=m.context_snippet,
                            script_url=script_url,
                        )
                        if fp_reason:
                            logger.debug(
                                f"[skip:{fp_reason}] {target} -> {m.pattern_name}: {m.redacted_value}"
                            )
                            continue
                        finding = {
                            "target": target,
                            "script_url": script_url,
                            **m.to_dict(),
                        }
                        all_findings.append(finding)
                        logger.warning(f"[🔥 SECRET FOUND] {target} -> {m.pattern_name}: {m.redacted_value}")
            except EgressViolationError as e:
                logger.warning(f"[!] RoE egress blocked script {script_url}: {e}")
            except Exception as e:
                logger.debug(f"Failed to fetch script {script_url}: {e}")

    existing_findings = []
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    existing_findings = loaded
        except Exception:
            existing_findings = []

    # Filter both existing and new findings, then deduplicate by unique (script_url, matched_value)
    merged_list = filter_and_deduplicate_js_secrets(existing_findings + all_findings)
    _write_json_lf(output_path, merged_list)

    logger.info(f"[✔] Secret harvesting complete. Staged {len(all_findings)} new ({len(merged_list)} cumulative) actionable matches to {output_path}")
    return merged_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mine secrets from client JavaScript bundles")
    parser.add_argument("--targets", nargs="+", default=[], help="Explicit target URLs to crawl")
    parser.add_argument("--all-programs", action="store_true", help="Sweep all enrolled programs from bounty_programs.json")
    parser.add_argument("--program", type=str, default="", help="Sweep a specific program by ID")
    parser.add_argument("--limit-programs", type=int, default=0, help="Limit number of programs swept")
    parser.add_argument("--max-scripts", type=int, default=15, help="Maximum scripts crawled per target")
    parser.add_argument("--out", default="data/hackerone_staging/js_leaked_secrets.json", help="Output JSON path")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent

    if args.targets:
        targets_to_crawl = args.targets
    elif args.all_programs or args.program:
        ingester = BountyScopeIngester(data_path=DEFAULT_BOUNTY_DATA_PATH)
        programs = ingester.list_programs()
        if args.program:
            programs = [p for p in programs if p.program_id.lower() == args.program.lower()]
        if args.limit_programs > 0:
            programs = programs[:args.limit_programs]
        targets_to_crawl = resolve_targets_from_programs(programs)
        logger.info(f"[+] Resolved {len(targets_to_crawl)} targets across {len(programs)} program(s)")
    else:
        targets_to_crawl = DEFAULT_TARGETS

    harvest_target_secrets(
        targets=targets_to_crawl,
        output_path=project_root / args.out,
        max_scripts_per_target=args.max_scripts,
    )
