#!/usr/bin/env python3
"""scripts/hunt_hackerone_vdps.py: Thin CLI adapter for orbit_security.hackerone_vdp_hunter.

Parses CLI flags, delegates the entire hunting pipeline to `orbit_security.hackerone_vdp_hunter`,
and formats human-readable or JSON output.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional

from orbit_security.hackerone_vdp_hunter import run_vdp_hunt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover and screen KYC-free HackerOne VDP wildcards and explicit scopes (never submits to BBPs)."
    )
    parser.add_argument("--max-programs", type=int, default=20, help="Max VDP programs to scan.")
    parser.add_argument("--program-offset", type=int, default=0, help="Offset into open VDP list.")
    parser.add_argument("--max-wildcards-per-program", type=int, default=5, help="Max wildcard roots per program.")
    parser.add_argument("--max-subdomains", type=int, default=25, help="Max CT subdomains per wildcard root.")
    parser.add_argument("--workers", type=int, default=12, help="Concurrent screening workers.")
    parser.add_argument("--include-covered", action="store_true", help="Also scan roots already in bounty_programs.json.")
    parser.add_argument("--use-crtsh", action="store_true", help="Always query crt.sh in addition to CertSpotter/Anubis.")
    parser.add_argument(
        "--use-subfinder",
        action="store_true",
        help="Run optional subfinder fallback when fewer than 5 passive subdomains are found.",
    )
    parser.add_argument("--skip-graphql-kyc", action="store_true", help="Skip per-program GraphQL KYC check.")
    parser.add_argument("--reverify-runs", type=int, default=2, help="Independent live re-verification runs before upload.")
    parser.add_argument("--critic-runs", type=int, default=3, help="Number of adversarial critic runs before upload.")
    parser.add_argument(
        "--use-ollama-critic",
        action="store_true",
        help="Enable local Ollama critic queries in addition to deterministic rubric.",
    )
    parser.add_argument("--critic-model", type=str, default="orbit-critic:latest", help="Ollama model for critic runs.")
    parser.add_argument(
        "--allow-passive-cname",
        action="store_true",
        help="Allow passive SaaS/marketing CNAME candidates without claimed PoC.",
    )
    parser.add_argument(
        "--purge-empty-cache",
        action="store_true",
        help="Purge empty 0-subdomain entries from data/vdp_ct_cache.json before scanning.",
    )
    parser.add_argument(
        "--ignore-signal-gate",
        action="store_true",
        help="Do not pre-filter programs where researcher signal is below target_signal.",
    )
    parser.add_argument(
        "--program-handles",
        type=str,
        default="",
        help="Comma-separated list of HackerOne program handles to scan.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--dry-run", action="store_true", default=True, help="Stage/verify only (default).")
    mode_group.add_argument("--submit-vdp", action="store_true", help="Submit verified KYC-free VDP findings live.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def format_hunt_summary(result: Dict[str, Any], *, show_purged_cache: bool = False) -> str:
    lines: List[str] = []
    if show_purged_cache:
        lines.append(f"Purged Empty CT Cache Entries:    {result['purged_empty_cache_count']}")
    lines.extend(
        [
            f"Total HackerOne Programs Checked: {result['total_programs_fetched']}",
            f"Open VDP Candidates:              {result['open_vdp_candidates']}",
            f"Skipped by Signal Gate:           {result['programs_skipped_signal_gate']}",
            f"VDP Programs Scanned:             {result['programs_with_uncovered_wildcards_scanned']}",
            f"Subdomains Screened:              {result['subdomains_screened']}",
            f"Findings Verified:                {result['findings_count']}",
        ]
    )
    for finding in result["findings"]:
        lines.append(
            f"  - [{finding['program_handle']}] {finding['host']} -> "
            f"{finding['finding_type']} ({finding['evidence_snippet']})"
        )
    for submission in result["submissions"]:
        gate_info = ""
        if isinstance(submission.get("quality_gate"), dict):
            qg = submission["quality_gate"]
            gate_info = (
                f" [Gate: {qg['verdict']} | Critic {qg['critic_passes']}/{qg['critic_total']} "
                f"| Reverify {qg['reverification_passes']}/{qg['reverification_runs']}]"
            )
        lines.append(
            f"  - Dispatch [{submission['program']} / {submission['host']}]: "
            f"{submission['status']}{gate_info} {submission.get('report_url') or ''}"
        )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_vdp_hunt(
        max_programs=args.max_programs,
        program_offset=args.program_offset,
        max_wildcards_per_program=args.max_wildcards_per_program,
        max_subdomains=args.max_subdomains,
        workers=args.workers,
        include_covered=args.include_covered,
        submit_vdp=args.submit_vdp,
        use_crtsh=args.use_crtsh,
        use_subfinder=args.use_subfinder,
        check_graphql_kyc=not args.skip_graphql_kyc,
        reverify_runs=args.reverify_runs,
        critic_runs=args.critic_runs,
        use_ollama_critic=args.use_ollama_critic,
        critic_model=args.critic_model,
        reject_passive_saas_cname=not args.allow_passive_cname,
        purge_empty_cache=args.purge_empty_cache,
        ignore_signal_gate=args.ignore_signal_gate,
        program_handles=args.program_handles or None,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_hunt_summary(result, show_purged_cache=args.purge_empty_cache))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
