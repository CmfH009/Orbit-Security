#!/usr/bin/env python3
"""Daily paid bug bounty discovery & automation-suitability ranker.

Reuses `HackerOneReadClient` from `A:\\system\\scripts\\h1_read.py` to fetch open,
bounty-paying HackerOne programs, inspect their structured scopes, score them for
automated/white-box Antigravity auditing, and write JSON artifacts under
`A:\\projects\\orbit-security\\daily_briefings\\`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SYSTEM_SCRIPTS = Path(r"A:\system\scripts")
if not _SYSTEM_SCRIPTS.is_dir():
    _SYSTEM_SCRIPTS = Path(r"C:\AgyHut\system\scripts")
if str(_SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_SCRIPTS))

from h1_read import HackerOneReadClient, load_credentials  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = _REPO_ROOT / "daily_briefings"


def score_program_candidate(prog: Dict[str, Any], scopes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Score an open paid HackerOne program for automated / white-box audit suitability."""
    attrs = prog.get("attributes") or {}
    if not attrs.get("offers_bounties") or attrs.get("submission_state") != "open":
        return None

    handle = str(attrs.get("handle") or "").strip()
    if not handle:
        return None

    paid_scopes = [
        s.get("attributes") or {}
        for s in (scopes or [])
        if (s.get("attributes") or {}).get("eligible_for_bounty")
        and (s.get("attributes") or {}).get("eligible_for_submission", True) is not False
    ]

    score = 0
    scope_types: List[str] = []
    sample_assets: List[str] = []
    has_source = False
    has_exec = False
    has_web_api = False
    only_hardware = bool(paid_scopes)

    for sa in paid_scopes:
        atype = str(sa.get("asset_type") or "").upper()
        ident = str(sa.get("asset_identifier") or "").strip()
        if atype and atype not in scope_types:
            scope_types.append(atype)
        if ident and len(sample_assets) < 4 and ident not in sample_assets:
            sample_assets.append(ident)
        if atype != "HARDWARE":
            only_hardware = False
        if atype in {"SOURCE_CODE", "OPEN_SOURCE"} or "github.com/" in ident.lower():
            has_source = True
        elif atype in {
            "EXECUTABLE",
            "DOWNLOADABLE_EXECUTABLES",
            "OTHER",
            "APPLE_STORE_APP_ID",
            "GOOGLE_PLAY_APP_ID",
        }:
            has_exec = True
        elif atype in {"API", "URL", "WILDCARD"}:
            has_web_api = True

    if has_source:
        score += 35
    if has_exec:
        score += 25
    if has_web_api:
        score += 20
    if only_hardware:
        score -= 20

    fast_payments = bool(attrs.get("fast_payments"))
    gold_safe_harbor = bool(attrs.get("gold_standard_safe_harbor"))
    started_at = str(attrs.get("started_accepting_at") or "")[:10]

    if fast_payments:
        score += 15
    if gold_safe_harbor:
        score += 10
    if started_at.startswith(("2025-", "2026-")):
        score += 10

    if has_source:
        kickoff = f"Clone/audit in-scope source repo(s) for `{handle}` with `h1-read program {handle} --scopes --paid-only`."
    elif has_exec:
        kickoff = f"Inspect client/executable binary & IPC/auth boundaries for `{handle}` via REA + `h1-read`."
    elif has_web_api:
        kickoff = f"Run passive scope/endpoint recon & auth-boundary review on `{handle}`."
    else:
        kickoff = f"Review policy & paid scope via `h1-read program {handle} --scopes --paid-only --policy`."

    return {
        "handle": handle,
        "name": str(attrs.get("name") or handle),
        "url": f"https://hackerone.com/{handle}",
        "score": score,
        "fast_payments": fast_payments,
        "gold_safe_harbor": gold_safe_harbor,
        "started_accepting_at": started_at,
        "paid_scope_count": len(paid_scopes),
        "paid_scope_types": scope_types,
        "sample_assets": sample_assets,
        "kickoff_hint": kickoff,
    }


def discover_candidates(
    client: HackerOneReadClient,
    *,
    pages: int = 3,
    inspect_limit: int = 15,
    top: int = 8,
) -> Dict[str, Any]:
    """Fetch open paid programs, inspect top scopes, and return ranked candidates."""
    raw_programs = client.list_programs(start_page=1, pages=pages)
    open_paid = [
        p
        for p in raw_programs
        if (p.get("attributes") or {}).get("offers_bounties")
        and (p.get("attributes") or {}).get("submission_state") == "open"
    ]
    open_paid.sort(
        key=lambda p: (
            bool((p.get("attributes") or {}).get("fast_payments")),
            bool((p.get("attributes") or {}).get("gold_standard_safe_harbor")),
            str((p.get("attributes") or {}).get("started_accepting_at") or ""),
        ),
        reverse=True,
    )

    candidates: List[Dict[str, Any]] = []
    for prog in open_paid[:inspect_limit]:
        handle = str((prog.get("attributes") or {}).get("handle") or "").strip()
        if not handle:
            continue
        try:
            full_prog = client.get_program(handle)
            scopes = (
                full_prog.get("relationships", {})
                .get("structured_scopes", {})
                .get("data", [])
            )
            merged = dict(prog)
            if full_prog.get("attributes"):
                merged["attributes"] = full_prog["attributes"]
        except Exception:
            scopes = []
            merged = prog
        scored = score_program_candidate(merged, scopes)
        if scored is not None:
            candidates.append(scored)

    candidates.sort(
        key=lambda c: (c["score"], c["fast_payments"], c["started_accepting_at"]),
        reverse=True,
    )
    return {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "date": datetime.date.today().isoformat(),
        "total_fetched": len(raw_programs),
        "open_paid_count": len(open_paid),
        "inspected_count": min(len(open_paid), inspect_limit),
        "candidates": candidates[:top],
    }


def write_candidates(payload: Dict[str, Any], output_dir: Path) -> Path:
    """Atomically write dated and latest paid bounty candidate JSON files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    date_key = str(payload.get("date") or datetime.date.today().isoformat())
    dated_path = output_dir / f"paid_bounty_candidates_{date_key}.json"
    latest_path = output_dir / "paid_bounty_candidates_latest.json"
    serialized = json.dumps(payload, indent=2)
    for target in (dated_path, latest_path):
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(serialized, encoding="utf-8")
        tmp.replace(target)
    return dated_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover and rank automation-ready paid HackerOne bounty programs."
    )
    parser.add_argument("--pages", type=int, default=3, help="HackerOne program pages to fetch (default: 3)")
    parser.add_argument("--inspect-limit", type=int, default=15, help="Top open-paid programs to inspect scopes for")
    parser.add_argument("--top", type=int, default=8, help="Max ranked candidates to persist")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true", help="Print candidates without writing files")
    args = parser.parse_args(argv)

    user, token = load_credentials()
    client = HackerOneReadClient(user, token)
    payload = discover_candidates(
        client,
        pages=args.pages,
        inspect_limit=args.inspect_limit,
        top=args.top,
    )

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    out_path = write_candidates(payload, args.output_dir)
    print(f"[+] Wrote {len(payload['candidates'])} paid bounty candidates to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
