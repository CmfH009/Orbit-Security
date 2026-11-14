#!/usr/bin/env python3
"""Read-only revenue, operational hygiene, and bounty readiness audit for Orbit Security."""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.bounty_radar import ADVISORY_ONLY_FLAW_TYPES, is_bounty_submittable  # noqa: E402
from orbit_security.private_alerting import COMMERCIAL_OUTREACH_FROZEN  # noqa: E402

SYNTHETIC_TEST_DOMAINS = frozenset({"t.com", "example.com", "test.com", "testcorp.com"})
SYNTHETIC_CLIENT_IDS = frozenset({"c1", "test-client", "dummy"})


def _load_json_safe(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _check_landing_docs_parity(repo_root: Path) -> Dict[str, Any]:
    sync_script = Path(__file__).resolve().parent / "sync_landing_to_docs.py"
    if not sync_script.is_file():
        return {"available": False, "in_sync": False, "shared_count": 0, "mismatched_count": 0}
    spec = importlib.util.spec_from_file_location("sync_landing_to_docs", sync_script)
    if spec is None or spec.loader is None:
        return {"available": False, "in_sync": False, "shared_count": 0, "mismatched_count": 0}
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    report = mod.compare(repo_root / "landing", repo_root / "docs")
    mismatched = len(report.get("mismatched", []))
    return {
        "available": True,
        "in_sync": mismatched == 0,
        "shared_count": len(report.get("shared", [])),
        "identical_count": len(report.get("identical", [])),
        "mismatched_count": mismatched,
    }


def _check_stripe_env() -> Dict[str, Any]:
    api_key_set = bool(os.getenv("STRIPE_SECRET_KEY") or os.getenv("STRIPE_API_KEY"))
    webhook_secret_set = bool(os.getenv("STRIPE_WEBHOOK_SECRET"))
    prices = {
        "STRIPE_PRICE_STARTER": bool(os.getenv("STRIPE_PRICE_STARTER")),
        "STRIPE_PRICE_SCALE": bool(os.getenv("STRIPE_PRICE_SCALE")),
        "STRIPE_PRICE_ENTERPRISE": bool(os.getenv("STRIPE_PRICE_ENTERPRISE")),
    }
    return {
        "api_key_configured": api_key_set,
        "webhook_secret_configured": webhook_secret_set,
        "price_overrides_configured": prices,
        "live_checkout_ready": api_key_set and webhook_secret_set,
    }


def _check_subscribers(data_dir: Path) -> Dict[str, Any]:
    raw = _load_json_safe(data_dir / "subscribers.json", {})
    subs = raw.get("subscribers", raw) if isinstance(raw, dict) else raw
    count = len(subs) if isinstance(subs, (list, dict)) else 0
    return {"exists": (data_dir / "subscribers.json").is_file(), "count": count}


def _check_clients(data_dir: Path) -> Dict[str, Any]:
    raw = _load_json_safe(data_dir / "clients.json", {})
    clients: List[Dict[str, Any]]
    if isinstance(raw, dict) and isinstance(raw.get("clients"), list):
        clients = raw["clients"]
    elif isinstance(raw, list):
        clients = raw
    elif isinstance(raw, dict):
        clients = list(raw.values())
    else:
        clients = []

    leaks: List[str] = []
    for entry in clients:
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("client_id", "")).strip()
        dom = str(entry.get("apex_domain") or entry.get("domain") or "").strip().lower()
        if cid in SYNTHETIC_CLIENT_IDS or dom in SYNTHETIC_TEST_DOMAINS:
            leaks.append(f"{cid}:{dom}")

    return {
        "client_count": len(clients),
        "synthetic_leaks": leaks,
        "hygiene_clean": len(leaks) == 0,
    }


def _check_bounty_catalog(data_dir: Path) -> Dict[str, Any]:
    raw = _load_json_safe(data_dir / "bounty_programs.json", {})
    programs = raw.get("programs", []) if isinstance(raw, dict) else []
    ids = [str(p.get("program_id", "")) for p in programs if isinstance(p, dict)]
    unique_ids = set(ids)
    cash_count = sum(1 for p in programs if isinstance(p, dict) and p.get("bounty_tier") == "cash")
    return {
        "total_entries": len(ids),
        "unique_programs": len(unique_ids),
        "duplicate_count": len(ids) - len(unique_ids),
        "cash_tier_count": cash_count,
    }


def _check_disclosures(data_dir: Path) -> Dict[str, Any]:
    disc_dir = data_dir / "disclosures"
    submittable_md: List[str] = []
    advisory_lingering_md: List[str] = []
    zip_bundles = 0

    if disc_dir.is_dir():
        for entry in sorted(disc_dir.iterdir()):
            if entry.is_dir():
                continue
            name = entry.name
            if name.endswith(".zip"):
                zip_bundles += 1
                continue
            if not name.endswith(".md"):
                continue
            stem = name[:-3].lower()
            is_adv = any(adv in stem for adv in ADVISORY_ONLY_FLAW_TYPES)
            if is_adv:
                advisory_lingering_md.append(name)
            else:
                ok_sub, _ = is_bounty_submittable(stem)
                # Filename contains program_flaw_domain; treat non-advisory .md with zip/matched flaw as staged
                if ok_sub or not is_adv:
                    submittable_md.append(name)

    state = _load_json_safe(data_dir / "bounty_radar_state.json", {})
    archive_dir = data_dir / "archive" / "legacy_passive_disclosures"
    archived_count = len(list(archive_dir.iterdir())) if archive_dir.is_dir() else 0

    return {
        "active_submittable_reports": len(submittable_md),
        "advisory_lingering_reports": len(advisory_lingering_md),
        "cryptographic_zip_bundles": zip_bundles,
        "archived_legacy_artifacts": archived_count,
        "radar_state_total_sweeps": int(state.get("total_sweeps", 0) or 0),
        "radar_state_submittable_count": int(state.get("total_submittable_findings", 0) or 0),
        "radar_state_advisory_count": int(state.get("total_advisory_observations", 0) or 0),
        "radar_state_legacy_counter": int(state.get("total_vulnerabilities_found", 0) or 0),
    }


def run_readiness_audit(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Run all read-only Orbit Security readiness checks and return structured metrics."""
    data_dir = repo_root / "data"
    kyc_status = os.getenv("ORBIT_KYC_STATUS", "PENDING_PHYSICAL_ID").strip() or "PENDING_PHYSICAL_ID"

    parity = _check_landing_docs_parity(repo_root)
    stripe = _check_stripe_env()
    subscribers = _check_subscribers(data_dir)
    clients = _check_clients(data_dir)
    catalog = _check_bounty_catalog(data_dir)
    disclosures = _check_disclosures(data_dir)

    blockers: List[str] = []
    if not parity["in_sync"]:
        blockers.append("LANDING_DOCS_DRIFT")
    if not clients["hygiene_clean"]:
        blockers.append("CLIENT_REGISTRY_SYNTHETIC_LEAKS")
    if catalog["duplicate_count"] > 0 or catalog["unique_programs"] < 45:
        blockers.append("BOUNTY_CATALOG_INTEGRITY")
    if disclosures["advisory_lingering_reports"] > 0:
        blockers.append("UNARCHIVED_ADVISORY_DISCLOSURES")
    if not stripe["live_checkout_ready"]:
        blockers.append("STRIPE_KEYS_UNCONFIGURED")
    if kyc_status != "VERIFIED":
        blockers.append(f"KYC_PAYOUT_{kyc_status}")

    return {
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "revenue_focus": "Option C (Dual-Track Minimal: Verified Bounties + Inbound Fixpack/Audit)",
        "commercial_outreach_frozen": bool(COMMERCIAL_OUTREACH_FROZEN),
        "kyc_payout_status": kyc_status,
        "landing_docs_parity": parity,
        "stripe_config": stripe,
        "subscribers": subscribers,
        "clients_hygiene": clients,
        "bounty_catalog": catalog,
        "disclosures_and_radar": disclosures,
        "blockers": blockers,
        "technical_floor_clean": (
            parity["in_sync"]
            and clients["hygiene_clean"]
            and catalog["duplicate_count"] == 0
            and catalog["unique_programs"] >= 45
            and disclosures["advisory_lingering_reports"] == 0
        ),
    }


def _render_human_report(report: Dict[str, Any]) -> str:
    parity = report["landing_docs_parity"]
    stripe = report["stripe_config"]
    clients = report["clients_hygiene"]
    catalog = report["bounty_catalog"]
    disc = report["disclosures_and_radar"]
    lines = [
        "========================================================================",
        "Orbit Security v1.2.0 - Readiness & Revenue Groundwork Audit",
        "========================================================================",
        f"Revenue Focus               : {report['revenue_focus']}",
        f"Technical Floor Clean       : {report['technical_floor_clean']}",
        f"Cold Email Outreach Frozen  : {report['commercial_outreach_frozen']}",
        f"KYC / Payout Verification   : {report['kyc_payout_status']}",
        "------------------------------------------------------------------------",
        f"Landing <-> Docs Parity     : in_sync={parity['in_sync']} ({parity.get('identical_count', 0)}/{parity.get('shared_count', 0)} shared)",
        f"Stripe Live Checkout Ready  : {stripe['live_checkout_ready']} (api_key={stripe['api_key_configured']}, webhook_secret={stripe['webhook_secret_configured']})",
        f"Paid Subscribers            : {report['subscribers']['count']}",
        f"Clients Registry Hygiene    : clean={clients['hygiene_clean']} (count={clients['client_count']}, leaks={clients['synthetic_leaks']})",
        f"Bounty Catalog              : {catalog['unique_programs']} unique ({catalog['duplicate_count']} dups, {catalog['cash_tier_count']} cash tier)",
        f"Staged Submittable Reports  : {disc['active_submittable_reports']} (.md), {disc['cryptographic_zip_bundles']} (.zip bundles)",
        f"Archived Passive Artifacts  : {disc['archived_legacy_artifacts']} items",
        f"Lingering Advisory Reports  : {disc['advisory_lingering_reports']}",
        f"Radar State Counters        : sweeps={disc['radar_state_total_sweeps']}, submittable={disc['radar_state_submittable_count']}, advisory={disc['radar_state_advisory_count']}, legacy_total={disc['radar_state_legacy_counter']}",
        "------------------------------------------------------------------------",
        f"Active Blockers             : {', '.join(report['blockers']) or 'NONE'}",
        "========================================================================",
    ]
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only readiness audit for Orbit Security.")
    parser.add_argument("--json", action="store_true", help="Output structured JSON report.")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Override repository root path.")
    args = parser.parse_args(argv)

    report = run_readiness_audit(repo_root=args.repo_root)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_render_human_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
