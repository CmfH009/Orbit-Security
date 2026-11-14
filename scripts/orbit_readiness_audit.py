#!/usr/bin/env python3
"""Read-only revenue, operational hygiene, and Track A/B readiness audit for Orbit Security."""

from __future__ import annotations

import argparse
import ast
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.bounty_radar import (  # noqa: E402
    ADVISORY_ONLY_FLAW_TYPES,
    SUBMITTABLE_BOUNTY_FLAW_TYPES,
    is_bounty_submittable,
)
from orbit_security.private_alerting import COMMERCIAL_OUTREACH_FROZEN  # noqa: E402

SYNTHETIC_TEST_DOMAINS = frozenset({"t.com", "example.com", "test.com", "testcorp.com"})
SYNTHETIC_CLIENT_IDS = frozenset({"c1", "test-client", "dummy"})

TRACK_B_REQUIRED_SCRIPTS = (
    "scripts/run_stripe_checkout.py",
    "scripts/run_stripe_webhook.py",
    "scripts/export_agency_bundle.py",
    "scripts/generate_client_portals.py",
    "scripts/sync_landing_to_docs.py",
    "scripts/verify_landing_pages.py",
)

TRACK_B_REQUIRED_MODULES = (
    "src/orbit_security/stripe_checkout.py",
    "src/orbit_security/stripe_webhook.py",
    "src/orbit_security/agency_retainer.py",
    "src/orbit_security/client_bundle_exporter.py",
    "src/orbit_security/dns_fixpack_optimizer.py",
)

TRACK_B_REQUIRED_WEB_PAGES = (
    "index.html",
    "signup.html",
    "audit.html",
    "fleet.html",
    "portals/index.html",
)


def _load_json_safe(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _slugify_agency_id(name: str) -> str:
    slug = (name or "unknown-agency").lower().strip()
    for ch in (" ", ".", "/", "_"):
        slug = slug.replace(ch, "-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def _check_landing_docs_parity(repo_root: Path) -> Dict[str, Any]:
    sync_script = Path(__file__).resolve().parent / "sync_landing_to_docs.py"
    if not sync_script.is_file():
        return {
            "available": False,
            "in_sync": False,
            "shared_count": 0,
            "identical_count": 0,
            "mismatched_count": 0,
            "landing_only_count": 0,
            "docs_only_count": 0,
            "mismatched_paths": [],
        }
    spec = importlib.util.spec_from_file_location("sync_landing_to_docs", sync_script)
    if spec is None or spec.loader is None:
        return {
            "available": False,
            "in_sync": False,
            "shared_count": 0,
            "identical_count": 0,
            "mismatched_count": 0,
            "landing_only_count": 0,
            "docs_only_count": 0,
            "mismatched_paths": [],
        }
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    report = mod.compare(repo_root / "landing", repo_root / "docs")
    mismatched_entries = report.get("mismatched", [])
    mismatched = len(mismatched_entries)
    return {
        "available": True,
        "in_sync": mismatched == 0,
        "shared_count": len(report.get("shared", [])),
        "identical_count": len(report.get("identical", [])),
        "mismatched_count": mismatched,
        "landing_only_count": len(report.get("landing_only", [])),
        "docs_only_count": len(report.get("docs_only", [])),
        "mismatched_paths": [m.get("path", "") for m in mismatched_entries],
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
    active_count = sum(1 for p in programs if isinstance(p, dict) and p.get("state", "active") != "paused")
    return {
        "total_entries": len(ids),
        "unique_programs": len(unique_ids),
        "duplicate_count": len(ids) - len(unique_ids),
        "cash_tier_count": cash_count,
        "active_count": active_count,
    }


def _classify_disclosure_stem(stem: str) -> Tuple[str, Optional[str]]:
    """Classify a disclosure filename stem using boundary-aware flaw matching."""
    padded = f"_{stem.lower()}_"
    for adv in sorted(ADVISORY_ONLY_FLAW_TYPES, key=len, reverse=True):
        if f"_{adv}_" in padded:
            return "advisory", adv
    for flaw in sorted(SUBMITTABLE_BOUNTY_FLAW_TYPES, key=len, reverse=True):
        if f"_{flaw}_" in padded:
            ok_sub, _ = is_bounty_submittable(flaw)
            if ok_sub:
                return "submittable", flaw
    return "unclassified", None


def _verify_zip_bundle(zip_path: Path) -> bool:
    """Verify ZIP readability, CRC32 integrity, manifest presence, and SHA-256 digests."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            if zf.testzip() is not None:
                return False
            names = set(zf.namelist())
            if not names or "manifest_sha256.json" not in names:
                return False
            manifest = json.loads(zf.read("manifest_sha256.json").decode("utf-8"))
            if not isinstance(manifest, dict):
                return False
            hashes = manifest.get("file_hashes_sha256")
            if isinstance(hashes, dict):
                for member, expected in hashes.items():
                    if member not in names:
                        return False
                    actual = hashlib.sha256(zf.read(member)).hexdigest()
                    if actual != str(expected).lower().strip():
                        return False
            return True
    except Exception:
        return False


def _canonical_zip_stem(filename: str) -> str:
    if filename.endswith("_bundle.zip"):
        return filename[: -len("_bundle.zip")]
    return filename[:-4]


def _check_disclosures(data_dir: Path) -> Dict[str, Any]:
    disc_dir = data_dir / "disclosures"
    submittable_md: List[str] = []
    advisory_lingering_md: List[str] = []
    unclassified_md: List[str] = []
    flaw_breakdown: Dict[str, int] = {}

    md_by_stem: Dict[str, str] = {}
    zip_by_stem: Dict[str, List[Path]] = {}
    zip_files: List[Path] = []

    if disc_dir.is_dir():
        for entry in sorted(disc_dir.iterdir()):
            if entry.is_dir():
                continue
            name = entry.name
            if name.endswith(".zip"):
                zip_files.append(entry)
                zip_by_stem.setdefault(_canonical_zip_stem(name), []).append(entry)
                continue
            if not name.endswith(".md"):
                continue

            stem = name[:-3]
            md_by_stem[stem] = name
            category, flaw = _classify_disclosure_stem(stem)
            if category == "advisory":
                advisory_lingering_md.append(name)
            elif category == "submittable" and flaw:
                submittable_md.append(name)
                flaw_breakdown[flaw] = flaw_breakdown.get(flaw, 0) + 1
            else:
                unclassified_md.append(name)

    corrupt_zips: List[str] = []
    valid_zip_names: set[str] = set()
    for zp in zip_files:
        if _verify_zip_bundle(zp):
            valid_zip_names.add(zp.name)
        else:
            corrupt_zips.append(zp.name)

    missing_bundle_zips = sorted(fn for stem, fn in md_by_stem.items() if stem not in zip_by_stem)
    orphan_bundle_zips = sorted(
        zp.name
        for stem, paths in zip_by_stem.items()
        for zp in paths
        if stem not in md_by_stem
    )
    duplicate_bundle_zips = sorted(
        zp.name
        for paths in zip_by_stem.values()
        if len(paths) > 1
        for zp in paths[1:]
    )
    paired_bundle_count = sum(
        1
        for stem in md_by_stem
        if stem in zip_by_stem and any(zp.name in valid_zip_names for zp in zip_by_stem[stem])
    )
    bundle_pairing_ok = (
        len(missing_bundle_zips) == 0
        and len(orphan_bundle_zips) == 0
        and len(corrupt_zips) == 0
        and len(duplicate_bundle_zips) == 0
    )

    state = _load_json_safe(data_dir / "bounty_radar_state.json", {})
    receipts = _load_json_safe(disc_dir / "live_verification_receipts.json", {})
    archive_dir = data_dir / "archive" / "legacy_passive_disclosures"
    archived_count = len(list(archive_dir.iterdir())) if archive_dir.is_dir() else 0

    return {
        "active_submittable_reports": len(submittable_md),
        "advisory_lingering_reports": len(advisory_lingering_md),
        "unclassified_disclosures": unclassified_md,
        "flaw_type_breakdown": flaw_breakdown,
        "cryptographic_zip_bundles": len(zip_files),
        "paired_bundle_count": paired_bundle_count,
        "missing_bundle_zips": missing_bundle_zips,
        "orphan_bundle_zips": orphan_bundle_zips,
        "corrupt_bundle_zips": corrupt_zips,
        "duplicate_bundle_zips": duplicate_bundle_zips,
        "bundle_pairing_ok": bundle_pairing_ok,
        "live_verification_receipts_total": int(receipts.get("total_high_signal", 0) or 0)
        if isinstance(receipts, dict)
        else 0,
        "live_verification_receipts_confirmed": int(receipts.get("confirmed_live_count", 0) or 0)
        if isinstance(receipts, dict)
        else 0,
        "archived_legacy_artifacts": archived_count,
        "radar_state_total_sweeps": int(state.get("total_sweeps", 0) or 0),
        "radar_state_submittable_count": int(state.get("total_submittable_findings", 0) or 0),
        "radar_state_advisory_count": int(state.get("total_advisory_observations", 0) or 0),
        "radar_state_legacy_counter": int(state.get("total_vulnerabilities_found", 0) or 0),
    }


def _check_python_files(repo_root: Path, rel_paths: Tuple[str, ...]) -> Tuple[List[str], List[str]]:
    missing: List[str] = []
    syntax_errors: List[str] = []
    for rel in rel_paths:
        path = repo_root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except Exception as exc:
            syntax_errors.append(f"{rel}: {exc}")
    return missing, syntax_errors


def _check_track_b_funnel(repo_root: Path, data_dir: Path) -> Dict[str, Any]:
    missing_scripts, script_syntax_errors = _check_python_files(repo_root, TRACK_B_REQUIRED_SCRIPTS)
    missing_modules, module_syntax_errors = _check_python_files(repo_root, TRACK_B_REQUIRED_MODULES)
    syntax_errors = script_syntax_errors + module_syntax_errors

    missing_web_pages: List[str] = []
    for tree in ("landing", "docs"):
        for rel in TRACK_B_REQUIRED_WEB_PAGES:
            if not (repo_root / tree / rel).is_file():
                missing_web_pages.append(f"{tree}/{rel}")

    checkout_hook_ok = True
    for tree in ("landing", "docs"):
        signup_path = repo_root / tree / "signup.html"
        if signup_path.is_file():
            try:
                content = signup_path.read_text(encoding="utf-8", errors="replace")
                if "/create-checkout-session" not in content:
                    checkout_hook_ok = False
            except Exception:
                checkout_hook_ok = False
        else:
            checkout_hook_ok = False

    retainers = _load_json_safe(data_dir / "agency_retainers.json", {})
    agencies = retainers.get("agencies", []) if isinstance(retainers, dict) else []
    missing_agency_portals: List[str] = []
    agency_count = 0
    for agency in agencies:
        if not isinstance(agency, dict):
            continue
        aid = str(agency.get("agency_id") or "").strip()
        if not aid:
            continue
        agency_count += 1
        slug = _slugify_agency_id(aid)
        for tree in ("landing", "docs"):
            portal_slug = repo_root / tree / "portals" / f"{slug}.html"
            portal_raw = repo_root / tree / "portals" / f"{aid}.html"
            if not (portal_slug.is_file() or portal_raw.is_file()):
                missing_agency_portals.append(f"{tree}/portals/{slug}.html")

    ready = (
        not missing_scripts
        and not missing_modules
        and not syntax_errors
        and not missing_web_pages
        and checkout_hook_ok
        and not missing_agency_portals
    )

    return {
        "required_scripts_total": len(TRACK_B_REQUIRED_SCRIPTS),
        "required_scripts_present": len(TRACK_B_REQUIRED_SCRIPTS) - len(missing_scripts),
        "missing_scripts": missing_scripts,
        "required_modules_total": len(TRACK_B_REQUIRED_MODULES),
        "required_modules_present": len(TRACK_B_REQUIRED_MODULES) - len(missing_modules),
        "missing_modules": missing_modules,
        "syntax_errors": syntax_errors,
        "missing_web_pages": missing_web_pages,
        "checkout_form_hook_present": checkout_hook_ok,
        "agency_retainer_count": agency_count,
        "missing_agency_portals": missing_agency_portals,
        "ready": ready,
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
    track_b_funnel = _check_track_b_funnel(repo_root, data_dir)

    blockers: List[str] = []
    if not COMMERCIAL_OUTREACH_FROZEN:
        blockers.append("COMMERCIAL_OUTREACH_UNFROZEN")
    if not parity["in_sync"]:
        blockers.append("LANDING_DOCS_DRIFT")
    if not clients["hygiene_clean"]:
        blockers.append("CLIENT_REGISTRY_SYNTHETIC_LEAKS")
    if catalog["duplicate_count"] > 0 or catalog["unique_programs"] < 45:
        blockers.append("BOUNTY_CATALOG_INTEGRITY")
    if disclosures["advisory_lingering_reports"] > 0:
        blockers.append("UNARCHIVED_ADVISORY_DISCLOSURES")
    if not disclosures["bundle_pairing_ok"]:
        blockers.append("DISCLOSURE_BUNDLE_PARITY_MISMATCH")
    if disclosures["unclassified_disclosures"]:
        blockers.append("UNCLASSIFIED_DISCLOSURES")
    if not track_b_funnel["ready"]:
        blockers.append("TRACK_B_FUNNEL_INCOMPLETE")
    if not stripe["live_checkout_ready"]:
        blockers.append("STRIPE_KEYS_UNCONFIGURED")
    if kyc_status != "VERIFIED":
        blockers.append(f"KYC_PAYOUT_{kyc_status}")

    technical_floor_clean = (
        bool(COMMERCIAL_OUTREACH_FROZEN)
        and parity["in_sync"]
        and clients["hygiene_clean"]
        and catalog["duplicate_count"] == 0
        and catalog["unique_programs"] >= 45
        and disclosures["advisory_lingering_reports"] == 0
        and disclosures["bundle_pairing_ok"]
        and not disclosures["unclassified_disclosures"]
        and track_b_funnel["ready"]
    )

    track_a_disclosures_ready = (
        catalog["duplicate_count"] == 0
        and catalog["unique_programs"] >= 45
        and disclosures["advisory_lingering_reports"] == 0
        and disclosures["bundle_pairing_ok"]
        and not disclosures["unclassified_disclosures"]
        and disclosures["active_submittable_reports"] > 0
    )
    track_b_offline_ready = parity["in_sync"] and clients["hygiene_clean"] and track_b_funnel["ready"]
    track_b_live_checkout_ready = track_b_offline_ready and stripe["live_checkout_ready"] and kyc_status == "VERIFIED"

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
        "track_b_funnel": track_b_funnel,
        "track_a_disclosures_ready": track_a_disclosures_ready,
        "track_b_offline_ready": track_b_offline_ready,
        "track_b_live_checkout_ready": track_b_live_checkout_ready,
        "blockers": blockers,
        "technical_floor_clean": technical_floor_clean,
    }


def _render_human_report(report: Dict[str, Any]) -> str:
    parity = report["landing_docs_parity"]
    stripe = report["stripe_config"]
    clients = report["clients_hygiene"]
    catalog = report["bounty_catalog"]
    disc = report["disclosures_and_radar"]
    tb = report["track_b_funnel"]
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
        f"Track B Funnel Readiness    : ready={tb['ready']} (scripts={tb['required_scripts_present']}/{tb['required_scripts_total']}, modules={tb['required_modules_present']}/{tb['required_modules_total']}, portals_missing={len(tb['missing_agency_portals'])})",
        f"Stripe Live Checkout Ready  : {stripe['live_checkout_ready']} (api_key={stripe['api_key_configured']}, webhook_secret={stripe['webhook_secret_configured']})",
        f"Paid Subscribers            : {report['subscribers']['count']}",
        f"Clients Registry Hygiene    : clean={clients['hygiene_clean']} (count={clients['client_count']}, leaks={clients['synthetic_leaks']})",
        f"Bounty Catalog              : {catalog['unique_programs']} unique ({catalog['duplicate_count']} dups, {catalog['cash_tier_count']} cash tier)",
        f"Staged Submittable Reports  : {disc['active_submittable_reports']} (.md), {disc['cryptographic_zip_bundles']} (.zip bundles)",
        f"Bundle Pairing Parity       : ok={disc['bundle_pairing_ok']} (paired={disc['paired_bundle_count']}, missing={len(disc['missing_bundle_zips'])}, orphan={len(disc['orphan_bundle_zips'])}, corrupt={len(disc['corrupt_bundle_zips'])})",
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
