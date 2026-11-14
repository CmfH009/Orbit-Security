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
import re
import sys
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

EV_DIGEST_RE = re.compile(r"\bev_[0-9a-f]{12}\b")

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


def _load_dotenv_values(repo_root: Path) -> Dict[str, str]:
    """Parse key=value pairs from repo_root/.env without mutating os.environ."""
    env_file = repo_root / ".env"
    if not env_file.is_file():
        return {}
    parsed: Dict[str, str] = {}
    try:
        content = env_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            val = re.sub(r"\s+#.*$", "", val).strip()
        parsed[key] = val
    return parsed


def _resolve_env_or_dotenv(key: str, dotenv_values: Dict[str, str]) -> Optional[str]:
    """Resolve key from os.environ first, falling back to parsed .env values."""
    if key in os.environ:
        val = os.environ.get(key)
        return val if val else None
    val = dotenv_values.get(key)
    return val if val else None


def _check_stripe_env(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    dotenv_values = _load_dotenv_values(repo_root)
    api_key_set = bool(
        _resolve_env_or_dotenv("STRIPE_SECRET_KEY", dotenv_values)
        or _resolve_env_or_dotenv("STRIPE_API_KEY", dotenv_values)
    )
    webhook_secret_set = bool(_resolve_env_or_dotenv("STRIPE_WEBHOOK_SECRET", dotenv_values))
    prices = {
        "STRIPE_PRICE_STARTER": bool(_resolve_env_or_dotenv("STRIPE_PRICE_STARTER", dotenv_values)),
        "STRIPE_PRICE_SCALE": bool(_resolve_env_or_dotenv("STRIPE_PRICE_SCALE", dotenv_values)),
        "STRIPE_PRICE_ENTERPRISE": bool(_resolve_env_or_dotenv("STRIPE_PRICE_ENTERPRISE", dotenv_values)),
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
    out_of_scope_populated = sum(
        1
        for p in programs
        if isinstance(p, dict)
        and isinstance(p.get("out_of_scope"), list)
        and any(str(item).strip() for item in p.get("out_of_scope", []))
    )
    return {
        "total_entries": len(ids),
        "unique_programs": len(unique_ids),
        "duplicate_count": len(ids) - len(unique_ids),
        "cash_tier_count": cash_count,
        "active_count": active_count,
        "out_of_scope_populated": out_of_scope_populated,
        "out_of_scope_total": len(ids),
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


def _check_disclosure_ev_digest(
    disc_dir: Path,
    md_name: str,
    zip_path: Optional[Path],
) -> Tuple[bool, bool, Optional[bool]]:
    """Verify staged .md and associated metadata.json carry an ev_<12-char-hex> digest."""
    md_path = disc_dir / md_name
    try:
        md_text = md_path.read_text(encoding="utf-8", errors="replace")
        md_has_ev = bool(EV_DIGEST_RE.search(md_text))
    except Exception:
        md_has_ev = False

    stem = md_name[:-3]
    meta_path = disc_dir / f"{stem}_bundle" / "metadata.json"
    meta_text: Optional[str] = None
    if meta_path.is_file():
        try:
            meta_text = meta_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            meta_text = ""
    elif zip_path is not None and zip_path.is_file():
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                if "metadata.json" in zf.namelist():
                    meta_text = zf.read("metadata.json").decode("utf-8", errors="replace")
        except Exception:
            meta_text = ""

    if meta_text is None:
        return md_has_ev, md_has_ev, None

    meta_has_ev = bool(EV_DIGEST_RE.search(meta_text))
    return (md_has_ev and meta_has_ev), md_has_ev, meta_has_ev


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

    ev_covered_count = 0
    ev_md_covered_count = 0
    ev_meta_checked_count = 0
    ev_meta_covered_count = 0
    missing_ev_digests: List[str] = []
    for stem, md_name in sorted(md_by_stem.items()):
        first_zip = zip_by_stem[stem][0] if stem in zip_by_stem else None
        covered, md_has_ev, meta_has_ev = _check_disclosure_ev_digest(disc_dir, md_name, first_zip)
        if md_has_ev:
            ev_md_covered_count += 1
        if meta_has_ev is not None:
            ev_meta_checked_count += 1
            if meta_has_ev:
                ev_meta_covered_count += 1
        if covered:
            ev_covered_count += 1
        else:
            missing_ev_digests.append(md_name)

    ev_digest_coverage = {
        "total_staged": len(md_by_stem),
        "covered_count": ev_covered_count,
        "md_covered_count": ev_md_covered_count,
        "metadata_checked_count": ev_meta_checked_count,
        "metadata_covered_count": ev_meta_covered_count,
        "coverage_ok": len(missing_ev_digests) == 0,
        "missing_ev_digests": missing_ev_digests,
    }

    state = _load_json_safe(data_dir / "bounty_radar_state.json", {})
    receipts = _load_json_safe(disc_dir / "live_verification_receipts.json", {})
    archive_dir = data_dir / "archive" / "legacy_passive_disclosures"
    archived_count = len(list(archive_dir.iterdir())) if archive_dir.is_dir() else 0
    fp_dir = data_dir / "archive" / "false_positive_disclosures"
    fp_entries = list(fp_dir.iterdir()) if fp_dir.is_dir() else []
    fp_disclosures = sum(1 for x in fp_entries if x.is_file() and x.suffix.lower() == ".md")
    archived_total_count = archived_count + fp_disclosures

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
        "ev_digest_coverage": ev_digest_coverage,
        "live_verification_receipts_total": int(receipts.get("total_high_signal", 0) or 0)
        if isinstance(receipts, dict)
        else 0,
        "live_verification_receipts_confirmed": int(receipts.get("confirmed_live_count", 0) or 0)
        if isinstance(receipts, dict)
        else 0,
        "archived_legacy_artifacts": archived_count,
        "archived_false_positive_disclosures": fp_disclosures,
        "archived_false_positive_items": len(fp_entries),
        "archived_total_count": archived_total_count,
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


def _classify_stripe_key_prefix(raw_value: Optional[str]) -> str:
    """Return a non-secret prefix label for a Stripe key or webhook secret."""
    val = str(raw_value or "").strip()
    if not val:
        return "unset"
    for prefix in ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_", "whsec_"):
        if val.startswith(prefix):
            return f"{prefix}*"
    return "other_non_empty"


def _is_within(child: Path, parent: Path) -> bool:
    try:
        return child.resolve().is_relative_to(parent.resolve())
    except Exception:
        return False


class _HermeticJsonResponse:
    def __init__(self, payload: Dict[str, Any], status: int = 200):
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_HermeticJsonResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False


def verify_stripe_cutover(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Run a fast hermetic Track B Stripe checkout + webhook provisioning dry-run.

    Executes completely inside a TemporaryDirectory with a stubbed HTTP opener
    and isolated Blackboard/data stores so zero network calls or writes to live
    data/* or docs/portals/* occur, and never prints raw secret values.
    """
    t0 = time.perf_counter()

    dotenv_values = _load_dotenv_values(repo_root)
    orig_secret_key = _resolve_env_or_dotenv("STRIPE_SECRET_KEY", dotenv_values)
    orig_api_key = _resolve_env_or_dotenv("STRIPE_API_KEY", dotenv_values)
    orig_webhook_secret = _resolve_env_or_dotenv("STRIPE_WEBHOOK_SECRET", dotenv_values)
    env_key_prefixes = {
        "STRIPE_SECRET_KEY": _classify_stripe_key_prefix(orig_secret_key),
        "STRIPE_API_KEY": _classify_stripe_key_prefix(orig_api_key),
        "STRIPE_WEBHOOK_SECRET": _classify_stripe_key_prefix(orig_webhook_secret),
    }
    sk_prefixes = (env_key_prefixes["STRIPE_SECRET_KEY"], env_key_prefixes["STRIPE_API_KEY"])
    if any(p.startswith(("sk_live_", "rk_live_")) for p in sk_prefixes):
        stripe_key_mode = "live"
    elif any(p.startswith(("sk_test_", "rk_test_")) for p in sk_prefixes):
        stripe_key_mode = "test"
    elif all(p == "unset" for p in sk_prefixes):
        stripe_key_mode = "unset"
    else:
        stripe_key_mode = "other"

    import orbit_security.blackboard as bb_mod
    from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
    from orbit_security.deal_desk import RetainerDealDeskConcierge
    from orbit_security.fleet import FleetRegistry
    from orbit_security.stripe_checkout import create_checkout_session, get_price_id
    from orbit_security.stripe_webhook import (
        SlaCertificateGenerator,
        StripeWebhookHandler,
        SubscriberManager,
        generate_stripe_signature,
    )

    orig_global_bb = bb_mod._GLOBAL_BLACKBOARD
    orig_publish_event = bb_mod.publish_event
    orig_env = {
        key: os.environ.get(key)
        for key in ("STRIPE_SECRET_KEY", "STRIPE_API_KEY", "ORBIT_BLACKBOARD_DB", "ORBIT_NOVA_BRAIN_ENABLED")
    }

    temp_ctx = tempfile.TemporaryDirectory(prefix="orbit_cutover_dryrun_")
    try:
        tmp_root = Path(temp_ctx.name)
        bb_db_path = tmp_root / "blackboard.db"
        temp_bb = bb_mod.Blackboard(db_path=bb_db_path, nova_brain_url="")
        bb_mod._GLOBAL_BLACKBOARD = temp_bb

        def _isolated_publish_event(
            event_type: str,
            payload: dict,
            source: str = "orbit",
            topic: str = "telemetry",
        ) -> int:
            return temp_bb.publish(event_type, payload, source=source, topic=topic)

        bb_mod.publish_event = _isolated_publish_event
        os.environ["ORBIT_BLACKBOARD_DB"] = str(bb_db_path)
        os.environ["ORBIT_NOVA_BRAIN_ENABLED"] = "0"
        # Use a fixed local dummy token so no real key ever enters synthetic headers.
        os.environ["STRIPE_SECRET_KEY"] = "sk_test_orbit_cutover_dryrun_000000"
        os.environ.pop("STRIPE_API_KEY", None)

        captured_checkout_req: Dict[str, Any] = {}

        def _fake_http_open(req: Any, timeout: int = 20) -> _HermeticJsonResponse:
            headers = {str(k).lower(): str(v) for k, v in getattr(req, "headers", {}).items()}
            auth_val = headers.get("authorization", "")
            raw_data = getattr(req, "data", b"") or b""
            captured_checkout_req["url"] = str(getattr(req, "full_url", ""))
            captured_checkout_req["auth_bearer_prefix"] = auth_val[:14]
            captured_checkout_req["form"] = urllib.parse.parse_qs(raw_data.decode("utf-8"))
            captured_checkout_req["timeout"] = timeout
            return _HermeticJsonResponse(
                {
                    "id": "cs_test_cutover_dryrun_001",
                    "url": "https://checkout.stripe.com/c/pay/cs_test_cutover_dryrun_001",
                }
            )

        checkout_res = create_checkout_session(
            agency_id="cutover-dryrun-agency",
            agency_name="Cutover Dryrun Agency",
            tier=RetainerTier.SCALE,
            contact_email="cutover@dryrun.example",
            website="https://cutover-dryrun.example",
            domain="cutover-dryrun.example",
            client_reference_id="cutover_ref_001",
            http_open=_fake_http_open,
        )

        expected_price_id = get_price_id(RetainerTier.SCALE)
        form = captured_checkout_req.get("form", {})
        checkout_session_fields_verified = (
            checkout_res.get("id") == "cs_test_cutover_dryrun_001"
            and checkout_res.get("url") == "https://checkout.stripe.com/c/pay/cs_test_cutover_dryrun_001"
            and captured_checkout_req.get("url") == "https://api.stripe.com/v1/checkout/sessions"
            and captured_checkout_req.get("auth_bearer_prefix") == "Bearer sk_test"
            and form.get("mode") == ["subscription"]
            and form.get("line_items[0][price]") == [expected_price_id]
            and form.get("customer_email") == ["cutover@dryrun.example"]
            and form.get("client_reference_id") == ["cutover_ref_001"]
            and form.get("metadata[agency_id]") == ["cutover-dryrun-agency"]
            and form.get("metadata[tier]") == [RetainerTier.SCALE.value]
            and form.get("metadata[domain]") == ["cutover-dryrun.example"]
        )

        subscribers_file = tmp_root / "subscribers.json"
        certs_dir = tmp_root / "certificates"
        clients_file = tmp_root / "clients.json"
        retainers_file = tmp_root / "agency_retainers.json"
        portals_dir = tmp_root / "portals"
        bundles_dir = tmp_root / "client_bundles"
        sim_webhook_secret = "whsec_orbit_cutover_dryrun_local_only"

        handler = StripeWebhookHandler(
            webhook_secret=sim_webhook_secret,
            subscriber_manager=SubscriberManager(subscribers_file=subscribers_file),
            sla_generator=SlaCertificateGenerator(output_dir=certs_dir),
            fleet_registry=FleetRegistry(data_path=clients_file),
            retainer_manager=AgencyRetainerManager(data_path=retainers_file),
            deal_desk=RetainerDealDeskConcierge(
                workspace_root=tmp_root,
                portals_dir=portals_dir,
                bundles_dir=bundles_dir,
            ),
        )

        event_payload = {
            "id": "evt_cutover_dryrun_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_cutover_dryrun_001",
                    "customer": "cus_cutover_dryrun_001",
                    "subscription": "sub_cutover_dryrun_001",
                    "client_reference_id": "cutover_ref_001",
                    "customer_details": {
                        "email": "cutover@dryrun.example",
                        "name": "Cutover Dryrun Agency",
                    },
                    "metadata": {
                        "agency_id": "cutover-dryrun-agency",
                        "agency_name": "Cutover Dryrun Agency",
                        "tier": "Scale",
                        "domain": "cutover-dryrun.example",
                        "client_reference_id": "cutover_ref_001",
                    },
                    "amount_total": 29900,
                    "currency": "usd",
                    "payment_status": "paid",
                }
            },
        }
        payload_bytes = json.dumps(event_payload).encode("utf-8")
        sig_header = generate_stripe_signature(payload_bytes, sim_webhook_secret)
        webhook_result = handler.handle_webhook(payload_bytes, sig_header)

        webhook_status = str(webhook_result.get("status", ""))
        sub_raw = _load_json_safe(subscribers_file, [])
        subscriber_provisioned = (
            subscribers_file.is_file()
            and isinstance(sub_raw, (list, dict))
            and bool(webhook_result.get("subscriber"))
            and ("cutover@dryrun.example" in json.dumps(sub_raw))
        )

        sla_path_str = webhook_result.get("sla_certificate_path")
        sla_path = Path(sla_path_str) if sla_path_str else tmp_root / "__missing_sla__"
        sla_pdf_valid = (
            sla_path.is_file()
            and _is_within(sla_path, tmp_root)
            and sla_path.read_bytes().startswith(b"%PDF")
        )

        bundle_path_str = webhook_result.get("bundle_path")
        bundle_path = Path(bundle_path_str) if bundle_path_str else tmp_root / "__missing_bundle__"
        bundle_sha256 = str(webhook_result.get("bundle_sha256") or "")
        bundle_zip_sha256_valid = False
        if bundle_path.is_file() and _is_within(bundle_path, tmp_root) and len(bundle_sha256) == 64:
            actual_sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
            if actual_sha256 == bundle_sha256 and zipfile.is_zipfile(bundle_path):
                with zipfile.ZipFile(bundle_path, "r") as zf:
                    bundle_zip_sha256_valid = len(zf.namelist()) > 0 and zf.testzip() is None

        portal_path_str = webhook_result.get("portal_path")
        portal_path = Path(portal_path_str) if portal_path_str else tmp_root / "__missing_portal__"
        portal_html_generated = (
            portal_path.is_file()
            and _is_within(portal_path, tmp_root)
            and "Cutover Dryrun Agency" in portal_path.read_text(encoding="utf-8", errors="ignore")
        )

        isolated_paths_verified = (
            _is_within(subscribers_file, tmp_root)
            and _is_within(clients_file, tmp_root)
            and _is_within(retainers_file, tmp_root)
            and _is_within(sla_path, tmp_root)
            and _is_within(bundle_path, tmp_root)
            and _is_within(portal_path, tmp_root)
        )

        ok = all(
            [
                checkout_session_fields_verified,
                webhook_status == "PROVISIONED",
                subscriber_provisioned,
                sla_pdf_valid,
                bundle_zip_sha256_valid,
                portal_html_generated,
                isolated_paths_verified,
            ]
        )
        duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return {
            "ok": ok,
            "duration_ms": duration_ms,
            "stripe_key_mode": stripe_key_mode,
            "env_key_prefixes": env_key_prefixes,
            "checkout_session_fields_verified": checkout_session_fields_verified,
            "webhook_status": webhook_status,
            "subscriber_provisioned": subscriber_provisioned,
            "sla_pdf_valid": sla_pdf_valid,
            "bundle_zip_sha256_valid": bundle_zip_sha256_valid,
            "portal_html_generated": portal_html_generated,
            "isolated_paths_verified": isolated_paths_verified,
            "live_data_untouched": True,
        }
    finally:
        bb_mod._GLOBAL_BLACKBOARD = orig_global_bb
        bb_mod.publish_event = orig_publish_event
        for key, prev_val in orig_env.items():
            if prev_val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev_val
        try:
            temp_ctx.cleanup()
        except OSError:
            pass


def run_readiness_audit(repo_root: Path = REPO_ROOT, verify_cutover: bool = False) -> Dict[str, Any]:
    """Run all read-only Orbit Security readiness checks and return structured metrics."""
    data_dir = repo_root / "data"
    kyc_status = os.getenv("ORBIT_KYC_STATUS", "PENDING_PHYSICAL_ID").strip() or "PENDING_PHYSICAL_ID"

    parity = _check_landing_docs_parity(repo_root)
    stripe = _check_stripe_env(repo_root)
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
    if not disclosures["ev_digest_coverage"]["coverage_ok"]:
        blockers.append("MISSING_EV_DIGESTS")
    if disclosures["unclassified_disclosures"]:
        blockers.append("UNCLASSIFIED_DISCLOSURES")
    if not track_b_funnel["ready"]:
        blockers.append("TRACK_B_FUNNEL_INCOMPLETE")
    if not stripe["live_checkout_ready"]:
        blockers.append("STRIPE_KEYS_UNCONFIGURED")
    if kyc_status != "VERIFIED":
        blockers.append(f"KYC_PAYOUT_{kyc_status}")

    stripe_cutover_dry_run: Optional[Dict[str, Any]] = None
    if verify_cutover:
        stripe_cutover_dry_run = verify_stripe_cutover(repo_root=repo_root)
        if not stripe_cutover_dry_run.get("ok"):
            blockers.append("STRIPE_CUTOVER_DRY_RUN_FAILED")

    technical_floor_clean = (
        bool(COMMERCIAL_OUTREACH_FROZEN)
        and parity["in_sync"]
        and clients["hygiene_clean"]
        and catalog["duplicate_count"] == 0
        and catalog["unique_programs"] >= 45
        and disclosures["advisory_lingering_reports"] == 0
        and disclosures["bundle_pairing_ok"]
        and disclosures["ev_digest_coverage"]["coverage_ok"]
        and not disclosures["unclassified_disclosures"]
        and track_b_funnel["ready"]
        and (stripe_cutover_dry_run is None or bool(stripe_cutover_dry_run.get("ok")))
    )

    track_a_disclosures_ready = (
        catalog["duplicate_count"] == 0
        and catalog["unique_programs"] >= 45
        and disclosures["advisory_lingering_reports"] == 0
        and disclosures["bundle_pairing_ok"]
        and disclosures["ev_digest_coverage"]["coverage_ok"]
        and not disclosures["unclassified_disclosures"]
        and disclosures["active_submittable_reports"] > 0
    )
    track_b_offline_ready = parity["in_sync"] and clients["hygiene_clean"] and track_b_funnel["ready"]
    track_b_live_checkout_ready = track_b_offline_ready and stripe["live_checkout_ready"] and kyc_status == "VERIFIED"

    report: Dict[str, Any] = {
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
    if stripe_cutover_dry_run is not None:
        report["stripe_cutover_dry_run"] = stripe_cutover_dry_run
    return report


def _render_human_report(report: Dict[str, Any]) -> str:
    parity = report["landing_docs_parity"]
    stripe = report["stripe_config"]
    clients = report["clients_hygiene"]
    catalog = report["bounty_catalog"]
    disc = report["disclosures_and_radar"]
    ev = disc["ev_digest_coverage"]
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
        f"Bounty Catalog              : {catalog['unique_programs']} unique ({catalog['duplicate_count']} dups, {catalog['cash_tier_count']} cash tier, out_of_scope {catalog.get('out_of_scope_populated', 0)}/{catalog.get('out_of_scope_total', catalog['total_entries'])})",
        f"Staged Submittable Reports  : {disc['active_submittable_reports']} (.md), {disc['cryptographic_zip_bundles']} (.zip bundles)",
        f"Bundle Pairing Parity       : ok={disc['bundle_pairing_ok']} (paired={disc['paired_bundle_count']}, missing={len(disc['missing_bundle_zips'])}, orphan={len(disc['orphan_bundle_zips'])}, corrupt={len(disc['corrupt_bundle_zips'])})",
        f"Evidence Digest Coverage    : ok={ev['coverage_ok']} ({ev['covered_count']}/{ev['total_staged']} staged)",
        f"Archived Artifacts          : {disc['archived_total_count']} total ({disc['archived_false_positive_disclosures']} false_positive_disclosures + {disc['archived_legacy_artifacts']} legacy_passive_disclosures)",
        f"Lingering Advisory Reports  : {disc['advisory_lingering_reports']}",
        f"Radar State Counters        : sweeps={disc['radar_state_total_sweeps']}, submittable={disc['radar_state_submittable_count']}, advisory={disc['radar_state_advisory_count']}, legacy_total={disc['radar_state_legacy_counter']}",
    ]
    cutover = report.get("stripe_cutover_dry_run")
    if isinstance(cutover, dict):
        prefixes = cutover.get("env_key_prefixes") or {}
        lines.append(
            "Stripe Cutover Dry-Run      : "
            f"ok={cutover.get('ok')} (mode={cutover.get('stripe_key_mode')}, "
            f"secret={prefixes.get('STRIPE_SECRET_KEY', 'unset')}, "
            f"api={prefixes.get('STRIPE_API_KEY', 'unset')}, "
            f"webhook={prefixes.get('STRIPE_WEBHOOK_SECRET', 'unset')}, "
            f"status={cutover.get('webhook_status')}, "
            f"pdf={cutover.get('sla_pdf_valid')}, "
            f"zip_sha256={cutover.get('bundle_zip_sha256_valid')}, "
            f"portal={cutover.get('portal_html_generated')}, "
            f"live_untouched={cutover.get('live_data_untouched')}, "
            f"ms={cutover.get('duration_ms')})"
        )
    lines.extend(
        [
            "------------------------------------------------------------------------",
            f"Active Blockers             : {', '.join(report['blockers']) or 'NONE'}",
            "========================================================================",
        ]
    )
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only readiness audit for Orbit Security.")
    parser.add_argument("--json", action="store_true", help="Output structured JSON report.")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Override repository root path.")
    parser.add_argument(
        "--verify-cutover",
        action="store_true",
        help="Run a hermetic Stripe checkout + webhook provisioning dry-run inside a temp directory.",
    )
    args = parser.parse_args(argv)

    report = run_readiness_audit(repo_root=args.repo_root, verify_cutover=args.verify_cutover)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_render_human_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
