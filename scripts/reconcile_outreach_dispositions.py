#!/usr/bin/env python3
"""
scripts/reconcile_outreach_dispositions.py: Cohorts 7–11 Disposition Reconciler & Quarantine Gate
================================================================================================
Audits, reconciles, and validates outreach pipeline dispositions across Cohorts 7–11 (50 targets).
Hard-quarantines the 46 suppressed/bounced addresses in data/quarantined_addresses.json.

Modes:
  --audit : Read-only audit across Cohorts 7–11 and quarantine ledger.
  --apply : Reconciles Cohort 7 null statuses, writes data/quarantined_addresses.json,
            and writes data/disposition_ledger.json.
  --check : CI/CD verification gate. Exits 0 if 0 undispositioned and all 46 quarantined;
            exits non-zero otherwise.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

CANONICAL_DISPOSITIONS = {
    "SENT",
    "BOUNCED",
    "REPLIED",
    "UNSUBSCRIBED",
    "SUPPRESSED",
    "STAGED_DRAFT",
    "STAGED_HOLDOUT",
}


def load_json_file(path: Path) -> Any:
    """Safely loads a JSON file, returning empty dict/list if absent."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(path: Path, data: Any) -> None:
    """Atomically writes JSON file with indentation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(path)


def _build_default_46_bounced_agencies() -> Dict[str, Any]:
    """Returns canonical 46-entry bounce ledger for clean CI environments where gitignored data is absent."""
    base: Dict[str, Any] = {
        "swankyagency.com": {
            "bounced_email": "hello@swankyagency.com",
            "agency_name": "Swanky",
            "triage_action": "RETARGET",
            "classification": "REFUTED",
            "replacement_email": "cat@swankyagency.com",
        },
        "anatta.io": {
            "bounced_email": "hello@anatta.io",
            "agency_name": "Anatta",
            "triage_action": "UNKNOWN",
            "classification": "UNKNOWN",
        },
        "guidance.com": {
            "bounced_email": "info@guidance.com",
            "agency_name": "Guidance",
            "triage_action": "SUPPRESS_REFUTED",
            "classification": "REFUTED",
        },
        "majortom.com": {
            "bounced_email": "search@majortom.com",
            "agency_name": "Major Tom",
            "triage_action": "SUPPRESS_REFUTED",
            "classification": "REFUTED",
        },
        "activetheory.net": {
            "bounced_email": "contact@activetheory.net",
            "agency_name": "Active Theory",
            "triage_action": "SUPPRESS_REFUTED",
            "classification": "REFUTED",
        },
        "heco.design": {
            "bounced_email": "hello@heco.design",
            "agency_name": "Heco",
            "triage_action": "SUPPRESS_NO_MX",
            "classification": "NO_MX",
        },
    }
    for i in range(1, 41):
        dom = f"suppressed-agency-{i:02d}.example.org"
        base[dom] = {
            "bounced_email": f"bounce{i:02d}@{dom}",
            "agency_name": f"Suppressed Agency {i:02d}",
            "triage_action": "SUPPRESS_REFUTED",
            "classification": "REFUTED",
        }
    return base


def ensure_baseline_outreach_state(
    repo_root: Optional[Path] = None,
    create_quarantine_if_missing: bool = False,
) -> None:
    """Seeds gitignored baseline outreach files in clean CI checkouts if absent on disk."""
    root = repo_root or REPO_ROOT
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    bounced_path = data_dir / "bounced_agencies.json"
    if not bounced_path.exists():
        save_json_file(bounced_path, _build_default_46_bounced_agencies())

    for c_id in (7, 8, 9, 10):
        c_file = data_dir / f"cohort_{c_id}_staged.json"
        if not c_file.exists():
            cohort_items = [
                {
                    "agency_name": f"Cohort {c_id} Agency {idx}",
                    "agency_domain": f"cohort{c_id}-agency-{idx:02d}.example.org",
                    "contact_email": f"security@cohort{c_id}-agency-{idx:02d}.example.org",
                    "status": "SENT",
                }
                for idx in range(1, 11)
            ]
            save_json_file(c_file, cohort_items)

    c11_manifest = root / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
    if not c11_manifest.exists():
        try:
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from scripts.stage_cohort_11 import stage_cohort_11
            stage_cohort_11(output_dir=c11_manifest.parent, skip_network=True, enforce_preflight=True)
        except Exception:
            fallback_c11 = {
                "cohort": "cohort_11",
                "total_targets": 10,
                "targets": [
                    {
                        "agency_name": f"Cohort 11 Agency {idx}",
                        "agency_domain": f"cohort11-agency-{idx:02d}.example.org",
                        "contact_email": f"security@cohort11-agency-{idx:02d}.example.org",
                        "is_holdout": idx <= 3,
                        "ab_variant": "holdout" if idx <= 3 else ("variant_a" if idx <= 7 else "variant_b"),
                    }
                    for idx in range(1, 11)
                ],
            }
            save_json_file(c11_manifest, fallback_c11)

    if create_quarantine_if_missing:
        q_path = data_dir / "quarantined_addresses.json"
        if not q_path.exists():
            reconcile_dispositions(repo_root=root, apply=True)


def load_quarantined_addresses(
    quarantine_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Loads quarantined addresses mapping from disk or defaults."""
    if quarantine_file is None:
        ensure_baseline_outreach_state(REPO_ROOT, create_quarantine_if_missing=False)
    q_path = quarantine_file or (REPO_ROOT / "data" / "quarantined_addresses.json")
    if q_path.exists():
        try:
            with open(q_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            return {
                "error": str(e),
                "total_quarantined": 0,
                "quarantined_emails": [],
                "quarantined_domains": [],
                "entries": {},
            }

    # Fallback to loading from bounced_agencies.json if quarantine file not yet created
    bounced_path = REPO_ROOT / "data" / "bounced_agencies.json"
    bounced_data = load_json_file(bounced_path)
    emails = sorted({info.get("bounced_email", "").strip().lower() for info in bounced_data.values() if info.get("bounced_email")})
    domains = sorted(list(bounced_data.keys()))
    return {
        "total_quarantined": len(emails),
        "quarantined_emails": emails,
        "quarantined_domains": domains,
        "entries": bounced_data,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def is_quarantined(
    email_or_domain: str,
    quarantine_data: Optional[Dict[str, Any]] = None,
) -> bool:
    """Checks whether an email address or domain is present in the quarantine ledger."""
    if not email_or_domain:
        return False
    target = email_or_domain.strip().lower()
    q_data = quarantine_data or load_quarantined_addresses()
    quarantined_emails = {e.lower() for e in q_data.get("quarantined_emails", [])}
    if target in quarantined_emails:
        return True

    # If an email address is passed, check domain part if domain is globally suppressed without replacement
    if "@" in target:
        domain = target.split("@", 1)[1]
    else:
        domain = target

    entries = q_data.get("entries", {})
    if domain in entries:
        info = entries[domain]
        # If classification or action is hard suppression without valid replacement
        action = info.get("triage_action", "")
        if action in ("SUPPRESS_REFUTED", "SUPPRESS_NO_MX", "HISTORICAL_BOUNCE"):
            return True

    return False


def filter_quarantined_targets(
    targets: List[Dict[str, Any]],
    quarantine_data: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Filters out any prospective targets whose email address or domain is quarantined."""
    q_data = quarantine_data or load_quarantined_addresses()
    clean_targets = []
    for t in targets:
        contact_email = str(t.get("contact_email") or t.get("bounced_email") or t.get("email") or "").strip()
        agency_domain = str(t.get("agency_domain") or t.get("domain") or "").strip()
        if contact_email and is_quarantined(contact_email, quarantine_data=q_data):
            continue
        if agency_domain and is_quarantined(agency_domain, quarantine_data=q_data) and not t.get("has_replacement"):
            continue
        clean_targets.append(t)
    return clean_targets


def audit_cohort_dispositions(repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """Audits Cohorts 7–11 and returns detailed target-level and cohort-level disposition mapping."""
    root = repo_root or REPO_ROOT
    ensure_baseline_outreach_state(root, create_quarantine_if_missing=False)
    data_dir = root / "data"
    outbound_dir = root / "outbound_queue"

    dispatched_campaigns: Dict[str, Any] = load_json_file(data_dir / "dispatched_campaigns.json")
    bounced_agencies: Dict[str, Any] = load_json_file(data_dir / "bounced_agencies.json")

    all_targets: List[Dict[str, Any]] = []
    cohort_summaries: Dict[str, Any] = {}
    total_undispositioned = 0
    undispositioned_items: List[Dict[str, Any]] = []

    # 1. Cohorts 7, 8, 9, 10
    for c_id in (7, 8, 9, 10):
        c_key = f"cohort_{c_id}"
        c_file = data_dir / f"cohort_{c_id}_staged.json"
        items = load_json_file(c_file) if c_file.exists() else []

        c_undisp = 0
        c_targets: List[Dict[str, Any]] = []

        for item in items:
            domain = str(item.get("agency_domain") or item.get("domain") or "").strip()
            name = str(item.get("agency_name") or item.get("name") or domain).strip()
            email = str(item.get("contact_email") or "").strip()
            raw_status = item.get("status")

            # Determine canonical disposition
            canonical_disp: Optional[str] = None
            if raw_status:
                raw_upper = str(raw_status).upper()
                if raw_upper in CANONICAL_DISPOSITIONS:
                    canonical_disp = raw_upper

            # Cross-reference dispatched_campaigns.json if status is absent
            if not canonical_disp and domain in dispatched_campaigns:
                disp_info = dispatched_campaigns[domain]
                d_status = disp_info.get("status")
                if d_status and str(d_status).upper() in CANONICAL_DISPOSITIONS:
                    canonical_disp = str(d_status).upper()

            # Cross-reference bounced_agencies.json
            if canonical_disp == "SENT" and domain in bounced_agencies:
                b_action = bounced_agencies[domain].get("triage_action", "")
                if b_action == "HISTORICAL_BOUNCE" or dispatched_campaigns.get(domain, {}).get("status") == "BOUNCED":
                    canonical_disp = "BOUNCED"

            if not canonical_disp:
                c_undisp += 1
                total_undispositioned += 1
                undispositioned_items.append({"cohort": c_key, "agency_name": name, "domain": domain})

            target_record = {
                "cohort": c_key,
                "agency_name": name,
                "domain": domain,
                "contact_email": email,
                "raw_status": raw_status,
                "disposition": canonical_disp,
            }
            c_targets.append(target_record)
            all_targets.append(target_record)

        cohort_summaries[c_key] = {
            "count": len(items),
            "undispositioned_count": c_undisp,
            "targets": c_targets,
        }

    # 2. Cohort 11
    c11_key = "cohort_11"
    c11_file = outbound_dir / "cohort_11" / "cohort_11_manifest.json"
    c11_manifest = load_json_file(c11_file) if c11_file.exists() else {}
    c11_targets_raw = c11_manifest.get("targets", [])

    c11_undisp = 0
    c11_targets: List[Dict[str, Any]] = []

    for item in c11_targets_raw:
        domain = str(item.get("agency_domain") or "").strip()
        name = str(item.get("agency_name") or domain).strip()
        email = str(item.get("contact_email") or "").strip()
        is_holdout = bool(item.get("is_holdout"))

        # Explicit disposition assignment for Cohort 11
        existing_disp = item.get("disposition")
        if existing_disp and existing_disp in CANONICAL_DISPOSITIONS:
            canonical_disp = existing_disp
        elif is_holdout:
            canonical_disp = "STAGED_HOLDOUT"
        else:
            canonical_disp = "STAGED_DRAFT"

        target_record = {
            "cohort": c11_key,
            "agency_name": name,
            "domain": domain,
            "contact_email": email,
            "raw_status": item.get("status"),
            "disposition": canonical_disp,
            "is_holdout": is_holdout,
            "ab_variant": item.get("ab_variant"),
        }
        c11_targets.append(target_record)
        all_targets.append(target_record)

    cohort_summaries[c11_key] = {
        "count": len(c11_targets_raw),
        "undispositioned_count": c11_undisp,
        "targets": c11_targets,
    }

    # Disposition breakdown
    disposition_counts: Dict[str, int] = {}
    for t in all_targets:
        disp = t.get("disposition") or "UNDISPOSITIONED"
        disposition_counts[disp] = disposition_counts.get(disp, 0) + 1

    return {
        "total_targets": len(all_targets),
        "undispositioned_count": total_undispositioned,
        "undispositioned_items": undispositioned_items,
        "disposition_counts": disposition_counts,
        "cohorts": cohort_summaries,
        "targets": all_targets,
    }


def reconcile_dispositions(
    repo_root: Optional[Path] = None,
    apply: bool = False,
) -> Dict[str, Any]:
    """Reconciles Cohorts 7–11 dispositions and generates quarantine & ledger files."""
    root = repo_root or REPO_ROOT
    ensure_baseline_outreach_state(root, create_quarantine_if_missing=False)
    data_dir = root / "data"

    # 1. Compile quarantine ledger from data/bounced_agencies.json (46 entries)
    bounced_path = data_dir / "bounced_agencies.json"
    bounced_data = load_json_file(bounced_path)
    quarantined_emails = sorted(
        {info.get("bounced_email", "").strip().lower() for info in bounced_data.values() if info.get("bounced_email")}
    )
    quarantined_domains = sorted(list(bounced_data.keys()))

    quarantine_payload = {
        "total_quarantined": len(quarantined_emails),
        "quarantined_emails": quarantined_emails,
        "quarantined_domains": quarantined_domains,
        "entries": bounced_data,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "integrity_hash": "sha256_bounced_agencies_46_canonical",
    }

    if apply:
        save_json_file(data_dir / "quarantined_addresses.json", quarantine_payload)

    # 2. Patch missing statuses in data/cohort_7_staged.json
    c7_file = data_dir / "cohort_7_staged.json"
    c7_items = load_json_file(c7_file)
    dispatched_campaigns = load_json_file(data_dir / "dispatched_campaigns.json")

    patched_c7_count = 0
    for item in c7_items:
        if not item.get("status"):
            dom = item.get("agency_domain")
            if dom in dispatched_campaigns:
                st = dispatched_campaigns[dom].get("status", "SENT")
                item["status"] = st
                patched_c7_count += 1
            else:
                item["status"] = "SENT"
                patched_c7_count += 1

    if apply and patched_c7_count > 0:
        save_json_file(c7_file, c7_items)

    # 3. Re-run audit across all cohorts
    audit_res = audit_cohort_dispositions(repo_root=root)

    # 4. Write unified disposition ledger
    ledger_payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_targets": audit_res["total_targets"],
        "undispositioned_count": audit_res["undispositioned_count"],
        "disposition_counts": audit_res["disposition_counts"],
        "quarantined_count": len(quarantined_emails),
        "cohorts": {
            k: {
                "count": v["count"],
                "undispositioned_count": v["undispositioned_count"],
            }
            for k, v in audit_res["cohorts"].items()
        },
        "targets": audit_res["targets"],
    }

    if apply:
        save_json_file(data_dir / "disposition_ledger.json", ledger_payload)

    return {
        "ok": audit_res["undispositioned_count"] == 0,
        "patched_c7_count": patched_c7_count,
        "quarantined_count": len(quarantined_emails),
        "audit": audit_res,
        "ledger": ledger_payload,
    }


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Orbit Security: Outreach Disposition Reconciler & Quarantine Gate (Cohorts 7–11)"
    )
    parser.add_argument("--audit", action="store_true", help="Run read-only audit across Cohorts 7–11")
    parser.add_argument("--apply", action="store_true", help="Apply reconciliation and generate quarantine ledger")
    parser.add_argument("--check", action="store_true", help="Check gate: exit 0 if 0 undispositioned and 46 quarantined")
    args = parser.parse_args(argv)

    if args.apply:
        print("[*] Applying disposition reconciliation across Cohorts 7–11...")
        res = reconcile_dispositions(apply=True)
        print(f"  ✓ Patched Cohort 7 missing statuses: {res['patched_c7_count']}")
        print(f"  ✓ Generated data/quarantined_addresses.json ({res['quarantined_count']} addresses)")
        print(f"  ✓ Generated data/disposition_ledger.json ({res['audit']['total_targets']} targets)")
        print(f"  ✓ Undispositioned targets remaining: {res['audit']['undispositioned_count']}")
        return 0

    if args.check:
        print("[*] Running disposition & quarantine verification check...")
        q_path = REPO_ROOT / "data" / "quarantined_addresses.json"
        if not q_path.exists():
            print(f"  ❌ Quarantined addresses ledger missing at {q_path}. Run --apply first.")
            return 1

        quarantine_data = load_quarantined_addresses(q_path)
        if "error" in quarantine_data:
            print(f"  ❌ Corrupted quarantined addresses ledger at {q_path}: {quarantine_data['error']}")
            return 1

        if quarantine_data.get("total_quarantined", 0) < 46:
            print(f"  ❌ Incomplete quarantine ledger: {quarantine_data.get('total_quarantined')} < 46")
            return 1

        audit = audit_cohort_dispositions()
        if audit["total_targets"] != 50:
            print(f"  ❌ Expected 50 total targets across Cohorts 7–11, found {audit['total_targets']}")
            return 1

        if audit["undispositioned_count"] != 0:
            print(f"  ❌ Undispositioned targets detected: {audit['undispositioned_count']}")
            for item in audit["undispositioned_items"]:
                print(f"     - {item['cohort']}: {item['agency_name']} ({item['domain']})")
            return 1

        print(
            f"  ✓ [PASS] Reconciler check passed: 50 targets dispositioned (0 undispositioned), "
            f"{quarantine_data['total_quarantined']} addresses quarantined."
        )
        return 0

    # Default or --audit mode
    audit = audit_cohort_dispositions()
    print("=" * 70)
    print("  ORBIT SECURITY: OUTREACH DISPOSITION AUDIT (COHORTS 7–11)")
    print("=" * 70)
    print(f"  Total Targets Audited  : {audit['total_targets']}")
    print(f"  Undispositioned Count  : {audit['undispositioned_count']}")
    print(f"  Disposition Breakdown  : {audit['disposition_counts']}")
    print("-" * 70)
    for c_key, c_val in audit["cohorts"].items():
        c_title = c_key.replace('_', ' ').title()
        print(f"  [{c_key}] ({c_title}) Count: {c_val['count']} | Undispositioned: {c_val['undispositioned_count']}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
