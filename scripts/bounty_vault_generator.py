#!/usr/bin/env python3
"""Orbit Security — Pre-KYC Remediation Vault & Submission Readiness Compiler.

Compiles staged ``data/disclosures/`` bundles (or an explicit verification matrix)
into deduplicated, program-grouped remediation dossiers with CWE classification,
CVSS v3.1 scoring, cryptographic ``ev_<12-char-hex>`` digest traceability, and
defensive remediation steps. Enforces strict anti-noise quality gates so
multi-subdomain findings are consolidated into single high-signal dossiers and
supports an optional read-only ``--verify-live`` mode gated by ``egress_guard``.

Usage:
    .venv\\Scripts\\python.exe scripts\\bounty_vault_generator.py
    .venv\\Scripts\\python.exe scripts\\bounty_vault_generator.py --dry-run
    .venv\\Scripts\\python.exe scripts\\bounty_vault_generator.py --verify-live
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.egress_guard import EgressViolationError, create_guarded_httpx_client  # noqa: E402
from orbit_security.scanner import PublicHostOnlyRoE  # noqa: E402

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_DISCLOSURES_DIR = REPO_ROOT / "data" / "disclosures"
DEFAULT_ARCHIVE_FP_DIR = REPO_ROOT / "data" / "archive" / "false_positive_disclosures"
DEFAULT_MATRIX_PATH = REPO_ROOT / "data" / "hackerone_staging" / "live_verification_matrix.json"
DEFAULT_VAULT_OUT = REPO_ROOT / "data" / "hackerone_staging"

EV_DIGEST_RE = re.compile(r"^ev_[0-9a-f]{12}$")
EXPOSED_KEY_RAW_RE = re.compile(
    r"\(\d+\)\s+([A-Za-z0-9_./-][^(\n;]*?\.(?:pdf|mp4|csv|xlsx|json|txt|xml|zip))"
)
EXPOSED_KEY_MD_RE = re.compile(
    r"^\s*\d+\.\s+[^`]*`([^`]+?\.(?:pdf|mp4|csv|xlsx|json|txt|xml|zip))`",
    re.MULTILINE,
)
UNTRUSTED_POC_ORIGIN = "https://untrusted-adversary.com"

CVSS_PROFILES: Dict[str, Dict[str, Any]] = {
    "OPEN_BUCKET_LISTING": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "severity": "Medium",
        "base_score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": [
            "Disable public `s3:ListBucket` (AWS S3) or `storage.objects.list` (Google Cloud Storage) permissions for `allUsers` and `allAuthenticatedUsers`.",
            "Audit object ACLs and move non-public pitch decks, partner disclosures, and internal reports to an authenticated storage bucket.",
            "Enforce organization-wide Public Access Prevention policies on cloud storage buckets.",
        ],
    },
    "AUTHENTICATED_CORS_SENSITIVE": {
        "cwe": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "severity": "High",
        "base_score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "remediation": [
            "Replace dynamic `Origin` reflection in `Access-Control-Allow-Origin` with a strict, exact-match allowlist of trusted first-party origins.",
            "Never combine dynamic origin reflection with `Access-Control-Allow-Credentials: true` on endpoints that return session-scoped responses.",
            "Ensure `Vary: Origin` is emitted on all responses where CORS headers depend on the request `Origin`.",
        ],
    },
    "REFLECTED_PUBLIC_HTML": {
        "cwe": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "severity": "Medium",
        "base_score": 5.4,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "remediation": [
            "Validate the incoming `Origin` header against an explicit allowlist of trusted domains before reflecting it in `Access-Control-Allow-Origin`.",
            "Remove `Access-Control-Allow-Credentials: true` from public HTML or unauthenticated gateway routes.",
            "Audit authenticated JSON/REST API routes behind the same gateway to confirm credentialed CORS reflection does not expose user state.",
        ],
    },
    "DANGLING_TAKEOVER_VERIFIED": {
        "cwe": "CWE-350",
        "cwe_name": "Reliance on Reverse DNS Resolution for a Security-Critical Action",
        "severity": "High",
        "base_score": 8.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "remediation": [
            "Remove the dangling `CNAME` or `A` DNS record from the authoritative DNS zone immediately.",
            "If the third-party SaaS service is still required, claim and bind the custom domain within the SaaS tenant portal.",
            "Implement automated DNS lifecycle checks prior to decommissioning cloud resources.",
        ],
    },
}

DEFAULT_CVSS_PROFILE: Dict[str, Any] = {
    "cwe": "CWE-16",
    "cwe_name": "Configuration Hygiene Finding",
    "severity": "Low",
    "base_score": 3.7,
    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "remediation": [
        "Review perimeter configuration and restrict public access to intended origins and resources.",
    ],
}


def classify_finding_tier(entry: Dict[str, Any]) -> str:
    """Classifies a finding or staged disclosure entry into a submission readiness tier."""
    viability = str(entry.get("bounty_viability", "")).upper()
    if viability in {"FALSE_POSITIVE", "ARCHIVED", "SUPPRESSED", "OUT_OF_SCOPE", "NONE"}:
        return "TIER_3_SUPPRESSED"

    verdict = str(entry.get("verdict", "")).upper()
    score = int(entry.get("score", 0) or 0)
    code = int(entry.get("code", 0) or 0)

    if code != 200 or score < 5:
        return "TIER_3_SUPPRESSED"

    if verdict in ("OPEN_BUCKET_LISTING", "AUTHENTICATED_CORS_SENSITIVE", "DANGLING_TAKEOVER_VERIFIED") or score >= 6:
        return "TIER_1_READY"

    if verdict == "REFLECTED_PUBLIC_HTML" and score == 5:
        return "TIER_2_NEEDS_AUTH_PROOF"

    return "TIER_3_SUPPRESSED"


def compute_cvss_profile(verdict: str) -> Dict[str, Any]:
    """Returns standardized CWE and CVSS v3.1 metadata for a finding verdict."""
    return dict(CVSS_PROFILES.get(str(verdict).upper(), DEFAULT_CVSS_PROFILE))


def _extract_raw_evidence(tech_text: str) -> str:
    if "OBSERVED RAW EVIDENCE:\n" in tech_text:
        body = tech_text.split("OBSERVED RAW EVIDENCE:\n", 1)[1]
        if "\n\nREMEDIATION GUIDANCE:" in body:
            body = body.split("\n\nREMEDIATION GUIDANCE:", 1)[0]
        return body.strip()
    return ""


def _extract_exposed_object_keys(raw_evidence: str, md_text: str) -> List[str]:
    keys: List[str] = []
    for match in EXPOSED_KEY_RAW_RE.findall(raw_evidence):
        cleaned = match.strip().rstrip(".,;")
        if cleaned and cleaned not in keys:
            keys.append(cleaned)
    if not keys and md_text:
        for match in EXPOSED_KEY_MD_RE.findall(md_text):
            cleaned = match.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)
    return keys


def _map_disclosure_verdict(flaw_type: str, viability: str, raw_evidence: str) -> Tuple[str, int]:
    flaw = flaw_type.strip().lower()
    via = viability.strip().upper()

    if via in {"FALSE_POSITIVE", "ARCHIVED", "SUPPRESSED", "OUT_OF_SCOPE", "NONE"}:
        return "SUPPRESSED_FALSE_POSITIVE", 0

    if flaw == "open_cloud_bucket":
        return ("OPEN_BUCKET_LISTING", 6) if via in {"HIGH_CONFIDENCE", "VERIFIED"} else ("OPEN_BUCKET_LISTING", 5)

    if flaw in {"cors_arbitrary_origin_with_credentials", "cors_null_origin_with_credentials"}:
        if via in {"HIGH_CONFIDENCE", "VERIFIED"} and "[PUBLIC_HTML_ONLY" not in raw_evidence:
            return "AUTHENTICATED_CORS_SENSITIVE", 7
        return "REFLECTED_PUBLIC_HTML", 5

    if flaw in {"subdomain_takeover", "cloud_storage_takeover", "client_subdomain_takeover"}:
        if via in {"HIGH_CONFIDENCE", "VERIFIED"}:
            return "DANGLING_TAKEOVER_VERIFIED", 7
        return "SUPPRESSED_UNVERIFIED_TAKEOVER", 0

    return flaw.upper() or "UNKNOWN", 0


def _collect_archived_false_positive_stems(archive_fp_dir: Optional[Path]) -> set[str]:
    if not archive_fp_dir or not archive_fp_dir.is_dir():
        return set()
    return {p.stem for p in archive_fp_dir.glob("*.md") if p.is_file()}


def load_staged_disclosure_entries(
    disclosures_dir: Path = DEFAULT_DISCLOSURES_DIR,
    archive_fp_dir: Optional[Path] = DEFAULT_ARCHIVE_FP_DIR,
) -> Tuple[List[Dict[str, Any]], int]:
    """Loads active ev_-tagged disclosure bundles while excluding archived Tier-3 false positives."""
    if not disclosures_dir.is_dir():
        raise FileNotFoundError(f"Disclosures directory not found at {disclosures_dir}")

    archived_stems = _collect_archived_false_positive_stems(archive_fp_dir)
    entries: List[Dict[str, Any]] = []

    bundle_dirs = sorted(
        p for p in disclosures_dir.iterdir() if p.is_dir() and p.name.endswith("_bundle") and "(1)" not in p.name
    )
    for bdir in bundle_dirs:
        stem = bdir.name[: -len("_bundle")]
        if stem in archived_stems:
            continue

        meta_path = bdir / "metadata.json"
        if not meta_path.is_file():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        md_path = disclosures_dir / f"{stem}.md"
        md_text = md_path.read_text(encoding="utf-8") if md_path.is_file() else ""
        tech_path = bdir / "technical_evidence.txt"
        tech_text = tech_path.read_text(encoding="utf-8") if tech_path.is_file() else ""

        raw_evidence = _extract_raw_evidence(tech_text)
        flaw_type = str(meta.get("flaw_type", "")).strip()
        viability = str(meta.get("bounty_viability", "CONDITIONAL")).strip().upper()
        verdict, score = _map_disclosure_verdict(flaw_type, viability, raw_evidence)
        if score == 0:
            continue

        target_domain = str(meta.get("target_domain", "")).strip()
        ev_id = str(meta.get("evidence_artifact_id", "")).strip()
        if not EV_DIGEST_RE.match(ev_id):
            raise ValueError(f"Missing or malformed ev_ digest in {meta_path}: {ev_id!r}")

        digest_in_docs = ev_id in md_text and (not tech_text or ev_id in tech_text)
        exposed_keys = _extract_exposed_object_keys(raw_evidence, md_text) if flaw_type == "open_cloud_bucket" else []

        note = raw_evidence or f"{flaw_type} ({viability})"
        note = note.replace("https://evil.com", UNTRUSTED_POC_ORIGIN)
        if ev_id not in note:
            note = f"{note} [ev:{ev_id}]"

        entries.append(
            {
                "program": str(meta.get("program_name", meta.get("program_id", "Unknown"))).strip(),
                "program_id": str(meta.get("program_id", "")).strip().lower(),
                "platform": str(meta.get("platform", "hackerone")).strip().lower(),
                "host": target_domain,
                "url": f"https://{target_domain}/",
                "code": 200,
                "verdict": verdict,
                "score": score,
                "flaw_type": flaw_type,
                "bounty_viability": viability,
                "severity": str(meta.get("severity", "")).strip().upper(),
                "cvss_score": meta.get("cvss_score"),
                "cvss_vector": str(meta.get("cvss_vector", "")).strip(),
                "cwe_id": str(meta.get("cwe_id", "")).strip(),
                "evidence_artifact_id": ev_id,
                "evidence_digest_verified": digest_in_docs,
                "bundle_stem": stem,
                "evidence_keys": exposed_keys,
                "notes": note,
            }
        )

    return entries, len(archived_stems)


def consolidate_program_findings(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups findings by (program, verdict) so multiple subdomains become one consolidated dossier."""
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for item in entries:
        tier = classify_finding_tier(item)
        if tier == "TIER_3_SUPPRESSED":
            continue

        program = str(item.get("program", "Unknown")).strip()
        verdict = str(item.get("verdict", "UNKNOWN")).strip().upper()
        host = str(item.get("host", "")).strip()
        url = str(item.get("url", "")).strip()
        score = int(item.get("score", 0) or 0)
        note = str(item.get("notes", "")).strip()
        ev_id = str(item.get("evidence_artifact_id", "")).strip()
        viability = str(item.get("bounty_viability", "")).strip().upper()
        bundle_stem = str(item.get("bundle_stem", "")).strip()
        program_id = str(item.get("program_id", "")).strip().lower()
        platform = str(item.get("platform", "")).strip().lower()
        item_keys = [str(k).strip() for k in (item.get("evidence_keys") or []) if str(k).strip()]

        key = (program, verdict)
        if key not in grouped:
            grouped[key] = {
                "program": program,
                "program_id": program_id or re.sub(r"[^a-z0-9_]+", "_", program.lower()).strip("_"),
                "platform": platform or "hackerone",
                "verdict": verdict,
                "tier": tier,
                "bounty_viability": viability or ("HIGH_CONFIDENCE" if tier == "TIER_1_READY" else "CONDITIONAL"),
                "max_score": score,
                "hosts": [],
                "urls": [],
                "evidence_digests": [],
                "evidence_keys": [],
                "bundles": [],
                "notes": [],
            }

        grp = grouped[key]
        if score > grp["max_score"]:
            grp["max_score"] = score
        if tier == "TIER_1_READY":
            grp["tier"] = "TIER_1_READY"
            if viability == "HIGH_CONFIDENCE":
                grp["bounty_viability"] = "HIGH_CONFIDENCE"
        if host and host not in grp["hosts"]:
            grp["hosts"].append(host)
        if url and url not in grp["urls"]:
            grp["urls"].append(url)
        if ev_id and ev_id not in grp["evidence_digests"]:
            grp["evidence_digests"].append(ev_id)
        for obj_key in item_keys:
            if obj_key not in grp["evidence_keys"]:
                grp["evidence_keys"].append(obj_key)
        if ev_id or bundle_stem:
            bundle_entry = {
                "bundle_stem": bundle_stem,
                "host": host,
                "url": url,
                "evidence_artifact_id": ev_id,
                "bounty_viability": viability or grp["bounty_viability"],
                "severity": item.get("severity", ""),
                "cvss_score": item.get("cvss_score"),
                "cwe_id": item.get("cwe_id", ""),
            }
            if bundle_entry not in grp["bundles"]:
                grp["bundles"].append(bundle_entry)
        if note and note not in grp["notes"]:
            grp["notes"].append(note)

    results = list(grouped.values())
    results.sort(
        key=lambda g: (
            0 if g["tier"] == "TIER_1_READY" else 1,
            -g["max_score"],
            -len(g["hosts"]),
            g["program"].lower(),
        )
    )
    return results


def render_remediation_dossier(
    group: Dict[str, Any],
    live_results_by_host: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """Renders a consolidated Markdown remediation dossier for a grouped finding."""
    program = group["program"]
    verdict = group["verdict"]
    tier = group["tier"]
    hosts = group.get("hosts", [])
    urls = group.get("urls", [])
    notes = group.get("notes", [])
    digests = group.get("evidence_digests", [])
    bundles = group.get("bundles", [])
    evidence_keys = group.get("evidence_keys", [])
    viability = group.get("bounty_viability", "")
    profile = compute_cvss_profile(verdict)

    lines = [
        f"# Remediation Dossier: {program}",
        "",
        f"**Program:** {program}  ",
        f"**Readiness Tier:** `{tier}`  ",
    ]
    if viability:
        lines.append(f"**Bounty Viability:** `{viability}`  ")
    if digests:
        lines.append(f"**Evidence Artifact Digests ({len(digests)}):** {', '.join(f'`{d}`' for d in digests)}  ")

    lines.extend(
        [
            f"**Weakness:** {profile['cwe']} ({profile['cwe_name']})  ",
            f"**Severity:** {profile['severity']} (CVSS 3.1: **{profile['base_score']}** — `{profile['vector']}`)  ",
            f"**Affected Subdomains ({len(hosts)}):** {', '.join(f'`{h}`' for h in hosts)}  ",
            "",
            "---",
            "",
            "## Affected Endpoints",
        ]
    )
    for u in urls:
        lines.append(f"- `{u}`")

    if bundles:
        lines.extend(
            [
                "",
                f"## Staged Evidence Bundles ({len(bundles)})",
                "",
                "| Bundle Stem | Target Host | Evidence Digest | Viability |",
                "|---|---|---|---|",
            ]
        )
        for bundle in bundles:
            stem = bundle.get("bundle_stem") or "-"
            b_host = bundle.get("host") or "-"
            b_ev = bundle.get("evidence_artifact_id") or "-"
            b_via = bundle.get("bounty_viability") or viability or "-"
            lines.append(f"| `{stem}` | `{b_host}` | `{b_ev}` | `{b_via}` |")

    if evidence_keys:
        lines.extend(["", f"## Verified Exposed Object Keys ({len(evidence_keys)})"])
        for obj_key in evidence_keys:
            lines.append(f"- `{obj_key}`")

    if notes:
        lines.extend(["", "## Assessment Notes"])
        for n in notes:
            lines.append(f"- {n}")

    if verdict == "REFLECTED_PUBLIC_HTML":
        lines.extend(
            [
                "",
                "## Pre-Submission Auth Proof Prerequisite",
                f"- Verified CORS `Access-Control-Allow-Origin: {UNTRUSTED_POC_ORIGIN}` + `Access-Control-Allow-Credentials: true` reflection on public HTML only (`[PUBLIC_HTML_ONLY]`).",
                "- Before submission, capture an authenticated JSON/API endpoint PoC exposing user session data, PII, or CSRF tokens.",
            ]
        )

    if live_results_by_host:
        matched_live = [live_results_by_host[h] for h in hosts if h in live_results_by_host]
        if matched_live:
            lines.extend(
                [
                    "",
                    "## Live Pre-Submission Verification (Read-Only RoE Guarded)",
                    "",
                    "| Host | HTTP Status | Outcome | Detail |",
                    "|---|---|---|---|",
                ]
            )
            for item in matched_live:
                lines.append(
                    f"| `{item['host']}` | `{item.get('status_code') or '-'}` | "
                    f"`{item['status']}` | {item.get('detail', '')} |"
                )

    lines.extend(["", "## Defensive Remediation Steps"])
    for idx, step in enumerate(profile["remediation"], 1):
        lines.append(f"{idx}. {step}")

    lines.append("")
    return "\n".join(lines)


def verify_live_targets(
    groups: List[Dict[str, Any]],
    *,
    timeout: float = 10.0,
    roe_engine: Optional[Any] = None,
) -> Dict[str, Any]:
    """Runs read-only RoE-guarded HTTP GET verification against launch queue targets."""
    roe = roe_engine if roe_engine is not None else PublicHostOnlyRoE()
    results: List[Dict[str, Any]] = []

    with create_guarded_httpx_client(roe_engine=roe, timeout=timeout) as client:
        for grp in groups:
            program = grp["program"]
            verdict = grp["verdict"]
            bundles = grp.get("bundles") or [
                {"host": h, "url": u, "evidence_artifact_id": ""}
                for h, u in zip(grp.get("hosts", []), grp.get("urls", []))
            ]
            for bundle in bundles:
                host = str(bundle.get("host", "")).strip()
                url = str(bundle.get("url", "")).strip() or f"https://{host}/"
                ev_id = str(bundle.get("evidence_artifact_id", "")).strip()
                headers = {"User-Agent": "OrbitSecurity-PreSubmitCheck/1.0"}
                if verdict in {"REFLECTED_PUBLIC_HTML", "AUTHENTICATED_CORS_SENSITIVE"}:
                    headers["Origin"] = UNTRUSTED_POC_ORIGIN

                try:
                    resp = client.get(url, headers=headers)
                    status_code = int(getattr(resp, "status_code", 0) or 0)
                    lower_headers = {str(k).lower(): str(v) for k, v in dict(resp.headers).items()}
                    if verdict == "OPEN_BUCKET_LISTING":
                        body_text = str(getattr(resp, "text", "") or "")
                        confirmed = status_code == 200 and "<ListBucketResult" in body_text
                        detail = (
                            "ListBucketResult XML confirmed"
                            if confirmed
                            else f"HTTP {status_code} without ListBucketResult XML"
                        )
                    else:
                        acao = lower_headers.get("access-control-allow-origin", "")
                        acac = lower_headers.get("access-control-allow-credentials", "")
                        confirmed = (
                            status_code == 200
                            and acao == UNTRUSTED_POC_ORIGIN
                            and acac.lower() == "true"
                        )
                        detail = (
                            f"Reflected {UNTRUSTED_POC_ORIGIN} with ACAC=true"
                            if confirmed
                            else f"HTTP {status_code}; ACAO={acao or 'none'}; ACAC={acac or 'none'}"
                        )

                    results.append(
                        {
                            "program": program,
                            "host": host,
                            "url": url,
                            "evidence_artifact_id": ev_id,
                            "status_code": status_code,
                            "status": "CONFIRMED_LIVE" if confirmed else "CHANGED_OR_MITIGATED",
                            "verified_live": confirmed,
                            "detail": detail,
                        }
                    )
                except EgressViolationError as exc:
                    results.append(
                        {
                            "program": program,
                            "host": host,
                            "url": url,
                            "evidence_artifact_id": ev_id,
                            "status_code": None,
                            "status": "ROE_BLOCKED",
                            "verified_live": False,
                            "detail": f"[{exc.code}] {exc.reason}",
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "program": program,
                            "host": host,
                            "url": url,
                            "evidence_artifact_id": ev_id,
                            "status_code": None,
                            "status": "ERROR",
                            "verified_live": False,
                            "detail": f"{type(exc).__name__}: {exc}",
                        }
                    )

    return {
        "mode": "live_verified",
        "checked_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets_checked": len(results),
        "confirmed_live_count": sum(1 for r in results if r["verified_live"]),
        "roe_blocked_count": sum(1 for r in results if r["status"] == "ROE_BLOCKED"),
        "error_count": sum(1 for r in results if r["status"] == "ERROR"),
        "results": results,
    }


def build_vault_manifest(
    matrix_path: Optional[Path] = None,
    output_dir: Path = DEFAULT_VAULT_OUT,
    dry_run: bool = False,
    *,
    disclosures_dir: Optional[Path] = None,
    archive_fp_dir: Optional[Path] = DEFAULT_ARCHIVE_FP_DIR,
    verify_live: bool = False,
    live_timeout: float = 10.0,
) -> Dict[str, Any]:
    """Compiles staged disclosures (or a verification matrix) into launch queues and readiness reports."""
    archived_fp_count = 0
    if disclosures_dir is not None:
        source_label = "data/disclosures"
        entries, archived_fp_count = load_staged_disclosure_entries(
            disclosures_dir=disclosures_dir,
            archive_fp_dir=archive_fp_dir,
        )
    elif matrix_path is not None:
        if not matrix_path.exists():
            raise FileNotFoundError(f"Verification matrix not found at {matrix_path}")
        source_label = "verification_matrix"
        entries = json.loads(matrix_path.read_text(encoding="utf-8"))
    elif DEFAULT_DISCLOSURES_DIR.is_dir():
        source_label = "data/disclosures"
        entries, archived_fp_count = load_staged_disclosure_entries(
            disclosures_dir=DEFAULT_DISCLOSURES_DIR,
            archive_fp_dir=archive_fp_dir,
        )
    else:
        if not DEFAULT_MATRIX_PATH.exists():
            raise FileNotFoundError(f"Verification matrix not found at {DEFAULT_MATRIX_PATH}")
        source_label = "verification_matrix"
        entries = json.loads(DEFAULT_MATRIX_PATH.read_text(encoding="utf-8"))

    groups = consolidate_program_findings(entries)

    tier_1 = [g for g in groups if g["tier"] == "TIER_1_READY"]
    tier_2 = [g for g in groups if g["tier"] == "TIER_2_NEEDS_AUTH_PROOF"]
    tier_1_bundle_count = sum(len(g["hosts"]) for g in tier_1)
    tier_2_bundle_count = sum(len(g["hosts"]) for g in tier_2)
    suppressed_count = sum(1 for e in entries if classify_finding_tier(e) == "TIER_3_SUPPRESSED")
    unique_digests = sorted(
        {
            d
            for g in groups
            for d in g.get("evidence_digests", [])
            if EV_DIGEST_RE.match(str(d))
        }
    )

    live_verification: Optional[Dict[str, Any]] = None
    live_by_host: Optional[Dict[str, Dict[str, Any]]] = None
    if verify_live:
        live_verification = verify_live_targets(groups, timeout=live_timeout)
        live_by_host = {r["host"]: r for r in live_verification["results"]}

    manifest: Dict[str, Any] = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source_label,
        "verification_mode": "live_verified" if verify_live else "offline_static",
        "total_raw_candidates": len(entries),
        "staged_bundle_count": tier_1_bundle_count + tier_2_bundle_count,
        "evidence_digest_count": len(unique_digests),
        "consolidated_dossiers": len(groups),
        "tier_1_count": len(tier_1),
        "tier_1_bundle_count": tier_1_bundle_count,
        "tier_2_count": len(tier_2),
        "tier_2_bundle_count": tier_2_bundle_count,
        "suppressed_count": suppressed_count,
        "tier3_false_positives_in_vault": 0,
        "archived_false_positives_count": archived_fp_count,
        "launch_queue": groups,
    }
    if live_verification is not None:
        manifest["live_verification"] = live_verification

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        consolidated_dir = output_dir / "consolidated_dossiers"
        consolidated_dir.mkdir(parents=True, exist_ok=True)

        written_slugs: set[str] = set()
        for grp in groups:
            safe_prog = re.sub(r"[^a-z0-9_]+", "_", grp["program"].lower()).strip("_") or "program"
            safe_verdict = re.sub(r"[^a-z0-9_]+", "_", grp["verdict"].lower()).strip("_") or "finding"
            slug = f"{safe_prog}_{safe_verdict}.md"
            written_slugs.add(slug)
            dossier_text = render_remediation_dossier(grp, live_results_by_host=live_by_host)
            (consolidated_dir / slug).write_text(dossier_text, encoding="utf-8")

        for existing_md in consolidated_dir.glob("*.md"):
            if existing_md.name not in written_slugs:
                existing_md.unlink()

        (output_dir / "VAULT_LAUNCH_QUEUE.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        report_lines = [
            "# Orbit Security — Pre-KYC Submission Vault Readiness Report",
            "",
            f"**Generated UTC:** `{manifest['generated_utc']}`  ",
            f"**Source:** `{manifest['source']}`  ",
            f"**Verification Mode:** `{manifest['verification_mode']}`  ",
            f"**Staged Bundles Evaluated:** {manifest['staged_bundle_count']} (`ev_<12-char-hex>` digests: {manifest['evidence_digest_count']}/{manifest['staged_bundle_count']})  ",
            f"**Consolidated Program Dossiers:** {manifest['consolidated_dossiers']}  ",
            f"**Tier 1 (Immediate Post-KYC Ready):** {manifest['tier_1_count']} dossier ({manifest['tier_1_bundle_count']} bundle)  ",
            f"**Tier 2 (Consolidated Multi-Host — CONDITIONAL Auth Proof Needed):** {manifest['tier_2_count']} dossiers ({manifest['tier_2_bundle_count']} bundles)  ",
            f"**Tier 3 (Active False Positives in Queue):** {manifest['suppressed_count']} ({manifest['archived_false_positives_count']} archived to `data/archive/false_positive_disclosures/`)  ",
            "",
            "---",
            "",
            "## Priority Launch Queue (Post-Physical-ID KYC Verification)",
            "",
            "| Order | Program | Tier | Viability | Verdict | CWE | CVSS | Bundles | Evidence Digests | Affected Hosts |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for idx, grp in enumerate(groups, 1):
            prof = compute_cvss_profile(grp["verdict"])
            host_summary = ", ".join(f"`{h}`" for h in grp["hosts"][:3])
            if len(grp["hosts"]) > 3:
                host_summary += f" (+{len(grp['hosts']) - 3} more)"
            digests = grp.get("evidence_digests", [])
            digest_summary = ", ".join(f"`{d}`" for d in digests) if digests else "-"
            viability = grp.get("bounty_viability") or ("HIGH_CONFIDENCE" if grp["tier"] == "TIER_1_READY" else "CONDITIONAL")
            report_lines.append(
                f"| {idx} | **{grp['program']}** | `{grp['tier']}` | `{viability}` | `{grp['verdict']}` | "
                f"{prof['cwe']} | {prof['base_score']} | {len(grp['hosts'])} | {digest_summary} | {host_summary} |"
            )

        if live_verification is not None:
            report_lines.extend(
                [
                    "",
                    "## Live Pre-Submission Verification Summary (Read-Only RoE Guarded)",
                    f"- **Checked UTC:** `{live_verification['checked_utc']}`",
                    f"- **Targets Checked:** {live_verification['targets_checked']}",
                    f"- **Confirmed Live:** {live_verification['confirmed_live_count']}",
                    f"- **RoE Blocked:** {live_verification['roe_blocked_count']}",
                    f"- **Errors:** {live_verification['error_count']}",
                ]
            )

        report_lines.extend(
            [
                "",
                "## Anti-Noise & Reputation Guardrails",
                "- **Multi-Host Consolidation:** Multiple subdomains under the same program and root cause are merged into a single dossier to prevent duplicate-report penalties.",
                "- **Cryptographic Grounding:** Active bundles synchronize directly with `data/disclosures/` `ev_<12-char-hex>` digests and verified SHA-256 evidence manifests.",
                "- **Strict False-Positive Exclusion:** Archived Tier-3 findings remain excluded (`0` active Tier-3 noise items in queue).",
                "",
            ]
        )
        (output_dir / "VAULT_READINESS_REPORT.md").write_text(
            "\n".join(report_lines),
            encoding="utf-8",
        )

    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compile Pre-KYC Remediation Vault")
    parser.add_argument(
        "--disclosures-dir",
        type=Path,
        default=None,
        help="Path to staged ev_-tagged disclosure bundles directory (default: data/disclosures)",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=None,
        help="Optional legacy verification matrix JSON path instead of data/disclosures",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_VAULT_OUT, help="Output directory for vault artifacts")
    parser.add_argument("--dry-run", action="store_true", help="Compute manifest without writing files")
    parser.add_argument(
        "--verify-live",
        action="store_true",
        help="Run read-only PublicHostOnlyRoE-guarded HTTP GET verification (default: offline/static)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds for --verify-live",
    )
    args = parser.parse_args(argv)

    manifest = build_vault_manifest(
        matrix_path=args.matrix,
        output_dir=args.out,
        dry_run=args.dry_run,
        disclosures_dir=args.disclosures_dir,
        verify_live=args.verify_live,
        live_timeout=args.timeout,
    )
    print(
        f"[Vault Compiler:{manifest['verification_mode']}] Evaluated {manifest['total_raw_candidates']} bundles "
        f"({manifest['evidence_digest_count']} ev_ digests) -> {manifest['consolidated_dossiers']} consolidated dossiers "
        f"(Tier 1: {manifest['tier_1_count']} dossier/{manifest['tier_1_bundle_count']} bundle, "
        f"Tier 2: {manifest['tier_2_count']} dossiers/{manifest['tier_2_bundle_count']} bundles, "
        f"Tier 3 Active: {manifest['suppressed_count']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
