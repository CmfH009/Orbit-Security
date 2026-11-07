#!/usr/bin/env python3
"""Orbit Security — Pre-KYC Remediation Vault & Submission Readiness Compiler.

Compiles local audit and verification matrices into deduplicated, program-grouped
remediation dossiers with CWE classification, CVSS v3.1 scoring, and defensive
remediation steps. Enforces strict anti-noise quality gates so multi-subdomain
findings are consolidated into single high-signal program dossiers.

Usage:
    .venv\\Scripts\\python.exe scripts\\bounty_vault_generator.py
    .venv\\Scripts\\python.exe scripts\\bounty_vault_generator.py --dry-run
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX_PATH = REPO_ROOT / "data" / "hackerone_staging" / "live_verification_matrix.json"
DEFAULT_VAULT_OUT = REPO_ROOT / "data" / "hackerone_staging"

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
    """Classifies a verification matrix entry into a submission readiness tier."""
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


def consolidate_program_findings(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups findings by (program, verdict) so multiple subdomains become one consolidated dossier."""
    grouped: Dict[tuple[str, str], Dict[str, Any]] = {}

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

        key = (program, verdict)
        if key not in grouped:
            grouped[key] = {
                "program": program,
                "verdict": verdict,
                "tier": tier,
                "max_score": score,
                "hosts": [],
                "urls": [],
                "notes": [],
            }

        grp = grouped[key]
        if score > grp["max_score"]:
            grp["max_score"] = score
        if tier == "TIER_1_READY":
            grp["tier"] = "TIER_1_READY"
        if host and host not in grp["hosts"]:
            grp["hosts"].append(host)
        if url and url not in grp["urls"]:
            grp["urls"].append(url)
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


def render_remediation_dossier(group: Dict[str, Any]) -> str:
    """Renders a consolidated Markdown remediation dossier for a grouped finding."""
    program = group["program"]
    verdict = group["verdict"]
    tier = group["tier"]
    hosts = group.get("hosts", [])
    urls = group.get("urls", [])
    notes = group.get("notes", [])
    profile = compute_cvss_profile(verdict)

    lines = [
        f"# Remediation Dossier: {program}",
        "",
        f"**Program:** {program}  ",
        f"**Readiness Tier:** `{tier}`  ",
        f"**Weakness:** {profile['cwe']} ({profile['cwe_name']})  ",
        f"**Severity:** {profile['severity']} (CVSS 3.1: **{profile['base_score']}** — `{profile['vector']}`)  ",
        f"**Affected Subdomains ({len(hosts)}):** {', '.join(f'`{h}`' for h in hosts)}  ",
        "",
        "---",
        "",
        "## Affected Endpoints",
    ]
    for u in urls:
        lines.append(f"- `{u}`")

    if notes:
        lines.extend(["", "## Assessment Notes"])
        for n in notes:
            lines.append(f"- {n}")

    lines.extend(["", "## Defensive Remediation Steps"])
    for idx, step in enumerate(profile["remediation"], 1):
        lines.append(f"{idx}. {step}")

    lines.append("")
    return "\n".join(lines)


def build_vault_manifest(
    matrix_path: Path = DEFAULT_MATRIX_PATH,
    output_dir: Path = DEFAULT_VAULT_OUT,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Compiles the verification matrix into consolidated launch queues and readiness reports."""
    if not matrix_path.exists():
        raise FileNotFoundError(f"Verification matrix not found at {matrix_path}")

    entries = json.loads(matrix_path.read_text(encoding="utf-8"))
    groups = consolidate_program_findings(entries)

    tier_1 = [g for g in groups if g["tier"] == "TIER_1_READY"]
    tier_2 = [g for g in groups if g["tier"] == "TIER_2_NEEDS_AUTH_PROOF"]
    suppressed_count = sum(1 for e in entries if classify_finding_tier(e) == "TIER_3_SUPPRESSED")

    manifest: Dict[str, Any] = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_raw_candidates": len(entries),
        "consolidated_dossiers": len(groups),
        "tier_1_count": len(tier_1),
        "tier_2_count": len(tier_2),
        "suppressed_count": suppressed_count,
        "launch_queue": groups,
    }

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        consolidated_dir = output_dir / "consolidated_dossiers"
        consolidated_dir.mkdir(parents=True, exist_ok=True)

        for grp in groups:
            safe_prog = re.sub(r"[^a-z0-9_]+", "_", grp["program"].lower()).strip("_") or "program"
            safe_verdict = re.sub(r"[^a-z0-9_]+", "_", grp["verdict"].lower()).strip("_") or "finding"
            slug = f"{safe_prog}_{safe_verdict}.md"
            dossier_text = render_remediation_dossier(grp)
            (consolidated_dir / slug).write_text(dossier_text, encoding="utf-8")

        (output_dir / "VAULT_LAUNCH_QUEUE.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        report_lines = [
            "# 🛡️ Orbit Security — Pre-KYC Submission Vault Readiness Report",
            "",
            f"**Generated UTC:** `{manifest['generated_utc']}`  ",
            f"**Raw Candidates Evaluated:** {manifest['total_raw_candidates']}  ",
            f"**Consolidated Program Dossiers:** {manifest['consolidated_dossiers']}  ",
            f"**Tier 1 (Immediate Post-KYC Ready):** {manifest['tier_1_count']}  ",
            f"**Tier 2 (Consolidated Multi-Host — Needs Auth Session Proof):** {manifest['tier_2_count']}  ",
            f"**Tier 3 (Suppressed Low-Signal / Dead):** {manifest['suppressed_count']}  ",
            "",
            "---",
            "",
            "## Priority Launch Queue (Post-DMV KYC Verification)",
            "",
            "| Order | Program | Tier | Verdict | CWE | CVSS | Affected Hosts |",
            "|---|---|---|---|---|---|---|",
        ]
        for idx, grp in enumerate(groups, 1):
            prof = compute_cvss_profile(grp["verdict"])
            host_summary = ", ".join(f"`{h}`" for h in grp["hosts"][:3])
            if len(grp["hosts"]) > 3:
                host_summary += f" (+{len(grp['hosts']) - 3} more)"
            report_lines.append(
                f"| {idx} | **{grp['program']}** | `{grp['tier']}` | `{grp['verdict']}` | "
                f"{prof['cwe']} | {prof['base_score']} | {host_summary} |"
            )

        report_lines.extend([
            "",
            "## Anti-Noise & Reputation Guardrails",
            "- **Multi-Host Consolidation:** Multiple subdomains under the same program and root cause are merged into a single dossier to prevent duplicate-report penalties.",
            "- **Strict Suppression:** Unverified, non-200, or low-severity hygiene items (`score < 5`) are automatically excluded from the submission queue.",
            "",
        ])
        (output_dir / "VAULT_READINESS_REPORT.md").write_text(
            "\n".join(report_lines), encoding="utf-8"
        )

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile Pre-KYC Remediation Vault")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH, help="Path to verification matrix JSON")
    parser.add_argument("--out", type=Path, default=DEFAULT_VAULT_OUT, help="Output directory for vault artifacts")
    parser.add_argument("--dry-run", action="store_true", help="Compute manifest without writing files")
    args = parser.parse_args()

    manifest = build_vault_manifest(
        matrix_path=args.matrix,
        output_dir=args.out,
        dry_run=args.dry_run,
    )
    print(
        f"[Vault Compiler] Evaluated {manifest['total_raw_candidates']} candidates -> "
        f"{manifest['consolidated_dossiers']} consolidated dossiers "
        f"(Tier 1 Ready: {manifest['tier_1_count']}, Tier 2 Consolidated: {manifest['tier_2_count']}, "
        f"Suppressed: {manifest['suppressed_count']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
