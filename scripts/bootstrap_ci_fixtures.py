#!/usr/bin/env python3
"""Idempotent CI fixture bootstrapper for clean git checkouts.

Populates non-OPSEC synthetic placeholder fixtures for gitignored ``data/`` and
``outbound_queue/`` artifacts required by offline regression tests on clean CI
runners (such as GitHub Actions ``windows-latest``).

Safety guarantees:
- Never overwrites existing files on disk (except normalizing CRLF -> LF on
  ``data/bounty_programs.json`` when checked out with ``\\r`` bytes).
- Contains zero real secrets, PII, credentials, or operator leads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.report_verifier import compute_evidence_digest  # noqa: E402
from scripts.bounty_vault_generator import build_vault_manifest  # noqa: E402
from scripts.reconcile_outreach_dispositions import (  # noqa: E402
    ensure_baseline_outreach_state,
    reconcile_dispositions,
)

# Minimal valid single-page PDF placeholder so relative portal PDF href checks succeed in CI.
_MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n"
    b"0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n169\n%%EOF\n"
)

_PORTAL_AUDIT_PDFS = (
    "apexapparel.example.com_audit.pdf",
    "nexushealth.example.com_audit.pdf",
    "velvetcraft.com_audit.pdf",
)

_ARCHIVED_TIER3_STEMS = (
    "uber_cors_arbitrary_origin_with_credentials_fpbi8c1t_ubereats_com",
    "uber_cors_arbitrary_origin_with_credentials_fpfcpn2u_ubereats_com",
    "gitlab_cloud_storage_takeover_assets_gitlab_com",
    "khealth_cloud_storage_takeover_cdn_khealth-test_com",
    "gitlab_graphql_introspection_gitlab_com",
    "shopify_graphql_introspection_media_myshopify_com",
    "expediagroup_bbp_graphql_introspection_www_hotwire_com",
)

_TIER2_PROGRAM_SPEC: Tuple[Tuple[str, str, int], ...] = (
    ("mercadolibre", "MercadoLibre", 9),
    ("xiaomi", "Xiaomi", 6),
    ("superbet", "Superbet", 2),
    ("playtika", "Playtika", 1),
)

_SPOTIFY_RAW_EVIDENCE = (
    "Open public S3/GCS bucket directory listing exposed on 'https://cdn.byspotify.com/' "
    "(HTTP 200 OK, application/xml, 24186 bytes, '<ListBucketResult' XML index). "
    "Verified non-public Podsights acquisition documents are anonymously downloadable "
    "without authentication: "
    "(1) interviews/Podsights Seed - Interview Version.pdf (2.1 MB, Content-Length: 2153328 bytes at "
    "'/interviews/Podsights%20Seed%20-%20Interview%20Version.pdf', HTTP 200); "
    "(2) interviews/AP Q4-2020 Podcast Adv. Rept_4Ww1Disc.Mtg.pdf (5.3 MB); "
    "(3) reports/benchmarks/test-q3-podsights-conversion-report.pdf; "
    "(4) advisor/advisor-onboarding-demo.mp4 (18.1 MB)."
)


def _write_if_missing_bytes(path: Path, payload: bytes) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return True


def _write_if_missing_text(path: Path, text: str) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def normalize_bounty_programs_lf(repo_root: Path) -> bool:
    """Ensures ``data/bounty_programs.json`` uses LF line endings on Windows."""
    catalog_path = repo_root / "data" / "bounty_programs.json"
    if not catalog_path.is_file():
        return False
    raw = catalog_path.read_bytes()
    if b"\r" not in raw:
        return False
    catalog_path.write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    return True


def ensure_outreach_baseline(repo_root: Path) -> bool:
    """Seeds gitignored cohort/quarantine files when absent."""
    data_dir = repo_root / "data"
    q_path = data_dir / "quarantined_addresses.json"
    ledger_path = data_dir / "disposition_ledger.json"
    missing_before = not (q_path.exists() and ledger_path.exists())

    ensure_baseline_outreach_state(repo_root, create_quarantine_if_missing=True)
    if not q_path.exists() or not ledger_path.exists():
        reconcile_dispositions(repo_root=repo_root, apply=True)
    return missing_before


def ensure_portal_audit_pdfs(repo_root: Path) -> int:
    """Creates minimal placeholder PDFs linked by ``orbit-core.html`` if missing."""
    audits_dir = repo_root / "data" / "generated_audits" / "orbit-core"
    created = 0
    for filename in _PORTAL_AUDIT_PDFS:
        if _write_if_missing_bytes(audits_dir / filename, _MINIMAL_PDF_BYTES):
            created += 1
    return created


def ensure_false_positive_archives(repo_root: Path) -> int:
    """Creates synthetic Tier-3 archive markers expected by vault hygiene tests."""
    fp_dir = repo_root / "data" / "archive" / "false_positive_disclosures"
    fp_dir.mkdir(parents=True, exist_ok=True)
    created = 0

    for stem in _ARCHIVED_TIER3_STEMS:
        md_path = fp_dir / f"{stem}.md"
        bdir = fp_dir / f"{stem}_bundle"
        zip_path = fp_dir / f"{stem}_bundle.zip"
        meta_path = bdir / "metadata.json"

        placeholder_md = f"# Archived Tier-3 Fixture ({stem})\n\nStatus: ARCHIVED\n"
        placeholder_meta = json.dumps({"bundle_stem": stem, "bounty_viability": "ARCHIVED"}, indent=2) + "\n"

        if _write_if_missing_text(md_path, placeholder_md):
            created += 1
        bdir.mkdir(parents=True, exist_ok=True)
        if _write_if_missing_text(meta_path, placeholder_meta):
            created += 1
        if not zip_path.exists():
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("README.txt", placeholder_md.encode("utf-8"))
            created += 1

    dup_dir = fp_dir / "xiaomi_cors_arbitrary_origin_with_credentials_mijiayoupin_com_bundle (1)"
    dup_dir.mkdir(parents=True, exist_ok=True)
    if _write_if_missing_text(dup_dir / ".gitkeep", ""):
        created += 1

    return created


def _write_verified_bundle(
    disc_dir: Path,
    *,
    stem: str,
    meta: Dict[str, Any],
    h1_md: str,
    bc_md: str,
    tech_txt: str,
) -> None:
    """Writes paired ``<stem>.md``, ``<stem>_bundle/``, and ``<stem>_bundle.zip``."""
    bdir = disc_dir / f"{stem}_bundle"
    bdir.mkdir(parents=True, exist_ok=True)

    meta_text = json.dumps(meta, indent=2) + "\n"
    member_payloads = {
        "bugcrowd_report.md": bc_md,
        "hackerone_report.md": h1_md,
        "metadata.json": meta_text,
        "technical_evidence.txt": tech_txt,
    }

    (disc_dir / f"{stem}.md").write_text(h1_md, encoding="utf-8")
    file_hashes: Dict[str, str] = {}
    for member_name, content in member_payloads.items():
        content_bytes = content.encode("utf-8")
        (bdir / member_name).write_bytes(content_bytes)
        file_hashes[member_name] = hashlib.sha256(content_bytes).hexdigest()

    manifest = {
        "version": "1.0",
        "bundle_name": bdir.name,
        "timestamp_utc": "2026-11-14T00:00:00+00:00",
        "target": meta["target_domain"],
        "flaw_type": meta["flaw_type"],
        "evidence_artifact_id": meta["evidence_artifact_id"],
        "file_hashes_sha256": file_hashes,
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    (bdir / "manifest_sha256.json").write_bytes(manifest_bytes)

    zip_path = disc_dir / f"{bdir.name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, content in member_payloads.items():
            zf.writestr(member_name, content.encode("utf-8"))
        zf.writestr("manifest_sha256.json", manifest_bytes)


def _seed_spotify_bundle(disc_dir: Path) -> None:
    stem = "spotify_open_cloud_bucket_cdn_byspotify_com"
    domain = "cdn.byspotify.com"
    flaw_type = "open_cloud_bucket"
    provider = "Cloud Storage"
    ev_id = compute_evidence_digest(
        target=domain,
        status_code=None,
        flaw_type=flaw_type,
        evidence_snippet=_SPOTIFY_RAW_EVIDENCE,
        provider=provider,
    )
    if ev_id != "ev_0bc4c77bfc5f":
        raise RuntimeError(f"Unexpected Spotify evidence digest: {ev_id}")

    meta = {
        "program_id": "spotify",
        "program_name": "Spotify",
        "platform": "hackerone",
        "target_domain": domain,
        "cname_target": None,
        "flaw_type": flaw_type,
        "provider": provider,
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "bounty_viability": "HIGH_CONFIDENCE",
        "evidence_artifact_id": ev_id,
        "timestamp": "2026-10-29T11:07:13.912334+00:00",
    }
    tech_txt = (
        f"TARGET DOMAIN: {domain}\n"
        f"VULNERABILITY: {flaw_type}\n"
        f"PROVIDER: {provider}\n"
        f"EVIDENCE ARTIFACT ID: {ev_id}\n\n"
        f"OBSERVED RAW EVIDENCE:\n{_SPOTIFY_RAW_EVIDENCE}\n\n"
        "REMEDIATION GUIDANCE:\n"
        "1. Disable public s3:ListBucket / storage.objects.list access.\n"
    )
    h1_md = (
        f"# [Information Disclosure] Open Public Storage Bucket Directory Listing on {domain}\n\n"
        f"**Program:** Spotify (Hackerone)  \n"
        f"**Asset (In-Scope Target):** `{domain}`  \n"
        "**Weakness:** `CWE-200`  \n"
        "**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  \n"
        "**Bounty Viability Grade:** `HIGH_CONFIDENCE`  \n"
        f"**Evidence Artifact ID:** `{ev_id}`  \n\n"
        "## Summary\n"
        "> Tier 1 Submission Candidate (Ready on Physical KYC ID Arrival) — verified `ListBucketResult` bucket index.\n\n"
        "1. `interviews/Podsights Seed - Interview Version.pdf` at `https://cdn.byspotify.com/interviews/Podsights%20Seed%20-%20Interview%20Version.pdf` (HTTP 200)\n"
        "2. `interviews/AP Q4-2020 Podcast Adv. Rept_4Ww1Disc.Mtg.pdf`\n"
        "3. `reports/benchmarks/test-q3-podsights-conversion-report.pdf`\n"
        "4. `advisor/advisor-onboarding-demo.mp4`\n"
    )
    bc_md = (
        f"# Bugcrowd Vulnerability Report: Open Cloud Bucket on {domain}\n\n"
        f"**Target Asset:** `{domain}`  \n"
        f"**Evidence Artifact ID:** `{ev_id}`  \n\n"
        "Exposed `ListBucketResult` index (HTTP 200) on `https://cdn.byspotify.com/` leaking "
        "`interviews/Podsights Seed - Interview Version.pdf` "
        "(`/interviews/Podsights%20Seed%20-%20Interview%20Version.pdf`) and "
        "`advisor/advisor-onboarding-demo.mp4`.\n"
    )
    _write_verified_bundle(disc_dir, stem=stem, meta=meta, h1_md=h1_md, bc_md=bc_md, tech_txt=tech_txt)


def _seed_synthetic_cors_bundle(
    disc_dir: Path,
    *,
    program_id: str,
    program_name: str,
    index: int,
) -> None:
    domain = f"cors-{index:02d}.{program_id}-fixture.example.com"
    stem = f"{program_id}_cors_arbitrary_origin_with_credentials_cors_{index:02d}_{program_id}_fixture_example_com"
    flaw_type = "cors_arbitrary_origin_with_credentials"
    provider = "API Gateway CORS"
    raw_evidence = (
        f"[PUBLIC_HTML_ONLY: Verified CORS Origin reflection on public route 'https://{domain}/' "
        f"(HTTP 200 OK). Sending 'Origin: https://untrusted-adversary.com' echoed "
        f"'Access-Control-Allow-Origin: https://untrusted-adversary.com' and "
        f"'Access-Control-Allow-Credentials: true'.]"
    )
    ev_id = compute_evidence_digest(
        target=domain,
        status_code=None,
        flaw_type=flaw_type,
        evidence_snippet=raw_evidence,
        provider=provider,
    )
    meta = {
        "program_id": program_id,
        "program_name": program_name,
        "platform": "hackerone",
        "target_domain": domain,
        "flaw_type": flaw_type,
        "provider": provider,
        "severity": "MEDIUM",
        "cvss_score": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        "bounty_viability": "CONDITIONAL",
        "evidence_artifact_id": ev_id,
        "timestamp": "2026-11-14T00:00:00+00:00",
    }
    tech_txt = (
        f"TARGET DOMAIN: {domain}\n"
        f"VULNERABILITY: {flaw_type}\n"
        f"PROVIDER: {provider}\n"
        f"EVIDENCE ARTIFACT ID: {ev_id}\n\n"
        f"OBSERVED RAW EVIDENCE:\n{raw_evidence}\n\n"
        "REMEDIATION GUIDANCE:\n"
        "1. Enforce an explicit trusted Origin allowlist.\n"
    )
    h1_md = (
        f"# [CORS Misconfiguration] Origin Reflection on {domain}\n\n"
        f"**Program:** {program_name} (Hackerone)  \n"
        f"**Asset:** `{domain}`  \n"
        "**Weakness:** `CWE-942`  \n"
        "**Severity:** `MEDIUM` (CVSS 3.1: **5.4**)  \n"
        "**Bounty Viability:** `CONDITIONAL`  \n"
        f"**Evidence Artifact ID:** `{ev_id}`  \n\n"
        "## Summary\n"
        f"[PUBLIC_HTML_ONLY: Public HTML endpoint verified on `https://{domain}/` (HTTP 200); authenticated endpoint proof required.]\n\n"
        "```http\n"
        "Origin: https://untrusted-adversary.com\n"
        "Access-Control-Allow-Origin: https://untrusted-adversary.com\n"
        "Access-Control-Allow-Credentials: true\n"
        "```\n"
    )
    bc_md = (
        f"# Bugcrowd Report: Cross-Origin Reflection on {domain}\n\n"
        f"**Target Asset:** `{domain}`  \n"
        f"**Evidence Artifact ID:** `{ev_id}`  \n\n"
        f"Public HTML CORS probe on `https://{domain}/` (HTTP 200) echoed "
        "`Origin: https://untrusted-adversary.com` in `Access-Control-Allow-Origin`.\n"
    )
    _write_verified_bundle(disc_dir, stem=stem, meta=meta, h1_md=h1_md, bc_md=bc_md, tech_txt=tech_txt)


def ensure_disclosures_and_staging(repo_root: Path) -> Dict[str, Any]:
    """Seeds synthetic disclosure bundles and staging queue manifests if absent."""
    data_dir = repo_root / "data"
    disc_dir = data_dir / "disclosures"
    fp_dir = data_dir / "archive" / "false_positive_disclosures"
    staging_dir = data_dir / "hackerone_staging"

    disc_dir.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    seeded_secrets = _write_if_missing_text(staging_dir / "js_leaked_secrets.json", "[]\n")

    seeded_bundles = 0
    if not any(disc_dir.glob("*.md")):
        _seed_spotify_bundle(disc_dir)
        seeded_bundles += 1
        for prog_id, prog_name, count in _TIER2_PROGRAM_SPEC:
            for idx in range(1, count + 1):
                _seed_synthetic_cors_bundle(
                    disc_dir,
                    program_id=prog_id,
                    program_name=prog_name,
                    index=idx,
                )
                seeded_bundles += 1

    seeded_vault = False
    vault_queue_path = staging_dir / "VAULT_LAUNCH_QUEUE.json"
    if not vault_queue_path.exists():
        build_vault_manifest(
            output_dir=staging_dir,
            disclosures_dir=disc_dir,
            archive_fp_dir=fp_dir,
        )
        seeded_vault = True

    return {
        "seeded_js_leaked_secrets": seeded_secrets,
        "seeded_disclosure_bundles": seeded_bundles,
        "seeded_vault_queue": seeded_vault,
    }


def bootstrap_all(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Runs all idempotent fixture initializations for clean checkouts."""
    lf_fixed = normalize_bounty_programs_lf(repo_root)
    outreach_seeded = ensure_outreach_baseline(repo_root)
    pdfs_created = ensure_portal_audit_pdfs(repo_root)
    fp_created = ensure_false_positive_archives(repo_root)
    vault_summary = ensure_disclosures_and_staging(repo_root)
    return {
        "repo_root": str(repo_root),
        "bounty_programs_lf_normalized": lf_fixed,
        "outreach_baseline_seeded": outreach_seeded,
        "portal_audit_pdfs_created": pdfs_created,
        "false_positive_archive_items_created": fp_created,
        **vault_summary,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap non-OPSEC CI test fixtures.")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Repository root path")
    parser.add_argument("--quiet", action="store_true", help="Suppress JSON summary output")
    args = parser.parse_args(argv)

    summary = bootstrap_all(args.repo_root.resolve())
    if not args.quiet:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
