#!/usr/bin/env python3
"""Sorts staged Orbit Security disclosure bundles into HackerOne submission tiers.

Classifies ``data/disclosures/`` bundles using ``metadata.json`` (including
``flaw_type``, ``bounty_viability``, and ``evidence_artifact_id`` digests) and
report evidence without letting ``CWE-200`` archival rules shadow verified
Tier-1 ``open_cloud_bucket`` findings.
"""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = REPO_ROOT / "data"


def classify_disclosure(
    md_path: Path,
    metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Classifies a disclosure markdown + optional metadata into (tier_bucket, reason)."""
    content = md_path.read_text(encoding="utf-8")
    meta = metadata or {}
    flaw_type = str(meta.get("flaw_type", "")).strip().lower()
    viability = str(meta.get("bounty_viability", "")).strip().upper()
    ev_id = str(meta.get("evidence_artifact_id", "")).strip()
    ev_suffix = f" [{ev_id}]" if ev_id else ""

    if viability in {"FALSE_POSITIVE", "ARCHIVED", "SUPPRESSED", "OUT_OF_SCOPE"}:
        return "archive", f"Archived or excluded false positive{ev_suffix}"

    # Check verified Tier-1 Open Cloud Bucket before CWE-200 GraphQL suppression rules
    if flaw_type == "open_cloud_bucket" or "Open Cloud Bucket" in content:
        if viability in {"HIGH_CONFIDENCE", "VERIFIED"} or "Podsights" in content or "Tier 1 Submission Candidate" in content:
            return "ready", f"Verified open storage bucket listing with sensitive object proofs{ev_suffix}"
        return "verify", f"Open storage bucket listing — confirm non-public object keys{ev_suffix}"

    if flaw_type == "mail_spoofing" or "Mail Spoofing" in content or "CWE-290" in content:
        return "archive", f"Missing DMARC/SPF — universally excluded from bug bounties{ev_suffix}"

    if flaw_type == "graphql_introspection" or "Graphql Introspection" in content:
        return "archive", f"GraphQL introspection on public schema — excluded non-exploitable baseline{ev_suffix}"

    if "No dangling CNAME" in content or (
        flaw_type == "cloud_storage_takeover" and viability not in {"HIGH_CONFIDENCE", "VERIFIED"}
    ):
        return "archive", f"No dangling CNAME (CDN/proxy false positive){ev_suffix}"

    if flaw_type in {"cors_arbitrary_origin_with_credentials", "cors_null_origin_with_credentials"} or (
        "Cors Arbitrary Origin With Credentials" in content or "CWE-942" in content
    ):
        if viability in {"HIGH_CONFIDENCE", "VERIFIED"} and "[PUBLIC_HTML_ONLY" not in content:
            return "ready", f"Verified credentialed CORS reflection on authenticated endpoint{ev_suffix}"
        return "verify", f"CORS credentials reflected (CONDITIONAL) — requires authenticated endpoint proof{ev_suffix}"

    if "CWE-200" in content:
        return "archive", f"Informational CWE-200 observation without exploit proof{ev_suffix}"

    return "archive", f"Unclassified or informational finding{ev_suffix}"


def triage_disclosures(
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Classifies active disclosures under ``data_dir / 'disclosures'`` into HackerOne staging tiers."""
    disc_dir = data_dir / "disclosures"
    staging_dir = data_dir / "hackerone_staging"

    ready_dir = staging_dir / "01_ready_for_submission"
    verify_dir = staging_dir / "02_needs_session_verification"
    archive_dir = staging_dir / "03_out_of_scope_archive"

    md_files = sorted(disc_dir.glob("*.md"))
    categorized: Dict[str, List[Tuple[str, str]]] = {"ready": [], "verify": [], "archive": []}

    dest_map = {"ready": ready_dir, "verify": verify_dir, "archive": archive_dir}
    if not dry_run:
        for d in dest_map.values():
            d.mkdir(parents=True, exist_ok=True)

    for md in md_files:
        stem = md.stem
        bundle_dir = disc_dir / f"{stem}_bundle"
        meta_path = bundle_dir / "metadata.json"
        meta: Dict[str, Any] = {}
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))

        bucket, reason = classify_disclosure(md, metadata=meta)
        categorized[bucket].append((md.name, reason))

        if not dry_run:
            dest = dest_map[bucket]
            shutil.copy2(md, dest / md.name)
            zip_path = disc_dir / f"{stem}_bundle.zip"
            if zip_path.is_file():
                shutil.copy2(zip_path, dest / zip_path.name)

    manifest_path = staging_dir / "TRIAGE_MANIFEST.md"
    if not dry_run:
        today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        lines = [
            "# HackerOne Staging Triage Manifest",
            "",
            f"Generated on {today_str}.",
            "",
            "## 1. Tier-1 Ready for Submission",
            "| File | Reason / Digest |",
            "| :--- | :--- |",
        ]
        for name, reason in categorized["ready"]:
            lines.append(f"| `{name}` | {reason} |")

        lines.extend(
            [
                "",
                "## 2. Tier-2 Candidates (Needs Authenticated Session/PII Verification)",
                "Verified credentialed CORS reflection on public HTML (`CONDITIONAL`); attach authenticated JSON/API session proof before submitting.",
                "",
                "| File | Reason / Target |",
                "| :--- | :--- |",
            ]
        )
        for name, reason in categorized["verify"]:
            lines.append(f"| `{name}` | {reason} |")

        lines.extend(
            [
                "",
                "## 3. Archived / Out of Scope (DO NOT SUBMIT)",
                "Submitting unverified or excluded classes risks N/A closures and HackerOne reputation penalties.",
                "",
                "| File | Reason for Exclusion |",
                "| :--- | :--- |",
            ]
        )
        for name, reason in sorted(categorized["archive"]):
            lines.append(f"| `{name}` | {reason} |")

        lines.append("")
        manifest_path.write_text("\n".join(lines), encoding="utf-8")

    return {
        "total_disclosures": len(md_files),
        "ready": categorized["ready"],
        "verify": categorized["verify"],
        "archive": categorized["archive"],
        "manifest_path": str(manifest_path),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Triage staged disclosures into HackerOne tiers")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Orbit data root directory")
    parser.add_argument("--dry-run", action="store_true", help="Classify disclosures without writing staging copies")
    args = parser.parse_args(argv)

    summary = triage_disclosures(data_dir=args.data_dir, dry_run=args.dry_run)
    print(f"Total markdown disclosures evaluated: {summary['total_disclosures']}")
    print(f"Ready for Direct Submission (Tier 1): {len(summary['ready'])}")
    print(f"Needs Session Verification (Tier 2): {len(summary['verify'])}")
    print(f"Archived / Out of Scope: {len(summary['archive'])}")
    if not args.dry_run:
        print(f"Wrote triage manifest to: {summary['manifest_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
