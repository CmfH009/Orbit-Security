#!/usr/bin/env python3
"""Classifier-safe, read-only vault metadata inspector for orbit-security.

Reads only structured JSON metadata (`metadata.json` in disclosure bundles and
`VAULT_LAUNCH_QUEUE.json`) without loading narrative `.md` or `.txt` reports.
Use `--redact-domains` when summarizing findings in cloud LLM sessions.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DISCLOSURES_DIR = REPO_ROOT / "data" / "disclosures"
DEFAULT_STAGING_DIR = REPO_ROOT / "data" / "hackerone_staging"


def _load_staging_digests(staging_dir: Path) -> dict[tuple[str, str], str]:
    queue_path = staging_dir / "VAULT_LAUNCH_QUEUE.json"
    if not queue_path.is_file():
        return {}
    try:
        data = json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}

    digests: dict[tuple[str, str], str] = {}
    for item in data.get("launch_queue", []):
        prog_id = str(item.get("program_id", "")).strip().lower()
        for bundle in item.get("bundles", []):
            host = str(bundle.get("host", "")).strip().lower()
            digest = str(bundle.get("evidence_artifact_id", "")).strip()
            if prog_id and host and digest:
                digests[(prog_id, host)] = digest
    return digests


def _iter_bundle_metadata(disclosures_dir: Path) -> list[dict[str, Any]]:
    if not disclosures_dir.is_dir():
        return []

    by_stem: dict[str, dict[str, Any]] = {}

    for entry in sorted(disclosures_dir.iterdir()):
        if entry.is_dir() and entry.name.endswith("_bundle") and "(1)" not in entry.name:
            meta_file = entry / "metadata.json"
            if meta_file.is_file():
                try:
                    stem = entry.name[: -len("_bundle")]
                    by_stem[stem] = json.loads(meta_file.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue

    for zp in sorted(disclosures_dir.glob("*_bundle.zip")):
        if "(1)" in zp.name:
            continue
        stem = zp.name[: -len("_bundle.zip")]
        if stem in by_stem:
            continue
        try:
            with zipfile.ZipFile(zp) as zf:
                if "metadata.json" in zf.namelist():
                    by_stem[stem] = json.loads(zf.read("metadata.json").decode("utf-8", errors="replace"))
        except Exception:
            continue

    return [by_stem[k] for k in sorted(by_stem)]


def collect_vault_records(
    disclosures_dir: Path = DEFAULT_DISCLOSURES_DIR,
    staging_dir: Path = DEFAULT_STAGING_DIR,
    *,
    program: str | None = None,
) -> list[dict[str, Any]]:
    """Collects structured metadata records from disclosures and compares against staging."""
    staging_digests = _load_staging_digests(staging_dir)
    program_filter = program.strip().lower() if program else None

    records: list[dict[str, Any]] = []
    for meta in _iter_bundle_metadata(disclosures_dir):
        prog_id = str(meta.get("program_id", "")).strip().lower()
        if program_filter and prog_id != program_filter:
            continue

        host = str(meta.get("target_domain", "")).strip()
        digest = str(meta.get("evidence_artifact_id", "")).strip()
        staged_digest = staging_digests.get((prog_id, host.lower()), "")
        records.append(
            {
                "program_id": prog_id,
                "program_name": str(meta.get("program_name", "")).strip(),
                "host": host,
                "flaw_type": str(meta.get("flaw_type", "")).strip(),
                "severity": str(meta.get("severity", "")).strip(),
                "cvss_score": meta.get("cvss_score"),
                "bounty_viability": str(meta.get("bounty_viability", "")).strip(),
                "evidence_artifact_id": digest,
                "timestamp": str(meta.get("timestamp", "")).strip(),
                "staging_digest": staged_digest or None,
                "staging_drift": bool(staged_digest and digest and staged_digest != digest),
            }
        )
    return records


def redact_records_domains(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministically replaces target hostnames with synthetic host-NN.example.test labels."""
    host_map: dict[str, str] = {}
    redacted: list[dict[str, Any]] = []
    for rec in records:
        row = dict(rec)
        raw_host = str(row.get("host", "")).strip().lower()
        if raw_host:
            if raw_host not in host_map:
                host_map[raw_host] = f"host-{len(host_map) + 1:02d}.example.test"
            row["host"] = host_map[raw_host]
        redacted.append(row)
    return redacted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classifier-safe structured vault inspector")
    parser.add_argument("--disclosures-dir", type=Path, default=DEFAULT_DISCLOSURES_DIR)
    parser.add_argument("--staging-dir", type=Path, default=DEFAULT_STAGING_DIR)
    parser.add_argument("--program", default=None, help="Filter by program_id (e.g., paypal)")
    parser.add_argument(
        "--redact-domains",
        action="store_true",
        help="Replace live target hostnames with synthetic host-NN.example.test aliases",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args(argv)

    records = collect_vault_records(args.disclosures_dir, args.staging_dir, program=args.program)
    if args.redact_domains:
        records = redact_records_domains(records)

    if args.json:
        print(json.dumps(records, indent=2))
        return 0

    if not records:
        print("No matching vault records found.")
        return 0

    print(
        f"{'PROGRAM':<14} {'HOST':<24} {'VIABILITY':<16} {'DISC_DIGEST':<16} "
        f"{'STAG_DIGEST':<16} {'DRIFT':<6} {'TIMESTAMP'}"
    )
    print("-" * 114)
    for r in records:
        print(
            f"{r['program_id']:<14} {r['host'][:23]:<24} {r['bounty_viability']:<16} "
            f"{(r['evidence_artifact_id'] or '-'):<16} {(r['staging_digest'] or '-'):<16} "
            f"{str(r['staging_drift']):<6} {r['timestamp']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
