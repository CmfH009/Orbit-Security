#!/usr/bin/env python3
"""Orbit Security: Cohort Outreach Audit Generator.

Scans each agency prospect's primary portfolio domain and generates a
co-branded perimeter-hygiene audit (PDF + Markdown) for outreach.

Usage:
    # Preview what would be done for the first 3 prospects
    python scripts/run_cohort_outreach.py --dry-run --limit 3

    # Scan only agencies whose name contains "Blue" (case-insensitive)
    python scripts/run_cohort_outreach.py --agency "Blue"

    # Run a limited batch with a custom output directory
    python scripts/run_cohort_outreach.py --limit 10 --output-dir out/audits
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure local src/ is on sys.path (same pattern as other scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.models import AgencyBranding
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner

DEFAULT_PROSPECTS_PATH = PROJECT_ROOT / "data" / "new_prospects.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "generated_audits"
RATE_LIMIT_SLEEP = 0.5  # seconds between scans (DNS-polite)


def slugify(name: str) -> str:
    """Convert an agency name to a filesystem-safe directory slug."""
    slug = (name or "unknown-agency").lower().strip()
    for ch in (" ", ".", "/", "_"):
        slug = slug.replace(ch, "-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def pick_domain(prospect: Dict[str, Any]) -> str:
    """First portfolio domain, falling back to the agency domain."""
    portfolios = prospect.get("portfolio_domains") or []
    if portfolios:
        return str(portfolios[0])
    return str(prospect.get("agency_domain", ""))


def build_branding(prospect: Dict[str, Any]) -> AgencyBranding:
    """Build a realistic, per-agency co-branding block."""
    agency_name = str(prospect.get("agency_name", "Unknown Agency"))
    agency_domain = str(prospect.get("agency_domain", "example.com"))
    return AgencyBranding(
        agency_name=agency_name,
        support_email=str(prospect.get("contact_email", f"hello@{agency_domain}")),
        website=f"https://{agency_domain}",
    )


async def scan_one(
    scanner: OrbitSecurityScanner, domain: str, branding: AgencyBranding
):
    """Run a single async domain scan."""
    return await scanner.scan_domain(domain, agency_branding=branding)


def write_reports(
    result, domain: str, agency_slug: str, output_dir: Path
) -> Tuple[str, str]:
    """Write PDF + Markdown audit reports. Returns (pdf_path, md_path)."""
    agency_dir = output_dir / agency_slug
    agency_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = agency_dir / f"{domain}_audit.pdf"
    md_path = agency_dir / f"{domain}_audit.md"

    ReportGenerator.generate_pdf(result, str(pdf_path))
    md_content = ReportGenerator.generate_markdown(result)
    md_path.write_text(md_content, encoding="utf-8")

    return str(pdf_path), str(md_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Orbit Security: Cohort Outreach Audit Generator"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max prospects to process (default: all)",
    )
    parser.add_argument(
        "--agency",
        type=str,
        default=None,
        help="Only process agencies whose name contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without scanning or writing files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_OUTPUT_DIR),
        help="Custom output directory (default: data/generated_audits)",
    )
    args = parser.parse_args()

    prospects_path = DEFAULT_PROSPECTS_PATH
    if not prospects_path.exists():
        print(f"[❌] Prospects file not found: {prospects_path}")
        sys.exit(1)

    with open(prospects_path, "r", encoding="utf-8") as f:
        prospects: List[Dict[str, Any]] = json.load(f)

    # Agency substring filter (case-insensitive)
    if args.agency:
        needle = args.agency.lower()
        prospects = [
            p
            for p in prospects
            if needle in str(p.get("agency_name", "")).lower()
        ]

    # Limit
    if args.limit is not None:
        prospects = prospects[: args.limit]

    output_dir = Path(args.output_dir)

    print("=" * 70)
    print("🛡️  ORBIT SECURITY: COHORT OUTREACH AUDIT GENERATOR")
    print("=" * 70)
    print(f"Prospects file : {prospects_path}")
    print(f"Prospects to process : {len(prospects)}")
    print(f"Output dir     : {output_dir}")
    print(f"Dry run        : {args.dry_run}")
    print("=" * 70)

    if args.dry_run:
        print("\n[DRY-RUN] No scanning or file writes will be performed.\n")
        for idx, p in enumerate(prospects, 1):
            domain = pick_domain(p)
            agency_slug = slugify(str(p.get("agency_name", "unknown")))
            agency_dir = output_dir / agency_slug
            print(f"[{idx}/{len(prospects)}] {p.get('agency_name')}")
            print(f"    Domain : {domain}")
            print(f"    PDF    : {agency_dir / f'{domain}_audit.pdf'}")
            print(f"    MD     : {agency_dir / f'{domain}_audit.md'}")
        print("\n[✔] Dry-run complete. Run without --dry-run to execute.")
        return

    scanner = OrbitSecurityScanner()
    processed = 0
    failed = 0

    for idx, p in enumerate(prospects, 1):
        agency_name = str(p.get("agency_name", "Unknown Agency"))
        domain = pick_domain(p)
        branding = build_branding(p)
        agency_slug = slugify(agency_name)

        print(f"\n[{idx}/{len(prospects)}] {agency_name} — {domain}")
        try:
            result = asyncio.run(scan_one(scanner, domain, branding))
            pdf_path, md_path = write_reports(
                result, domain, agency_slug, output_dir
            )
            print(
                f"    Score: {result.score}/100 | "
                f"Grade: {result.grade} | "
                f"Findings: {len(result.findings)}"
            )
            print(f"    PDF : {pdf_path}")
            print(f"    MD  : {md_path}")
            processed += 1
        except Exception as e:
            failed += 1
            print(f"    [❌] Scan failed for {domain}: {e}")

        # DNS-polite rate limiting between scans (skip after the last one)
        if idx < len(prospects):
            time.sleep(RATE_LIMIT_SLEEP)

    print("\n" + "=" * 70)
    print(f"✓ Cohort outreach complete: {processed} succeeded, {failed} failed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
