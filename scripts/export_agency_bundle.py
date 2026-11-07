#!/usr/bin/env python3
"""scripts/export_agency_bundle.py: CLI for White-Label Client Remediation & Export Bundle Generator.

Usage:
  python scripts/export_agency_bundle.py --agency eastside-co
  python scripts/export_agency_bundle.py --agency eastside-co --output-dir data/test_bundles
  python scripts/export_agency_bundle.py --agency brand-studio --name "Brand Studio" --domains "brandstudio.io,app.brandstudio.io" --json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure src/ is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.client_bundle_exporter import ClientBundleExporter


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Orbit Security: White-Label Client Remediation & Export Bundle Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--agency",
        type=str,
        required=True,
        help="Agency identifier or slug (e.g. eastside-co, brand-studio)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Human-readable agency name (defaults to resolved agency retainer or title-cased slug)",
    )
    parser.add_argument(
        "--domains",
        type=str,
        default=None,
        help="Comma-separated client perimeter domains (e.g. 'domain1.com,domain2.com')",
    )
    parser.add_argument(
        "--primary-color",
        type=str,
        default=None,
        help="Custom primary brand hex color (e.g. '#0B132B')",
    )
    parser.add_argument(
        "--accent-color",
        type=str,
        default=None,
        help="Custom accent brand hex color (e.g. '#48CAE4')",
    )
    parser.add_argument(
        "--tagline",
        type=str,
        default=None,
        help="Agency tagline or value proposition statement",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default=None,
        help="Retainer tier name (e.g. 'Scale', 'Enterprise', 'Remediation')",
    )
    parser.add_argument(
        "--support-email",
        type=str,
        default=None,
        help="Designated security support contact email",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write generated bundle archives (defaults to data/client_bundles)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON to stdout",
    )

    args = parser.parse_args()

    # Parse domains list
    domains_list = None
    if args.domains:
        domains_list = [d.strip() for d in args.domains.split(",") if d.strip()]

    output_dir = Path(args.output_dir) if args.output_dir else None

    exporter = ClientBundleExporter(bundles_dir=output_dir)

    try:
        result = exporter.export_bundle(
            agency_slug=args.agency,
            agency_name=args.name,
            domains=domains_list,
            primary_color=args.primary_color,
            accent_color=args.accent_color,
            tagline=args.tagline,
            tier=args.tier,
            support_email=args.support_email,
            output_dir=output_dir,
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            bundle_p = result["bundle_path"]
            sha = result["sha256"]
            print("=" * 70)
            print("  ORBIT SECURITY — WHITE-LABEL CLIENT REMEDIATION BUNDLE")
            print("=" * 70)
            print(f"  Agency:       {result.get('agency_name')} ({result.get('agency_slug')})")
            print(f"  Bundle ZIP:   {bundle_p}")
            print(f"  SHA-256:      {sha}")
            print(f"  Generated At: {result.get('generated_at')}")
            print("-" * 70)
            print("  Archive Manifest Files:")
            for f in result.get("files", []):
                print(f"    - {f}")
            print("=" * 70)
            print("  [OK] Atomic package created successfully.")

        return 0
    except Exception as ex:
        if args.json:
            print(json.dumps({"ok": False, "error": str(ex)}, indent=2))
        else:
            print(f"[ERROR] Failed to export agency bundle: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
