"""orbit_security.tools.compact_radar_feed: Radar Payload Compaction Tool.
========================================================================
Compacts 250,000+ raw vulnerability records into an ultra-fast, lightweight
static JSON dataset (docs/assets/kev_epss_radar.json) for client-side rendering
on GitHub Pages in <50ms.

Filtering Strategy:
1. All official CISA Known Exploited Vulnerabilities (~1,200 entries).
2. High-threat non-KEV CVEs filtered to EPSS score >= 0.50 or percentile >= 0.97.
3. Pre-joined and minified with zero whitespace (under 250 KB target).
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orbit_security.tools.compact_radar_feed")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DOCS_ASSETS = REPO_ROOT / "docs" / "assets"
LANDING_ASSETS = REPO_ROOT / "landing" / "assets"
DEFAULT_OUTPUT_FILE = DOCS_ASSETS / "kev_epss_radar.json"


def compact_radar_dataset(
    cisa_kev_data: Dict[str, Any],
    epss_data: Dict[str, Dict[str, Any]],
    output_path: Optional[Path] = None,
    sync_to_landing: bool = True,
    epss_threshold: float = 0.50,
    percentile_threshold: float = 0.97,
) -> Dict[str, Any]:
    """Pre-joins CISA KEV and EPSS into a high-density, minified static payload."""
    vulnerabilities = cisa_kev_data.get("vulnerabilities", [])
    kev_map: Dict[str, Dict[str, Any]] = {}

    for v in vulnerabilities:
        cve = v.get("cveID", "").strip().upper()
        if not cve:
            continue
        kev_map[cve] = {
            "cve": cve,
            "vendor": v.get("vendorProject", "Unknown"),
            "product": v.get("product", "Unknown"),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "short_description": v.get("shortDescription", ""),
            "action_required": v.get("requiredAction", "Patch immediately"),
            "due_date": v.get("dueDate", ""),
            "is_cisa_kev": True,
            "epss": 0.0,
            "percentile": 0.0,
        }

    # Enrich KEVs with EPSS scores
    for cve, record in kev_map.items():
        epss_info = epss_data.get(cve)
        if epss_info:
            try:
                record["epss"] = float(epss_info.get("epss", 0.0))
                record["percentile"] = float(epss_info.get("percentile", 0.0))
            except (ValueError, TypeError):
                pass

    # Extract high-velocity non-KEV vulnerabilities
    non_kev_high_velocity: Dict[str, Dict[str, Any]] = {}
    for cve, epss_info in epss_data.items():
        cve_upper = cve.strip().upper()
        if cve_upper in kev_map:
            continue  # Already captured in KEV map
        try:
            score = float(epss_info.get("epss", 0.0))
            perc = float(epss_info.get("percentile", 0.0))
        except (ValueError, TypeError):
            continue

        if score >= epss_threshold or perc >= percentile_threshold:
            non_kev_high_velocity[cve_upper] = {
                "cve": cve_upper,
                "vendor": epss_info.get("vendor", "Multiple / Unknown"),
                "product": epss_info.get("product", "Ecosystem Component"),
                "vulnerability_name": f"High Velocity Threat ({cve_upper})",
                "date_added": epss_info.get("date", ""),
                "short_description": "Observed high weaponization velocity in the wild.",
                "action_required": "Prioritize patching based on EPSS weaponization velocity.",
                "due_date": "",
                "is_cisa_kev": False,
                "epss": score,
                "percentile": perc,
            }

    combined_entries = list(kev_map.values()) + list(non_kev_high_velocity.values())
    combined_entries.sort(key=lambda x: (x["is_cisa_kev"], x["epss"]), reverse=True)

    compact_payload = {
        "generated_at": cisa_kev_data.get("catalogVersion", "2026-10-25"),
        "total_tracked": len(combined_entries),
        "cisa_kev_count": len(kev_map),
        "high_velocity_count": len(non_kev_high_velocity),
        "vulnerabilities": combined_entries,
    }

    if output_path is None:
        output_path = DEFAULT_OUTPUT_FILE

    output_path.parent.mkdir(parents=True, exist_ok=True)
    minified_json = json.dumps(compact_payload, separators=(",", ":"))
    output_path.write_text(minified_json, encoding="utf-8")

    if sync_to_landing:
        landing_dest = LANDING_ASSETS / output_path.name
        landing_dest.parent.mkdir(parents=True, exist_ok=True)
        landing_dest.write_text(minified_json, encoding="utf-8")

    return compact_payload


def main():
    parser = argparse.ArgumentParser(description="Compile compacted CISA KEV + EPSS radar dataset")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE, help="Target JSON output path")
    parser.add_argument("--threshold", type=float, default=0.50, help="EPSS score inclusion threshold")
    args = parser.parse_args()

    from orbit_security.cisa_kev import CisaKevCatalog
    from orbit_security.epss import EpssCorrelator

    kev_catalog = CisaKevCatalog()
    epss_correlator = EpssCorrelator()

    compact_radar_dataset(
        cisa_kev_data=kev_catalog.catalog_data or {},
        epss_data=epss_correlator.cache or {},
        output_path=args.output,
    )
    print(f"Radar dataset compiled to {args.output}")


if __name__ == "__main__":
    main()
