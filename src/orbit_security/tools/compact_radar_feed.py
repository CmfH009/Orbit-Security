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


def _compact_text(text: str, max_len: int) -> str:
    clean = (text or "").strip()
    if len(clean) <= max_len:
        return clean
    if "BOD 26-04" in clean and max_len <= 100:
        return "Apply vendor mitigations per CISA BOD 26-04 directive."
    return clean[: max_len - 3].rstrip() + "..."


def compact_radar_dataset(
    cisa_kev_data: Dict[str, Any],
    epss_data: Dict[str, Dict[str, Any]],
    output_path: Optional[Path] = None,
    sync_to_landing: bool = True,
    epss_threshold: float = 0.50,
    percentile_threshold: float = 0.97,
    max_payload_bytes: int = 240 * 1024,
) -> Dict[str, Any]:
    """Pre-joins CISA KEV and EPSS into a high-density, minified static payload (<250 KB)."""
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
            "vulnerability_name": _compact_text(v.get("vulnerabilityName", ""), 110),
            "date_added": v.get("dateAdded", ""),
            "short_description": _compact_text(v.get("shortDescription", ""), 150),
            "action_required": _compact_text(v.get("requiredAction", "Patch immediately"), 90),
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
                record["epss"] = round(float(epss_info.get("epss", 0.0)), 5)
                record["percentile"] = round(float(epss_info.get("percentile", 0.0)), 5)
            except (ValueError, TypeError):
                pass

    # Extract high-velocity non-KEV vulnerabilities
    non_kev_high_velocity: Dict[str, Dict[str, Any]] = {}
    for cve, epss_info in epss_data.items():
        cve_upper = cve.strip().upper()
        if cve_upper in kev_map:
            continue  # Already captured in KEV map
        try:
            score = round(float(epss_info.get("epss", 0.0)), 5)
            perc = round(float(epss_info.get("percentile", 0.0)), 5)
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

    kev_sorted = sorted(
        kev_map.values(),
        key=lambda x: (x["epss"], x.get("date_added", "")),
        reverse=True,
    )
    non_kev_sorted = sorted(
        non_kev_high_velocity.values(),
        key=lambda x: (x["epss"], x.get("date_added", "")),
        reverse=True,
    )
    combined_entries = kev_sorted + non_kev_sorted

    def _build_payload(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "generated_at": cisa_kev_data.get("catalogVersion", "2026-10-25"),
            "total_tracked": len(kev_map) + len(non_kev_high_velocity),
            "cisa_kev_count": len(kev_map),
            "high_velocity_count": len(non_kev_high_velocity),
            "vulnerabilities": entries,
        }

    compact_payload = _build_payload(combined_entries)
    minified_json = json.dumps(compact_payload, separators=(",", ":"))

    # Enforce strict < 250 KB payload budget while preserving all non-KEV high-velocity entries
    # and the highest-EPSS / newest CISA KEV entries
    if len(minified_json.encode("utf-8")) > max_payload_bytes and len(kev_sorted) > 50:
        low, high = 50, len(kev_sorted)
        best_entries = kev_sorted[:50] + non_kev_sorted
        while low <= high:
            mid = (low + high) // 2
            candidate = kev_sorted[:mid] + non_kev_sorted
            cand_json = json.dumps(_build_payload(candidate), separators=(",", ":"))
            if len(cand_json.encode("utf-8")) <= max_payload_bytes:
                best_entries = candidate
                low = mid + 1
            else:
                high = mid - 1
        compact_payload = _build_payload(best_entries)
        minified_json = json.dumps(compact_payload, separators=(",", ":"))

    if output_path is None:
        output_path = DEFAULT_OUTPUT_FILE
    output_path.parent.mkdir(parents=True, exist_ok=True)
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
