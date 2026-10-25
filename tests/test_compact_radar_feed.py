"""Unit tests for orbit_security.tools.compact_radar_feed (TDD).

Validates:
1. High-density compaction of CISA KEV and EPSS data.
2. Filtering of high-velocity non-KEV CVEs (epss >= 0.50 or percentile >= 0.97).
3. Payload size stays well under 250 KB target.
4. Byte synchronization between docs/assets and landing/assets.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from orbit_security.tools.compact_radar_feed import compact_radar_dataset


def test_compact_radar_dataset_filtering_and_size(tmp_path):
    output_file = tmp_path / "test_radar.json"

    cisa_kev_fixture = {
        "catalogVersion": "2026-10-25",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-21887",
                "vendorProject": "Ivanti",
                "product": "Connect Secure",
                "vulnerabilityName": "Command Injection",
                "dateAdded": "2024-01-16",
                "shortDescription": "Command injection vulnerability in web components.",
                "requiredAction": "Apply vendor mitigation.",
                "dueDate": "2024-01-22",
            },
            {
                "cveID": "CVE-2021-41773",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "vulnerabilityName": "Path Traversal",
                "dateAdded": "2021-11-03",
                "shortDescription": "Path traversal flaw in Apache HTTP Server 2.4.49.",
                "requiredAction": "Patch immediately.",
                "dueDate": "2021-11-17",
            },
        ],
    }

    epss_fixture = {
        "CVE-2024-21887": {"epss": "0.94210", "percentile": "0.99120", "date": "2026-10-24"},
        "CVE-2021-41773": {"epss": "0.97430", "percentile": "0.99840", "date": "2026-10-24"},
        # High velocity non-KEV (should be included)
        "CVE-2026-9999": {"epss": "0.85000", "percentile": "0.98500", "vendor": "ExampleCorp", "product": "Widget"},
        # Low velocity non-KEV (should be excluded)
        "CVE-2026-0001": {"epss": "0.02100", "percentile": "0.35000", "vendor": "SafeCorp", "product": "App"},
    }

    result = compact_radar_dataset(
        cisa_kev_data=cisa_kev_fixture,
        epss_data=epss_fixture,
        output_path=output_file,
        sync_to_landing=False,
    )

    assert result["total_tracked"] == 3
    assert result["cisa_kev_count"] == 2
    assert result["high_velocity_count"] == 1

    # Check file exists and is minified
    assert output_file.exists()
    raw_content = output_file.read_text(encoding="utf-8")
    assert "\n" not in raw_content, "Compacted output must be single-line minified JSON"
    assert len(raw_content.encode("utf-8")) < 250 * 1024, "Payload must be under 250 KB"

    # Verify KEV entries enriched
    parsed = json.loads(raw_content)
    ivanti = next(v for v in parsed["vulnerabilities"] if v["cve"] == "CVE-2024-21887")
    assert ivanti["is_cisa_kev"] is True
    assert ivanti["epss"] == 0.9421
    assert ivanti["percentile"] == 0.9912

    # Verify high velocity non-KEV included
    high_vel = next(v for v in parsed["vulnerabilities"] if v["cve"] == "CVE-2026-9999")
    assert high_vel["is_cisa_kev"] is False
    assert high_vel["epss"] == 0.85


def test_compact_radar_dataset_enforces_250kb_budget_on_full_catalog(tmp_path):
    """Verifies that even with 1,800 verbose CISA KEV entries, compacted output stays < 250 KB."""
    output_file = tmp_path / "large_radar.json"
    verbose_desc = (
        "A remote code execution vulnerability in enterprise appliance web management interface "
        "allows unauthenticated attackers to execute arbitrary OS commands with root privileges. "
    ) * 3
    verbose_action = (
        "Apply mitigations in accordance with vendor instructions, ensuring compliance with "
        "CISA BOD 26-04 Prioritizing Security Updates Based on Risk guidance immediately."
    )
    large_vulns = [
        {
            "cveID": f"CVE-2026-{10000 + i}",
            "vendorProject": f"Vendor-{i % 40}",
            "product": f"Appliance-{i % 80}",
            "vulnerabilityName": f"Enterprise Appliance RCE Vulnerability #{i}",
            "dateAdded": f"2026-10-{(i % 28) + 1:02d}",
            "shortDescription": verbose_desc,
            "requiredAction": verbose_action,
            "dueDate": "2026-11-15",
        }
        for i in range(1800)
    ]
    cisa_kev_large = {"catalogVersion": "2026.10.25", "vulnerabilities": large_vulns}
    epss_fixture = {
        "CVE-2026-10005": {"epss": "0.96100", "percentile": "0.99800", "date": "2026-10-25"},
        "CVE-2026-99999": {"epss": "0.88000", "percentile": "0.99100", "vendor": "CloudCorp", "product": "Edge"},
    }

    result = compact_radar_dataset(
        cisa_kev_data=cisa_kev_large,
        epss_data=epss_fixture,
        output_path=output_file,
        sync_to_landing=False,
    )

    raw_bytes = output_file.read_bytes()
    assert len(raw_bytes) < 250 * 1024, f"Expected < 250 KB, got {len(raw_bytes)} bytes"
    assert result["cisa_kev_count"] == 1800
    assert result["high_velocity_count"] == 1
    # Highest EPSS KEV entry must be preserved first
    assert result["vulnerabilities"][0]["cve"] == "CVE-2026-10005"
    assert result["vulnerabilities"][0]["epss"] == 0.961


def test_compact_radar_cli_integration_with_catalog_and_epss(tmp_path):
    """Verifies CisaKevCatalog.catalog_data and EpssCorrelator.cache integration."""
    from orbit_security.cisa_kev import CisaKevCatalog
    from orbit_security.epss import EpssCorrelator

    kev_catalog = CisaKevCatalog()
    epss_correlator = EpssCorrelator()

    assert isinstance(kev_catalog.catalog_data, dict)
    assert "vulnerabilities" in kev_catalog.catalog_data
    assert isinstance(epss_correlator.cache, dict)
    assert len(epss_correlator.cache) > 0

    out_path = tmp_path / "cli_radar.json"
    res = compact_radar_dataset(
        cisa_kev_data=kev_catalog.catalog_data,
        epss_data=epss_correlator.cache,
        output_path=out_path,
        sync_to_landing=False,
    )
    assert out_path.exists()
    assert out_path.stat().st_size < 250 * 1024
    assert res["total_tracked"] > 0


def test_github_pages_live_radar_showcase_ui_and_asset_parity():
    """Verifies Project #3: Interactive CISA KEV & EPSS Intelligence Radar UI on GitHub Pages."""
    repo_root = Path(__file__).resolve().parent.parent
    docs_json = repo_root / "docs" / "assets" / "kev_epss_radar.json"
    landing_json = repo_root / "landing" / "assets" / "kev_epss_radar.json"

    assert docs_json.exists(), "docs/assets/kev_epss_radar.json must exist"
    assert landing_json.exists(), "landing/assets/kev_epss_radar.json must exist"
    assert docs_json.read_bytes() == landing_json.read_bytes(), "Radar JSON must be byte-identical"
    assert docs_json.stat().st_size < 250 * 1024, "Radar JSON must be < 250 KB"

    for tree in ("landing", "docs"):
        index_html = (repo_root / tree / "index.html").read_text(encoding="utf-8")
        assert 'id="kev-epss-radar"' in index_html
        assert 'id="kevRadarSearchInput"' in index_html
        assert 'id="kevRadarResultsGrid"' in index_html
        assert 'id="kevRadarDetailPanel"' in index_html

        radar_js = (repo_root / tree / "assets" / "orbit_radar.js").read_text(encoding="utf-8")
        assert "assets/kev_epss_radar.json" in radar_js
        assert "initKevEpssRadar" in radar_js
        assert "filterKevEpssRadar" in radar_js
        assert "selectKevRadarCve" in radar_js


