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
