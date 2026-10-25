"""Unit tests for CISA KEV (Known Exploited Vulnerabilities) Correlator Engine (TDD).

Validates:
1. Catalog caching with 24h TTL and bundled fixture fallback.
2. Header banner parsing (Server, X-Powered-By, etc.) and version extraction.
3. Version-bounded matching: bare headers (e.g. 'Server: Apache') NEVER trigger false positives.
4. Precision matching on vulnerable versions (e.g. Apache/2.4.49 -> CVE-2021-41773).
5. Standardized event publishing to SQLite WAL Blackboard.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.cisa_kev import (
    CisaKevCatalog,
    KevVulnerability,
    parse_header_software_version,
)


@pytest.fixture
def sample_kev_catalog_data():
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.10.20",
        "dateReleased": "2026-10-20T12:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-41773",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "vulnerabilityName": "Apache HTTP Server Path Traversal and Remote Code Execution",
                "dateAdded": "2021-11-03",
                "shortDescription": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-11-17",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Affects 2.4.49",
            },
            {
                "cveID": "CVE-2024-21887",
                "vendorProject": "Ivanti",
                "product": "Connect Secure",
                "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
                "dateAdded": "2024-01-12",
                "shortDescription": "A command injection vulnerability in web components of Ivanti Connect Secure.",
                "requiredAction": "Apply mitigations per vendor advisory.",
                "dueDate": "2024-01-22",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Affects 9.x, 22.x",
            },
        ],
    }


def test_parse_header_software_version():
    # Standard server banners
    vendor, product, ver = parse_header_software_version("Apache/2.4.49 (Unix)")
    assert vendor == "apache"
    assert "http_server" in product or "apache" in product
    assert ver == "2.4.49"

    vendor, product, ver = parse_header_software_version("nginx/1.20.1")
    assert vendor == "nginx"
    assert ver == "1.20.1"

    vendor, product, ver = parse_header_software_version("PHP/8.1.0")
    assert vendor == "php"
    assert ver == "8.1.0"

    # Bare banners without version numbers
    vendor, product, ver = parse_header_software_version("Apache")
    assert vendor == "apache"
    assert ver is None

    vendor, product, ver = parse_header_software_version("cloudflare")
    assert vendor == "cloudflare"
    assert ver is None


def test_cisa_kev_offline_fixture_fallback(tmp_path, sample_kev_catalog_data):
    cache_file = tmp_path / "cisa_kev_cache.json"
    catalog = CisaKevCatalog(cache_file=cache_file, offline_fixture=sample_kev_catalog_data)
    assert len(catalog.vulnerabilities) == 2
    assert "CVE-2021-41773" in catalog.vulnerabilities
    assert "CVE-2024-21887" in catalog.vulnerabilities


def test_cisa_kev_cache_ttl_behavior(tmp_path, sample_kev_catalog_data):
    cache_file = tmp_path / "cisa_kev_cache.json"
    cache_payload = {
        "timestamp": time.time(),
        "catalog": sample_kev_catalog_data,
    }
    cache_file.write_text(json.dumps(cache_payload), encoding="utf-8")

    catalog = CisaKevCatalog(cache_file=cache_file)
    assert catalog.is_cache_valid(ttl_seconds=86400) is True

    # Expired cache
    old_cache_payload = {
        "timestamp": time.time() - 90000,
        "catalog": sample_kev_catalog_data,
    }
    cache_file.write_text(json.dumps(old_cache_payload), encoding="utf-8")
    assert catalog.is_cache_valid(ttl_seconds=86400) is False


def test_version_bounded_matching_no_false_positives(tmp_path, sample_kev_catalog_data):
    cache_file = tmp_path / "cisa_kev_cache.json"
    catalog = CisaKevCatalog(cache_file=cache_file, offline_fixture=sample_kev_catalog_data)

    # Bare banner without version must NOT match
    matches = catalog.correlate_server_headers({"Server": "Apache"})
    assert len(matches) == 0

    matches = catalog.correlate_server_headers({"Server": "cloudflare"})
    assert len(matches) == 0


def test_correlate_server_headers_matches_vulnerable_version(tmp_path, sample_kev_catalog_data):
    cache_file = tmp_path / "cisa_kev_cache.json"
    catalog = CisaKevCatalog(cache_file=cache_file, offline_fixture=sample_kev_catalog_data)

    headers = {
        "Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1l",
        "X-Powered-By": "PHP/7.4.3",
    }
    matches = catalog.correlate_server_headers(headers)
    assert len(matches) == 1
    match = matches[0]
    assert match.cve_id == "CVE-2021-41773"
    assert match.vendor_project == "Apache"
    assert match.known_ransomware_use == "Known"


def test_publish_blackboard_event_on_match(tmp_path, sample_kev_catalog_data):
    cache_file = tmp_path / "cisa_kev_cache.json"
    catalog = CisaKevCatalog(cache_file=cache_file, offline_fixture=sample_kev_catalog_data)

    mock_bb = MagicMock()
    headers = {"Server": "Apache/2.4.49"}
    matches = catalog.correlate_server_headers(headers, domain="vulnerable.agency.internal", blackboard=mock_bb)

    assert len(matches) == 1
    mock_bb.publish.assert_called_once()
    call_kwargs = mock_bb.publish.call_args[1]
    assert call_kwargs["event_type"] == "CISA_KEV_MATCH_DETECTED"
    assert call_kwargs["source"] == "cisa_kev_correlator"
    assert call_kwargs["topic"] == "cve_radar"
    payload = call_kwargs["payload"]
    assert payload["cve_id"] == "CVE-2021-41773"
    assert payload["product"] == "HTTP Server"
    assert payload["domain"] == "vulnerable.agency.internal"
