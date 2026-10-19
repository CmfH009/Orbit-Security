"""Tests for PublicAPIsIntelHarvester (recon OSINT bridge wiring)."""

import json
import pytest
from pathlib import Path

from orbit_security.recon_harvester import PublicAPIsIntelHarvester

MOCK_RESOURCES = {
    "count": 5,
    "entries": [
        {
            "API": "VirusTotal",
            "Description": "Analyse suspicious files, domains, IPs and URLs to detect malware",
            "Auth": "apiKey",
            "Cors": "unknown",
            "Link": "https://developers.virustotal.com/reference",
            "Category": "Security",
        },
        {
            "API": "urlscan.io",
            "Description": "Investigate URLs and domains",
            "Auth": "apiKey",
            "Cors": "yes",
            "Link": "https://urlscan.io",
            "Category": "Security",
        },
        {
            "API": "Example Domain API",
            "Description": "Official API for example.com domain intelligence",
            "Auth": "No",
            "Cors": "yes",
            "Link": "https://api.example.com/v1",
            "Category": "Security",
        },
        {
            "API": "Example Geo IP",
            "Description": "Geolocation lookup for example.com hosted assets",
            "Auth": "OAuth",
            "Cors": "no",
            "Link": "https://ip.example.com/lookup",
            "Category": "Geocoding",
        },
        {
            "API": "Random Dog",
            "Description": "Random pictures of dogs",
            "Auth": "No",
            "Cors": "yes",
            "Link": "https://random.dog",
            "Category": "Animals",
        },
    ],
}


@pytest.fixture
def mock_db_file(tmp_path):
    p = tmp_path / "resources.json"
    p.write_text(json.dumps(MOCK_RESOURCES), encoding="utf-8")
    return p


def test_harvester_available_with_catalog(mock_db_file):
    harvester = PublicAPIsIntelHarvester(db_path=mock_db_file)
    assert harvester.available() is True


def test_harvest_returns_structured_intel(mock_db_file):
    harvester = PublicAPIsIntelHarvester(db_path=mock_db_file)
    result = harvester.harvest_public_api_intel("example.com", limit=10)

    assert result["apex_domain"] == "example.com"
    assert result["bridge_available"] is True
    assert result["total_catalog_apis"] == 5
    assert result["security_osint_count"] == 4  # Animals excluded
    assert result["error"] is None

    # Security/OSINT endpoints present (Random Dog excluded)
    names = {ep["name"] for ep in result["security_osint_endpoints"]}
    assert "VirusTotal" in names
    assert "urlscan.io" in names
    assert "Random Dog" not in names

    # Domain matches: entries whose domain/name mention example.com
    match_names = {ep["name"] for ep in result["domain_matches"]}
    assert "Example Domain API" in match_names
    assert "Example Geo IP" in match_names

    # Pivot domains extracted from security/OSINT entries
    assert "developers.virustotal.com" in result["pivot_domains"]
    assert "api.example.com" in result["pivot_domains"]


def test_invalid_domain_returns_error(mock_db_file):
    harvester = PublicAPIsIntelHarvester(db_path=mock_db_file)
    result = harvester.harvest_public_api_intel("not-a-domain")
    assert result["error"] is not None
    assert result["bridge_available"] is True


def test_limit_applies(mock_db_file):
    harvester = PublicAPIsIntelHarvester(db_path=mock_db_file)
    result = harvester.harvest_public_api_intel("example.com", limit=1)
    assert len(result["security_osint_endpoints"]) == 1
