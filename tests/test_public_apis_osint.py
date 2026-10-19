"""Tests for Orbit Security Public APIs OSINT Bridge."""

import json
import pytest
from pathlib import Path
from orbit.recon.public_apis_osint import PublicApisOsintBridge, ApiEndpoint, SECURITY_OSINT_CATEGORIES

MOCK_RESOURCES = {
    "count": 4,
    "entries": [
        {
            "API": "VirusTotal",
            "Description": "Analyse suspicious files, domains, IPs and URLs to detect malware",
            "Auth": "apiKey",
            "Cors": "unknown",
            "Link": "https://developers.virustotal.com/reference",
            "Category": "Security"
        },
        {
            "API": "HaveIBeenPwned",
            "Description": "Check if an email or phone is in a data breach",
            "Auth": "apiKey",
            "Cors": "no",
            "Link": "https://haveibeenpwned.com/API/v3",
            "Category": "Security"
        },
        {
            "API": "OpenStreetCam",
            "Description": "Street view imagery for OSINT geocoding",
            "Auth": "OAuth",
            "Cors": "yes",
            "Link": "https://openstreetcam.org",
            "Category": "Geocoding"
        },
        {
            "API": "Random Dog",
            "Description": "Random pictures of dogs",
            "Auth": "No",
            "Cors": "yes",
            "Link": "https://random.dog",
            "Category": "Animals"
        }
    ]
}

@pytest.fixture
def mock_db_file(tmp_path):
    p = tmp_path / "resources.json"
    p.write_text(json.dumps(MOCK_RESOURCES), encoding="utf-8")
    return p

def test_bridge_load_and_counts(mock_db_file):
    bridge = PublicApisOsintBridge(db_path=mock_db_file)
    assert bridge.total_count == 4
    categories = bridge.get_categories()
    assert "Security" in categories
    assert "Geocoding" in categories
    assert "Animals" in categories

def test_security_osint_filtering(mock_db_file):
    bridge = PublicApisOsintBridge(db_path=mock_db_file)
    osint_apis = bridge.filter_security_and_osint()
    names = [a.name for a in osint_apis]
    assert "VirusTotal" in names
    assert "HaveIBeenPwned" in names
    assert "OpenStreetCam" in names
    assert "Random Dog" not in names

def test_search_and_auth_filtering(mock_db_file):
    bridge = PublicApisOsintBridge(db_path=mock_db_file)
    res = bridge.search("malware")
    assert len(res) == 1
    assert res[0].name == "VirusTotal"

    res_auth = bridge.search("", auth_type="apikey")
    assert len(res_auth) == 2

def test_domain_extraction(mock_db_file):
    bridge = PublicApisOsintBridge(db_path=mock_db_file)
    domains = bridge.extract_domains()
    assert "developers.virustotal.com" in domains
    assert "haveibeenpwned.com" in domains
    assert "openstreetcam.org" in domains
    assert "random.dog" in domains

def test_live_reference_db_if_exists():
    real_path = Path(r"A:\reference\public-apis\db\resources.json")
    if real_path.exists():
        bridge = PublicApisOsintBridge(real_path)
        assert bridge.total_count >= 1600
        sec = bridge.filter_security_and_osint()
        assert len(sec) > 30
