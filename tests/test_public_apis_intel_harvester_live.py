r"""Live-network integration tests for PublicAPIsIntelHarvester.

These tests exercise the *real* public-apis catalog at
``A:\reference\public-apis\db\resources.json`` through the
``orbit.recon.public_apis_osint`` bridge wired into
``PublicAPIsIntelHarvester``. No packets are sent to any target domain.

All tests are marked ``live`` so they can be optionally deselected, e.g.::

    uv run pytest -m "not live"

If the reference catalog is missing, every test in this module skips
gracefully (see the module-level ``pytestmark``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from orbit_security.recon_harvester import PublicAPIsIntelHarvester

CATALOG_PATH = Path(r"A:\reference\public-apis\db\resources.json")

EXPECTED_KEYS = {
    "apex_domain",
    "bridge_available",
    "total_catalog_apis",
    "security_osint_count",
    "security_osint_endpoints",
    "domain_matches",
    "pivot_domains",
    "error",
}

pytestmark = [
    pytest.mark.skipif(
        not CATALOG_PATH.exists(),
        reason=f"Live public-apis catalog not found at {CATALOG_PATH}",
    ),
    pytest.mark.live,
]


class TestPublicAPIsIntelHarvesterLive:
    def test_live_harvester_loads_catalog(self):
        """Bridge loads the real catalog and reports >= 1600 catalog APIs."""
        harvester = PublicAPIsIntelHarvester(db_path=CATALOG_PATH)
        assert harvester.available() is True
        result = harvester.harvest_public_api_intel("example.com")
        assert result["bridge_available"] is True
        assert result["total_catalog_apis"] >= 1600

    def test_live_security_osint_count(self):
        """Security/OSINT category filter returns more than 30 endpoints."""
        harvester = PublicAPIsIntelHarvester(db_path=CATALOG_PATH)
        result = harvester.harvest_public_api_intel("example.com")
        assert result["bridge_available"] is True
        assert result["security_osint_count"] > 30

    def test_live_domain_matches_structure(self):
        """Harvest for a valid apex domain returns the expected result keys."""
        harvester = PublicAPIsIntelHarvester(db_path=CATALOG_PATH)
        result = harvester.harvest_public_api_intel("example.com")
        assert set(result.keys()) == EXPECTED_KEYS
        assert result["apex_domain"] == "example.com"
        assert result["bridge_available"] is True
        assert isinstance(result["total_catalog_apis"], int)
        assert isinstance(result["security_osint_count"], int)
        assert isinstance(result["security_osint_endpoints"], list)
        assert isinstance(result["domain_matches"], list)
        assert isinstance(result["pivot_domains"], list)
        assert result["error"] is None

    def test_live_pivot_domains_nonempty(self):
        """Pivot domains extracted from security/OSINT entries are non-empty strings."""
        harvester = PublicAPIsIntelHarvester(db_path=CATALOG_PATH)
        result = harvester.harvest_public_api_intel("example.com")
        assert result["error"] is None
        pivot_domains = result["pivot_domains"]
        assert isinstance(pivot_domains, list)
        assert len(pivot_domains) > 0
        assert all(isinstance(domain, str) for domain in pivot_domains)

    def test_live_invalid_domain_error(self):
        """An invalid apex domain (no dot) yields a non-None error."""
        harvester = PublicAPIsIntelHarvester(db_path=CATALOG_PATH)
        result = harvester.harvest_public_api_intel("invalid")
        assert result["error"] is not None
