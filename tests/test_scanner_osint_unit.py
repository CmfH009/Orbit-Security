"""Unit tests for OSINT intelligence wiring in OrbitSecurityScanner.scan_domain().

Mock-based: no network, no external targets. Verifies that osint_intel is
attached to DomainAuditResult and that harvester unavailability is handled
gracefully.
"""

from unittest.mock import MagicMock, patch
import pytest

from orbit_security.models import DomainAuditResult, AgencyBranding


def test_domain_audit_result_has_osint_intel_field():
    """DomainAuditResult exposes osint_intel (default empty dict)."""
    result = DomainAuditResult(domain="example.com")
    assert result.osint_intel == {}


@pytest.mark.asyncio
async def test_scan_domain_attaches_osint_intel():
    """scan_domain attaches osint_intel from PublicAPIsIntelHarvester."""
    from orbit_security.scanner import OrbitSecurityScanner

    fake_intel = {
        "apex_domain": "example.com",
        "bridge_available": True,
        "total_catalog_apis": 1690,
        "security_osint_count": 271,
        "domain_matches": [],
        "pivot_domains": ["api.example.com"],
        "error": None,
    }

    scanner = OrbitSecurityScanner()

    with patch(
        "orbit_security.recon_harvester.PublicAPIsIntelHarvester"
    ) as mock_harvester_cls:
        mock_harvester = MagicMock()
        mock_harvester.harvest_public_api_intel.return_value = fake_intel
        mock_harvester_cls.return_value = mock_harvester

        result = await scanner.scan_domain("example.com")

    assert result.osint_intel["bridge_available"] is True
    assert result.osint_intel["total_catalog_apis"] == 1690
    assert result.osint_intel["security_osint_count"] == 271
    assert result.osint_intel["pivot_domains"] == ["api.example.com"]
    assert result.osint_intel["error"] is None


@pytest.mark.asyncio
async def test_scan_domain_handles_osint_harvester_failure_gracefully():
    """If PublicAPIsIntelHarvester raises, scan_domain still completes with error recorded."""
    from orbit_security.scanner import OrbitSecurityScanner

    scanner = OrbitSecurityScanner()

    with patch(
        "orbit_security.recon_harvester.PublicAPIsIntelHarvester"
    ) as mock_harvester_cls:
        mock_harvester = MagicMock()
        mock_harvester.harvest_public_api_intel.side_effect = RuntimeError("catalog missing")
        mock_harvester_cls.return_value = mock_harvester

        result = await scanner.scan_domain("example.com")

    assert result.osint_intel["bridge_available"] is False
    assert "catalog missing" in result.osint_intel["error"]
    # Scan still completes normally despite OSINT failure
    assert result.domain == "example.com"
    assert isinstance(result.findings, list)


@pytest.mark.asyncio
async def test_scan_domain_osint_bridge_unavailable():
    """If harvester reports bridge unavailable, osint_intel reflects it."""
    from orbit_security.scanner import OrbitSecurityScanner

    fake_intel = {
        "apex_domain": "example.com",
        "bridge_available": False,
        "total_catalog_apis": 0,
        "security_osint_count": 0,
        "domain_matches": [],
        "pivot_domains": [],
        "error": "OSINT bridge unavailable",
    }

    scanner = OrbitSecurityScanner()

    with patch(
        "orbit_security.recon_harvester.PublicAPIsIntelHarvester"
    ) as mock_harvester_cls:
        mock_harvester = MagicMock()
        mock_harvester.harvest_public_api_intel.return_value = fake_intel
        mock_harvester_cls.return_value = mock_harvester

        result = await scanner.scan_domain("example.com")

    assert result.osint_intel["bridge_available"] is False
    assert result.osint_intel["error"] == "OSINT bridge unavailable"
