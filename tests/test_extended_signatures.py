import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import dns.resolver

from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, sync_github_signatures, SaasSignature
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity


def test_signatures_database_enrichment():
    """Verify that can-i-take-over-xyz signatures are properly ingested."""
    names = {s.name for s in SAAS_TAKEOVER_SIGNATURES}
    assert "Microsoft Azure" in names
    assert "AWS Elastic Beanstalk" in names
    assert "Bitbucket" in names
    assert "Ghost" in names
    assert "Fastly" in names
    assert "Help Scout" in names
    assert "Fly.io" in names
    assert "HubSpot" in names
    assert len(SAAS_TAKEOVER_SIGNATURES) >= 30


def test_sync_github_signatures_offline_resilience():
    """Verify that sync_github_signatures handles offline/network errors gracefully."""
    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
        count = sync_github_signatures("https://invalid.example.local/test.json", timeout=0.1)
        assert count >= len(SAAS_TAKEOVER_SIGNATURES)


@pytest.mark.asyncio
async def test_nxdomain_takeover_detection():
    """Verify NXDOMAIN takeover triggers on vulnerable providers like Azure."""
    scanner = OrbitSecurityScanner()

    # Mock CNAME pointing to dangling Azure web app
    mock_cname_rdata = MagicMock()
    mock_cname_rdata.target.to_text.return_value = "myapp.azurewebsites.net."

    def mock_resolve(qname, rdtype):
        if rdtype == "CNAME":
            return [mock_cname_rdata]
        elif rdtype == "A":
            raise dns.resolver.NXDOMAIN("Domain not found")
        raise Exception("Unhandled query")

    with patch.object(scanner.resolver, "resolve", side_effect=mock_resolve):
        finding = await scanner.check_subdomain_takeover("portal.example.com")
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "NXDOMAIN" in finding.title
        assert "Microsoft Azure" in finding.title
        assert "portal.example.com" in finding.target
