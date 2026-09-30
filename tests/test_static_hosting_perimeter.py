import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from orbit_security.scanner import OrbitSecurityScanner, is_static_hosting_domain
from orbit_security.recon import calculate_score, resolve_dns


def test_is_static_hosting_domain_detection():
    assert is_static_hosting_domain("cmfh009.github.io") is True
    assert is_static_hosting_domain("test.pages.dev") is True
    assert is_static_hosting_domain("app.vercel.app") is True
    assert is_static_hosting_domain("client.netlify.app") is True
    assert is_static_hosting_domain("github.io") is True
    assert is_static_hosting_domain("example.com") is False
    assert is_static_hosting_domain("shopify.com") is False


@pytest.mark.asyncio
async def test_audit_dmarc_static_hosting_protection():
    scanner = OrbitSecurityScanner()
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=Exception("No direct record")):
        # On static host, missing direct DMARC should not penalize
        finding = await scanner.audit_dmarc("cmfh009.github.io")
        assert finding is None


@pytest.mark.asyncio
async def test_audit_spf_static_hosting_protection():
    scanner = OrbitSecurityScanner()
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=Exception("No direct record")):
        # On static host, missing direct SPF should not penalize
        finding = await scanner.audit_spf("cmfh009.github.io")
        assert finding is None


@pytest.mark.asyncio
async def test_scan_domain_static_hosting_grade_a():
    scanner = OrbitSecurityScanner()
    # Mock network calls to simulate clean static host
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'",
    }
    mock_resp.text = "<!doctype html><html><body>Test</body></html>"
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch.object(scanner, "create_http_client", return_value=mock_client):
        with patch.object(scanner, "fetch_subdomains_from_crtsh", return_value=[]):
            with patch("dns.asyncresolver.Resolver.resolve", side_effect=Exception("No DNS answer")):
                with patch.object(scanner, "audit_ssl", return_value=None):
                    res = await scanner.scan_domain("cmfh009.github.io", use_crtsh=False)
                    assert res.score >= 95
                    assert res.grade in ("A+", "A")


def test_recon_calculate_score_static_hosting():
    mock_dns = {"dangling_risk": False, "mx_records": []}
    mock_web = {
        "exposures": [],
        "missing_headers": [
            {"header": "Strict-Transport-Security"},
            {"header": "X-Frame-Options"},
            {"header": "X-Content-Type-Options"},
            {"header": "Referrer-Policy"},
            {"header": "Permissions-Policy"},
            {"header": "Cross-Origin-Opener-Policy"},
        ],
    }
    score = calculate_score(mock_dns, mock_web, domain="cmfh009.github.io")
    assert score >= 95
