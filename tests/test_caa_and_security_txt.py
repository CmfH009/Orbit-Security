import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES
from orbit_security.remediation import DnsRemediationGenerator


@pytest.mark.asyncio
async def test_audit_caa_present():
    scanner = OrbitSecurityScanner()
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = '0 issue "letsencrypt.org"'

    with patch.object(scanner.resolver, "resolve", return_value=[mock_rdata]):
        finding = await scanner.audit_caa("example.com")
        assert finding is None


@pytest.mark.asyncio
async def test_audit_caa_missing():
    scanner = OrbitSecurityScanner()
    with patch.object(scanner.resolver, "resolve", side_effect=Exception("NoAnswer")):
        finding = await scanner.audit_caa("example.com")
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert "CAA" in finding.title
        assert "RFC 8659" in finding.title
        assert finding.target == "example.com"


@pytest.mark.asyncio
async def test_audit_security_txt_present():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/plain"}
    mock_resp.text = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
    mock_client.get.return_value = mock_resp

    finding = await scanner.audit_security_txt("https://example.com", client=mock_client)
    assert finding is None


@pytest.mark.asyncio
async def test_audit_security_txt_missing():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = "<html>404 Not Found</html>"
    mock_client.get.return_value = mock_resp

    finding = await scanner.audit_security_txt("https://example.com", client=mock_client)
    assert finding is not None
    assert finding.severity == Severity.LOW
    assert "security.txt" in finding.title
    assert "RFC 9116" in finding.title


@pytest.mark.asyncio
async def test_audit_security_txt_spa_html_rejected():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
    mock_resp.text = "<!DOCTYPE html><html><body>Contact: sales@example.com</body></html>"
    mock_client.get.return_value = mock_resp

    finding = await scanner.audit_security_txt("https://example.com", client=mock_client)
    assert finding is not None
    assert "security.txt" in finding.title


@pytest.mark.asyncio
async def test_server_banner_version_disclosure():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.2",
    }
    mock_client.get.return_value = mock_resp

    findings = await scanner.audit_security_headers("https://example.com", client=mock_client)
    version_finding = next((f for f in findings if "Version Disclosure" in f.title), None)
    assert version_finding is not None
    assert version_finding.severity == Severity.LOW
    assert "Apache/2.4.52" in version_finding.evidence
    assert "PHP/8.1.2" in version_finding.evidence


def test_new_saas_signatures():
    names = {s.name for s in SAAS_TAKEOVER_SIGNATURES}
    assert "Vercel" in names
    assert "Supabase" in names
    assert "Render" in names
    assert "Cloudflare Pages" in names
    assert "Firebase Hosting" in names
    assert "BigCommerce" in names
    assert "Notion" in names

    vercel = next(s for s in SAAS_TAKEOVER_SIGNATURES if s.name == "Vercel")
    assert any("vercel-dns.com" in p for p in vercel.cname_patterns)
    assert any("The deployment could not be found" in f for f in vercel.fingerprints)


def test_generate_caa_fix():
    snippets = DnsRemediationGenerator.generate_caa_fix("myagency.com", alert_email="ops@myagency.com")
    assert len(snippets) == 2
    providers = {s.provider for s in snippets}
    assert "Cloudflare" in providers
    assert "AWS Route 53" in providers

    cf = next(s for s in snippets if s.provider == "Cloudflare")
    assert cf.record_type == "CAA"
    assert "letsencrypt.org" in cf.record_value
    assert "iodef" in cf.record_value


def test_generate_security_txt():
    txt = DnsRemediationGenerator.generate_security_txt("myclient.com")
    assert "Contact: mailto:security@myclient.com" in txt
    assert "Expires:" in txt
    assert "Canonical: https://myclient.com/.well-known/security.txt" in txt
