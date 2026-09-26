import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import dns.exception

from orbit_security.models import Severity
from orbit_security.scanner import OrbitSecurityScanner, is_safe_ip, is_safe_host


def test_is_safe_ip():
    # Private / internal IPs
    assert not is_safe_ip("127.0.0.1")
    assert not is_safe_ip("10.0.0.1")
    assert not is_safe_ip("192.168.1.50")
    assert not is_safe_ip("172.16.0.1")
    assert not is_safe_ip("169.254.169.254")
    assert not is_safe_ip("::1")
    assert not is_safe_ip("fe80::1")
    assert not is_safe_ip("fd00:ec2::254")

    # Valid public IPs
    assert is_safe_ip("8.8.8.8")
    assert is_safe_ip("1.1.1.1")
    assert is_safe_ip("142.250.190.46")


def test_is_safe_host():
    assert not is_safe_host("127.0.0.1")
    assert not is_safe_host("localhost")
    assert not is_safe_host("metadata.google.internal")
    assert not is_safe_host("instance-data")
    assert not is_safe_host("corp.local")
    assert not is_safe_host("internal.company.internal")
    assert is_safe_host("example.com")


@pytest.mark.asyncio
async def test_scan_domain_blocks_ssrf():
    scanner = OrbitSecurityScanner()
    result = await scanner.scan_domain("127.0.0.1")
    assert len(result.findings) == 1
    assert result.findings[0].category == "Input Validation"
    assert "Target Disallowed" in result.findings[0].title


@pytest.mark.asyncio
async def test_dmarc_multi_chunk_joining():
    scanner = OrbitSecurityScanner()
    # Simulate RFC 1035 multi-chunk TXT record (>255 bytes split into multiple chunks)
    mock_txt = MagicMock()
    mock_txt.strings = [
        b"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; ",
        b"rua=mailto:dmarc-reports@enterprise.example.com; ",
        b"ruf=mailto:dmarc-forensics@enterprise.example.com; rf=afrf; pct=100",
    ]
    mock_response = [mock_txt]

    with patch("dns.asyncresolver.Resolver.resolve", return_value=mock_response):
        finding = await scanner.audit_dmarc("enterprise.example.com")
        assert finding is None  # Properly joined and verified p=reject


@pytest.mark.asyncio
async def test_spf_multi_chunk_joining():
    scanner = OrbitSecurityScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [
        b"v=spf1 include:_spf.google.com include:mailgun.org ",
        b"include:sendgrid.net ip4:198.51.100.1 ~all",
    ]
    mock_response = [mock_txt]

    with patch("dns.asyncresolver.Resolver.resolve", return_value=mock_response):
        finding = await scanner.audit_spf("enterprise.example.com")
        assert finding is None  # Properly joined, valid SPF with ~all


@pytest.mark.asyncio
async def test_dns_timeout_isolation():
    scanner = OrbitSecurityScanner()
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        side_effect=dns.exception.Timeout("Query timed out after 8.0s"),
    ):
        dmarc_finding = await scanner.audit_dmarc("laggy-domain.com")
        assert dmarc_finding is not None
        assert dmarc_finding.severity == Severity.LOW
        assert "DNS Resolution Timeout" in dmarc_finding.title

        spf_finding = await scanner.audit_spf("laggy-domain.com")
        assert spf_finding is not None
        assert spf_finding.severity == Severity.LOW
        assert "DNS Resolution Timeout" in spf_finding.title


@pytest.mark.asyncio
async def test_spa_html_guard_in_exposures():
    scanner = OrbitSecurityScanner()

    # Mock SPA server returning 200 OK HTML for any route (common in Single Page Applications)
    mock_spa_client = AsyncMock()
    mock_spa_resp = MagicMock()
    mock_spa_resp.status_code = 200
    mock_spa_resp.headers = {"content-type": "text/html; charset=utf-8"}
    mock_spa_resp.text = "<!DOCTYPE html><html><head><title>App</title></head><body>DB_PASSWORD missing</body></html>"
    mock_spa_client.get.return_value = mock_spa_resp

    findings = await scanner.audit_exposures("https://example.com", client=mock_spa_client)
    # The SPA guard must reject text/html and <!DOCTYPE html for sensitive dotfiles
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_legitimate_exposure_detected():
    scanner = OrbitSecurityScanner()

    mock_real_client = AsyncMock()
    mock_real_resp = MagicMock()
    mock_real_resp.status_code = 200
    mock_real_resp.headers = {"content-type": "text/plain"}
    mock_real_resp.text = "DB_PASSWORD=supersecret_production_pass\nAPI_KEY=live_sk_12345"
    mock_real_client.get.return_value = mock_real_resp

    findings = await scanner.audit_exposures("https://example.com", client=mock_real_client)
    assert len(findings) > 0
    assert any(f.severity == Severity.CRITICAL and "Exposed Environment Secrets" in f.title for f in findings)
