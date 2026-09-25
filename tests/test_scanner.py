import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from agency_sentry.models import DomainAuditResult, Finding, Severity, AgencyBranding
from agency_sentry.signatures import SAAS_TAKEOVER_SIGNATURES
from agency_sentry.scanner import AgencySentryScanner


def test_score_and_grade_calculation():
    audit = DomainAuditResult(domain="example.com")
    grade, score = audit.calculate_grade_and_score()
    assert score == 100
    assert grade == "A+"

    audit.findings.append(
        Finding(
            title="Dangling CNAME / Subdomain Takeover",
            severity=Severity.CRITICAL,
            category="Subdomain & DNS",
            description="Subdomain vulnerable to takeover",
            remediation="Delete CNAME",
            target="promo.example.com",
            evidence="CNAME unbouncepages.com"
        )
    )
    grade, score = audit.calculate_grade_and_score()
    assert score == 65
    assert grade == "C"

    audit.findings.append(
        Finding(
            title="Missing DMARC Policy",
            severity=Severity.HIGH,
            category="Email Authentication",
            description="Domain has no DMARC",
            remediation="Add TXT record",
            target="example.com"
        )
    )
    grade, score = audit.calculate_grade_and_score()
    assert score == 45
    assert grade == "D"


@pytest.mark.asyncio
async def test_dmarc_evaluation_missing():
    scanner = AgencySentryScanner()
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=Exception("No answer")):
        finding = await scanner.audit_dmarc("example.com")
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "Missing DMARC" in finding.title


@pytest.mark.asyncio
async def test_dmarc_evaluation_p_none():
    scanner = AgencySentryScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    mock_response = [mock_txt]

    with patch("dns.asyncresolver.Resolver.resolve", return_value=mock_response):
        finding = await scanner.audit_dmarc("example.com")
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "p=none" in finding.description


@pytest.mark.asyncio
async def test_dmarc_evaluation_p_reject():
    scanner = AgencySentryScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    mock_response = [mock_txt]

    with patch("dns.asyncresolver.Resolver.resolve", return_value=mock_response):
        finding = await scanner.audit_dmarc("example.com")
        assert finding is None


@pytest.mark.asyncio
async def test_exposure_detection():
    scanner = AgencySentryScanner()
    
    mock_client = AsyncMock()
    # Mock .env response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "DB_HOST=localhost\nDB_PASSWORD=supersecret\n"
    mock_client.get.return_value = mock_response

    findings = await scanner.audit_exposures("https://example.com", client=mock_client)
    assert len(findings) > 0
    assert any(f.severity == Severity.CRITICAL and "/.env" in f.target for f in findings)


@pytest.mark.asyncio
async def test_subdomain_takeover_detection():
    scanner = AgencySentryScanner()

    mock_rdata = MagicMock()
    mock_rdata.target.to_text.return_value = "unbouncepages.com."
    mock_cname_response = [mock_rdata]

    mock_client = AsyncMock()
    mock_http_resp = MagicMock()
    mock_http_resp.status_code = 404
    mock_http_resp.text = "The requested URL was not found on this server"
    mock_client.get.return_value = mock_http_resp

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, return_value=mock_cname_response):
        finding = await scanner.check_subdomain_takeover("promo.example.com", client=mock_client)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "Unbounce" in finding.title
