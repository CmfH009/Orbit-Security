import asyncio
import pytest
from unittest.mock import MagicMock, patch
import dns.exception

from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity


@pytest.mark.asyncio
async def test_audit_bimi_present():
    scanner = OrbitSecurityScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem;"]
    
    with patch.object(scanner.resolver, "resolve", return_value=[mock_txt]):
        finding = await scanner.audit_bimi("example.com")
        assert finding is None


@pytest.mark.asyncio
async def test_audit_bimi_missing():
    scanner = OrbitSecurityScanner()
    with patch.object(scanner.resolver, "resolve", side_effect=Exception("NXDOMAIN")):
        finding = await scanner.audit_bimi("example.com")
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert "BIMI" in finding.title
        assert "default._bimi.example.com" in finding.target


@pytest.mark.asyncio
async def test_audit_mta_sts_present():
    scanner = OrbitSecurityScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=STSv1; id=20260901;"]

    with patch.object(scanner.resolver, "resolve", return_value=[mock_txt]):
        finding = await scanner.audit_mta_sts("example.com")
        assert finding is None


@pytest.mark.asyncio
async def test_audit_mta_sts_missing():
    scanner = OrbitSecurityScanner()
    with patch.object(scanner.resolver, "resolve", side_effect=Exception("No answer")):
        finding = await scanner.audit_mta_sts("example.com")
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert "MTA-STS" in finding.title
        assert "_mta-sts.example.com" in finding.target


@pytest.mark.asyncio
async def test_audit_tls_rpt_present():
    scanner = OrbitSecurityScanner()
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=TLSRPTv1; rua=mailto:reports@example.com;"]

    with patch.object(scanner.resolver, "resolve", return_value=[mock_txt]):
        finding = await scanner.audit_tls_rpt("example.com")
        assert finding is None


@pytest.mark.asyncio
async def test_audit_tls_rpt_missing():
    scanner = OrbitSecurityScanner()
    with patch.object(scanner.resolver, "resolve", side_effect=Exception("No TXT record")):
        finding = await scanner.audit_tls_rpt("example.com")
        assert finding is not None
        assert finding.severity == Severity.INFO
        assert "TLS Reporting" in finding.title


@pytest.mark.asyncio
async def test_email_audits_timeout_resilience():
    scanner = OrbitSecurityScanner()
    with patch.object(scanner.resolver, "resolve", side_effect=dns.exception.Timeout("Timed out")):
        bimi_f = await scanner.audit_bimi("slow.example.com")
        mta_f = await scanner.audit_mta_sts("slow.example.com")
        tls_f = await scanner.audit_tls_rpt("slow.example.com")
        # Timeouts should not crash or produce false positive critical errors
        assert bimi_f is None
        assert mta_f is None
        assert tls_f is None
