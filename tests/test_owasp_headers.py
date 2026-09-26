import pytest
from unittest.mock import AsyncMock, MagicMock
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity


@pytest.mark.asyncio
async def test_audit_security_headers_all_hardened():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    mock_client.get.return_value = mock_resp

    findings = await scanner.audit_security_headers("https://hardened.example.com", client=mock_client)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_audit_security_headers_missing_owasp():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_client.get.return_value = mock_resp

    findings = await scanner.audit_security_headers("https://bare.example.com", client=mock_client)
    titles = [f.title for f in findings]
    assert any("HSTS" in t for t in titles)
    assert any("Content Security Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Permissions-Policy" in t for t in titles)
    assert any("Cross-Origin-Opener-Policy" in t for t in titles)


@pytest.mark.asyncio
async def test_audit_security_headers_hsts_incomplete():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    # Has max-age, but missing includeSubDomains and preload
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    mock_client.get.return_value = mock_resp

    findings = await scanner.audit_security_headers("https://example.com", client=mock_client)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "HSTS Header Incomplete" in findings[0].title
