import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orbit_security.scanner import (
    OrbitSecurityScanner,
    is_static_hosting_domain,
    is_parked_or_reserved_domain,
)
from orbit_security.models import Severity, Finding

STATIC_HOST = "cmfh009.github.io"


def _mock_client(status_code=200, headers=None, text=""):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.text = text
    client = AsyncMock()
    client.get = AsyncMock(return_value=mock_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client, mock_resp


@pytest.mark.asyncio
async def test_static_host_skips_hsts_finding():
    scanner = OrbitSecurityScanner()
    client, _ = _mock_client(headers={})

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_security_headers(
            f"https://{STATIC_HOST}", client=client
        )

    titles = [f.title for f in findings]
    # Headers managed at the CDN edge must be skipped entirely on static hosts.
    assert "Missing HSTS Header (HTTP Strict Transport Security)" not in titles
    assert "Missing Content Security Policy (CSP)" not in titles
    assert "Missing X-Frame-Options (Clickjacking Protection)" not in titles
    assert "Missing Referrer-Policy Header" not in titles
    # Non-edge headers are kept (as INFO).
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Permissions-Policy" in t for t in titles)


@pytest.mark.asyncio
async def test_static_host_skips_dotfile_exposures():
    scanner = OrbitSecurityScanner()
    # /.env returns a match-worthy response; it must be skipped on static hosts.
    client, _ = _mock_client(
        headers={"content-type": "text/plain"},
        text="DB_PASSWORD=supersecret\nAWS_SECRET_ACCESS_KEY=abc\n",
    )

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_exposures(
            f"https://{STATIC_HOST}", client=client
        )

    targets = [f.target for f in findings]
    assert not any("/.env" in t for t in targets)
    assert not any("/.git" in t for t in targets)


@pytest.mark.asyncio
async def test_reserved_domain_returns_parked_finding_only():
    scanner = OrbitSecurityScanner()
    client = _mock_client()[0]

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        with patch.object(scanner, "create_http_client", return_value=client):
            res = await scanner.scan_domain("example.com", use_crtsh=False)

    assert res.score == 100
    assert res.grade == "A+"
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.title == "Reserved / Parked Domain (No Active Audit)"
    assert f.severity == Severity.INFO
    assert f.target == "example.com"


@pytest.mark.asyncio
async def test_example_com_is_reserved():
    assert await is_parked_or_reserved_domain("example.com") is True
    assert await is_parked_or_reserved_domain("example.org") is True
    assert await is_parked_or_reserved_domain("example.net") is True
    assert await is_parked_or_reserved_domain("example.edu") is True
    assert await is_parked_or_reserved_domain("example.int") is True
    assert await is_parked_or_reserved_domain("example.co") is True
    assert await is_parked_or_reserved_domain("site.test") is True
    assert await is_parked_or_reserved_domain("site.invalid") is True
    assert await is_parked_or_reserved_domain("site.localhost") is True
    assert await is_parked_or_reserved_domain("site.example") is True

    # Non-reserved domain with a failing network client is not parked.
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("network down"))
    assert await is_parked_or_reserved_domain("normal-site.com", client=mock_client) is False
