import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orbit_security.models import Severity
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.recon import SENSITIVE_PATHS, check_headers_and_exposures
from orbit_security.remediation import DnsRemediationGenerator


def _make_stream_response(status_code=200, headers=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {"content-type": "text/plain"}
    resp.text = text
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client, resp


@pytest.mark.asyncio
async def test_audit_exposures_detects_composer_installed_json():
    scanner = OrbitSecurityScanner()
    composer_body = '{"packages": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}'

    async def fake_get(url):
        resp = MagicMock()
        resp.headers = {"content-type": "application/json"}
        if url.endswith("/vendor/composer/installed.json"):
            resp.status_code = 200
            resp.text = composer_body
        else:
            resp.status_code = 404
            resp.text = ""
        return resp

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=fake_get)

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_exposures("https://agency-client.com", client=mock_client)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "/vendor/composer/installed.json" in f.target
    assert "Composer" in f.title


@pytest.mark.asyncio
async def test_audit_exposures_detects_phpunit_eval_stdin_rce():
    scanner = OrbitSecurityScanner()
    phpunit_body = "<?php\nnamespace PHPUnit\\Util\\PHP;\neval('?>' . file_get_contents('php://input'));"

    async def fake_get(url):
        resp = MagicMock()
        resp.headers = {"content-type": "text/plain"}
        if url.endswith("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"):
            resp.status_code = 200
            resp.text = phpunit_body
        else:
            resp.status_code = 404
            resp.text = ""
        return resp

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=fake_get)

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_exposures("https://agency-client.com", client=mock_client)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "CVE-2017-9841" in f.title or "PHPUnit" in f.title
    assert "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" in f.target


@pytest.mark.asyncio
async def test_static_host_skips_vendor_php_exposures():
    scanner = OrbitSecurityScanner()
    client, _ = _make_stream_response(
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"packages": []}\nphp://input\neval(',
    )

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_exposures("https://cmfh009.github.io", client=client)

    targets = [f.target for f in findings]
    assert not any("/vendor/" in t for t in targets)


@pytest.mark.asyncio
async def test_php_version_and_pearcmd_guidance_in_headers():
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
        "X-Powered-By": "PHP/8.2.15",
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        findings = await scanner.audit_security_headers("https://php-client.com", client=mock_client)

    version_findings = [f for f in findings if "Version Disclosure" in f.title]
    assert len(version_findings) == 1
    vf = version_findings[0]
    assert "X-Powered-By: PHP/8.2.15" in vf.evidence
    assert "expose_php = Off" in vf.remediation
    assert "register_argc_argv = Off" in vf.remediation


@pytest.mark.asyncio
async def test_waf_bot_mitigation_detection():
    scanner = OrbitSecurityScanner()
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 418
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "CF-Ray": "8d66f1029a81-DFW",
        "Server": "cloudflare",
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("orbit_security.scanner.async_is_safe_host", return_value=True):
        mitigation = await scanner.detect_waf_and_bot_mitigation("https://protected.com", client=mock_client)

    assert mitigation["active"] is True
    assert "Cloudflare" in mitigation["providers"]
    assert mitigation["teapot_418_defense"] is True


def test_recon_sensitive_paths_include_composer_and_phpunit():
    paths = [p for p, _ in SENSITIVE_PATHS]
    assert "/vendor/composer/installed.json" in paths
    assert "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" in paths


def test_nginx_php_teapot_shield_generator():
    snippet = DnsRemediationGenerator.generate_nginx_php_teapot_shield("agency-client.com")
    assert "return 418;" in snippet
    assert "eval-stdin\\.php" in snippet
    assert "pearcmd" in snippet
    assert "invokefunction" in snippet
    assert "register_argc_argv = Off" in snippet
