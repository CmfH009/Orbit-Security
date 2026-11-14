"""Regression tests for Round 2 ROE-EGRESS-001 compliance and pytest daemon-thread isolation."""

from __future__ import annotations

from pathlib import Path
import threading
from unittest.mock import MagicMock, patch

import httpx
import pytest

from orbit_security.ast_sentinel import audit_egress_guard_compliance
from orbit_security.dns_cache import is_dns_cache_running
from orbit_security.egress_guard import EgressViolationError
from orbit_security.recon import check_headers_and_exposures
from orbit_security.recon_harvester import CertificateTransparencyStreamer
from orbit_security.smuggling_sentinel import HttpRequestSmugglingSentinel
from orbit_security.tools.adhx_client import ADHXClient
from orbit_security.tools.xh_probe import XHProbe


def test_round2_modules_have_zero_egress_violations() -> None:
    src_dir = Path(__file__).resolve().parent.parent / "src" / "orbit_security"
    targets = [
        src_dir / "dns_cache.py",
        src_dir / "recon.py",
        src_dir / "recon_harvester.py",
        src_dir / "smuggling_sentinel.py",
        src_dir / "tools" / "adhx_client.py",
        src_dir / "tools" / "xh_probe.py",
    ]
    violations = audit_egress_guard_compliance(targets)
    assert violations == [], f"Unexpected ROE-EGRESS-001 violations: {violations}"


def test_dns_cache_probe_blocks_non_loopback_hosts_and_allows_loopback() -> None:
    with patch("socket.socket", side_effect=AssertionError("Must block non-loopback host")):
        assert is_dns_cache_running(host="8.8.8.8") is False
        assert is_dns_cache_running(host="169.254.169.254") is False
        assert is_dns_cache_running(host="attacker.example.com") is False

    mock_sock = MagicMock()
    mock_sock.recvfrom.return_value = (b"\x00" * 20, ("127.0.0.1", 53))
    with patch("socket.socket", return_value=mock_sock):
        assert is_dns_cache_running(host="127.0.0.1", port=5354) is True
    mock_sock.close.assert_called_once()


def test_recon_check_headers_blocks_internal_dns_and_redirect_ssrf() -> None:
    # Layer 1: PublicHostOnlyRoE scope blocks private/loopback DNS resolution
    with patch("orbit_security.recon.is_safe_host", return_value=True), patch(
        "socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
    ):
        report = check_headers_and_exposures("rebind.example.com")
        assert "ROE_SCOPE_BLOCKED" in report.get("error", "")
        assert report["exposures"] == []

    # Layer 2: Even if RoE scope check is bypassed, egress_guard blocks bogon DNS resolution
    with patch("orbit_security.recon.is_safe_host", return_value=True), patch(
        "orbit_security.scanner.PublicHostOnlyRoE.is_target_permitted",
        return_value=True,
    ), patch(
        "socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
    ):
        report = check_headers_and_exposures("rebind.example.com")
        assert "ROE_BOGON_BLOCKED" in report.get("error", "")
        assert report["exposures"] == []

    # Verify redirect hop to metadata IP is caught via create_guarded_httpx_client event hooks
    def _fake_transport_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    with patch(
        "socket.getaddrinfo",
        side_effect=lambda h, *a, **kw: (
            [(2, 1, 6, "", ("169.254.169.254", 0))]
            if "169.254" in h
            else [(2, 1, 6, "", ("93.184.216.34", 0))]
        ),
    ):
        from orbit_security.egress_guard import create_guarded_httpx_client
        from orbit_security.scanner import PublicHostOnlyRoE

        client = create_guarded_httpx_client(
            roe_engine=PublicHostOnlyRoE(),
            transport=httpx.MockTransport(_fake_transport_handler),
        )
        with client:
            with pytest.raises(EgressViolationError) as exc_info:
                client.get("https://public.example.com/")
            assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"


def test_recon_harvester_probe_tls_sans_blocks_dns_rebinding_before_socket() -> None:
    with patch("orbit_security.recon_harvester.is_safe_host", return_value=True), patch(
        "socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("10.0.0.5", 0))],
    ), patch("socket.create_connection", side_effect=AssertionError("Must block before socket connect")):
        assert CertificateTransparencyStreamer.probe_tls_sans("internal-rebind.example.com") == []


def test_smuggling_sentinel_blocks_dns_rebinding_before_raw_socket() -> None:
    with patch("orbit_security.smuggling_sentinel.is_safe_host", return_value=True), patch(
        "socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("169.254.169.254", 0))],
    ), patch("socket.create_connection", side_effect=AssertionError("Must block before socket connect")):
        elapsed, status, body = HttpRequestSmugglingSentinel._send_raw_http(
            host="rebind-smug.example.com",
            port=443,
            raw_payload=b"GET / HTTP/1.1\r\nHost: rebind-smug.example.com\r\n\r\n",
        )
        assert (elapsed, status, body) == (0.0, 0, b"")
        assert HttpRequestSmugglingSentinel.audit_h2_te_downgrade("rebind-smug.example.com") is None


def test_adhx_client_blocks_ssrf_across_httpx_and_urllib_fallback() -> None:
    client = ADHXClient(base_url="http://127.0.0.1:8080/api")
    with pytest.raises(EgressViolationError):
        client._http_get_json("http://127.0.0.1:8080/api/tweet/1")

    with patch.dict("sys.modules", {"httpx": None}), patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("Must block before urlopen"),
    ):
        with pytest.raises(EgressViolationError):
            client._http_get_json("http://169.254.169.254/latest/meta-data/")


def test_xh_probe_enforces_egress_across_cli_cert_and_fallback() -> None:
    probe = XHProbe(xh_path="nonexistent_xh.exe")

    with patch("socket.create_connection", side_effect=AssertionError("Must block before TLS socket")):
        with pytest.raises(EgressViolationError):
            probe.inspect_certificate("https://127.0.0.1:443")

    with pytest.raises(EgressViolationError):
        probe._fallback_httpx_probe(
            url="http://169.254.169.254/latest",
            method="GET",
            headers=None,
            timeout_sec=1.0,
            follow_redirects=False,
            verify_ssl=True,
            inspect_cert=False,
            offline=False,
        )

    with patch.object(probe, "is_installed", return_value=True), patch(
        "subprocess.run",
        side_effect=AssertionError("Must block before xh CLI execution"),
    ):
        with pytest.raises(EgressViolationError):
            probe.probe("http://127.0.0.1:9000/status", offline=False)


def test_conftest_blocks_run_menu_background_telemetry_scanner_thread() -> None:
    ran = []

    def background_telemetry_scanner() -> None:
        ran.append("leaked")

    background_telemetry_scanner.__module__ = "run_menu"
    t_leaked = threading.Thread(target=background_telemetry_scanner, daemon=True)
    t_leaked.start()
    assert ran == []
    assert not t_leaked.is_alive()
    assert not t_leaked._started.is_set()

    # Normal threads must continue functioning unaffected
    normal_ran = []

    def normal_worker() -> None:
        normal_ran.append("ok")

    t_ok = threading.Thread(target=normal_worker, daemon=True)
    t_ok.start()
    t_ok.join(timeout=2.0)
    assert normal_ran == ["ok"]

    # Zero leaked run_menu background_telemetry_scanner threads in the live pytest process
    scanner_threads = [
        t for t in threading.enumerate() if "background_telemetry_scanner" in t.name and t.is_alive()
    ]
    assert scanner_threads == []
