"""tests/test_egress_roe_guard.py: Unit tests for Transport-Layer RoE Egress & Redirect Guard."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch
import pytest
import httpx
import requests
from requests.adapters import HTTPAdapter

from orbit_security.egress_guard import (
    EgressViolationError,
    evaluate_egress_target,
    enforce_egress_or_raise,
    create_guarded_httpx_client,
    create_guarded_async_httpx_client,
    create_guarded_requests_session,
    _is_bogon_or_internal_ip,
)


class MockRoEEngine:
    """Mock RoE engine with wildcard allowlist and specific subdomains out of scope."""

    def __init__(self, in_scope_domains: list[str], out_of_scope_domains: list[str]) -> None:
        self.in_scope = in_scope_domains
        self.out_of_scope = out_of_scope_domains

    def is_target_permitted(self, host: str) -> bool:
        clean = host.strip().lower()
        # Explicit out of scope check
        for oos in self.out_of_scope:
            if clean == oos or clean.endswith("." + oos):
                return False
        # In scope check
        for pattern in self.in_scope:
            if pattern.startswith("*."):
                apex = pattern[2:]
                if clean == apex or clean.endswith("." + apex):
                    return True
            elif clean == pattern:
                return True
        return False


class MockBlackboard:
    """Mock blackboard capturing published RoE security events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def publish(self, event_type: str, payload: dict[str, Any], **kwargs: Any) -> None:
        self.events.append((event_type, payload))


@pytest.fixture
def roe_engine() -> MockRoEEngine:
    return MockRoEEngine(
        in_scope_domains=["*.example.com", "allowed-partner.net"],
        out_of_scope_domains=["internal.example.com", "stg.example.com"],
    )


@pytest.fixture
def mock_blackboard() -> MockBlackboard:
    return MockBlackboard()


def test_bogon_ip_detection() -> None:
    # IPv4 loopback & RFC1918
    assert _is_bogon_or_internal_ip("127.0.0.1") is True
    assert _is_bogon_or_internal_ip("10.0.0.5") is True
    assert _is_bogon_or_internal_ip("172.16.50.1") is True
    assert _is_bogon_or_internal_ip("192.168.1.100") is True
    # Link-local & cloud metadata
    assert _is_bogon_or_internal_ip("169.254.169.254") is True
    # RFC6598 CGNAT
    assert _is_bogon_or_internal_ip("100.64.0.1") is True
    assert _is_bogon_or_internal_ip("100.127.255.255") is True
    # IPv6 loopback, ULA, link-local
    assert _is_bogon_or_internal_ip("::1") is True
    assert _is_bogon_or_internal_ip("fc00::1") is True
    assert _is_bogon_or_internal_ip("fe80::1") is True
    # Public routable IPs
    assert _is_bogon_or_internal_ip("93.184.216.34") is False
    assert _is_bogon_or_internal_ip("1.1.1.1") is False
    assert _is_bogon_or_internal_ip("2606:4700:4700::1111") is False


def test_direct_outbound_request_blocked_if_out_of_scope(
    roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    client = create_guarded_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("93.184.216.34",),
    )
    with pytest.raises(EgressViolationError) as exc_info:
        client.get("https://unauthorized-target.org/api")

    assert exc_info.value.code == "ROE_SCOPE_BLOCKED"
    assert len(mock_blackboard.events) == 1
    event_type, payload = mock_blackboard.events[0]
    assert event_type == "ROE_SCOPE_BLOCKED"
    assert payload["hostname"] == "unauthorized-target.org"
    assert payload["is_redirect"] is False


def test_httpx_redirect_to_out_of_scope_domain_blocked(
    roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://app.example.com/redirect-out":
            return httpx.Response(302, headers={"Location": "https://evil-attacker.com/leak"})
        return httpx.Response(200, text="OK")

    client = create_guarded_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("93.184.216.34",),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(EgressViolationError) as exc_info:
        client.get("https://app.example.com/redirect-out")

    assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"
    assert "evil-attacker.com" in exc_info.value.target
    assert len(mock_blackboard.events) == 1
    event_type, payload = mock_blackboard.events[0]
    assert event_type == "ROE_REDIRECT_BLOCKED"
    assert payload["hostname"] == "evil-attacker.com"
    assert payload["is_redirect"] is True
    assert payload["source_url"] == "https://app.example.com/redirect-out"


def test_httpx_redirect_to_excluded_subdomain_blocked(
    roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://app.example.com/go-internal":
            return httpx.Response(301, headers={"Location": "https://internal.example.com/vault"})
        return httpx.Response(200, text="OK")

    client = create_guarded_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("93.184.216.34",),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(EgressViolationError) as exc_info:
        client.get("https://app.example.com/go-internal")

    assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"
    assert "internal.example.com" in exc_info.value.target
    assert any(ev[0] == "ROE_REDIRECT_BLOCKED" for ev in mock_blackboard.events)


@pytest.mark.parametrize(
    "bogon_ip",
    [
        "127.0.0.1",
        "10.10.10.1",
        "172.20.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.50",
        "::1",
    ],
)
def test_dns_resolution_bogon_and_private_ip_blocked(
    bogon_ip: str, roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    client = create_guarded_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: (bogon_ip,),
    )
    with pytest.raises(EgressViolationError) as exc_info:
        client.get("https://app.example.com/status")

    assert exc_info.value.code == "ROE_BOGON_BLOCKED"
    assert any(ev[0] == "ROE_BOGON_BLOCKED" for ev in mock_blackboard.events)


def test_valid_multi_hop_in_scope_redirects_succeed(roe_engine: MockRoEEngine) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://app.example.com/hop1":
            return httpx.Response(302, headers={"Location": "https://auth.example.com/hop2"})
        elif url == "https://auth.example.com/hop2":
            return httpx.Response(302, headers={"Location": "https://allowed-partner.net/landing"})
        elif url == "https://allowed-partner.net/landing":
            return httpx.Response(200, text="AUTHORIZED_ACCESS")
        return httpx.Response(404)

    client = create_guarded_httpx_client(
        roe_engine=roe_engine,
        resolver=lambda _: ("93.184.216.34",),
        transport=httpx.MockTransport(handler),
    )

    resp = client.get("https://app.example.com/hop1")
    assert resp.status_code == 200
    assert resp.text == "AUTHORIZED_ACCESS"


@pytest.mark.asyncio
async def test_async_httpx_client_redirect_and_bogon_blocking(
    roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://app.example.com/async-redirect":
            return httpx.Response(307, headers={"Location": "https://rogue-target.com/drain"})
        return httpx.Response(200, text="ASYNC_OK")

    client = create_guarded_async_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("93.184.216.34",),
        transport=httpx.MockTransport(handler),
    )

    async with client:
        with pytest.raises(EgressViolationError) as exc_info:
            await client.get("https://app.example.com/async-redirect")
        assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"

    # Async bogon check
    bogon_client = create_guarded_async_httpx_client(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("127.0.0.1",),
    )
    async with bogon_client:
        with pytest.raises(EgressViolationError) as exc_info:
            await bogon_client.get("https://app.example.com/probe")
        assert exc_info.value.code == "ROE_BOGON_BLOCKED"


def test_requests_session_redirect_and_scope_blocking(
    roe_engine: MockRoEEngine, mock_blackboard: MockBlackboard
) -> None:
    session = create_guarded_requests_session(
        roe_engine=roe_engine,
        blackboard=mock_blackboard,
        resolver=lambda _: ("93.184.216.34",),
    )

    # 1. Direct out of scope
    with pytest.raises(EgressViolationError) as exc_info:
        session.get("https://out-of-scope.org/api")
    assert exc_info.value.code == "ROE_SCOPE_BLOCKED"

    # 2. Redirect to out-of-scope
    def mock_send_redirect(self: HTTPAdapter, request: Any, *args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.request = request
        resp.url = str(request.url)
        resp.status_code = 302
        resp.headers["Location"] = "https://unauthorized.org/exfil"
        return resp

    with patch.object(HTTPAdapter, "send", mock_send_redirect):
        with pytest.raises(EgressViolationError) as exc_info:
            session.get("https://app.example.com/login")
        assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"

    # 3. Multi-hop in-scope redirect succeeds
    def mock_send_multihop(self: HTTPAdapter, request: Any, *args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.request = request
        url = str(request.url)
        resp.url = url
        if url == "https://app.example.com/auth":
            resp.status_code = 302
            resp.headers["Location"] = "https://allowed-partner.net/dashboard"
        elif url == "https://allowed-partner.net/dashboard":
            resp.status_code = 200
            resp._content = b"OK_SESSION"
        return resp

    with patch.object(HTTPAdapter, "send", mock_send_multihop):
        res = session.get("https://app.example.com/auth")
        assert res.status_code == 200
        assert res.text == "OK_SESSION"


def test_dangerous_uri_schemes_blocked(roe_engine: MockRoEEngine) -> None:
    decision = evaluate_egress_target("file:///etc/passwd", roe_engine)
    assert decision.allowed is False
    assert decision.violation_code == "ROE_SCHEME_BLOCKED"

    decision2 = evaluate_egress_target("gopher://127.0.0.1:70", roe_engine)
    assert decision2.allowed is False
    assert decision2.violation_code == "ROE_SCHEME_BLOCKED"
