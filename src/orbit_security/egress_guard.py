from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urljoin, urlsplit

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]
    HTTPAdapter = object  # type: ignore[misc, assignment]


# CGNAT range (RFC 6598) not always flagged by ipaddress.is_private across Python versions
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class EgressViolationError(PermissionError):
    """Raised when an outbound request or redirect violates Zero-Trust RoE or SSRF boundaries."""

    def __init__(self, code: str, target: str, reason: str) -> None:
        self.code = code
        self.target = target
        self.reason = reason
        super().__init__(f"[{code}] Blocked egress to '{target}': {reason}")


class RoEEngineProtocol(Protocol):
    def is_target_permitted(self, target: str) -> bool: ...


class BlackboardProtocol(Protocol):
    def publish(self, event_type: str, payload: dict[str, Any], **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    hostname: str
    resolved_ips: tuple[str, ...] = ()
    violation_code: str | None = None
    reason: str = ""


def _is_bogon_or_internal_ip(raw_ip: str) -> bool:
    """Return True if the IP belongs to loopback, private, link-local, CGNAT, or reserved space."""
    # Strip IPv6 zone index if present (e.g., fe80::1%eth0)
    clean_ip = raw_ip.split("%", 1)[0]
    ip_obj = ipaddress.ip_address(clean_ip)
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NETWORK:
        return True
    return False


def _resolve_host_ips(hostname: str) -> tuple[str, ...]:
    """Resolve hostname to unique A/AAAA addresses, or return literal IP directly."""
    try:
        ipaddress.ip_address(hostname)
        return (hostname,)
    except ValueError:
        pass

    addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        if sockaddr:
            ip_str = str(sockaddr[0])
            if ip_str not in seen:
                seen.append(ip_str)
    return tuple(seen)


def evaluate_egress_target(
    url: str,
    roe_engine: RoEEngineProtocol,
    *,
    is_redirect: bool = False,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
) -> EgressDecision:
    """Validate URL scheme, RoE program scope, and resolved IP addresses."""
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return EgressDecision(
            allowed=False,
            hostname=parsed.hostname or "",
            violation_code="ROE_SCHEME_BLOCKED",
            reason=f"Unsupported or dangerous URI scheme '{scheme}'",
        )

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return EgressDecision(
            allowed=False,
            hostname="",
            violation_code="ROE_INVALID_HOST",
            reason="Missing target hostname in outbound URL",
        )

    # 1. Zero-Trust Rules of Engagement check (allowlist + explicit program.out_of_scope)
    if not roe_engine.is_target_permitted(hostname):
        code = "ROE_REDIRECT_BLOCKED" if is_redirect else "ROE_SCOPE_BLOCKED"
        return EgressDecision(
            allowed=False,
            hostname=hostname,
            violation_code=code,
            reason=f"Host '{hostname}' is out of scope or explicitly excluded by program RoE",
        )

    # 2. DNS resolution & bogon/SSRF protection
    try:
        resolved_ips = resolver(hostname)
    except socket.gaierror as exc:
        return EgressDecision(
            allowed=False,
            hostname=hostname,
            violation_code="ROE_DNS_FAILED",
            reason=f"DNS resolution failed for '{hostname}': {exc}",
        )

    for ip_str in resolved_ips:
        if _is_bogon_or_internal_ip(ip_str):
            return EgressDecision(
                allowed=False,
                hostname=hostname,
                resolved_ips=resolved_ips,
                violation_code="ROE_BOGON_BLOCKED",
                reason=f"Host '{hostname}' resolved to restricted internal/bogon IP '{ip_str}'",
            )

    return EgressDecision(allowed=True, hostname=hostname, resolved_ips=resolved_ips)


def enforce_egress_or_raise(
    url: str,
    roe_engine: RoEEngineProtocol,
    blackboard: BlackboardProtocol | None = None,
    *,
    is_redirect: bool = False,
    source_url: str | None = None,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
) -> EgressDecision:
    """Evaluate target egress and publish structured telemetry to blackboard on block."""
    decision = evaluate_egress_target(
        url,
        roe_engine,
        is_redirect=is_redirect,
        resolver=resolver,
    )
    if not decision.allowed:
        code = decision.violation_code or "ROE_EGRESS_BLOCKED"
        if blackboard is not None:
            payload: dict[str, Any] = {
                "target_url": url,
                "hostname": decision.hostname,
                "resolved_ips": list(decision.resolved_ips),
                "is_redirect": is_redirect,
                "reason": decision.reason,
            }
            if source_url:
                payload["source_url"] = source_url
            blackboard.publish(code, payload)
        raise EgressViolationError(code=code, target=url, reason=decision.reason)
    return decision


# ---------------------------------------------------------------------------
# httpx Client Factories (Sync & Async)
# ---------------------------------------------------------------------------

def _build_httpx_hooks(
    roe_engine: RoEEngineProtocol,
    blackboard: BlackboardProtocol | None = None,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
) -> dict[str, list[Callable[..., Any]]]:
    def on_request(request: Any) -> None:
        is_redirect = bool(request.extensions.get("orbit_is_redirect", False))
        source_url = request.extensions.get("orbit_source_url")
        enforce_egress_or_raise(
            str(request.url),
            roe_engine,
            blackboard=blackboard,
            is_redirect=is_redirect,
            source_url=source_url,
            resolver=resolver,
        )

    def on_response(response: Any) -> None:
        if response.is_redirect and "location" in response.headers:
            current_url = str(response.request.url)
            next_url = urljoin(current_url, response.headers["location"])
            # Pre-validate redirect hop immediately so ROE_REDIRECT_BLOCKED is logged
            enforce_egress_or_raise(
                next_url,
                roe_engine,
                blackboard=blackboard,
                is_redirect=True,
                source_url=current_url,
                resolver=resolver,
            )

    async def on_async_request(request: Any) -> None:
        on_request(request)

    async def on_async_response(response: Any) -> None:
        on_response(response)

    return {
        "sync_request": [on_request],
        "sync_response": [on_response],
        "async_request": [on_async_request],
        "async_response": [on_async_response],
    }


def create_guarded_httpx_client(
    roe_engine: RoEEngineProtocol,
    blackboard: BlackboardProtocol | None = None,
    *,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
    **kwargs: Any,
) -> Any:
    """Create a synchronous httpx.Client gated by RulesOfEngagementEngine."""
    if httpx is None:
        raise RuntimeError("httpx is not installed in this environment")
    hooks = _build_httpx_hooks(roe_engine, blackboard=blackboard, resolver=resolver)
    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        event_hooks={
            "request": hooks["sync_request"],
            "response": hooks["sync_response"],
        },
        **kwargs,
    )


def create_guarded_async_httpx_client(
    roe_engine: RoEEngineProtocol,
    blackboard: BlackboardProtocol | None = None,
    *,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
    **kwargs: Any,
) -> Any:
    """Create an asynchronous httpx.AsyncClient gated by RulesOfEngagementEngine."""
    if httpx is None:
        raise RuntimeError("httpx is not installed in this environment")
    hooks = _build_httpx_hooks(roe_engine, blackboard=blackboard, resolver=resolver)
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        event_hooks={
            "request": hooks["async_request"],
            "response": hooks["async_response"],
        },
        **kwargs,
    )


# ---------------------------------------------------------------------------
# requests Session Factory & Transport Adapter
# ---------------------------------------------------------------------------

class RoEHTTPAdapter(HTTPAdapter):
    """Requests transport adapter validating every initial request and redirect hop."""

    def __init__(
        self,
        roe_engine: RoEEngineProtocol,
        blackboard: BlackboardProtocol | None = None,
        resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
        **kwargs: Any,
    ) -> None:
        self._roe_engine = roe_engine
        self._blackboard = blackboard
        self._resolver = resolver
        super().__init__(**kwargs)

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        # requests.Session sets 'Referer' or tracks history during resolve_redirects;
        # hook response redirects explicitly as well as every outbound send().
        enforce_egress_or_raise(
            str(request.url),
            self._roe_engine,
            blackboard=self._blackboard,
            is_redirect=False,
            resolver=self._resolver,
        )
        response = super().send(request, *args, **kwargs)
        if response.is_redirect and "location" in response.headers:
            current_url = str(request.url)
            next_url = urljoin(current_url, response.headers["location"])
            enforce_egress_or_raise(
                next_url,
                self._roe_engine,
                blackboard=self._blackboard,
                is_redirect=True,
                source_url=current_url,
                resolver=self._resolver,
            )
        return response


def create_guarded_requests_session(
    roe_engine: RoEEngineProtocol,
    blackboard: BlackboardProtocol | None = None,
    *,
    max_redirects: int = 5,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_host_ips,
) -> Any:
    """Create a requests.Session with RoEHTTPAdapter mounted on http:// and https://."""
    if requests is None:
        raise RuntimeError("requests is not installed in this environment")
    session = requests.Session()
    session.max_redirects = max_redirects
    adapter = RoEHTTPAdapter(
        roe_engine=roe_engine,
        blackboard=blackboard,
        resolver=resolver,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
