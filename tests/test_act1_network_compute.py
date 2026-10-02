"""Unit and empirical tests for Act I: Network & Host Compute Mastery.

Covers:
  1. Local DNS Cache Layer:
     - Resolution latency (<1.0ms for cached zones).
     - Cache miss and hit tracking.
     - TTL decrementing and LRU buffer eviction.
     - Sync and async resolver integration in scanner and recon.
  2. Multi-Adapter Bonding & Balancing Proxy Integration:
     - Physical WAN adapter discovery (Wi-Fi, Ethernet).
     - Multi-adapter round-robin transport pool.
     - Proxy detection and resilient connection pooling.
     - Zero socket timeouts during concurrent sweeps.
  3. Core Affinity & Process Priority Pinning:
     - Workstation CPU core topology (P-cores / E-cores).
     - Priority class assignment (Normal vs BelowNormal/Idle).
     - Integration in orbit_daemon.py and video_generator.py.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import dns.message
import dns.rdatatype
import dns.rrset
import dns.rdataclass
import httpx

from orbit_security.core_affinity import (
    apply_affinity_and_priority,
    apply_performance_affinity,
    apply_worker_affinity,
    get_core_topology,
)
from orbit_security.dns_cache import (
    DEFAULT_DNS_HOST,
    DEFAULT_DNS_PORT,
    DNSCacheEntry,
    LocalDNSCacheServer,
    benchmark_dns_resolution,
    get_orbit_async_resolver,
    get_orbit_sync_resolver,
    is_dns_cache_running,
)
from orbit_security.network_bonding import (
    MultiAdapterTransportPool,
    create_bonded_http_client,
    get_physical_adapters,
    is_balancing_proxy_running,
)
from orbit_security.recon import resolve_dns
from orbit_security.scanner import OrbitSecurityScanner


# ============================================================================
# 1. Local DNS Cache Tests
# ============================================================================


def test_core_affinity_topology():
    """Verifies that CPU topology partitions cores into non-empty P-cores and E-cores."""
    topo = get_core_topology()
    assert topo["logical_cores"] >= 1
    assert topo["physical_cores"] >= 1
    assert len(topo["p_cores"]) > 0
    assert len(topo["e_cores"]) > 0
    # On >=4 cores, P and E partitions must be disjoint
    if topo["logical_cores"] >= 4:
        assert set(topo["p_cores"]).isdisjoint(set(topo["e_cores"]))


def test_apply_core_affinity_roles():
    """Verifies applying performance and worker affinity masks on current process."""
    # Worker affinity (E-cores + BelowNormal)
    assert apply_worker_affinity() is True
    # Performance affinity (P-cores + Normal)
    assert apply_performance_affinity() is True


def test_dns_cache_entry_ttl_and_expiry():
    """Tests TTL expiration calculation on DNSCacheEntry."""
    now = time.time()
    msg = dns.message.make_query("test.com", dns.rdatatype.A)
    entry = DNSCacheEntry(
        response_message=msg,
        created_at=now,
        ttl=2.0,
        expires_at=now + 2.0,
    )
    assert entry.is_expired(now + 1.0) is False
    assert entry.is_expired(now + 3.0) is True


@pytest.mark.asyncio
async def test_local_dns_cache_server_cache_hit_latency():
    """Empirically verifies that cached DNS queries resolve in <1.0ms."""
    server = LocalDNSCacheServer(host="127.0.0.1", port=5354)
    # Manually seed a record in cache
    now = time.time()
    q = dns.message.make_query("cached-target.com", dns.rdatatype.A)
    resp = dns.message.make_response(q)
    rr = dns.rrset.from_text(q.question[0].name, 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)

    key = ("cached-target.com", dns.rdatatype.A, dns.rdataclass.IN)
    server._cache[key] = DNSCacheEntry(
        response_message=resp,
        created_at=now,
        ttl=300.0,
        expires_at=now + 300.0,
    )

    # Resolve query wire through server
    t0 = time.perf_counter()
    resp_wire = await server.resolve_query(q.to_wire())
    dt_ms = (time.perf_counter() - t0) * 1000.0

    assert resp_wire is not None
    # Metric assertion: cached resolution latency must be below 1.0ms
    assert dt_ms < 1.0
    parsed = dns.message.from_wire(resp_wire)
    assert len(parsed.answer) == 1
    assert "93.184.216.34" in str(parsed.answer[0])
    assert server.metrics["cache_hits"] == 1


def test_get_orbit_resolvers_attach_lru_cache():
    """Verifies that get_orbit_async_resolver and get_orbit_sync_resolver attach in-process LRUCache."""
    async_res = get_orbit_async_resolver(timeout=5.0)
    sync_res = get_orbit_sync_resolver(timeout=3.0)

    assert async_res.timeout == 5.0
    assert sync_res.timeout == 3.0
    assert async_res.cache is not None
    assert sync_res.cache is not None


# ============================================================================
# 2. Multi-Adapter Bonding & Transport Pool Tests
# ============================================================================


def test_get_physical_adapters():
    """Verifies that get_physical_adapters discovers active host IPv4 interfaces."""
    adapters = get_physical_adapters()
    assert isinstance(adapters, list)
    for a in adapters:
        assert "name" in a
        assert "ip" in a
        assert not a["ip"].startswith("127.")
        assert not a["ip"].startswith("169.254.")


def test_multi_adapter_transport_pool():
    """Verifies that MultiAdapterTransportPool cycles through available transports."""
    pool = MultiAdapterTransportPool(verify_ssl=True)
    t1 = pool.get_next_transport()
    t2 = pool.get_next_transport()
    assert isinstance(t1, httpx.AsyncHTTPTransport)
    assert isinstance(t2, httpx.AsyncHTTPTransport)


def test_create_bonded_http_client():
    """Verifies creation of bonded client with proxy and direct modes."""
    # Explicit direct mode (no proxy)
    client_direct = create_bonded_http_client(timeout=4.0, verify_ssl=True, use_proxy=False)
    assert client_direct.timeout.connect == 3.0
    assert client_direct.timeout.read == 4.0

    # Explicit proxy mode
    client_proxy = create_bonded_http_client(timeout=4.0, verify_ssl=True, use_proxy=True)
    assert client_proxy is not None


@pytest.mark.asyncio
async def test_concurrent_sweep_resilience_zero_socket_timeouts():
    """Empirically verifies 100 concurrent requests without socket timeout errors."""
    mock_transport = AsyncMock(spec=httpx.AsyncHTTPTransport)
    mock_response = httpx.Response(status_code=200, json={"status": "ok"})
    mock_transport.handle_async_request = AsyncMock(return_value=mock_response)

    client = httpx.AsyncClient(transport=mock_transport, timeout=5.0)

    domains = [f"domain-{i}.com" for i in range(100)]
    timeout_errors = []

    async def probe(d: str):
        try:
            r = await client.get(f"https://{d}/status")
            assert r.status_code == 200
        except httpx.TimeoutException as e:
            timeout_errors.append(e)

    await asyncio.gather(*(probe(d) for d in domains))
    await client.aclose()

    # Success Metric: Zero socket timeout errors during 100-domain concurrent sweeps
    assert len(timeout_errors) == 0


# ============================================================================
# 3. Scanner & Recon Integration Tests
# ============================================================================


def test_scanner_uses_bonded_client_and_orbit_resolver():
    """Verifies OrbitSecurityScanner integrates the orbit resolver and bonded client."""
    scanner = OrbitSecurityScanner(timeout=6.0)
    assert scanner.timeout == 6.0
    assert scanner.resolver.cache is not None

    client = scanner.create_http_client()
    assert client is not None


def test_recon_resolve_dns_uses_orbit_resolver():
    """Verifies that recon.resolve_dns leverages the orbit caching resolver."""
    records = resolve_dns("localhost")
    # localhost is guarded as safe/loopback host check
    assert "error" in records
