"""High-performance local DNS caching resolver for Orbit Security.

Push bare-metal workstation and local network throughput to near-zero latency
(<1.0ms for cached zones) and zero resource waste.
Provides:
  - LocalDNSCacheServer: Asynchronous UDP/TCP DNS caching server on 127.0.0.1:53 (or custom port).
  - In-memory LRU TTL buffer with up to 256MB capacity.
  - Upstream multi-resolver forwarding (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4).
  - Client resolver factories (get_orbit_async_resolver, get_orbit_sync_resolver).
  - In-process LRU cache integration for sub-millisecond repeated queries.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver

logger = logging.getLogger("orbit_security.dns_cache")

DEFAULT_DNS_HOST = "127.0.0.1"
DEFAULT_DNS_PORT = int(os.environ.get("ORBIT_DNS_PORT", "53"))
DEFAULT_CACHE_SIZE_MB = 256
DEFAULT_UPSTREAMS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

# Shared process-level LRU cache for zero-overhead in-memory lookups
_GLOBAL_LRU_CACHE = dns.resolver.LRUCache(max_size=50000)


@dataclass
class DNSCacheEntry:
    """Individual cached DNS record entry with TTL and memory tracking."""

    response_message: dns.message.Message
    created_at: float
    ttl: float
    expires_at: float
    hit_count: int = 0
    estimated_size_bytes: int = 512

    def is_expired(self, now: Optional[float] = None) -> bool:
        ts = now if now is not None else time.time()
        return ts >= self.expires_at


class LocalDNSCacheServer:
    """Asynchronous local DNS caching daemon for 127.0.0.1:53."""

    def __init__(
        self,
        host: str = DEFAULT_DNS_HOST,
        port: int = DEFAULT_DNS_PORT,
        max_cache_mb: int = DEFAULT_CACHE_SIZE_MB,
        upstreams: Optional[List[str]] = None,
        min_ttl: int = 60,
        max_ttl: int = 86400,
    ):
        self.host = host
        self.port = port
        self.max_cache_bytes = max_cache_mb * 1024 * 1024
        self.upstreams = upstreams or list(DEFAULT_UPSTREAMS)
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl

        self._cache: collections.OrderedDict[Tuple[str, int, int], DNSCacheEntry] = (
            collections.OrderedDict()
        )
        self._cache_bytes = 0
        self._lock = asyncio.Lock()

        # Telemetry & performance metrics
        self.metrics: Dict[str, Any] = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "upstream_errors": 0,
            "total_latency_ms": 0.0,
            "cached_records_count": 0,
            "cache_bytes_used": 0,
            "start_time": time.time(),
        }

        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._running = False

    @property
    def hit_ratio(self) -> float:
        total = self.metrics["total_queries"]
        if total == 0:
            return 0.0
        return round((self.metrics["cache_hits"] / total) * 100.0, 2)

    @property
    def avg_latency_ms(self) -> float:
        total = self.metrics["total_queries"]
        if total == 0:
            return 0.0
        return round(self.metrics["total_latency_ms"] / total, 3)

    def _compute_ttl(self, msg: dns.message.Message) -> float:
        """Determines effective TTL from answer and authority record sets."""
        ttls: List[int] = []
        for section in (msg.answer, msg.authority):
            for rrset in section:
                if rrset.ttl > 0:
                    ttls.append(rrset.ttl)
        if not ttls:
            return float(self.min_ttl)
        effective = min(ttls)
        return float(max(self.min_ttl, min(effective, self.max_ttl)))

    def _get_cache_key(
        self, qname: str, rdtype: int, rdclass: int
    ) -> Tuple[str, int, int]:
        return (qname.strip().rstrip(".").lower(), rdtype, rdclass)

    def _evict_if_needed(self, new_bytes: int):
        """Enforces LRU eviction when memory ceiling is exceeded."""
        while (
            self._cache_bytes + new_bytes > self.max_cache_bytes
            and len(self._cache) > 0
        ):
            _, evicted = self._cache.popitem(last=False)
            self._cache_bytes = max(0, self._cache_bytes - evicted.estimated_size_bytes)

    def prune_expired(self):
        """Removes expired DNS cache entries."""
        now = time.time()
        keys_to_remove = [k for k, v in self._cache.items() if v.is_expired(now)]
        for k in keys_to_remove:
            entry = self._cache.pop(k, None)
            if entry:
                self._cache_bytes = max(
                    0, self._cache_bytes - entry.estimated_size_bytes
                )
        self.metrics["cached_records_count"] = len(self._cache)
        self.metrics["cache_bytes_used"] = self._cache_bytes

    async def resolve_query(
        self, query_wire: bytes, client_addr: Any = None
    ) -> Optional[bytes]:
        """Processes a DNS query wire packet, returning wire bytes response."""
        t_start = time.perf_counter()
        self.metrics["total_queries"] += 1

        try:
            query = dns.message.from_wire(query_wire)
        except Exception as e:
            logger.debug("Failed to parse DNS query wire: %s", e)
            self.metrics["upstream_errors"] += 1
            return None

        if not query.question:
            resp = dns.message.make_response(query)
            resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire()

        q = query.question[0]
        qname_str = q.name.to_text()
        rdtype = q.rdtype
        rdclass = q.rdclass
        key = self._get_cache_key(qname_str, rdtype, rdclass)
        now = time.time()

        # Check Cache
        cached_entry = self._cache.get(key)
        if cached_entry and not cached_entry.is_expired(now):
            self._cache.move_to_end(key)
            cached_entry.hit_count += 1
            self.metrics["cache_hits"] += 1

            # Prepare tailored response matching incoming transaction ID
            resp = dns.message.from_wire(cached_entry.response_message.to_wire())
            resp.id = query.id
            # Decrement TTLs proportionally
            remaining_ttl = max(1, int(cached_entry.expires_at - now))
            for rrset in resp.answer:
                rrset.ttl = remaining_ttl
            for rrset in resp.authority:
                rrset.ttl = remaining_ttl

            latency_ms = (time.perf_counter() - t_start) * 1000.0
            self.metrics["total_latency_ms"] += latency_ms
            return resp.to_wire()

        # Cache Miss: Forward upstream
        self.metrics["cache_misses"] += 1
        upstream_resp: Optional[dns.message.Message] = None

        for upstream in self.upstreams:
            try:
                upstream_resp = await dns.asyncquery.udp(query, upstream, timeout=2.0)
                if upstream_resp.flags & dns.flags.TC:
                    upstream_resp = await dns.asyncquery.tcp(
                        query, upstream, timeout=3.0
                    )
                if upstream_resp:
                    break
            except Exception:
                continue

        if not upstream_resp:
            self.metrics["upstream_errors"] += 1
            resp = dns.message.make_response(query)
            resp.set_rcode(dns.rcode.SERVFAIL)
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            self.metrics["total_latency_ms"] += latency_ms
            return resp.to_wire()

        # Calculate TTL and cache positive/negative answer
        ttl = self._compute_ttl(upstream_resp)
        wire_data = upstream_resp.to_wire()
        est_size = len(wire_data) + 256

        self._evict_if_needed(est_size)
        entry = DNSCacheEntry(
            response_message=upstream_resp,
            created_at=now,
            ttl=ttl,
            expires_at=now + ttl,
            hit_count=0,
            estimated_size_bytes=est_size,
        )
        self._cache[key] = entry
        self._cache_bytes += est_size
        self.metrics["cached_records_count"] = len(self._cache)
        self.metrics["cache_bytes_used"] = self._cache_bytes

        latency_ms = (time.perf_counter() - t_start) * 1000.0
        self.metrics["total_latency_ms"] += latency_ms
        return wire_data

    class _DatagramProtocol(asyncio.DatagramProtocol):
        def __init__(self, server: LocalDNSCacheServer):
            self.server = server
            self.transport: Optional[asyncio.DatagramTransport] = None

        def connection_made(self, transport: asyncio.DatagramTransport):
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Tuple[str, int]):
            asyncio.create_task(self._handle(data, addr))

        async def _handle(self, data: bytes, addr: Tuple[str, int]):
            try:
                resp_wire = await self.server.resolve_query(data, addr)
                if resp_wire and self.transport:
                    self.transport.sendto(resp_wire, addr)
            except Exception as e:
                logger.debug("UDP DNS handler error: %s", e)

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            while True:
                length_bytes = await reader.readexactly(2)
                length = int.from_bytes(length_bytes, byteorder="big")
                query_wire = await reader.readexactly(length)
                resp_wire = await self.resolve_query(
                    query_wire, writer.get_extra_info("peername")
                )
                if resp_wire:
                    resp_len = len(resp_wire).to_bytes(2, byteorder="big")
                    writer.write(resp_len + resp_wire)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug("TCP DNS client error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Starts asynchronous UDP and TCP listeners on host:port."""
        if self._running:
            return
        loop = asyncio.get_running_loop()

        # UDP endpoint
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self._DatagramProtocol(self),
            local_addr=(self.host, self.port),
            family=socket.AF_INET,
        )
        self._udp_transport = transport

        # TCP endpoint
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client, host=self.host, port=self.port
        )
        self._running = True
        logger.info(
            "✓ Local DNS Cache Resolver active on %s:%d (Buffer: %dMB)",
            self.host,
            self.port,
            self.max_cache_bytes // (1024 * 1024),
        )

    async def stop(self):
        """Stops listeners and flushes active sockets."""
        self._running = False
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
        logger.info("Local DNS Cache Resolver stopped.")


def is_dns_cache_running(
    host: str = DEFAULT_DNS_HOST,
    port: int = DEFAULT_DNS_PORT,
    timeout: float = 0.15,
) -> bool:
    """Verifies whether the local DNS cache resolver is actively responding on host:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Construct lightweight DNS query for localhost
        q = dns.message.make_query("localhost", dns.rdatatype.A)
        sock.sendto(q.to_wire(), (host, port))
        data, _ = sock.recvfrom(512)
        sock.close()
        return len(data) > 12
    except Exception:
        return False


def get_orbit_async_resolver(
    timeout: float = 8.0,
    port: int = DEFAULT_DNS_PORT,
    fallback_nameservers: Optional[List[str]] = None,
) -> dns.asyncresolver.Resolver:
    """Creates a high-performance dns.asyncresolver.Resolver routed through localhost cache first.

    If 127.0.0.1 is active, queries resolve with <1.0ms latency.
    Falls back gracefully to high-availability external resolvers (Cloudflare/Google).
    Equipped with in-process LRUCache for zero-overhead repeated query caching.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.cache = _GLOBAL_LRU_CACHE

    has_local = is_dns_cache_running(DEFAULT_DNS_HOST, port)
    fallbacks = fallback_nameservers or list(DEFAULT_UPSTREAMS)

    if has_local:
        resolver.nameservers = [DEFAULT_DNS_HOST] + fallbacks
        resolver.port = port
    else:
        resolver.nameservers = fallbacks
        resolver.port = 53

    return resolver


def get_orbit_sync_resolver(
    timeout: float = 4.0,
    port: int = DEFAULT_DNS_PORT,
    fallback_nameservers: Optional[List[str]] = None,
) -> dns.resolver.Resolver:
    """Creates a synchronous dns.resolver.Resolver routed through localhost cache first."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.cache = _GLOBAL_LRU_CACHE

    has_local = is_dns_cache_running(DEFAULT_DNS_HOST, port)
    fallbacks = fallback_nameservers or list(DEFAULT_UPSTREAMS)

    if has_local:
        resolver.nameservers = [DEFAULT_DNS_HOST] + fallbacks
        resolver.port = port
    else:
        resolver.nameservers = fallbacks
        resolver.port = 53

    return resolver


async def benchmark_dns_resolution(
    domain: str = "example.com",
    qtype: str = "A",
    iterations: int = 5,
    resolver: Optional[Any] = None,
) -> Dict[str, Any]:
    """Empirically measures DNS resolution latency across multiple iterations."""
    res = resolver or get_orbit_async_resolver()
    rdtype = dns.rdatatype.from_text(qtype)
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            if hasattr(res, "resolve") and asyncio.iscoroutinefunction(res.resolve):
                await res.resolve(domain, rdtype)
            else:
                res.resolve(domain, rdtype)
            dt = (time.perf_counter() - t0) * 1000.0
            latencies.append(dt)
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            latencies.append(dt)

    return {
        "domain": domain,
        "qtype": qtype,
        "iterations": iterations,
        "min_ms": round(min(latencies), 3) if latencies else 0.0,
        "max_ms": round(max(latencies), 3) if latencies else 0.0,
        "avg_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "latencies_ms": [round(l, 3) for l in latencies],
    }
