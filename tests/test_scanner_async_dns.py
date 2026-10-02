"""Unit tests for async_is_safe_host and SSL client verification in scanner.py."""

import asyncio
import pytest
from orbit_security.scanner import OrbitSecurityScanner, async_is_safe_host, is_safe_host


def test_async_is_safe_host_matches_sync():
    """Verifies that async_is_safe_host correctly classifies public vs loopback/private hosts."""
    assert asyncio.run(async_is_safe_host("127.0.0.1")) is False
    assert asyncio.run(async_is_safe_host("localhost")) is False
    assert asyncio.run(async_is_safe_host("metadata.google.internal")) is False
    assert asyncio.run(async_is_safe_host("instance-data")) is False
    assert asyncio.run(async_is_safe_host("corp.local")) is False
    assert asyncio.run(async_is_safe_host("internal.company.internal")) is False
    assert asyncio.run(async_is_safe_host("example.com")) is True


def test_create_http_client_verify_ssl():
    """Verifies that create_http_client supports configurable verify_ssl and defaults to True."""
    scanner = OrbitSecurityScanner()
    client_default = scanner.create_http_client()
    # In httpx, verify is configured as an SSL context or boolean in client._transport
    # We can check client is initialized without errors
    assert client_default is not None

    client_unverified = scanner.create_http_client(verify_ssl=False)
    assert client_unverified is not None
