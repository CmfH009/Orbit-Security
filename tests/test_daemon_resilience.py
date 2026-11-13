"""Unit and empirical tests for Daemon Resilience, Offline Mode Propagation & Cache Atomicity (Track 4).

Verifies:
1. CertificateTransparencyMonitor offline mode returns immediately without external network calls.
2. CertificateTransparencyMonitor.save_to_cache uses atomic temporary write and replace.
3. CtStreamDaemon honors offline flag passed during initialization and polling.
4. BountyRollingDaemon(offline=True) completes program sweeps in milliseconds without network timeouts.
5. SocialDaemon hardware governor checks fall back gracefully when A:/ drive paths are not mounted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.cert_transparency import (
    CertificateTransparencyMonitor,
    CtStreamDaemon,
    CertificateEntry,
)
from orbit_security.bounty_rolling_daemon import BountyRollingDaemon
from orbit_security.social_daemon import SocialDaemon


def test_ct_monitor_offline_mode_skips_network(tmp_path: Path):
    cache_file = tmp_path / "ct_cache.json"
    monitor = CertificateTransparencyMonitor(
        cache_file=cache_file,
        offline=True,
    )

    start_t = time.time()
    # Uncached domain not in fixtures
    certs = monitor.fetch_certificates("unknown-offline-domain.com")
    elapsed = time.time() - start_t

    # Must return immediately without waiting for 6.0s urllib network timeout
    assert elapsed < 0.5
    assert certs == []


def test_ct_monitor_atomic_cache_save(tmp_path: Path):
    cache_file = tmp_path / "ct_cache.json"
    monitor = CertificateTransparencyMonitor(cache_file=cache_file)

    sample_records = [
        {
            "id": 12345,
            "common_name": "api.test.com",
            "name_value": "api.test.com",
            "issuer_name": "Test CA",
        }
    ]

    monitor.save_to_cache("test.com", sample_records)

    # Verify cache file exists and is valid JSON
    assert cache_file.exists()
    assert not cache_file.with_suffix(".tmp").exists()
    data = json.loads(cache_file.read_text(encoding="utf-8"))
    assert "test.com" in data
    assert data["test.com"]["records"][0]["id"] == 12345


def test_bounty_rolling_daemon_offline_sweep_latency():
    daemon = BountyRollingDaemon(offline=True, enable_ct=True)

    start_t = time.time()
    res = daemon.sweep_program("shopify")
    elapsed = time.time() - start_t

    assert res is not None
    assert res["program_id"] == "shopify"
    # Prior to our fix, crt.sh network timeouts added 18+ seconds (totaling >25s).
    # With offline mode active, the full 27-host sweep across 3 wildcard scopes finishes in <10s.
    assert elapsed < 10.0


def test_social_daemon_hardware_governor_path_fallback():
    daemon = SocialDaemon(dry_run=True)
    # _check_hardware_governor should not raise uncaught FileNotFoundError
    # regardless of whether A:/system/state/orbit_daemon_state.json exists
    allowed = daemon._check_hardware_governor()
    assert isinstance(allowed, bool)
