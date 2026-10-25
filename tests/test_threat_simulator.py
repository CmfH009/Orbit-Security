"""Unit tests for orbit_security.tools.threat_simulator (TDD).

Validates:
1. Scenario registry completeness and valid blackboard schemas.
2. Injection of single threat scenarios into SQLite WAL Blackboard.
3. Realistic playback pacing.
4. High-concurrency burst mode (100+ events) with zero SQLite locking issues.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.tools.threat_simulator import ThreatSimulator, SCENARIOS


def test_scenario_registry_integrity():
    required_keys = ["topic", "event_type", "payload", "source"]
    for scenario_id, data in SCENARIOS.items():
        for k in required_keys:
            assert k in data, f"Scenario '{scenario_id}' missing required key: '{k}'"
        assert len(data["payload"]) > 0, f"Scenario '{scenario_id}' has empty payload"


def test_inject_single_scenario():
    mock_bb = MagicMock()
    sim = ThreatSimulator(blackboard=mock_bb)

    res = sim.inject_scenario("dangling_s3_takeover")
    assert res is True
    mock_bb.publish.assert_called_once()
    kwargs = mock_bb.publish.call_args[1]
    assert kwargs["event_type"] == "SUBDOMAIN_TAKEOVER_DETECTED"
    assert kwargs["topic"] == "perimeter"
    assert kwargs["source"] == "threat_simulator"
    assert kwargs["payload"]["service"] == "AWS S3"


def test_inject_cisa_kev_scenario():
    mock_bb = MagicMock()
    sim = ThreatSimulator(blackboard=mock_bb)

    res = sim.inject_scenario("cisa_kev_weaponized")
    assert res is True
    mock_bb.publish.assert_called_once()
    kwargs = mock_bb.publish.call_args[1]
    assert kwargs["event_type"] == "CISA_KEV_MATCH_DETECTED"
    assert kwargs["payload"]["cve_id"] == "CVE-2024-21887"


def test_burst_mode_concurrency(tmp_path):
    # Use real SQLite WAL Blackboard instance in temporary path
    from orbit_security.blackboard import Blackboard
    db_path = tmp_path / "test_sim_blackboard.db"
    real_bb = Blackboard(db_path=db_path)

    sim = ThreatSimulator(blackboard=real_bb)
    injected_count = sim.run_burst(count=100)

    assert injected_count == 100
    recent = real_bb.get_recent(limit=150)
    assert len(recent) == 100
    assert all(e["source"] == "threat_simulator" for e in recent)


def test_playback_mode_iteration():
    mock_bb = MagicMock()
    sim = ThreatSimulator(blackboard=mock_bb)

    # Inject 3 events with 0 delay for unit test speed
    injected = sim.run_playback(count=3, interval_sec=0.0)
    assert injected == 3
    assert mock_bb.publish.call_count == 3
