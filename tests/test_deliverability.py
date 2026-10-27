"""Tests for the outbound deliverability gate."""

import json
from pathlib import Path

import pytest

from orbit_security.deliverability import (
    DeliverabilityBlocked,
    assert_deliverable,
    bounce_stats,
)


def _write(path: Path, entries: int) -> Path:
    path.write_text(
        json.dumps({f"k{i}": {"v": i} for i in range(entries)}), encoding="utf-8"
    )
    return path


def test_bounce_stats_empty(tmp_path):
    sent, bounced, rate = bounce_stats(
        tmp_path / "dispatched.json", tmp_path / "bounced.json"
    )
    assert (sent, bounced, rate) == (0, 0, 0.0)


def test_bounce_stats_counts_dict_entries(tmp_path):
    dispatched = _write(tmp_path / "dispatched.json", 40)
    bounced = _write(tmp_path / "bounced.json", 10)
    assert bounce_stats(dispatched, bounced) == (40, 10, 0.25)


def test_small_sample_is_allowed(tmp_path):
    dispatched = _write(tmp_path / "dispatched.json", 5)
    bounced = _write(tmp_path / "bounced.json", 4)
    sent, bounced_n, rate = assert_deliverable(
        dispatched_path=dispatched, bounced_path=bounced
    )
    assert (sent, bounced_n) == (5, 4)
    assert rate > 0.05


def test_high_bounce_rate_blocks(tmp_path):
    dispatched = _write(tmp_path / "dispatched.json", 178)
    bounced = _write(tmp_path / "bounced.json", 46)
    with pytest.raises(DeliverabilityBlocked):
        assert_deliverable(dispatched_path=dispatched, bounced_path=bounced)


def test_force_overrides_block(tmp_path):
    dispatched = _write(tmp_path / "dispatched.json", 178)
    bounced = _write(tmp_path / "bounced.json", 46)
    sent, bounced_n, rate = assert_deliverable(
        force=True, dispatched_path=dispatched, bounced_path=bounced
    )
    assert sent == 178 and bounced_n == 46
    assert rate > 0.05


def test_env_override(tmp_path, monkeypatch):
    dispatched = _write(tmp_path / "dispatched.json", 100)
    bounced = _write(tmp_path / "bounced.json", 30)
    monkeypatch.setenv("ORBIT_ALLOW_HIGH_BOUNCE", "1")
    sent, bounced_n, _ = assert_deliverable(
        dispatched_path=dispatched, bounced_path=bounced
    )
    assert (sent, bounced_n) == (100, 30)


def test_healthy_rate_passes(tmp_path):
    dispatched = _write(tmp_path / "dispatched.json", 200)
    bounced = _write(tmp_path / "bounced.json", 4)
    sent, bounced_n, rate = assert_deliverable(
        dispatched_path=dispatched, bounced_path=bounced
    )
    assert (sent, bounced_n) == (200, 4)
    assert rate == pytest.approx(0.02)
