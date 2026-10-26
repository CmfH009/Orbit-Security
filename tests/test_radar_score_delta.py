"""Unit tests for the Historical Score Delta & Prospect Re-Scan Buying-Signal Tracker.

Contract under test (``RadarLeadEnricher._save_enriched_lead``):
- Keeps at most 12 rolling snapshots in ``enrichment_history``.
- Each snapshot carries a UTC ISO-8601 timestamp plus score/grade/posture.
- ``score_delta`` is the difference between the current and previous scan.
- ``is_buying_signal`` fires when the score drops by >= 10 points OR when the
  domain has been probed at least 3 times.
"""

from __future__ import annotations

import datetime
import json

import pytest

from orbit_security.radar_lead_enricher import RadarLeadEnricher
from orbit_security.radar_telemetry import format_discord_radar_embed


def _save(enricher: RadarLeadEnricher, domain: str, score: int, **extra) -> None:
    profile = {"computed_score": score, "computed_grade": "B", **extra}
    enricher._save_enriched_lead(domain, profile)


def _read(leads_file):
    return json.loads(leads_file.read_text(encoding="utf-8"))


@pytest.fixture
def enricher(tmp_path):
    return RadarLeadEnricher(leads_file=tmp_path / "leads.json")


def test_first_scan_initializes_history_without_buying_signal(tmp_path, enricher):
    domain = "acmesignal.com"
    _save(enricher, domain, 65, dmarc_status="none")

    record = _read(tmp_path / "leads.json")[domain]

    assert len(record["enrichment_history"]) == 1
    assert record["enrichment_history"][0]["score"] == 65
    assert record["enrichment_history"][0]["grade"] == "B"
    assert record["enrichment_history"][0]["dmarc_status"] == "none"
    assert record["score_delta"] == 0
    assert record["previous_score"] == 65
    assert record["probe_count"] == 1
    assert record["is_buying_signal"] is False


def test_history_snapshot_timestamps_are_utc_iso8601(tmp_path, enricher):
    _save(enricher, "acmesignal.com", 70)

    snapshot = _read(tmp_path / "leads.json")["acmesignal.com"]["enrichment_history"][0]
    parsed = datetime.datetime.fromisoformat(snapshot["timestamp"])

    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.timedelta(0)
    assert snapshot["timestamp"].endswith("+00:00")


def test_score_delta_between_two_scans(tmp_path, enricher):
    domain = "acmesignal.com"
    _save(enricher, domain, 65)
    _save(enricher, domain, 92)

    record = _read(tmp_path / "leads.json")[domain]

    assert len(record["enrichment_history"]) == 2
    assert [s["score"] for s in record["enrichment_history"]] == [65, 92]
    assert record["previous_score"] == 65
    assert record["score_delta"] == 27
    assert record["probe_count"] == 2
    # Improvement at probe #2 is not one of the two buying-signal triggers.
    assert record["is_buying_signal"] is False


def test_buying_signal_triggers_on_score_drop_of_ten_points(tmp_path, enricher):
    domain = "regressedbrand.com"
    _save(enricher, domain, 80)
    _save(enricher, domain, 70, dmarc_status="missing")

    record = _read(tmp_path / "leads.json")[domain]

    assert record["score_delta"] == -10
    assert record["previous_score"] == 80
    assert record["probe_count"] == 2
    assert record["is_buying_signal"] is True


def test_buying_signal_ignores_drops_smaller_than_ten_points(tmp_path, enricher):
    domain = "minorregress.com"
    _save(enricher, domain, 80)
    _save(enricher, domain, 71)

    record = _read(tmp_path / "leads.json")[domain]

    assert record["score_delta"] == -9
    assert record["probe_count"] == 2
    assert record["is_buying_signal"] is False


def test_buying_signal_triggers_at_third_probe(tmp_path, enricher):
    domain = "repeatprobe.com"
    for score in (70, 70, 70):
        _save(enricher, domain, score)

    record = _read(tmp_path / "leads.json")[domain]

    assert record["probe_count"] == 3
    assert record["score_delta"] == 0
    assert record["is_buying_signal"] is True


def test_history_caps_at_twelve_rolling_snapshots(tmp_path, enricher):
    domain = "longtail.com"
    for score in range(50, 64):  # 14 scans
        _save(enricher, domain, score)

    record = _read(tmp_path / "leads.json")[domain]
    history = record["enrichment_history"]

    assert len(history) == 12
    assert record["probe_count"] == 12
    # The two oldest snapshots (50, 51) must have rolled off.
    assert history[0]["score"] == 52
    assert history[-1]["score"] == 63
    assert record["previous_score"] == 62
    assert record["score_delta"] == 1
    assert record["is_buying_signal"] is True


def test_repeated_saves_do_not_mutate_prior_snapshots(tmp_path, enricher):
    domain = "immutablehistory.com"
    _save(enricher, domain, 90, dmarc_status="enforced")
    _save(enricher, domain, 90, dmarc_status="none")

    history = _read(tmp_path / "leads.json")[domain]["enrichment_history"]

    assert history[0]["dmarc_status"] == "enforced"
    assert history[1]["dmarc_status"] == "none"


def test_discord_embed_flags_buying_signal_on_score_drop():
    record = {"domain": "regressedbrand.com", "score": 70, "grade": "C"}
    enrichment = {
        "computed_score": 70,
        "computed_grade": "C",
        "previous_score": 85,
        "score_delta": -15,
        "probe_count": 2,
        "is_buying_signal": True,
    }

    embed = format_discord_radar_embed(record, enrichment=enrichment)["embeds"][0]
    fields = {f["name"]: f["value"] for f in embed["fields"]}

    signal_field = next(name for name in fields if "BUYING SIGNAL" in name)
    assert "Probe #2" in fields[signal_field]
    assert "-15" in fields[signal_field]
    assert "85" in fields[signal_field] and "70" in fields[signal_field]
    assert embed["fields"][0]["name"] == signal_field


def test_discord_embed_flags_buying_signal_on_repeat_probe():
    record = {"domain": "repeatprobe.com", "score": 88, "grade": "A"}
    enrichment = {
        "computed_score": 88,
        "computed_grade": "A",
        "previous_score": 88,
        "score_delta": 0,
        "probe_count": 3,
        "is_buying_signal": True,
    }

    embed = format_discord_radar_embed(record, enrichment=enrichment)["embeds"][0]
    fields = {f["name"]: f["value"] for f in embed["fields"]}

    signal_field = next(name for name in fields if "BUYING SIGNAL" in name)
    assert "Probe #3" in fields[signal_field]


def test_discord_embed_shows_delta_without_signal_flag():
    record = {"domain": "acmesignal.com", "score": 92, "grade": "A"}
    enrichment = {
        "computed_score": 92,
        "computed_grade": "A",
        "previous_score": 65,
        "score_delta": 27,
        "probe_count": 2,
        "is_buying_signal": False,
    }

    embed = format_discord_radar_embed(record, enrichment=enrichment)["embeds"][0]
    fields = {f["name"]: f["value"] for f in embed["fields"]}

    assert not any("BUYING SIGNAL" in name for name in fields)
    delta_field = next(name for name in fields if "Delta" in name or "Re-Scan" in name)
    assert "+27" in fields[delta_field]
    assert "65" in fields[delta_field] and "92" in fields[delta_field]


def test_discord_embed_omits_delta_for_first_scan():
    record = {"domain": "freshscan.com", "score": 78, "grade": "B"}
    enrichment = {"computed_score": 78, "computed_grade": "B"}

    embed = format_discord_radar_embed(record, enrichment=enrichment)["embeds"][0]
    fields = {f["name"]: f["value"] for f in embed["fields"]}

    assert not any("BUYING SIGNAL" in name for name in fields)
    assert not any("Delta" in name or "Re-Scan" in name for name in fields)
