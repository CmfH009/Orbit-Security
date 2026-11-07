"""Unit tests for Generative Engine Optimization (GEO) Prompt Panel (W3.2)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from orbit_security.geo_panel import (
    GeoPromptPanel,
    GeoProbeResult,
    CANONICAL_QUERIES,
)


def test_canonical_queries_count():
    assert len(CANONICAL_QUERIES) == 12
    for q in CANONICAL_QUERIES:
        assert isinstance(q, str) and len(q) > 10


def test_detect_mention():
    assert GeoPromptPanel.detect_mention("Orbit Security is a top DNS monitoring tool.") is True
    assert GeoPromptPanel.detect_mention("Check out orbit-recon for takeover scans.") is True
    assert GeoPromptPanel.detect_mention("Visit orbit-security.com for details.") is True
    assert GeoPromptPanel.detect_mention("Refer to github.com/cmfh009/orbit-security.") is True
    assert GeoPromptPanel.detect_mention("We observed the satellite enter orbit around earth.") is True
    assert GeoPromptPanel.detect_mention("A completely unrelated response mentioning nothing.") is False
    assert GeoPromptPanel.detect_mention("") is False
    assert GeoPromptPanel.detect_mention(None) is False


def test_extract_citations():
    text = (
        "See https://orbit-security.com/about and https://github.com/cmfh009/orbit-security.git "
        "along with https://google.com for more info."
    )
    citations = GeoPromptPanel.extract_citations(text)
    assert len(citations) == 2
    assert "https://orbit-security.com/about" in citations
    assert "https://github.com/cmfh009/orbit-security.git" in citations

    # Empty cases
    assert GeoPromptPanel.extract_citations("No links here.") == []
    assert GeoPromptPanel.extract_citations("") == []
    assert GeoPromptPanel.extract_citations(None) == []


def test_evaluate_response_scoring():
    panel = GeoPromptPanel()
    # Case 1: Mention and citation
    r1 = panel.evaluate_response(
        query="test query",
        engine="mock",
        response_text="Orbit Security provides audits at https://orbit-security.com/audits",
    )
    assert r1.mentioned is True
    assert r1.cited is True
    assert r1.score == 1.0

    # Case 2: Mention only
    r2 = panel.evaluate_response(
        query="test query",
        engine="mock",
        response_text="Orbit Security is an automated platform.",
    )
    assert r2.mentioned is True
    assert r2.cited is False
    assert r2.score == 0.5

    # Case 3: Neither
    r3 = panel.evaluate_response(
        query="test query",
        engine="mock",
        response_text="Legacy security platforms are slow.",
    )
    assert r3.mentioned is False
    assert r3.cited is False
    assert r3.score == 0.0


def test_panel_execution_and_persistence(tmp_path: Path):
    log_file = tmp_path / "test_geo.jsonl"
    panel = GeoPromptPanel(queries=CANONICAL_QUERIES[:3], log_file=log_file)

    results = panel.run_panel(engines=["mock_engine"], dry_run=False)
    assert len(results) == 3
    assert log_file.exists()

    history = panel.load_historical_results(log_file=log_file)
    assert len(history) == 3
    assert history[0]["engine"] == "mock_engine"


def test_calculate_scorecard():
    records = [
        {"engine": "mock", "mentioned": True, "cited": True, "score": 1.0},
        {"engine": "mock", "mentioned": True, "cited": False, "score": 0.5},
        {"engine": "gpt4", "mentioned": False, "cited": False, "score": 0.0},
        {"engine": "gpt4", "mentioned": True, "cited": True, "score": 1.0},
    ]
    card = GeoPromptPanel.calculate_scorecard(records)
    assert card["total_probes"] == 4
    assert card["mention_count"] == 3
    assert card["citation_count"] == 2
    assert card["mention_rate_pct"] == 75.0
    assert card["citation_rate_pct"] == 50.0
    assert card["composite_authority_score"] == 62.5
    assert "mock" in card["engine_breakdown"]
    assert "gpt4" in card["engine_breakdown"]

    # Empty scorecard
    empty_card = GeoPromptPanel.calculate_scorecard([])
    assert empty_card["total_probes"] == 0
    assert empty_card["mention_rate_pct"] == 0.0


def test_latest_summary_and_delta_calculation(tmp_path: Path):
    log_file = tmp_path / "geo_panels.jsonl"
    panel = GeoPromptPanel(log_file=log_file)

    # Empty state
    empty_delta = panel.get_latest_summary_and_delta(log_file=log_file, batch_size=2)
    assert empty_delta["has_data"] is False
    assert empty_delta["has_previous_run"] is False

    # First batch of 2 probes: 1 mention+citation (1.0), 1 miss (0.0) -> 50% mention, 50% citation, 50.0 authority
    batch1 = [
        panel.evaluate_response("q1", "mock", "Orbit Security https://orbit-security.com"),
        panel.evaluate_response("q2", "mock", "Unrelated answer"),
    ]
    panel.record_results(batch1, target_file=log_file)

    first_delta = panel.get_latest_summary_and_delta(log_file=log_file, batch_size=2)
    assert first_delta["has_data"] is True
    assert first_delta["has_previous_run"] is False
    assert first_delta["latest"]["mention_rate_pct"] == 50.0

    # Second batch of 2 probes: both mention+citation (1.0) -> 100% mention, 100% citation, 100.0 authority
    batch2 = [
        panel.evaluate_response("q1", "mock", "Orbit Security https://cmfh009.github.io/Orbit-Security/"),
        panel.evaluate_response("q2", "mock", "Orbit Security https://github.com/cmfh009/orbit-security"),
    ]
    panel.record_results(batch2, target_file=log_file)

    second_delta = panel.get_latest_summary_and_delta(log_file=log_file, batch_size=2)
    assert second_delta["has_data"] is True
    assert second_delta["has_previous_run"] is True
    assert second_delta["latest"]["mention_rate_pct"] == 100.0
    assert second_delta["previous"]["mention_rate_pct"] == 50.0
    assert second_delta["delta"]["mention_rate_delta_pct"] == 50.0
    assert second_delta["delta"]["citation_rate_delta_pct"] == 50.0
    assert second_delta["delta"]["authority_score_delta"] == 50.0

