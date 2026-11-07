"""Unit tests for Daily Briefing GitHub Actions HEAD status reconciliation."""

from __future__ import annotations

import json
import pytest

from scripts.daily_briefing import (
    query_live_github_ci_status,
    reconcile_ci_alerts_with_live_status,
)


def test_reconcile_ci_alerts_marks_stale_email_alerts_resolved_when_head_is_green():
    stale_email_alerts = [
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (42a8f0d)",
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (cf922c4)",
    ]
    live_ci = {
        "status": "ok",
        "head_sha": "717b2aa",
        "all_green": True,
        "failing_workflows": [],
        "passing_workflows": ["Orbit Security CI", "Orbit Security Perimeter Sentinel"],
    }

    reconciled = reconcile_ci_alerts_with_live_status(stale_email_alerts, live_ci)
    assert reconciled["active_failures"] == 0
    assert len(reconciled["resolved_alerts"]) == 2
    assert "717b2aa" in reconciled["summary_markdown"]
    assert "RESOLVED on HEAD 717b2aa" in reconciled["summary_markdown"]
    assert "green on HEAD" in reconciled["spoken_note"]


def test_reconcile_ci_alerts_surfaces_active_failures_when_head_is_failing():
    email_alerts = [
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (717b2aa)",
    ]
    live_ci = {
        "status": "ok",
        "head_sha": "717b2aa",
        "all_green": False,
        "failing_workflows": ["Orbit Security CI"],
        "passing_workflows": ["Orbit Security Perimeter Sentinel"],
    }

    reconciled = reconcile_ci_alerts_with_live_status(email_alerts, live_ci)
    assert reconciled["active_failures"] == 1
    assert "Orbit Security CI" in reconciled["summary_markdown"]
    assert "failing on HEAD" in reconciled["spoken_note"]


def test_query_live_github_ci_status_parses_workflow_runs(monkeypatch):
    sample_api_payload = {
        "workflow_runs": [
            {
                "name": "Orbit Security CI",
                "head_sha": "717b2aa9999999",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Orbit Security Perimeter Sentinel",
                "head_sha": "717b2aa9999999",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Orbit Security CI",
                "head_sha": "42a8f0d1111111",
                "status": "completed",
                "conclusion": "failure",
            },
        ]
    }

    class DummyResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(sample_api_payload).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=6.0: DummyResp())

    res = query_live_github_ci_status()
    assert res["status"] == "ok"
    assert res["head_sha"] == "717b2aa"
    assert res["all_green"] is True
    assert res["failing_workflows"] == []
    assert "Orbit Security CI" in res["passing_workflows"]


def test_query_geo_panel_telemetry_surfaces_summary_and_delta(tmp_path):
    from orbit_security.geo_panel import GeoPromptPanel
    from scripts.daily_briefing import query_geo_panel_telemetry

    log_file = tmp_path / "geo_panels.jsonl"
    panel = GeoPromptPanel(log_file=log_file)
    panel.run_panel(engines=["mock"], dry_run=False)
    panel.run_panel(engines=["mock"], dry_run=False)

    geo = query_geo_panel_telemetry(log_file=str(log_file))
    assert geo["has_data"] is True
    assert geo["has_previous_run"] is True
    assert geo["total_records"] == 24
    assert "Latest 12-Query Panel" in geo["summary_markdown"]
    assert "Panel Run-over-Run Delta" in geo["summary_markdown"]

