"""Unit tests for the Unified Morning Cockpit integrations."""

from __future__ import annotations

import os
import pytest
from scripts.unified_morning_cockpit import (
    query_system_telemetry,
    query_projects_radar,
    query_calendar_and_tasks,
    query_intel_and_world_news,
)


def test_query_system_telemetry_returns_valid_structure():
    telemetry = query_system_telemetry()
    assert isinstance(telemetry, dict)
    assert "cpu_name" in telemetry
    assert "temp_c" in telemetry
    assert isinstance(telemetry["temp_c"], (int, float))
    assert "uptime" in telemetry
    assert "ram_used_gb" in telemetry
    assert "ram_total_gb" in telemetry
    assert "drives" in telemetry
    assert "open_ports" in telemetry
    assert isinstance(telemetry["open_ports"], list)


def test_query_projects_radar_discovers_repositories():
    radar = query_projects_radar()
    assert isinstance(radar, dict)
    assert "total_projects" in radar
    assert radar["total_projects"] > 0
    assert "projects" in radar
    assert "recently_active" in radar
    # Verify project item structure
    first = radar["projects"][0]
    assert "name" in first
    assert "branch" in first
    assert "last_commit" in first
    assert "roadmap" in first


def test_query_calendar_and_tasks_handles_unconfigured(monkeypatch):
    monkeypatch.delenv("GOOGLE_CALENDAR_ICAL_URL", raising=False)
    cal = query_calendar_and_tasks()
    assert isinstance(cal, dict)
    assert "configured" in cal
    assert "events_today" in cal
    assert "birthdays" in cal


def test_query_intel_and_world_news_returns_content():
    news = query_intel_and_world_news()
    assert isinstance(news, dict)
    assert "ai_innovations" in news
    assert "world_news" in news
    assert len(news["ai_innovations"]) > 0 or len(news["world_news"]) > 0
