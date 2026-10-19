"""Unit tests for score change detection / trending (agency_retainer.py).

Covers:
  - update_site_audit() pushes a pre-update snapshot onto scan_history.
  - scan_history is capped at MAX_SCAN_HISTORY (12) entries.
  - previous_score / previous_grade / score_delta computation.
  - get_score_trend() returns baseline/improved/declined/stable correctly.
  - First scan establishes a baseline (score_delta None, trend 'baseline').
  - Portal HTML contains delta badges when history exists.
  - generate_client_portals.py delta_badge() helper renders correct markup.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from orbit_security.agency_retainer import (
    AgencyClientSite,
    AgencyRetainerManager,
    MAX_SCAN_HISTORY,
    RetainerTier,
)


SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "generate_client_portals.py"


def load_portal_module():
    spec = importlib.util.spec_from_file_location("generate_client_portals", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gcp = load_portal_module()


# ---------------------------------------------------------------- update_site_audit history


def _fresh_manager(tmp_path) -> AgencyRetainerManager:
    data_file = tmp_path / "agency_retainers.json"
    manager = AgencyRetainerManager(data_path=data_file)
    manager.register_agency(
        agency_id="trend-agency",
        agency_name="Trend Agency",
        tier=RetainerTier.SCALE,
    )
    manager.add_client_domain("trend-agency", "example.com", client_name="Example Co")
    return manager


def test_first_scan_establishes_baseline(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 80, "B", 1, 2, 3)

    site = manager.get_agency("trend-agency").client_domains[0]
    # No prior scan -> baseline, no delta, empty history.
    assert site.score_delta is None
    assert site.previous_score is None
    assert site.previous_grade is None
    assert site.scan_history == []
    assert site.get_score_trend() == "baseline"


def test_second_scan_computes_delta_and_history(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 80, "B", 1, 2, 3)
    manager.update_site_audit("trend-agency", "example.com", 92, "A+", 0, 1, 2)

    site = manager.get_agency("trend-agency").client_domains[0]
    # Pre-update (80/B) snapshot pushed onto history.
    assert len(site.scan_history) == 1
    assert site.scan_history[0]["score"] == 80
    assert site.scan_history[0]["grade"] == "B"
    assert site.scan_history[0]["scanned_at"] is not None
    # Delta computed vs. previous scan.
    assert site.previous_score == 80
    assert site.previous_grade == "B"
    assert site.score_delta == 12
    assert site.get_score_trend() == "improved"
    assert site.last_score == 92
    assert site.last_grade == "A+"


def test_declined_trend(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 90, "A")
    manager.update_site_audit("trend-agency", "example.com", 70, "D")

    site = manager.get_agency("trend-agency").client_domains[0]
    assert site.score_delta == -20
    assert site.get_score_trend() == "declined"


def test_stable_trend(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 90, "A")
    manager.update_site_audit("trend-agency", "example.com", 90, "A")

    site = manager.get_agency("trend-agency").client_domains[0]
    assert site.score_delta == 0
    assert site.get_score_trend() == "stable"


def test_scan_history_capped_at_max(tmp_path):
    manager = _fresh_manager(tmp_path)
    # First scan establishes baseline; each subsequent scan appends one entry.
    total_scans = MAX_SCAN_HISTORY + 5
    for i in range(total_scans):
        manager.update_site_audit("trend-agency", "example.com", 50 + i, "B", 0, 0, 0)

    site = manager.get_agency("trend-agency").client_domains[0]
    # 17 scans -> 16 snapshots appended (first scan is baseline), capped to 12.
    assert len(site.scan_history) == MAX_SCAN_HISTORY
    # Most recent history entry is the pre-update snapshot of the LAST scan,
    # i.e. the score from the second-to-last scan (index total_scans - 2).
    assert site.scan_history[-1]["score"] == 50 + total_scans - 2
    # Oldest entries are pruned; retained window starts at snapshot #(16-12).
    assert site.scan_history[0]["score"] == 50 + (total_scans - 1 - MAX_SCAN_HISTORY)


def test_history_and_delta_persist_to_disk(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 80, "B")
    manager.update_site_audit("trend-agency", "example.com", 85, "B")

    # Reload from disk and confirm history/delta survive round-trip.
    reloaded = AgencyRetainerManager(data_path=manager.data_path)
    site = reloaded.get_agency("trend-agency").client_domains[0]
    assert site.score_delta == 5
    assert len(site.scan_history) == 1
    assert site.get_score_trend() == "improved"


def test_legacy_client_without_history_defaults(tmp_path):
    """Sites loaded from older JSON (no scan_history key) get safe defaults."""
    site = AgencyClientSite(domain="legacy.com", client_name="Legacy")
    assert site.scan_history == []
    assert site.previous_score is None
    assert site.previous_grade is None
    assert site.score_delta is None
    assert site.get_score_trend() == "baseline"


# ---------------------------------------------------------------- portal delta badge


def _site_with_delta(delta: int) -> AgencyClientSite:
    site = AgencyClientSite(domain="x.com", client_name="X")
    site.score_delta = delta
    site.scan_history = [{"score": 50, "grade": "F", "scanned_at": "2026-01-01T00:00:00"}]
    return site


def test_delta_badge_improved():
    html_out = gcp.delta_badge(_site_with_delta(12))
    assert "↑" in html_out
    assert "+12" in html_out
    assert "#10B981" in html_out


def test_delta_badge_declined():
    html_out = gcp.delta_badge(_site_with_delta(-8))
    assert "↓" in html_out
    assert "-8" in html_out
    assert "#EF4444" in html_out


def test_delta_badge_stable():
    html_out = gcp.delta_badge(_site_with_delta(0))
    assert "→" in html_out
    assert "0" in html_out
    assert "#94A3B8" in html_out


def test_delta_badge_baseline():
    site = AgencyClientSite(domain="x.com", client_name="X")  # no history
    html_out = gcp.delta_badge(site)
    assert "baseline" in html_out
    assert "↑" not in html_out and "↓" not in html_out


def test_portal_html_contains_delta_badge(tmp_path):
    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 80, "B")
    manager.update_site_audit("trend-agency", "example.com", 92, "A+", 0, 0, 0)
    agency = manager.get_agency("trend-agency")

    html_out = gcp.render_portal_html(agency, pdf_hrefs={})
    assert "delta-badge" in html_out
    assert "↑" in html_out
    assert "+12" in html_out


def test_builtin_renderer_contains_delta_badge(tmp_path):
    from orbit_security.agency_retainer import AgencyPortalRenderer

    manager = _fresh_manager(tmp_path)
    manager.update_site_audit("trend-agency", "example.com", 90, "A")
    manager.update_site_audit("trend-agency", "example.com", 70, "D", 1, 0, 0)
    agency = manager.get_agency("trend-agency")

    html_out = AgencyPortalRenderer.render_portal_html(agency)
    assert "↓" in html_out
    assert "-20" in html_out
