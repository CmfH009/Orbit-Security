"""Unit tests for scripts/generate_client_portals.py.

Covers:
- slugify() and grade_color() pure functions
- main() --dry-run prints the plan without writing files
- main() live run generates portals with expected content
- main() --agency substring filter (case-insensitive)
- main() error isolation (one failed agency doesn't crash the batch)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import importlib.util

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "generate_client_portals.py"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_client_portals", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gcp = load_module()


# ---------------------------------------------------------------- slugify

@pytest.mark.parametrize(
    "name,expected",
    [
        ("eastside-co", "eastside-co"),
        ("Blue Stout", "blue-stout"),
        ("  Spaced  ", "spaced"),
        ("A.B.C.", "a-b-c"),
        ("Double--Dash", "double-dash"),
    ],
)
def test_slugify(name, expected):
    assert gcp.slugify(name) == expected


# ---------------------------------------------------------------- grade_color

@pytest.mark.parametrize(
    "grade,expected",
    [
        ("A+", "#10B981"),
        ("A", "#10B981"),
        ("B", "#10B981"),
        ("C", "#10B981"),
        ("D", "#F59E0B"),
        ("F", "#EF4444"),
        (None, "#EF4444"),
    ],
)
def test_grade_color(grade, expected):
    assert gcp.grade_color(grade) == expected


# ---------------------------------------------------------------- find_client_pdf / pdf_href

def test_find_client_pdf_returns_none_when_missing(tmp_path):
    assert gcp.find_client_pdf("no-such-agency", "example.com") is None


def test_pdf_href_placeholder_when_no_pdf(tmp_path):
    assert gcp.pdf_href(tmp_path / "portals", None) == "#"


# ---------------------------------------------------------------- main() dry-run

def test_main_dry_run_prints_plan_without_writing(capsys, tmp_path, monkeypatch):
    """--dry-run prints the portal plan but writes no HTML files."""
    out_dir = tmp_path / "portals"
    monkeypatch.setattr(gcp, "DEFAULT_OUTPUT_DIR", out_dir)
    monkeypatch.setattr(
        sys, "argv", ["generate_client_portals.py", "--dry-run", "--limit", "2"]
    )

    gcp.main()

    out = capsys.readouterr().out
    assert "[DRY-RUN] No HTML files will be written." in out
    assert "Would generate" in out
    assert "Eastside Co (3 clients)" in out
    assert "We Make Websites (2 clients)" in out
    assert not out_dir.exists(), "no files should be written in dry-run"


# ---------------------------------------------------------------- main() live run

def test_main_live_run_writes_portals(capsys, tmp_path, monkeypatch):
    """Live run writes one HTML portal per agency with expected content."""
    out_dir = tmp_path / "portals"
    monkeypatch.setattr(gcp, "DEFAULT_OUTPUT_DIR", out_dir)
    monkeypatch.setattr(
        sys, "argv", ["generate_client_portals.py", "--limit", "1"]
    )

    gcp.main()

    out = capsys.readouterr().out
    assert "[✓] Portal generated for Eastside Co (3 clients)" in out
    assert "1 portals generated, 0 failed." in out

    html_path = out_dir / "eastside-co.html"
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Eastside Co" in content
    assert "Enterprise Shopify Plus Technical Solutions" in content
    assert "ops@eastsideco.com" in content
    assert "security.eastsideco.com" in content
    assert "Candy Kittens" in content
    assert "Wildfang Apparel" in content
    assert "trolli.com" in content
    assert "Dashboard Summary" in content
    assert "score-badge" in content
    assert "No PDF Audit" in content  # placeholder when no audit PDF exists
    assert "Orbit Security Labs" in content


# ---------------------------------------------------------------- main() agency filter

def test_main_agency_filter(capsys, tmp_path, monkeypatch):
    """--agency narrows to agencies whose agency_id contains the substring."""
    out_dir = tmp_path / "portals"
    monkeypatch.setattr(gcp, "DEFAULT_OUTPUT_DIR", out_dir)
    monkeypatch.setattr(
        sys, "argv", ["generate_client_portals.py", "--agency", "BARREL"]
    )

    gcp.main()

    out = capsys.readouterr().out
    assert "Barrel (1 clients)" in out
    assert "Eastside Co" not in out
    assert "1 portals generated, 0 failed." in out


# ---------------------------------------------------------------- main() error isolation

def test_main_error_isolation_continues_batch(capsys, tmp_path, monkeypatch):
    """If one agency fails to render, the batch continues with the next."""
    out_dir = tmp_path / "portals"
    monkeypatch.setattr(gcp, "DEFAULT_OUTPUT_DIR", out_dir)

    original_render = gcp.render_portal_html

    def failing_render(agency, pdf_hrefs):
        if agency.agency_id == "we-make-websites":
            raise RuntimeError("boom")
        return original_render(agency, pdf_hrefs)

    monkeypatch.setattr(gcp, "render_portal_html", failing_render)
    monkeypatch.setattr(
        sys, "argv", ["generate_client_portals.py", "--limit", "2"]
    )

    gcp.main()

    out = capsys.readouterr().out
    assert "[✓] Portal generated for Eastside Co (3 clients)" in out
    assert "[❌] Portal failed for We Make Websites: boom" in out
    assert "1 portals generated, 1 failed." in out
    assert (out_dir / "eastside-co.html").exists()
