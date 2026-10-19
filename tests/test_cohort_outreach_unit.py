"""Unit tests for scripts/run_cohort_outreach.py (mock-based, no external targets).

Covers:
- slugify(), pick_domain(), build_branding() pure functions
- main() --dry-run lists prospects without scanning/writing
- main() error isolation (one failed scan doesn't crash the batch)
- main() --agency substring filter
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

import importlib.util

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "run_cohort_outreach.py"


def load_cohort_module():
    spec = importlib.util.spec_from_file_location("run_cohort_outreach", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


co = load_cohort_module()


# ---------------------------------------------------------------- slugify

@pytest.mark.parametrize(
    "name,expected",
    [
        ("Blue Stout", "blue-stout"),
        ("BVA Agency", "bva-agency"),
        ("Corra", "corra"),
        ("A.B.C.", "a-b-c"),
        ("  Spaced  ", "spaced"),
        ("Double--Dash", "double-dash"),
    ],
)
def test_slugify(name, expected):
    assert co.slugify(name) == expected


# ---------------------------------------------------------------- pick_domain

def test_pick_domain_uses_first_portfolio():
    prospect = {
        "agency_name": "Blue Stout",
        "agency_domain": "bluestout.com",
        "portfolio_domains": ["goruck.com", "bulletproof.com"],
    }
    assert co.pick_domain(prospect) == "goruck.com"


def test_pick_domain_falls_back_to_agency_domain():
    prospect = {
        "agency_name": "NoPortfolio",
        "agency_domain": "noportfolio.com",
        "portfolio_domains": [],
    }
    assert co.pick_domain(prospect) == "noportfolio.com"


def test_pick_domain_no_portfolios_key():
    prospect = {"agency_name": "X", "agency_domain": "x.com"}
    assert co.pick_domain(prospect) == "x.com"


# ---------------------------------------------------------------- build_branding

def test_build_branding_fields():
    prospect = {
        "agency_name": "Blue Stout",
        "agency_domain": "bluestout.com",
        "contact_email": "hello@bluestout.com",
    }
    branding = co.build_branding(prospect)
    assert branding.agency_name == "Blue Stout"
    assert branding.support_email == "hello@bluestout.com"
    assert branding.website == "https://bluestout.com"


def test_build_branding_defaults():
    prospect = {"agency_name": "Unknown", "agency_domain": "example.com"}
    branding = co.build_branding(prospect)
    assert branding.agency_name == "Unknown"
    assert branding.support_email == "hello@example.com"
    assert branding.website == "https://example.com"


# ---------------------------------------------------------------- main() dry-run

def test_main_dry_run_lists_without_scanning(capsys, tmp_path, monkeypatch):
    """--dry-run prints prospect plan but does not scan or write files."""
    # Use a tiny prospects file
    prospects = [
        {"agency_name": "Blue Stout", "agency_domain": "bluestout.com",
         "portfolio_domains": ["goruck.com"], "contact_email": "hello@bluestout.com"},
        {"agency_name": "BVA Agency", "agency_domain": "bva.com",
         "portfolio_domains": ["untuckit.com"], "contact_email": "info@bva.com"},
    ]
    prospects_path = tmp_path / "prospects.json"
    prospects_path.write_text(json.dumps(prospects), encoding="utf-8")

    monkeypatch.setattr(co, "DEFAULT_PROSPECTS_PATH", prospects_path)
    monkeypatch.setattr(co, "DEFAULT_OUTPUT_DIR", tmp_path / "out")

    scan_called = {"count": 0}
    original_scan_one = co.scan_one

    async def fake_scan_one(*a, **k):
        scan_called["count"] += 1
        return original_scan_one(*a, **k)

    monkeypatch.setattr(co, "scan_one", fake_scan_one)

    monkeypatch.setattr(
        sys, "argv",
        ["run_cohort_outreach.py", "--dry-run", "--limit", "2",
         "--output-dir", str(tmp_path / "audits")],
    )
    co.main()

    out = capsys.readouterr().out
    assert "[DRY-RUN] No scanning or file writes will be performed." in out
    assert "Blue Stout" in out
    assert "BVA Agency" in out
    assert "goruck.com" in out
    assert "untuckit.com" in out
    assert scan_called["count"] == 0, "scan_one should not be called in dry-run"
    assert not (tmp_path / "audits").exists(), "no files should be written in dry-run"


# ---------------------------------------------------------------- main() error isolation

def test_main_error_isolation_continues_batch(capsys, tmp_path, monkeypatch):
    """If one scan fails, the batch continues with the next prospect."""
    prospects = [
        {"agency_name": "Fail Agency", "agency_domain": "fail.com",
         "portfolio_domains": ["fail.com"], "contact_email": "x@fail.com"},
        {"agency_name": "Ok Agency", "agency_domain": "ok.com",
         "portfolio_domains": ["ok.com"], "contact_email": "x@ok.com"},
    ]
    prospects_path = tmp_path / "prospects.json"
    prospects_path.write_text(json.dumps(prospects), encoding="utf-8")

    monkeypatch.setattr(co, "DEFAULT_PROSPECTS_PATH", prospects_path)
    monkeypatch.setattr(co, "DEFAULT_OUTPUT_DIR", tmp_path / "out")

    # First scan raises, second succeeds
    async def fake_scan_one_fail(scanner, domain, branding):
        if domain == "fail.com":
            raise RuntimeError("boom")
    # Use the real scan_one for ok.com? No—we want to avoid real network.
    # Just make both return a fake result; only fail.com raises.
    async def fake_scan_one(scanner, domain, branding):
        if domain == "fail.com":
            raise RuntimeError("boom")
        result = MagicMock()
        result.score = 85
        result.grade = "B"
        result.findings = []
        return result

    monkeypatch.setattr(co, "scan_one", fake_scan_one)
    monkeypatch.setattr(co, "write_reports", lambda *a, **k: ("/tmp/fake.pdf", "/tmp/fake.md"))

    monkeypatch.setattr(
        sys, "argv",
        ["run_cohort_outreach.py", "--limit", "2",
         "--output-dir", str(tmp_path / "audits")],
    )
    co.main()

    out = capsys.readouterr().out
    assert "[❌] Scan failed for fail.com: boom" in out
    assert "Ok Agency" in out
    assert "Score: 85/100" in out
    assert "✓ Cohort outreach complete: 1 succeeded, 1 failed, 0 emailed." in out


# ---------------------------------------------------------------- main() agency filter

def test_main_agency_filter(capsys, tmp_path, monkeypatch):
    """--agency substring filter narrows the prospect list (case-insensitive)."""
    prospects = [
        {"agency_name": "Blue Stout", "agency_domain": "bluestout.com",
         "portfolio_domains": ["goruck.com"], "contact_email": "x@bluestout.com"},
        {"agency_name": "Red Rocket", "agency_domain": "redrocket.com",
         "portfolio_domains": ["red.com"], "contact_email": "x@redrocket.com"},
    ]
    prospects_path = tmp_path / "prospects.json"
    prospects_path.write_text(json.dumps(prospects), encoding="utf-8")

    monkeypatch.setattr(co, "DEFAULT_PROSPECTS_PATH", prospects_path)
    monkeypatch.setattr(co, "DEFAULT_OUTPUT_DIR", tmp_path / "out")

    async def fake_scan_one(scanner, domain, branding):
        result = MagicMock()
        result.score = 90
        result.grade = "A"
        result.findings = []
        return result

    monkeypatch.setattr(co, "scan_one", fake_scan_one)
    monkeypatch.setattr(co, "write_reports", lambda *a, **k: ("/tmp/fake.pdf", "/tmp/fake.md"))

    monkeypatch.setattr(
        sys, "argv",
        ["run_cohort_outreach.py", "--agency", "blue",
         "--output-dir", str(tmp_path / "audits")],
    )
    co.main()

    out = capsys.readouterr().out
    assert "Blue Stout" in out
    assert "Red Rocket" not in out
    assert "Prospects to process : 1" in out
