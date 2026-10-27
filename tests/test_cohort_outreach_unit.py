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


# ---------------------------------------------------------------- preflight_verify_prospects

def test_preflight_verify_prospects_filtering_and_replacement(tmp_path):
    """Verifies that NO_MX and unrecoverable REFUTED are suppressed, while replacements are substituted."""
    cache_data = {
        "results": [
            {
                "agency_domain": "noplace.com",
                "classification": "NO_MX",
                "replacement_addresses": [],
            },
            {
                "agency_domain": "refuted-noreplace.com",
                "classification": "REFUTED",
                "replacement_addresses": [],
            },
            {
                "agency_domain": "refuted-replaced.com",
                "classification": "REFUTED",
                "replacement_addresses": ["verified@refuted-replaced.com"],
            },
            {
                "agency_domain": "confirmed.com",
                "classification": "CONFIRMED",
                "replacement_addresses": [],
            },
        ]
    }
    cache_path = tmp_path / "verification.json"
    cache_path.write_text(json.dumps(cache_data), encoding="utf-8")

    prospects = [
        {"agency_name": "No MX Agency", "agency_domain": "noplace.com", "contact_email": "x@noplace.com"},
        {"agency_name": "Refuted No Replace", "agency_domain": "refuted-noreplace.com", "contact_email": "guess@refuted-noreplace.com"},
        {"agency_name": "Refuted Replace", "agency_domain": "refuted-replaced.com", "contact_email": "guess@refuted-replaced.com"},
        {"agency_name": "Confirmed Agency", "agency_domain": "confirmed.com", "contact_email": "real@confirmed.com"},
        {"agency_name": "Unknown Agency", "agency_domain": "unknown.com", "contact_email": "hello@unknown.com"},
    ]

    allowed, suppressed = co.preflight_verify_prospects(prospects, cache_path=cache_path, auto_substitute=True)

    allowed_domains = [p["agency_domain"] for p in allowed]
    assert "noplace.com" not in allowed_domains
    assert "refuted-noreplace.com" not in allowed_domains
    assert "refuted-replaced.com" in allowed_domains
    assert "confirmed.com" in allowed_domains
    assert "unknown.com" in allowed_domains

    # Check auto-substitution
    replaced_prospect = next(p for p in allowed if p["agency_domain"] == "refuted-replaced.com")
    assert replaced_prospect["contact_email"] == "verified@refuted-replaced.com"

    # Check suppression reasons
    suppressed_reasons = {p["agency_domain"]: reason for p, reason in suppressed}
    assert "NO_MX" in suppressed_reasons["noplace.com"]
    assert "REFUTED" in suppressed_reasons["refuted-noreplace.com"]


def test_main_verify_contacts_cli(capsys, tmp_path, monkeypatch):
    """Verifies that --verify-contacts suppresses unverified prospects during execution."""
    cache_data = {
        "results": [
            {
                "agency_domain": "bad-mx.com",
                "classification": "NO_MX",
                "replacement_addresses": [],
            },
            {
                "agency_domain": "good.com",
                "classification": "CONFIRMED",
                "replacement_addresses": [],
            },
        ]
    }
    cache_path = tmp_path / "verification.json"
    cache_path.write_text(json.dumps(cache_data), encoding="utf-8")

    prospects = [
        {"agency_name": "Bad MX", "agency_domain": "bad-mx.com", "portfolio_domains": ["bad.com"], "contact_email": "x@bad-mx.com"},
        {"agency_name": "Good", "agency_domain": "good.com", "portfolio_domains": ["good.com"], "contact_email": "x@good.com"},
    ]
    prospects_path = tmp_path / "prospects.json"
    prospects_path.write_text(json.dumps(prospects), encoding="utf-8")

    monkeypatch.setattr(co, "DEFAULT_PROSPECTS_PATH", prospects_path)
    monkeypatch.setattr(co, "DEFAULT_VERIFICATION_PATH", cache_path)
    monkeypatch.setattr(co, "DEFAULT_OUTPUT_DIR", tmp_path / "out")

    monkeypatch.setattr(
        sys, "argv",
        ["run_cohort_outreach.py", "--verify-contacts", "--dry-run",
         "--output-dir", str(tmp_path / "audits")],
    )
    co.main()

    out = capsys.readouterr().out
    assert "Suppressed 1 unverified/refuted mailboxes:" in out
    assert "Bad MX (bad-mx.com): NO_MX" in out
    assert "Pre-flight gate: 1 allowed, 1 suppressed." in out
    assert "Good" in out
    assert "Bad MX" not in out.split("[DRY-RUN]")[1]
