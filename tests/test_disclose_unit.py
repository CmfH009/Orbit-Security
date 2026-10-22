"""Unit tests for the `disclose` CLI subcommand (mock-based, no external targets).

Covers:
- --dry-run preview (with/without --now, with nonexistent program)
- --dry-run off-peak window gating, driven by an injected clock (deterministic
  at any hour of the day)
- --list / --json delegation to triage_bounties (empty disclosures dir)
- --view not-found returns exit code 1
- --dry-run takes precedence over sweep (no run_sweep call)
"""

import datetime
from argparse import Namespace
from unittest.mock import patch
import pytest

from orbit_security.cli import run_disclose


# The off-peak window is 2:00 AM - 5:00 AM MST (UTC-7), i.e. 09:00-12:00 UTC.
# Both instants below are therefore fully deterministic regardless of when the
# suite happens to run.
INSIDE_WINDOW_UTC = datetime.datetime(2026, 1, 15, 11, 0, tzinfo=datetime.timezone.utc)
OUTSIDE_WINDOW_UTC = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=datetime.timezone.utc)


def make_args(**kwargs):
    """Build an argparse-like Namespace with disclose defaults."""
    base = {
        "list": False,
        "view": None,
        "copy": None,
        "json": False,
        "grade": None,
        "program": None,
        "now": False,
        "max_targets": 15,
        "passive_ct": False,
        "output_dir": "data/disclosures",
        "webhook_discord": None,
        "webhook_slack": None,
        "dry_run": False,
    }
    base.update(kwargs)
    return Namespace(**base)


@pytest.mark.asyncio
async def test_disclose_dry_run_preview_with_now(capsys):
    """--dry-run --now shows preview and says sweep would execute."""
    args = make_args(dry_run=True, program="shopify", now=True)
    # Inject an outside-window clock so the result depends only on --now.
    result = await run_disclose(args, now_utc=OUTSIDE_WINDOW_UTC)
    assert result == 0
    out = capsys.readouterr().out
    assert "DRY-RUN — no external targets will be probed" in out
    assert "shopify" in out
    assert "Sweep would execute" in out


@pytest.mark.asyncio
async def test_disclose_dry_run_outside_window(capsys):
    """--dry-run without --now outside off-peak says sweep blocked."""
    args = make_args(dry_run=True, now=False)
    result = await run_disclose(args, now_utc=OUTSIDE_WINDOW_UTC)
    assert result == 0
    out = capsys.readouterr().out
    assert "DRY-RUN — no external targets will be probed" in out
    assert "OUTSIDE WINDOW" in out
    assert "would NOT execute" in out
    assert "add --now to force" in out


@pytest.mark.asyncio
async def test_disclose_dry_run_inside_window(capsys):
    """--dry-run without --now inside off-peak says the sweep would execute."""
    args = make_args(dry_run=True, now=False)
    result = await run_disclose(args, now_utc=INSIDE_WINDOW_UTC)
    assert result == 0
    out = capsys.readouterr().out
    assert "DRY-RUN — no external targets will be probed" in out
    assert "IN WINDOW" in out
    assert "Sweep would execute" in out
    assert "would NOT execute" not in out


@pytest.mark.asyncio
async def test_disclose_dry_run_now_forces_execution_outside_window(capsys):
    """--now overrides the off-peak gate even when the clock is outside it."""
    args = make_args(dry_run=True, now=True)
    result = await run_disclose(args, now_utc=OUTSIDE_WINDOW_UTC)
    assert result == 0
    out = capsys.readouterr().out
    assert "OUTSIDE WINDOW" in out
    assert "--now would bypass" in out
    assert "Sweep would execute" in out
    assert "would NOT execute" not in out


@pytest.mark.asyncio
async def test_disclose_dry_run_uses_real_clock_when_not_injected(capsys):
    """No injected clock => the live UTC clock drives the window decision."""
    args = make_args(dry_run=True, now=False)
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "DRY-RUN — no external targets will be probed" in out
    assert ("would NOT execute" in out) != ("Sweep would execute" in out)


@pytest.mark.asyncio
async def test_disclose_dry_run_nonexistent_program(capsys):
    """--dry-run with unknown --program warns but continues cleanly."""
    args = make_args(dry_run=True, program="definitely_not_a_program")
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "not found" in out
    assert "Skipping" in out


@pytest.mark.asyncio
async def test_disclose_dry_run_lists_programs_and_patterns(capsys):
    """--dry-run prints the programs-that-would-be-swept table."""
    args = make_args(dry_run=True)
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "Programs That Would Be Swept" in out
    assert "shopify" in out
    assert "Total in-scope patterns" in out


@pytest.mark.asyncio
async def test_disclose_list_empty_disclosures(capsys, tmp_path):
    """--list with empty disclosures dir returns 0 and prints empty message."""
    args = make_args(list=True, output_dir=str(tmp_path / "disclosures"))
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "No vulnerability disclosures match" in out


@pytest.mark.asyncio
async def test_disclose_json_empty(capsys, tmp_path):
    """--json with empty disclosures returns 0 and prints empty array."""
    args = make_args(json=True, output_dir=str(tmp_path / "disclosures"))
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "[]" in out


@pytest.mark.asyncio
async def test_disclose_view_not_found_returns_one(capsys):
    """--view with no matching domain returns exit code 1."""
    args = make_args(view="nonexistent.example.com")
    result = await run_disclose(args)
    assert result == 1
    out = capsys.readouterr().out
    assert "No disclosure found matching domain" in out


@pytest.mark.asyncio
async def test_disclose_list_takes_precedence_over_dry_run(capsys, tmp_path):
    """--list and --dry-run together: delegation wins, dry-run not shown."""
    args = make_args(list=True, dry_run=True, output_dir=str(tmp_path / "disclosures"))
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" not in out
    assert "No vulnerability disclosures match" in out


@pytest.mark.asyncio
async def test_disclose_grade_filter_empty(capsys, tmp_path):
    """--grade with no disclosures returns 0 and prints empty message."""
    args = make_args(grade="HIGH_CONFIDENCE", output_dir=str(tmp_path / "disclosures"))
    result = await run_disclose(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "No vulnerability disclosures match" in out


@pytest.mark.asyncio
async def test_disclose_sweep_path_not_called_when_list(monkeypatch):
    """--list short-circuits before run_sweep is ever reached."""
    called = {"sweep": False}

    def fake_run_sweep(*a, **k):
        called["sweep"] = True
        return {"status": "COMPLETED", "vulnerabilities_found": 0}

    # Patch the class method so any BountyRadarSupervisor instance uses it.
    from orbit_security.bounty_radar import BountyRadarSupervisor

    monkeypatch.setattr(BountyRadarSupervisor, "run_sweep", fake_run_sweep, raising=False)

    args = make_args(list=True, output_dir="/tmp/nonexistent_disclosures")
    await run_disclose(args)
    assert called["sweep"] is False, "run_sweep should not be called when --list is set"
