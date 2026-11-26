"""Unit tests for scripts/discover_paid_bounties.py."""

from __future__ import annotations

import json
from pathlib import Path
import sys

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from discover_paid_bounties import discover_candidates, score_program_candidate, write_candidates  # noqa: E402


def test_score_program_candidate_filters_closed_and_vdp():
    closed = {"attributes": {"handle": "closed-prog", "offers_bounties": True, "submission_state": "disabled"}}
    vdp = {"attributes": {"handle": "vdp-prog", "offers_bounties": False, "submission_state": "open"}}
    assert score_program_candidate(closed, []) is None
    assert score_program_candidate(vdp, []) is None


def test_score_program_candidate_prefers_source_and_fast_payments():
    prog = {
        "attributes": {
            "handle": "acme-oss",
            "name": "Acme OSS",
            "offers_bounties": True,
            "submission_state": "open",
            "fast_payments": True,
            "gold_standard_safe_harbor": True,
            "started_accepting_at": "2026-04-01T00:00:00Z",
        }
    }
    scopes = [
        {"attributes": {"asset_type": "SOURCE_CODE", "asset_identifier": "https://github.com/acme/cli", "eligible_for_bounty": True}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.acme.test", "eligible_for_bounty": True}},
    ]
    res = score_program_candidate(prog, scopes)
    assert res is not None
    # 35 (source) + 20 (web/api) + 15 (fast) + 10 (gold) + 10 (recent) = 90
    assert res["score"] == 90
    assert res["url"] == "https://hackerone.com/acme-oss"
    assert "SOURCE_CODE" in res["paid_scope_types"]


def test_score_program_candidate_penalizes_hardware_only():
    prog = {
        "attributes": {
            "handle": "hw-only",
            "offers_bounties": True,
            "submission_state": "open",
            "fast_payments": False,
            "gold_standard_safe_harbor": False,
        }
    }
    scopes = [{"attributes": {"asset_type": "HARDWARE", "asset_identifier": "Router v1", "eligible_for_bounty": True}}]
    res = score_program_candidate(prog, scopes)
    assert res is not None
    assert res["score"] == -20


def test_discover_candidates_and_write(tmp_path: Path):
    class FakeClient:
        def list_programs(self, start_page=1, pages=3):
            return [
                {"attributes": {"handle": "vdp", "offers_bounties": False, "submission_state": "open"}},
                {"attributes": {"handle": "paid-oss", "offers_bounties": True, "submission_state": "open", "fast_payments": True}},
            ]

        def get_program(self, handle):
            return {
                "attributes": {"handle": handle, "name": "Paid OSS", "offers_bounties": True, "submission_state": "open", "fast_payments": True},
                "relationships": {
                    "structured_scopes": {
                        "data": [
                            {"attributes": {"asset_type": "SOURCE_CODE", "asset_identifier": "https://github.com/org/repo", "eligible_for_bounty": True}}
                        ]
                    }
                },
            }

    payload = discover_candidates(FakeClient(), pages=1, inspect_limit=5, top=5)
    assert payload["open_paid_count"] == 1
    assert len(payload["candidates"]) == 1
    assert payload["candidates"][0]["handle"] == "paid-oss"

    out = write_candidates(payload, tmp_path)
    assert out.is_file()
    latest = json.loads((tmp_path / "paid_bounty_candidates_latest.json").read_text(encoding="utf-8"))
    assert latest["candidates"][0]["handle"] == "paid-oss"


def test_import_succeeds_without_h1_read(monkeypatch):
    import importlib.util

    monkeypatch.setitem(sys.modules, "h1_read", None)
    script_path = _SCRIPTS_DIR / "discover_paid_bounties.py"
    spec = importlib.util.spec_from_file_location("discover_paid_bounties_no_h1", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "score_program_candidate")
