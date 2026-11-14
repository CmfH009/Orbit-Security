"""Tests for Sprint 3: RoE-Filtered CT & Subdomain Batch Fan-Out."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from orbit_security.blackboard import Blackboard
from orbit_security.bounty_radar import BountyProgram, BountyScopeIngester
from orbit_security.bounty_rolling_daemon import BountyRollingDaemon
from orbit_security.cert_transparency import (
    CtStreamDaemon,
    MicrogravitySubdomainDispatcher,
    chunked_publish_events,
)


class _BatchSpyBlackboard:
    def __init__(self, real_bb: Blackboard):
        self._bb = real_bb
        self.publish_calls = 0
        self.publish_batch_calls: List[int] = []

    def publish(self, event_type: str, payload: Dict[str, Any], source: str = "orbit", topic: str = "telemetry") -> int:
        self.publish_calls += 1
        return self._bb.publish(event_type, payload, source=source, topic=topic)

    def publish_batch(
        self,
        events: List[Dict[str, Any]],
        default_source: str = "shuttle",
        default_topic: str = "telemetry",
    ) -> List[int]:
        self.publish_batch_calls.append(len(events))
        return self._bb.publish_batch(events, default_source=default_source, default_topic=default_topic)

    def get_recent(self, **kwargs):
        return self._bb.get_recent(**kwargs)


@pytest.fixture()
def ct_fixtures():
    return {
        "alpha.com": [
            {
                "id": 101,
                "common_name": "alpha.com",
                "name_value": "alpha.com\napi.alpha.com\nblocked.alpha.com\nevil.org",
                "issuer_name": "Let's Encrypt",
                "logged_at": "2026-11-10T00:00:00",
            },
            {
                "id": 102,
                "common_name": "dev.alpha.com",
                "name_value": "dev.alpha.com\napi.alpha.com",
                "issuer_name": "Let's Encrypt",
                "logged_at": "2026-11-11T00:00:00",
            },
        ],
        "beta.com": [
            {
                "id": 201,
                "common_name": "portal.beta.com",
                "name_value": "portal.beta.com\nstatus.beta.com",
                "issuer_name": "DigiCert",
                "logged_at": "2026-11-12T00:00:00",
            }
        ],
    }


class TestMicrogravitySubdomainDispatcher:
    def test_chunked_publish_events_uses_publish_batch(self, tmp_path):
        real_bb = Blackboard(db_path=tmp_path / "chunk.db")
        spy = _BatchSpyBlackboard(real_bb)
        events = [
            {"event_type": "CT_LOG_NEW_SUBDOMAIN", "payload": {"subdomain": f"s{i}.alpha.com"}}
            for i in range(5)
        ]

        ids = chunked_publish_events(spy, events, chunk_size=2, default_source="ct_stream_daemon", default_topic="threat_intel")

        assert len(ids) == 5
        assert spy.publish_calls == 0
        assert spy.publish_batch_calls == [2, 2, 1]

    def test_dispatcher_filters_by_roe_deduplicates_and_batches(self, tmp_path, ct_fixtures):
        real_bb = Blackboard(db_path=tmp_path / "fanout.db")
        spy = _BatchSpyBlackboard(real_bb)
        prog_alpha = BountyProgram(
            program_id="alpha",
            name="Alpha",
            in_scope=["*.alpha.com"],
            out_of_scope=["blocked.alpha.com"],
        )
        prog_beta = BountyProgram(
            program_id="beta",
            name="Beta",
            in_scope=["*.beta.com"],
            out_of_scope=[],
        )

        daemon = CtStreamDaemon(
            watermark_file=tmp_path / "wm.json",
            cache_file=tmp_path / "cache.json",
            blackboard=spy,
            offline_fixtures=ct_fixtures,
            offline=True,
        )
        dispatcher = MicrogravitySubdomainDispatcher(
            ct_daemon=daemon,
            blackboard=spy,
            max_workers=2,
            batch_size=3,
        )

        summary = dispatcher.fan_out_programs([prog_alpha, prog_beta])

        assert summary["programs_scanned"] == 2
        assert summary["mg_cli_active"] is False  # Explicitly documents mg.exe lacks DNS verb
        subs = set(summary["discovered_subdomains"])
        assert {"alpha.com", "api.alpha.com", "dev.alpha.com", "portal.beta.com", "status.beta.com"} == subs
        assert "blocked.alpha.com" not in subs
        assert "evil.org" not in subs
        assert spy.publish_calls == 0
        assert len(spy.publish_batch_calls) >= 1

        stored = real_bb.get_recent(limit=50, event_type="CT_LOG_NEW_SUBDOMAIN")
        stored_subs = {e["payload"]["subdomain"] for e in stored}
        assert "blocked.alpha.com" not in stored_subs
        assert "api.alpha.com" in stored_subs

    def test_daemon_sweep_passes_roe_program_before_blackboard_emit(self, tmp_path, ct_fixtures):
        import json
        from dataclasses import asdict

        programs_file = tmp_path / "bounty_programs.json"
        prog = BountyProgram(
            program_id="alpha",
            name="Alpha",
            in_scope=["*.alpha.com"],
            out_of_scope=["blocked.alpha.com"],
        )
        programs_file.write_text(json.dumps({"programs": [asdict(prog)]}), encoding="utf-8")
        real_bb = Blackboard(db_path=tmp_path / "daemon_ct.db")
        spy = _BatchSpyBlackboard(real_bb)
        daemon = CtStreamDaemon(
            watermark_file=tmp_path / "wm2.json",
            cache_file=tmp_path / "cache2.json",
            blackboard=spy,
            offline_fixtures=ct_fixtures,
            offline=True,
        )
        rolling = BountyRollingDaemon(
            programs_path=programs_file,
            offline=True,
            blackboard=spy,
            ct_daemon=daemon,
            enable_ct=True,
        )

        res = rolling.sweep_ct_logs_for_program("alpha")

        assert res is not None
        assert "blocked.alpha.com" not in res["new_subdomains"]
        assert "api.alpha.com" in res["new_subdomains"]
        stored = real_bb.get_recent(limit=50, event_type="CT_LOG_NEW_SUBDOMAIN")
        assert all(ev["payload"]["subdomain"] != "blocked.alpha.com" for ev in stored)
