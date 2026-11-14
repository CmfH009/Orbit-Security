"""Tests for Step 2: Signal-over-Noise Bounty Eligibility & Disclosure Gate."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from orbit_security.bounty_active_prober import ActiveProbeFinding, BountyActiveProber
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyRadarSupervisor,
    BountyScopeIngester,
    BountyTakeoverSweeper,
    BountyVulnerability,
    is_bounty_submittable,
)


class TestBountySignalGate:
    def test_advisory_noise_rejected_while_exploitable_vectors_pass(self):
        prog = BountyProgram(
            program_id="example",
            name="Example",
            in_scope=["*.example.com"],
            excluded_vulnerabilities=["graphql_introspection"],
        )

        ok_takeover, reason_takeover = is_bounty_submittable(
            "subdomain_takeover",
            severity="HIGH",
            program=prog,
            bounty_viability="HIGH_CONFIDENCE",
        )
        assert ok_takeover is True
        assert reason_takeover == "SUBMITTABLE"

        ok_dom, _ = is_bounty_submittable("dom_xss_sink", severity="HIGH", program=prog)
        assert ok_dom is True

        ok_mail, reason_mail = is_bounty_submittable("mail_spoofing", severity="MEDIUM", program=prog)
        assert ok_mail is False
        assert "ADVISORY_HYGIENE_ONLY" in reason_mail

        ok_hsts, _ = is_bounty_submittable("missing_hsts", severity="MEDIUM", program=prog)
        assert ok_hsts is False

        ok_cors_wild, _ = is_bounty_submittable("cors_wildcard", severity="MEDIUM", program=prog)
        assert ok_cors_wild is False

        ok_excluded, reason_excl = is_bounty_submittable("graphql_introspection", severity="MEDIUM", program=prog)
        assert ok_excluded is False
        assert reason_excl == "EXCLUDED_BY_PROGRAM_POLICY"

        ok_low, reason_low = is_bounty_submittable(
            "subdomain_takeover",
            severity="LOW",
            program=prog,
            bounty_viability="INFORMATIONAL_LOW",
        )
        assert ok_low is False
        assert reason_low == "INFORMATIONAL_LOW"

    def test_supervisor_run_sweep_excludes_mail_spoofing_from_disclosures_and_submittable_count(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        state_file = tmp_path / "bounty_state.json"
        disclosures_dir = tmp_path / "disclosures"

        ingester = BountyScopeIngester(data_path=data_file)
        prog = BountyProgram(program_id="test_corp", name="Test Corp", in_scope=["*.testcorp.com"], max_bounty=5000)
        ingester.programs = {"test_corp": prog}
        ingester.save()

        sweeper = BountyTakeoverSweeper()
        supervisor = BountyRadarSupervisor(ingester=ingester, sweeper=sweeper, state_file=state_file)

        takeover_v = BountyVulnerability(
            program_id="test_corp",
            program_name="Test Corp",
            platform="hackerone",
            target_domain="assets.testcorp.com",
            cname_target="dead.s3.amazonaws.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            evidence="NoSuchBucket",
            bounty_viability="HIGH_CONFIDENCE",
        )
        mail_v = BountyVulnerability(
            program_id="test_corp",
            program_name="Test Corp",
            platform="hackerone",
            target_domain="mail.testcorp.com",
            flaw_type="mail_spoofing",
            bounty_viability="CONDITIONAL",
        )

        with patch.object(sweeper, "sweep_program", return_value=[takeover_v, mail_v]):
            res = supervisor.run_sweep(
                program_id="test_corp",
                force_now=True,
                save_disclosures=True,
                output_dir=disclosures_dir,
            )

        assert res["status"] == "COMPLETED"
        assert len(res["disclosed_files"]) == 1
        assert "subdomain_takeover" in res["disclosed_files"][0]
        assert supervisor.state["total_submittable_findings"] == 1
        assert supervisor.state["total_advisory_observations"] == 1

    def test_active_prober_state_tracks_submittable_vs_advisory(self, tmp_path):
        state_file = tmp_path / "radar_state.json"
        prober = BountyActiveProber(disclosures_dir=tmp_path, state_file=state_file)
        prog = BountyProgram(program_id="ex", name="Ex", in_scope=["*.ex.com"])

        f_hsts = ActiveProbeFinding(
            program_id="ex",
            target_domain="www.ex.com",
            flaw_type="missing_hsts",
            severity="MEDIUM",
            score=5.0,
        )
        f_bucket = ActiveProbeFinding(
            program_id="ex",
            target_domain="cdn.ex.com",
            flaw_type="cloud_storage_takeover",
            severity="HIGH",
            score=8.6,
        )

        prober._update_radar_state(f_hsts, prog, tmp_path / "hsts.md")
        prober._update_radar_state(f_bucket, prog, tmp_path / "bucket.md")

        import json
        saved = json.loads(state_file.read_text(encoding="utf-8"))
        assert saved["total_submittable_findings"] == 1
        assert saved["total_advisory_observations"] == 1

    def test_bounty_programs_catalog_has_no_duplicate_ids_and_meets_minimum(self):
        import json
        from pathlib import Path

        catalog = Path(__file__).resolve().parent.parent / "data" / "bounty_programs.json"
        raw = json.loads(catalog.read_text(encoding="utf-8")).get("programs", [])
        ids = [entry["program_id"] for entry in raw]
        assert len(ids) == len(set(ids)), "Duplicate program_id entries detected in data/bounty_programs.json"
        assert len(ids) >= 45
