"""Unit tests for P0 Outreach Track & Deliverability Hardening."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orbit_security import sherlock_osint as so
from orbit_security.osint_verifier import KNOWN_LEADERSHIP_OSINT, ExecutiveOSINTVerifier
from orbit_security.social_swarm import PerimeterRoastCrafter


class TestStageFleetPilotVerificationAndPreflight:
    """Tests verification.json loading, verification_report.json fallback, and check_outreach_preflight()."""

    def test_preflight_prefers_verification_json_and_parses_results_and_domains(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.stage_fleet_pilot as sfp

        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)
        ver_dir = tmp_path / "data" / "contact_verification"
        ver_dir.mkdir(parents=True, exist_ok=True)

        # Primary verification.json uses both "results" (domain/status) and "domains" map
        (ver_dir / "verification.json").write_text(
            json.dumps(
                {
                    "results": [
                        {"domain": "good-one.com", "status": "CONFIRMED"},
                        {"agency_domain": "unknown-one.com", "classification": "UNKNOWN"},
                    ],
                    "domains": {
                        "bad-mx.com": {"classification": "NO_MX"},
                        "refuted-one.com": {"status": "REFUTED"},
                    },
                }
            ),
            encoding="utf-8",
        )
        # Fallback verification_report.json should NOT override verification.json
        (ver_dir / "verification_report.json").write_text(
            json.dumps(
                {
                    "results": [
                        {"agency_domain": "bad-mx.com", "classification": "CONFIRMED"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        gate = sfp.run_deliverability_preflight(
            [
                {"id": "g1", "domain": "good-one.com", "contact_email": "cto@good-one.com"},
                {"id": "u1", "domain": "unknown-one.com", "contact_email": "cto@unknown-one.com"},
                {"id": "b1", "domain": "bad-mx.com", "contact_email": "cto@bad-mx.com"},
                {"id": "r1", "domain": "refuted-one.com", "contact_email": "cto@refuted-one.com"},
            ]
        )
        assert gate["total_checked"] == 4
        assert gate["confirmed_count"] == 1
        assert gate["unknown_count"] == 1
        assert gate["no_mx_count"] == 1
        assert gate["refuted_count"] == 1
        assert gate["passed"] is False
        assert gate["gate_passed"] is False

    def test_preflight_falls_back_to_verification_report_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.stage_fleet_pilot as sfp

        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)
        ver_dir = tmp_path / "data" / "contact_verification"
        ver_dir.mkdir(parents=True, exist_ok=True)

        (ver_dir / "verification_report.json").write_text(
            json.dumps(
                {
                    "domains": {
                        "fallback-nomx.com": {"classification": "NO_MX"},
                    }
                }
            ),
            encoding="utf-8",
        )

        gate = sfp.run_deliverability_preflight(
            [{"id": "f1", "domain": "fallback-nomx.com", "contact_email": "lead@fallback-nomx.com"}]
        )
        assert gate["no_mx_count"] == 1
        assert gate["passed"] is False

    def test_check_outreach_preflight_reads_freeze_bounce_and_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.stage_fleet_pilot as sfp
        from orbit_security import deliverability, private_alerting

        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(private_alerting, "COMMERCIAL_OUTREACH_FROZEN", True)
        monkeypatch.setattr(deliverability, "bounce_stats", lambda: (185, 46, 0.2486))

        res_missing = sfp.check_outreach_preflight()
        assert res_missing == {
            "commercial_outreach_frozen": True,
            "bounce_rate": 0.2486,
            "total_tracked": 185,
            "verification_cache_loaded": False,
        }

        ver_dir = tmp_path / "data" / "contact_verification"
        ver_dir.mkdir(parents=True, exist_ok=True)
        (ver_dir / "verification.json").write_text(
            json.dumps({"results": [{"agency_domain": "charleagency.com", "classification": "CONFIRMED"}]}),
            encoding="utf-8",
        )
        monkeypatch.setattr(private_alerting, "COMMERCIAL_OUTREACH_FROZEN", False)
        res_loaded = sfp.check_outreach_preflight()
        assert res_loaded["commercial_outreach_frozen"] is False
        assert res_loaded["verification_cache_loaded"] is True
        assert res_loaded["total_tracked"] == 185


class TestExecutiveOSINTVerifierSherlock:
    """Tests Sherlock OSINT delegation and candidate email synthesis/validation."""

    def test_known_leadership_osint_retains_all_12_recovery_entries(self) -> None:
        expected_domains = {
            "swankyagency.com",
            "avexdesigns.com",
            "askphill.com",
            "chromatichq.com",
            "digitas.com",
            "rga.com",
            "work.co",
            "basicagency.com",
            "majortom.com",
            "immersive-g.com",
            "b-reel.com",
            "goodface.agency",
        }
        assert expected_domains.issubset(set(KNOWN_LEADERSHIP_OSINT.keys()))

    def test_discover_via_sherlock_delegates_and_checks_candidate_email(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[list[str]] = []

        def _fake_sherlock(usernames, **_kwargs):
            captured.append(list(usernames))
            return so.SherlockSweepResult(
                available=True,
                executable="sherlock.exe",
                usernames=list(usernames),
                sites_filter=[],
                findings=[
                    so.SherlockMatch(
                        username=usernames[0],
                        site="GitHub",
                        url_user=f"https://github.com/{usernames[0]}",
                        http_status=200,
                    )
                ],
                elapsed_ms=12.5,
                errors=[],
            )

        monkeypatch.setattr(so, "run_sherlock_osint", _fake_sherlock)

        fake_mx = MagicMock()
        fake_mx.preference = 10
        fake_mx.exchange = "aspmx.l.google.com."

        verifier = ExecutiveOSINTVerifier()
        with patch("orbit_security.osint_verifier.dns.resolver.Resolver.resolve", return_value=[fake_mx]):
            with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("142.250.115.27", 25))]):
                res = verifier.discover_via_sherlock("@john", domain="https://AvexDesigns.com/about")

        assert captured == [["john"]]
        assert res["ok"] is True
        assert res["available"] is True
        assert res["handle"] == "john"
        assert res["domain"] == "avexdesigns.com"
        assert res["findings_count"] == 1
        assert res["findings"][0]["site"] == "GitHub"
        assert res["candidate_email"] == "john@avexdesigns.com"
        assert res["email_syntax_valid"] is True
        assert res["mx_verified"] is True
        assert res["mx_records"] == ["aspmx.l.google.com"]
        assert res["deliverable"] is True

    def test_discover_via_sherlock_handles_failures_and_missing_domain_gracefully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _failing_sherlock(_usernames, **_kwargs):
            raise RuntimeError("Sherlock subprocess crash")

        monkeypatch.setattr(so, "run_sherlock_osint", _failing_sherlock)
        verifier = ExecutiveOSINTVerifier()

        with patch("orbit_security.osint_verifier.dns.resolver.Resolver.resolve", side_effect=Exception("NoAnswer")):
            res = verifier.discover_via_sherlock("nick", domain="web-only.example")

        assert res["ok"] is False
        assert res["available"] is False
        assert "Sherlock subprocess crash" in res["errors"][0]
        assert res["candidate_email"] == "nick@web-only.example"
        assert res["email_syntax_valid"] is True
        assert res["mx_verified"] is False
        assert res["deliverable"] is False

        res_no_domain = verifier.discover_via_sherlock("")
        assert res_no_domain["ok"] is False
        assert res_no_domain["candidate_email"] is None
        assert res_no_domain["errors"] == ["Empty handle provided"]


class TestPerimeterRoastCrafterAnonymization:
    """Tests anonymized_post_text generation and anonymize_target toggle."""

    @pytest.mark.parametrize("blunder_type", ["dangling_cname", "dmarc_reject", "headers"])
    def test_craft_roast_always_produces_anonymized_post_text_and_respects_flag(
        self, blunder_type: str
    ) -> None:
        crafter = PerimeterRoastCrafter()
        with patch("orbit_security.social_swarm.publish_event"):
            non_anon = crafter.craft_roast(
                agency_name="Avex Designs",
                domain="avexdesigns.com",
                initial_score=35,
                rescued_score=85,
                blunder_type=blunder_type,
            )
            anon = crafter.craft_roast(
                agency_name="Avex Designs",
                domain="avexdesigns.com",
                initial_score=35,
                rescued_score=85,
                blunder_type=blunder_type,
                anonymize_target=True,
            )

        assert non_anon["anonymized"] is False
        assert "Avex Designs" in non_anon["post_text"]
        assert "avexdesigns.com" in non_anon["post_text"]
        assert "an enterprise commerce agency" in non_anon["anonymized_post_text"]
        assert "[redacted-client-domain]" in non_anon["anonymized_post_text"]
        assert "Avex Designs" not in non_anon["anonymized_post_text"]
        assert "avexdesigns.com" not in non_anon["anonymized_post_text"]

        assert anon["anonymized"] is True
        assert anon["post_text"] == anon["anonymized_post_text"]
        assert anon["char_count"] == len(anon["post_text"])
        assert "Avex Designs" not in anon["post_text"]
        assert "avexdesigns.com" not in anon["post_text"]
        assert "an enterprise commerce agency" in anon["post_text"]
        assert "[redacted-client-domain]" in anon["post_text"]
