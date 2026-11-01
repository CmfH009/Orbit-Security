"""Unit tests for outreach pipeline hygiene, MX false-positive prevention, and portal subst-drive sync."""

from __future__ import annotations

import email
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.deal_desk import RetainerDealDeskConcierge
from orbit_security.mailer import EmailDispatcher
from orbit_security.osint_verifier import KNOWN_LEADERSHIP_OSINT, ExecutiveOSINTVerifier


class TestOSINTVerifierMXAndRecovery:
    """Verifies MX false-positive fix and KNOWN_LEADERSHIP_OSINT reconciliation with recovery_plan.md."""

    def test_verify_domain_mx_rejects_web_only_domain_with_empty_mx(self):
        """A domain with no MX records must return ok=False even if port 80/25 A-records resolve."""
        verifier = ExecutiveOSINTVerifier()
        with patch("orbit_security.osint_verifier.dns.resolver.Resolver.resolve", side_effect=Exception("NoAnswer")):
            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
                res = verifier.verify_domain_mx("heco.design")
                assert res["ok"] is False
                assert res["resolvable"] is False
                assert res["mx_records"] == []
                assert res["ips"] == []
                mock_getaddrinfo.assert_not_called()

    def test_verify_domain_mx_succeeds_when_mx_records_present(self):
        """A domain with valid MX records resolves the primary MX exchange IP on port 25."""
        verifier = ExecutiveOSINTVerifier()
        fake_mx = MagicMock()
        fake_mx.preference = 10
        fake_mx.exchange = "aspmx.l.google.com."
        with patch("orbit_security.osint_verifier.dns.resolver.Resolver.resolve", return_value=[fake_mx]):
            with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("142.250.115.27", 25))]):
                res = verifier.verify_domain_mx("avexdesigns.com")
                assert res["ok"] is True
                assert res["resolvable"] is True
                assert res["mx_records"] == ["aspmx.l.google.com"]
                assert res["ips"] == ["142.250.115.27"]

    def test_known_leadership_osint_reconciled_with_recovery_plan(self):
        """All 12 verified addresses from recovery_plan.md must be present and resolvable."""
        verifier = ExecutiveOSINTVerifier()
        expected_recovery = {
            "swankyagency.com": "cat@swankyagency.com",
            "avexdesigns.com": "newbusiness@avexdesigns.com",
            "askphill.com": "sales@askphill.com",
            "chromatichq.com": "info@chromatichq.com",
            "digitas.com": "amsterdam@digitas.com",
            "rga.com": "argentina@rga.com",
            "work.co": "newbiz@work.co",
            "basicagency.com": "biz@basicagency.com",
            "majortom.com": "hello@majortom.com",
            "immersive-g.com": "inquiries@immersive-g.com",
            "b-reel.com": "newbiz@b-reel.com",
            "goodface.agency": "hi@goodface.agency",
        }
        for domain, expected_email in expected_recovery.items():
            assert domain in KNOWN_LEADERSHIP_OSINT
            res = verifier.resolve_leadership(domain, prefer_recovery=True)
            assert res["resolved"] is True
            assert res["verified_email"] == expected_email
            assert res["email"] == expected_email
            assert res["syntax_valid"] is True

    def test_audit_outreach_manifest_detects_bounced_and_respects_verified_recovery_aliases(self, tmp_path):
        """Bounced non-generic addresses must be queued for recovery with verified_recovery_email, while non-bounced verified recovery aliases are not false-flagged."""
        verifier = ExecutiveOSINTVerifier(workspace_root=tmp_path)
        manifest_file = tmp_path / "pilot_manifest.json"
        manifest_file.write_text(
            json.dumps(
                {
                    "agencies": [
                        {
                            "id": "avex_designs",
                            "name": "Avex Designs",
                            "domain": "avexdesigns.com",
                            "contact_email": "john@avexdesigns.com",
                            "dispatch_status": "BOUNCED",
                        },
                        {
                            "id": "ask_phill",
                            "name": "Ask Phill",
                            "domain": "askphill.com",
                            "contact_email": "phill@askphill.com",
                            "dispatch_status": "BOUNCED",
                        },
                        {
                            "id": "chromatic",
                            "name": "Chromatic",
                            "domain": "chromatichq.com",
                            "contact_email": "info@chromatichq.com",
                            "dispatch_status": "STAGED",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        audit = verifier.audit_outreach_manifest(manifest_file)
        assert audit["ok"] is True
        assert audit["total_agencies"] == 3
        assert audit["verified_contacts"] == 1
        assert audit["generic_or_bounced_count"] == 2
        assert audit["recoverable_count"] == 2
        rec_map = {r["agency_id"]: r["recommended_email"] for r in audit["recoverable"]}
        assert rec_map["avex_designs"] == "newbusiness@avexdesigns.com"
        assert rec_map["ask_phill"] == "sales@askphill.com"


class TestStageFleetPilotFollowupAndHeaders:
    """Verifies RFC 5322 In-Reply-To/References headers and --followup SENT filtering."""

    def test_followup_eml_contains_in_reply_to_and_references(self, tmp_path, monkeypatch):
        import scripts.stage_fleet_pilot as sfp

        monkeypatch.setattr(sfp, "OUTPUT_DIR", tmp_path / "outreach")
        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)
        dispatcher = EmailDispatcher(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="carson@orbit-security.io",
            smtp_password="secret",
        )
        manifest = sfp.generate_pilot_drafts(dispatcher=dispatcher, batch=1, force=False)
        first = manifest["agencies"][0]
        pitch_eml = tmp_path / first["eml_file"]
        followup_eml = tmp_path / first["followup_eml_file"]

        with open(pitch_eml, "rb") as pf:
            pitch_msg = email.message_from_binary_file(pf)
        with open(followup_eml, "rb") as ff:
            followup_msg = email.message_from_binary_file(ff)

        pitch_mid = pitch_msg.get("Message-ID")
        assert pitch_mid is not None
        assert followup_msg.get("In-Reply-To") == pitch_mid
        assert followup_msg.get("References") == pitch_mid
        assert followup_msg.get("Message-ID") is not None
        assert followup_msg.get("Message-ID") != pitch_mid

    def test_followup_loop_filters_only_sent_leads(self, tmp_path, monkeypatch, capsys):
        import scripts.stage_fleet_pilot as sfp

        out_dir = tmp_path / "outreach"
        out_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(sfp, "OUTPUT_DIR", out_dir)
        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)

        # Pre-seed manifest where only 10up is SENT, alley_interactive is BOUNCED, avex_designs is STAGED
        seeded_manifest = {
            "batch_id": "fleet_pilot_01",
            "agencies": [
                {"id": "10up", "dispatch_status": "SENT", "dispatched_at": "2026-10-20T00:00:00+00:00"},
                {"id": "alley_interactive", "dispatch_status": "BOUNCED"},
                {"id": "avex_designs", "dispatch_status": "STAGED"},
            ],
        }
        (out_dir / "pilot_manifest.json").write_text(json.dumps(seeded_manifest), encoding="utf-8")

        monkeypatch.setattr("sys.argv", ["stage_fleet_pilot.py", "--followup", "--dry-run"])
        rc = sfp.main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Targets Staged:  1 agencies (10 non-SENT skipped)" in out
        assert "10up (10up.com)" in out
        assert "Alley Interactive (alley.com)" not in out
        assert "Avex Designs (avexdesigns.com)" not in out

    def test_followup_failure_does_not_overwrite_initial_pitch_dispatch_status(self, tmp_path, monkeypatch):
        import scripts.stage_fleet_pilot as sfp

        out_dir = tmp_path / "outreach"
        out_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(sfp, "OUTPUT_DIR", out_dir)
        monkeypatch.setattr(sfp, "REPO_ROOT", tmp_path)

        seeded_manifest = {
            "batch_id": "fleet_pilot_01",
            "agencies": [
                {"id": "10up", "dispatch_status": "SENT", "dispatched_at": "2026-10-01T00:00:00+00:00"},
            ],
        }
        (out_dir / "pilot_manifest.json").write_text(json.dumps(seeded_manifest), encoding="utf-8")

        with patch.object(EmailDispatcher, "is_configured", return_value=True):
            with patch.object(EmailDispatcher, "send_raw_eml", side_effect=RuntimeError("SMTP temporary error")):
                monkeypatch.setattr("sys.argv", ["stage_fleet_pilot.py", "--followup", "--agency", "10up", "--send", "--sleep", "0"])
                sfp.main()

        saved = json.loads((out_dir / "pilot_manifest.json").read_text(encoding="utf-8"))
        ag_10up = next(a for a in saved["agencies"] if a["id"] == "10up")
        assert ag_10up["dispatch_status"] == "SENT"
        assert ag_10up["followup_dispatch_status"] == "FAILED"


class TestDealDeskSubstDrivePortalSync:
    """Verifies RetainerDealDeskConcierge syncs to subproject landing/portals when workspace_root is root drive."""

    def test_generate_portal_syncs_to_subproject_landing_portals(self, tmp_path):
        docs_portals = tmp_path / "projects" / "orbit-security" / "docs" / "portals"
        landing_portals = tmp_path / "projects" / "orbit-security" / "landing" / "portals"
        docs_portals.mkdir(parents=True, exist_ok=True)
        landing_portals.mkdir(parents=True, exist_ok=True)

        concierge = RetainerDealDeskConcierge(workspace_root=tmp_path)
        res = concierge.generate_portal_for_agency(
            agency_id="absolute_web",
            agency_name="Absolute Web",
            tier="remediation",
            primary_client_domain="absoluteweb.com",
        )
        assert res["ok"] is True
        assert (docs_portals / "absolute_web.html").exists()
        assert (landing_portals / "absolute_web.html").exists()
        assert (docs_portals / "absolute_web.html").read_text(encoding="utf-8") == (
            landing_portals / "absolute_web.html"
        ).read_text(encoding="utf-8")

    def test_generate_portal_with_custom_portals_dir_does_not_leak_to_repo_landing(self, tmp_path):
        from orbit_security.deal_desk import REPO_ROOT

        custom_portals = tmp_path / "custom_portals"
        concierge = RetainerDealDeskConcierge(portals_dir=custom_portals)
        res = concierge.generate_portal_for_agency(
            agency_id="isolated_fuzz_portal_check",
            agency_name="Isolated Fuzz Portal",
        )
        assert res["ok"] is True
        assert (custom_portals / "isolated_fuzz_portal_check.html").exists()
        assert not (REPO_ROOT / "landing" / "portals" / "isolated_fuzz_portal_check.html").exists()
        assert not (REPO_ROOT / "docs" / "portals" / "isolated_fuzz_portal_check.html").exists()

