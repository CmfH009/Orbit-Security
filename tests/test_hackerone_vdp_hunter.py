"""tests/test_hackerone_vdp_hunter.py: Unit tests for scripts/hunt_hackerone_vdps.py."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from hunt_hackerone_vdps import (  # noqa: E402
    SENSITIVE_EXPOSURE_PATHS,
    VdpFinding,
    VdpProgram,
    check_exposed_config_or_git,
    check_open_bucket_listing,
    check_takeover_claimability,
    discover_passive_subdomains,
    evaluate_submission_quality_gate,
    filter_kyc_free_vdp_programs,
    is_duplicate_finding,
    main,
    match_structured_scope,
    render_vdp_dossier,
    run_vdp_hunt,
    screen_host_non_destructively,
    select_weakness_id,
    submit_vdp_finding,
)


class _MockResponse:
    def __init__(self, body: str | dict | list, status: int = 200, headers: dict | None = None):
        if isinstance(body, (dict, list)):
            self._raw = json.dumps(body).encode("utf-8")
        else:
            self._raw = body.encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._raw if n < 0 else self._raw[:n]

    def __enter__(self) -> "_MockResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestVdpProgramFiltering(unittest.TestCase):
    def test_filters_strictly_for_open_kyc_free_vdps(self):
        raw_programs = [
            {
                "id": "1",
                "attributes": {
                    "handle": "good-vdp",
                    "name": "Good VDP",
                    "offers_bounties": False,
                    "submission_state": "open",
                    "state": "public_mode",
                },
            },
            {
                "id": "2",
                "attributes": {
                    "handle": "paid-bbp",
                    "name": "Paid BBP",
                    "offers_bounties": True,
                    "submission_state": "open",
                    "state": "public_mode",
                },
            },
            {
                "id": "3",
                "attributes": {
                    "handle": "paused-vdp",
                    "name": "Paused VDP",
                    "offers_bounties": False,
                    "submission_state": "paused",
                    "state": "public_mode",
                },
            },
            {
                "id": "4",
                "attributes": {
                    "handle": "kyc-vdp",
                    "name": "KYC VDP",
                    "offers_bounties": False,
                    "submission_state": "open",
                    "state": "public_mode",
                    "i_must_verify_identity_to_submit": True,
                },
            },
        ]

        filtered = filter_kyc_free_vdp_programs(raw_programs)
        self.assertEqual([p["attributes"]["handle"] for p in filtered], ["good-vdp"])


class TestScopeAndWeaknessMatching(unittest.TestCase):
    def test_match_structured_scope_respects_out_of_scope(self):
        scopes = [
            {
                "id": "101",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.example.org",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "102",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "blocked.example.org",
                    "eligible_for_submission": False,
                },
            },
        ]

        matched = match_structured_scope("app.example.org", scopes)
        self.assertIsNotNone(matched)
        self.assertEqual(matched["id"], "101")

        blocked = match_structured_scope("blocked.example.org", scopes)
        self.assertIsNone(blocked)

        unrelated = match_structured_scope("app.otherdomain.com", scopes)
        self.assertIsNone(unrelated)

    def test_select_weakness_id_matches_preferred_cwe(self):
        weaknesses = [
            {"id": "18", "attributes": {"external_id": "cwe-200", "name": "Information Exposure"}},
            {"id": "99", "attributes": {"external_id": "cwe-350", "name": "Reliance on Reverse DNS"}},
        ]

        self.assertEqual(select_weakness_id("dangling_cname", weaknesses), "99")
        self.assertEqual(select_weakness_id("open_bucket", weaknesses), "18")
        self.assertEqual(select_weakness_id("exposed_git", weaknesses), "18")


class TestNonDestructiveDetectors(unittest.TestCase):
    def test_check_open_bucket_listing_detects_xml_with_contents(self):
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ListBucketResult><Name>corp-public-leak</Name>"
            "<Contents><Key>backups/db_prod.sql</Key></Contents>"
            "</ListBucketResult>"
        )
        res = check_open_bucket_listing("https://assets.example.org/", 200, xml)
        self.assertIsNotNone(res)
        self.assertEqual(res["bucket_name"], "corp-public-leak")
        self.assertIn("backups/db_prod.sql", res["sample_keys"])

    def test_check_open_bucket_listing_ignores_empty_or_html(self):
        html = "<html><body><h1>Not Found</h1></body></html>"
        self.assertIsNone(check_open_bucket_listing("https://assets.example.org/", 200, html))

        empty_xml = "<ListBucketResult><Name>empty-cdn</Name></ListBucketResult>"
        self.assertIsNone(check_open_bucket_listing("https://assets.example.org/", 200, empty_xml))

    def test_check_exposed_config_or_git_detects_git_head_and_rejects_spa_html(self):
        self.assertIsNotNone(check_exposed_config_or_git("/.git/HEAD", 200, "ref: refs/heads/main\n"))
        self.assertIsNone(check_exposed_config_or_git("/.git/HEAD", 200, "<!doctype html><html><body>SPA</body></html>"))
        env_body = "APP_ENV=production\nDB_PASSWORD=super_secret_pw\nAWS_SECRET_ACCESS_KEY=abcd1234\n"
        self.assertIsNotNone(check_exposed_config_or_git("/.env", 200, env_body))
        self.assertIsNone(check_exposed_config_or_git("/.env", 404, "Not found"))


class TestSubmissionAndDuplicateGuards(unittest.TestCase):
    def _sample_program(self, *, offers_bounties: bool = False, kyc_required: bool = False) -> VdpProgram:
        return VdpProgram(
            handle="acme-vdp",
            name="Acme Corp VDP",
            offers_bounties=offers_bounties,
            submission_state="open",
            i_must_verify_identity_to_submit=kyc_required,
            policy="Include header X-Acme-VDP: HackerOne-arsoncarson",
            structured_scopes=[
                {
                    "id": "555",
                    "attributes": {
                        "asset_type": "WILDCARD",
                        "asset_identifier": "*.acme.example",
                        "eligible_for_submission": True,
                    },
                }
            ],
            weaknesses=[
                {"id": "18", "attributes": {"external_id": "cwe-200", "name": "Information Exposure"}}
            ],
            compliance_headers={"X-Acme-VDP": "HackerOne-arsoncarson"},
        )

    def _sample_finding(self) -> VdpFinding:
        return VdpFinding(
            program_handle="acme-vdp",
            program_name="Acme Corp VDP",
            host="old-promo.acme.example",
            finding_type="dangling_cname",
            title="Dangling DNS CNAME to Unattached Unbounce SaaS Endpoint on old-promo.acme.example",
            severity="medium",
            weakness_id="18",
            structured_scope_id="555",
            cname_target="unbouncepages.com",
            a_records=["52.1.2.3"],
            http_status=404,
            http_url="https://old-promo.acme.example/",
            evidence_snippet="The requested URL was not found on this server",
            remediation="Remove the dangling DNS CNAME record.",
            captured_utc="2026-11-14T20:00:00+00:00",
        )

    def test_duplicate_guard_blocks_existing_report_or_dossier(self):
        existing_reports = [
            {
                "id": "4204024",
                "attributes": {"title": "Dangling DNS CNAME on test.hulu.com", "state": "new"},
            }
        ]
        self.assertTrue(is_duplicate_finding("test.hulu.com", existing_reports, []))
        self.assertFalse(is_duplicate_finding("old-promo.acme.example", existing_reports, []))

    def test_submit_vdp_finding_refuses_bbp_and_kyc_programs(self):
        finding = self._sample_finding()
        bbp_prog = self._sample_program(offers_bounties=True, kyc_required=False)
        res_bbp = submit_vdp_finding(bbp_prog, finding, "user", "tok", dry_run=False, existing_reports=[])
        self.assertEqual(res_bbp["status"], "BLOCKED_BBP_NOT_VDP")

        kyc_prog = self._sample_program(offers_bounties=False, kyc_required=True)
        res_kyc = submit_vdp_finding(kyc_prog, finding, "user", "tok", dry_run=False, existing_reports=[])
        self.assertEqual(res_kyc["status"], "BLOCKED_KYC_REQUIRED")

    @patch("hunt_hackerone_vdps.urllib.request.urlopen")
    def test_submit_vdp_finding_posts_to_hackerone_when_live_and_kyc_free(self, mock_urlopen):
        mock_urlopen.return_value = _MockResponse(
            {
                "data": {
                    "id": "4205000",
                    "attributes": {"state": "new", "created_at": "2026-11-14T21:00:00Z"},
                }
            },
            status=201,
        )
        prog = self._sample_program(offers_bounties=False, kyc_required=False)
        finding = self._sample_finding()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            res = submit_vdp_finding(
                prog,
                finding,
                "user",
                "tok",
                dry_run=False,
                existing_reports=[],
                vdp_ready_dir=tmp / "vdp_ready",
                manifest_path=tmp / "manifest.json",
                skip_live_reverify=True,
                critic_runs=3,
            )

            self.assertEqual(res["status"], "SUBMITTED")
            self.assertEqual(res["report_id"], "4205000")
            self.assertEqual(res["quality_gate"]["verdict"], "APPROVED")
            self.assertEqual(res["quality_gate"]["critic_passes"], 3)
            self.assertTrue((tmp / "vdp_ready" / "acme-vdp_vdp_old-promo_acme_example.md").exists())
            req = mock_urlopen.call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            self.assertEqual(body["data"]["attributes"]["team_handle"], "acme-vdp")
            self.assertEqual(body["data"]["attributes"]["structured_scope_id"], 555)
            self.assertEqual(body["data"]["attributes"]["weakness_id"], 18)

    def test_quality_gate_approves_after_three_independent_critic_runs(self):
        prog = self._sample_program()
        finding = self._sample_finding()
        seen_runs = []

        def _critic(prompt: str, run_idx: int, persona: str) -> str:
            seen_runs.append((run_idx, persona))
            return json.dumps({"verdict": "PASS", "confidence": 0.95, "reason": f"Run {run_idx} verified."})

        gate = evaluate_submission_quality_gate(
            prog,
            finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
            ollama_fn=_critic,
        )
        self.assertTrue(gate.passed)
        self.assertEqual(gate.verdict, "APPROVED")
        self.assertEqual(gate.critic_passes, 3)
        self.assertEqual(gate.critic_rejections, 0)
        self.assertEqual(len(seen_runs), 3)
        self.assertTrue(gate.evidence_artifact_id.startswith("ev_"))

    def test_quality_gate_blocks_upload_when_any_critic_run_vetoes(self):
        prog = self._sample_program()
        finding = self._sample_finding()

        def _skeptic_veto(prompt: str, run_idx: int, persona: str) -> str:
            if run_idx == 2:
                return json.dumps(
                    {
                        "verdict": "REJECT",
                        "confidence": 0.91,
                        "reason": "CNAME is a benign proxy alias, likely Informative.",
                    }
                )
            return json.dumps({"verdict": "PASS", "confidence": 0.9, "reason": "ok"})

        gate = evaluate_submission_quality_gate(
            prog,
            finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
            ollama_fn=_skeptic_veto,
        )
        self.assertFalse(gate.passed)
        self.assertEqual(gate.verdict, "REJECTED")
        self.assertEqual(gate.critic_rejections, 1)
        self.assertTrue(any("Informative" in r for r in gate.blocking_reasons))

        with tempfile.TemporaryDirectory() as tmpdir:
            res = submit_vdp_finding(
                prog,
                finding,
                "user",
                "tok",
                dry_run=False,
                existing_reports=[],
                vdp_ready_dir=Path(tmpdir) / "vdp_ready",
                manifest_path=Path(tmpdir) / "manifest.json",
                quality_gate=gate,
            )
            self.assertEqual(res["status"], "BLOCKED_QUALITY_GATE")

    def test_quality_gate_rejects_policy_exclusion_and_reverify_drift(self):
        prog = self._sample_program()
        prog.policy = "Subdomain takeover vulnerabilities are explicitly out of scope and ineligible."
        finding = self._sample_finding()
        gate = evaluate_submission_quality_gate(
            prog,
            finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
        )
        self.assertFalse(gate.passed)
        self.assertFalse(gate.deterministic_checks["policy_not_excluded"])

        clean_prog = self._sample_program()
        with patch("hunt_hackerone_vdps._reverify_finding_live", return_value=(False, "HTTP drifted to 200 OK")):
            drifted = evaluate_submission_quality_gate(
                clean_prog,
                finding,
                reverify_runs=2,
                critic_runs=3,
                skip_live_reverify=False,
            )
        self.assertFalse(drifted.passed)
        self.assertEqual(drifted.reverification_passes, 0)

    def test_claimability_rejects_cloudfront_request_blocked_and_occupied_azure_tenant(self):
        cf_blocked = "<TITLE>ERROR: The request could not be satisfied</TITLE><H1>403 ERROR</H1>Request blocked. We can't connect to the server for this app or website at this time."
        ok_cf, reason_cf = check_takeover_claimability(
            "AWS CloudFront", "d1us4rquzcjouf.cloudfront.net", cf_blocked
        )
        self.assertFalse(ok_cf)
        self.assertIn("Request blocked", reason_cf)

        cf_unattached = "<TITLE>ERROR: The request could not be satisfied</TITLE><H1>403 ERROR</H1>Bad request."
        ok_cf2, _ = check_takeover_claimability(
            "AWS CloudFront", "d1us4rquzcjouf.cloudfront.net", cf_unattached
        )
        self.assertTrue(ok_cf2)

        with patch("hunt_hackerone_vdps.fetch_http_sample", return_value=(200, {}, "<title>MRL Pipeline Portal</title>")):
            ok_az, reason_az = check_takeover_claimability(
                "Microsoft Azure", "eppdapduiprodnew.azurewebsites.net", "404 Web Site not found"
            )
            self.assertFalse(ok_az)
            self.assertIn("occupied tenant", reason_az)

    def test_nxdomain_cname_reverification_passes_without_http_connection(self):
        prog = self._sample_program()
        nx_finding = VdpFinding(
            program_handle="acme-vdp",
            program_name="Acme Corp VDP",
            host="demo.acme.example",
            finding_type="dangling_cname",
            title="Dangling DNS CNAME to Unattached Microsoft Azure Endpoint on demo.acme.example",
            severity="medium",
            weakness_id="18",
            structured_scope_id="555",
            cname_target="deletedapp.centralus.cloudapp.azure.com",
            a_records=[],
            http_status=0,
            http_url="http://demo.acme.example/",
            evidence_snippet="NXDOMAIN (Dangling Service Endpoint)",
            remediation="Remove the dangling DNS CNAME record.",
            captured_utc="2026-11-14T20:00:00+00:00",
            provider="Microsoft Azure",
        )

        def _fake_doh(host: str, record_type: str = "CNAME", timeout: int = 5):
            if record_type == "CNAME" and host == "demo.acme.example":
                return {"Status": 0, "Answer": [{"type": 5, "data": "deletedapp.centralus.cloudapp.azure.com."}]}
            return {"Status": 3, "Answer": []}

        with patch("hunt_hackerone_vdps.resolve_dns_doh", side_effect=_fake_doh):
            gate = evaluate_submission_quality_gate(
                prog,
                nx_finding,
                reverify_runs=2,
                critic_runs=3,
                skip_live_reverify=False,
            )
        self.assertTrue(gate.passed)
        self.assertEqual(gate.reverification_passes, 2)
        self.assertEqual(gate.critic_passes, 3)
        md, _ = render_vdp_dossier(prog, nx_finding)
        self.assertIn("NXDOMAIN (Status: 3)", md)

    @patch("hunt_hackerone_vdps.urllib.request.urlopen")
    def test_discover_passive_subdomains_merges_certspotter_and_anubis(self, mock_urlopen):
        def _side_effect(req, timeout=10):
            url = req.full_url
            if "certspotter" in url:
                return _MockResponse([{"dns_names": ["*.acme.example", "try.acme.example"]}])
            if "anubisdb" in url:
                return _MockResponse(["shop.acme.example", "other.domain.com"])
            return _MockResponse("", status=404)

        mock_urlopen.side_effect = _side_effect
        with tempfile.TemporaryDirectory() as tmpdir:
            subs = discover_passive_subdomains(
                "acme.example",
                cache_path=Path(tmpdir) / "ct_cache.json",
            )
            self.assertEqual(subs, {"try.acme.example", "shop.acme.example"})

    def test_render_vdp_dossier_includes_compliance_headers_and_sha(self):
        prog = self._sample_program()
        finding = self._sample_finding()
        md, digest = render_vdp_dossier(prog, finding)
        self.assertIn("old-promo.acme.example", md)
        self.assertIn("X-Acme-VDP: HackerOne-arsoncarson", md)
        self.assertEqual(len(digest), 64)

    @patch("hunt_hackerone_vdps.urllib.request.urlopen")
    def test_submit_403_moves_dossier_to_blocked_without_polluting_vdp_ready(self, mock_urlopen):
        import io
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.hackerone.com/v1/hackers/reports",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"errors":[{"status":403}]}'),
        )
        prog = self._sample_program()
        prog.target_signal = 1.0
        finding = self._sample_finding()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ready_dir = tmp / "vdp_ready"
            res = submit_vdp_finding(
                prog,
                finding,
                "user",
                "tok",
                dry_run=False,
                existing_reports=[],
                vdp_ready_dir=ready_dir,
                manifest_path=tmp / "manifest.json",
                skip_live_reverify=True,
                critic_runs=3,
            )
            self.assertEqual(res["status"], "BLOCKED_PROGRAM_FORBIDDEN")
            self.assertEqual(res["http_status"], 403)
            self.assertFalse((ready_dir / "acme-vdp_vdp_old-promo_acme_example.md").exists())
            self.assertTrue((tmp / "vdp_blocked" / "acme-vdp_vdp_old-promo_acme_example.md").exists())

    def test_submit_blocks_when_researcher_signal_below_program_target_signal(self):
        prog = self._sample_program()
        prog.target_signal = 1.0
        finding = self._sample_finding()
        res = submit_vdp_finding(
            prog,
            finding,
            "user",
            "tok",
            dry_run=True,
            existing_reports=[],
            researcher_signal=0.0,
            skip_live_reverify=True,
        )
        self.assertEqual(res["status"], "BLOCKED_SIGNAL_REQUIREMENT")
        self.assertEqual(res["required_signal"], 1.0)

    def test_quality_gate_rejects_dangling_cname_when_policy_requires_active_poc(self):
        prog = self._sample_program()
        prog.policy = (
            "Please note: subdomain takeover reports require a working proof-of-concept "
            "demonstrating control over the domain. Passive DNS checks alone are not accepted."
        )
        finding = self._sample_finding()
        gate = evaluate_submission_quality_gate(
            prog,
            finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
        )
        self.assertFalse(gate.passed)
        self.assertFalse(gate.deterministic_checks["policy_not_excluded"])

    def test_detects_actuator_aws_creds_and_backup_configs_while_rejecting_html(self):
        act_json = '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASS":"***"}}]}'
        res_act = check_exposed_config_or_git("/actuator/env", 200, act_json)
        self.assertIsNotNone(res_act)
        self.assertEqual(res_act["finding_type"], "exposed_actuator")
        self.assertIsNone(check_exposed_config_or_git("/actuator/env", 200, "<html><body>Not found</body></html>"))

        aws_creds = "[default]\naws_access_key_id = AKIAEXAMPLE123456\naws_secret_access_key = secretvalue\n"
        res_aws = check_exposed_config_or_git("/.aws/credentials", 200, aws_creds)
        self.assertIsNotNone(res_aws)
        self.assertEqual(res_aws["finding_type"], "exposed_aws_credentials")
        self.assertNotIn("secretvalue", res_aws["snippet"])

        wp_bak = "<?php\ndefine('DB_NAME', 'prod_db');\ndefine('DB_PASSWORD', 'hunter2_secret');\n"
        res_bak = check_exposed_config_or_git("/wp-config.php~", 200, wp_bak)
        self.assertIsNotNone(res_bak)
        self.assertEqual(res_bak["finding_type"], "exposed_backup_config")
        self.assertNotIn("hunter2_secret", res_bak["snippet"])

    def test_quality_gate_rejects_static_public_cdn_bucket_and_passive_saas_cname(self):
        prog = self._sample_program()
        static_bucket = VdpFinding(
            program_handle="acme-vdp",
            program_name="Acme Corp VDP",
            host="cdn.acme.example",
            finding_type="open_bucket",
            title="Open Public Cloud Storage Bucket (public-web) Directory Listing on cdn.acme.example",
            severity="medium",
            weakness_id="18",
            structured_scope_id="555",
            cname_target=None,
            a_records=["1.2.3.4"],
            http_status=200,
            http_url="https://cdn.acme.example/",
            evidence_snippet="<ListBucketResult><Name>public-web</Name> sample_keys=['assets/app.js', 'styles/main.css', 'img/logo.png']",
            remediation="Disable public bucket listing.",
            captured_utc="2026-11-14T20:00:00+00:00",
            extra={"bucket_name": "public-web", "sample_keys": ["assets/app.js", "styles/main.css", "img/logo.png"]},
        )
        gate_bucket = evaluate_submission_quality_gate(
            prog,
            static_bucket,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
        )
        self.assertFalse(gate_bucket.passed)
        self.assertFalse(gate_bucket.deterministic_checks["material_security_impact"])

        cname_finding = self._sample_finding()
        cname_finding.provider = "Unbounce"
        gate_cname = evaluate_submission_quality_gate(
            prog,
            cname_finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
            reject_passive_saas_cname=True,
        )
        self.assertFalse(gate_cname.passed)
        self.assertFalse(gate_cname.deterministic_checks["material_security_impact"])

    def test_inferred_signal_floor_blocks_target_signal_programs_after_informative(self):
        prog = self._sample_program()
        prog.target_signal = 1.0
        finding = self._sample_finding()
        existing_reports = [
            {"id": "4204160", "attributes": {"state": "informative", "title": "other.example.com"}}
        ]
        res = submit_vdp_finding(
            prog,
            finding,
            "user",
            "tok",
            dry_run=True,
            existing_reports=existing_reports,
            skip_live_reverify=True,
        )
        self.assertEqual(res["status"], "BLOCKED_SIGNAL_REQUIREMENT")


class TestVdpReconAndHighSignalIntegration(unittest.TestCase):
    def _program_with_all_cwe_weaknesses(self) -> VdpProgram:
        return VdpProgram(
            handle="acme-vdp",
            name="Acme Corp VDP",
            offers_bounties=False,
            submission_state="open",
            i_must_verify_identity_to_submit=False,
            policy="Standard safe harbor VDP policy.",
            structured_scopes=[
                {
                    "id": "555",
                    "attributes": {
                        "asset_type": "WILDCARD",
                        "asset_identifier": "*.acme.example",
                        "eligible_for_submission": True,
                    },
                }
            ],
            weaknesses=[
                {"id": "18", "attributes": {"external_id": "cwe-200", "name": "Information Exposure"}},
                {"id": "22", "attributes": {"external_id": "cwe-538", "name": "Sensitive File Exposure"}},
                {"id": "33", "attributes": {"external_id": "cwe-798", "name": "Use of Hard-coded Credentials"}},
                {"id": "44", "attributes": {"external_id": "cwe-942", "name": "Overly Permissive CORS Policy"}},
                {"id": "55", "attributes": {"external_id": "cwe-284", "name": "Improper Access Control"}},
            ],
            compliance_headers={"X-Acme-VDP": "HackerOne-arsoncarson"},
        )

    @patch("orbit_security.vdp_recon_sources.shutil.which", return_value=None)
    @patch("hunt_hackerone_vdps.urllib.request.urlopen")
    def test_zero_subdomain_ct_lookups_not_cached_and_purge_empty_cache(self, mock_urlopen, _mock_which):
        import time

        mock_urlopen.return_value = _MockResponse("", status=404)
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "vdp_ct_cache.json"

            # 0-subdomain discovery must NOT write an empty cache entry
            subs = discover_passive_subdomains("empty.example", cache_path=cache_path)
            self.assertEqual(subs, set())
            self.assertFalse(cache_path.exists())

            # Pre-populate an empty poisoned entry + a valid non-empty entry
            now = time.time()
            cache_path.write_text(
                json.dumps(
                    {
                        "poisoned.example": {"timestamp": now, "subdomains": []},
                        "healthy.example": {"timestamp": now, "subdomains": ["api.healthy.example"]},
                    }
                ),
                encoding="utf-8",
            )

            # Healthy entry hits cache without urlopen
            before_calls = mock_urlopen.call_count
            self.assertEqual(
                discover_passive_subdomains("healthy.example", cache_path=cache_path),
                {"api.healthy.example"},
            )
            self.assertEqual(mock_urlopen.call_count, before_calls)

            # Empty poisoned entry is treated as cache miss and triggers urlopen
            self.assertEqual(
                discover_passive_subdomains("poisoned.example", cache_path=cache_path),
                set(),
            )
            self.assertGreater(mock_urlopen.call_count, before_calls)

            # Purging removes poisoned empty entries and preserves healthy entries
            summary = run_vdp_hunt(cache_path=cache_path, purge_empty_cache=True, max_programs=0)
            self.assertEqual(summary["purged_empty_cache_count"], 1)
            self.assertEqual(summary["purged_empty_cache_roots"], ["poisoned.example"])
            remaining = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(list(remaining.keys()), ["healthy.example"])

    def test_run_vdp_hunt_screens_explicit_url_and_domain_scopes_without_wildcards(self):
        raw_programs = [
            {"id": "1", "attributes": {"handle": "explicit-vdp", "offers_bounties": False, "submission_state": "open"}},
            {"id": "2", "attributes": {"handle": "ignored-vdp", "offers_bounties": False, "submission_state": "open"}},
        ]
        explicit_prog = VdpProgram(
            handle="explicit-vdp",
            name="Explicit VDP",
            offers_bounties=False,
            submission_state="open",
            i_must_verify_identity_to_submit=False,
            structured_scopes=[
                {
                    "id": "701",
                    "attributes": {
                        "asset_type": "URL",
                        "asset_identifier": "https://portal.explicit.example/login",
                        "eligible_for_submission": True,
                    },
                },
                {
                    "id": "702",
                    "attributes": {
                        "asset_type": "DOMAIN",
                        "asset_identifier": "api.explicit.example",
                        "eligible_for_submission": True,
                    },
                },
                {
                    "id": "703",
                    "attributes": {
                        "asset_type": "URL",
                        "asset_identifier": "https://blocked.explicit.example/",
                        "eligible_for_submission": False,
                    },
                },
            ],
        )
        screened_hosts: list[tuple[str, str]] = []

        def _fake_fetch_h1(path, auth_header, **kwargs):
            if "/me/reports" in path:
                return []
            return raw_programs

        def _fake_hydrate(raw_prog, auth_header, **kwargs):
            handle = raw_prog["attributes"]["handle"]
            if handle == "explicit-vdp":
                return explicit_prog
            raise AssertionError(f"Unexpected program hydrated: {handle}")

        def _fake_screen(prog, host, detector=None):
            screened_hosts.append((prog.handle, host))
            return None

        with (
            patch("hunt_hackerone_vdps.load_hackerone_credentials", return_value=("user", "tok")),
            patch("hunt_hackerone_vdps.fetch_paginated_h1", side_effect=_fake_fetch_h1),
            patch("hunt_hackerone_vdps.hydrate_vdp_program", side_effect=_fake_hydrate),
            patch("hunt_hackerone_vdps.screen_host_non_destructively", side_effect=_fake_screen),
            tempfile.TemporaryDirectory() as tmpdir,
        ):
            summary = run_vdp_hunt(
                max_programs=10,
                workers=1,
                program_handles="explicit-vdp",
                covered_domains={"portal.explicit.example"},
                vdp_ready_dir=Path(tmpdir) / "vdp_ready",
                manifest_path=Path(tmpdir) / "manifest.json",
            )

        self.assertEqual(summary["programs_with_uncovered_wildcards_scanned"], 1)
        self.assertEqual(summary["subdomains_screened"], 2)
        self.assertEqual(
            screened_hosts,
            [
                ("explicit-vdp", "portal.explicit.example"),
                ("explicit-vdp", "api.explicit.example"),
            ],
        )

    def test_run_vdp_hunt_signal_gate_prefilter_and_ignore_override(self):
        raw_programs = [
            {"id": "1", "attributes": {"handle": "high-sig-vdp", "offers_bounties": False, "submission_state": "open"}},
            {"id": "2", "attributes": {"handle": "zero-sig-vdp", "offers_bounties": False, "submission_state": "open"}},
        ]
        prog_high = VdpProgram(
            handle="high-sig-vdp",
            name="High Signal VDP",
            offers_bounties=False,
            submission_state="open",
            i_must_verify_identity_to_submit=False,
            target_signal=1.0,
            structured_scopes=[
                {"id": "1", "attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.highsig.example", "eligible_for_submission": True}}
            ],
        )
        prog_zero = VdpProgram(
            handle="zero-sig-vdp",
            name="Zero Signal VDP",
            offers_bounties=False,
            submission_state="open",
            i_must_verify_identity_to_submit=False,
            target_signal=0.0,
            structured_scopes=[
                {"id": "2", "attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.zerosig.example", "eligible_for_submission": True}}
            ],
        )

        def _fake_fetch_h1(path, auth_header, **kwargs):
            if "/me/reports" in path:
                return [{"id": "4204160", "attributes": {"state": "informative", "title": "old.example"}}]
            return raw_programs

        def _fake_hydrate(raw_prog, auth_header, **kwargs):
            return prog_high if raw_prog["attributes"]["handle"] == "high-sig-vdp" else prog_zero

        ct_called_roots: list[str] = []

        def _fake_ct(root, **kwargs):
            ct_called_roots.append(root)
            return {f"app.{root}"}

        with (
            patch("hunt_hackerone_vdps.load_hackerone_credentials", return_value=("user", "tok")),
            patch("hunt_hackerone_vdps.fetch_paginated_h1", side_effect=_fake_fetch_h1),
            patch("hunt_hackerone_vdps.hydrate_vdp_program", side_effect=_fake_hydrate),
            patch("hunt_hackerone_vdps.discover_passive_subdomains", side_effect=_fake_ct),
            patch("hunt_hackerone_vdps.screen_host_non_destructively", return_value=None),
            tempfile.TemporaryDirectory() as tmpdir,
        ):
            summary_filtered = run_vdp_hunt(
                max_programs=10,
                workers=1,
                covered_domains=set(),
                vdp_ready_dir=Path(tmpdir) / "vdp_ready",
                manifest_path=Path(tmpdir) / "manifest.json",
            )
            self.assertEqual(summary_filtered["programs_skipped_signal_gate"], 1)
            self.assertEqual(summary_filtered["programs_with_uncovered_wildcards_scanned"], 1)
            self.assertEqual(ct_called_roots, ["zerosig.example"])

            ct_called_roots.clear()
            summary_ignored = run_vdp_hunt(
                max_programs=10,
                workers=1,
                covered_domains=set(),
                ignore_signal_gate=True,
                vdp_ready_dir=Path(tmpdir) / "vdp_ready",
                manifest_path=Path(tmpdir) / "manifest.json",
            )
            self.assertEqual(summary_ignored["programs_skipped_signal_gate"], 0)
            self.assertEqual(summary_ignored["programs_with_uncovered_wildcards_scanned"], 2)
            self.assertEqual(ct_called_roots, ["highsig.example", "zerosig.example"])

    def test_cli_main_forwards_purge_ignore_signal_and_handles_flags(self):
        fake_summary = {
            "total_programs_fetched": 1,
            "open_vdp_candidates": 1,
            "programs_skipped_signal_gate": 0,
            "programs_with_uncovered_wildcards_scanned": 0,
            "wildcards_scanned": [],
            "explicit_hosts_scanned": [],
            "subdomains_screened": 0,
            "findings_count": 0,
            "findings": [],
            "submissions": [],
            "purged_empty_cache_count": 2,
            "purged_empty_cache_roots": ["a.example", "b.example"],
        }
        with patch("hunt_hackerone_vdps.run_vdp_hunt", return_value=fake_summary) as mock_run:
            rc = main(
                [
                    "--purge-empty-cache",
                    "--ignore-signal-gate",
                    "--program-handles",
                    "acme,beta",
                    "--max-programs",
                    "0",
                    "--json",
                ]
            )
        self.assertEqual(rc, 0)
        kwargs = mock_run.call_args.kwargs
        self.assertTrue(kwargs["purge_empty_cache"])
        self.assertTrue(kwargs["ignore_signal_gate"])
        self.assertEqual(kwargs["program_handles"], "acme,beta")
        self.assertEqual(kwargs["max_programs"], 0)

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_end_to_end_extended_sensitive_exposures_and_quality_gate(self, _mock_doh, _mock_sleep):
        for expected_path in ("/.git/config", "/.svn/entries", "/.DS_Store", "/server-status", "/actuator/mappings"):
            self.assertIn(expected_path, SENSITIVE_EXPOSURE_PATHS)

        prog = self._program_with_all_cwe_weaknesses()
        cases = [
            (
                "/.git/config",
                "exposed_git",
                "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://bot:secretpass@github.com/acme/api.git\n",
            ),
            (
                "/.svn/entries",
                "exposed_svn",
                "10\n\ndir\n412\nhttps://svn.acme.example/repo/trunk\n",
            ),
            (
                "/.DS_Store",
                "exposed_ds_store",
                "\x00\x00\x00\x01Bud1\x00\x00\x10\x00.env.production\x00db_backup.sql",
            ),
            (
                "/server-status",
                "exposed_server_status",
                (
                    "<!DOCTYPE HTML><html><body><h1>Apache Server Status for app.acme.example</h1>"
                    "<dt>Total Accesses: 9001</dt><dt>Scoreboard: _W_</dt>"
                    "<table><tr><th>Client</th><th>VHost</th><th>Request</th></tr>"
                    "<tr><td>203.0.113.10</td><td>app.acme.example</td><td>GET /internal/admin HTTP/1.1</td></tr>"
                    "</table></body></html>"
                ),
            ),
            (
                "/actuator/mappings",
                "exposed_actuator",
                json.dumps({"contexts": {"application": {"mappings": {"dispatcherServlets": {"a": [1]}}}}}),
            ),
        ]

        for target_path, expected_type, payload_body in cases:
            with self.subTest(path=target_path):
                def _fake_fetch(url, headers=None, max_bytes=8192, timeout=5):
                    if url == "https://app.acme.example/":
                        return (200, {"Content-Type": "text/html"}, "<html><body>App Home</body></html>")
                    if url == f"https://app.acme.example{target_path}":
                        return (200, {}, payload_body)
                    if target_path == "/actuator/mappings" and url == "https://app.acme.example/actuator/env":
                        return (200, {}, '{"status":"disabled"}')
                    return (404, {}, "Not Found")

                with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_fetch):
                    finding = screen_host_non_destructively(prog, "app.acme.example")
                    self.assertIsNotNone(finding)
                    self.assertEqual(finding.finding_type, expected_type)
                    self.assertEqual(finding.http_url, f"https://app.acme.example{target_path}")
                    gate = evaluate_submission_quality_gate(
                        prog,
                        finding,
                        reverify_runs=2,
                        critic_runs=3,
                        skip_live_reverify=False,
                    )
                self.assertTrue(gate.passed, f"{target_path} blocked: {gate.blocking_reasons}")
                self.assertEqual(gate.verdict, "APPROVED")
                self.assertEqual(gate.reverification_passes, 2)
                self.assertEqual(gate.critic_passes, 3)
                self.assertTrue(gate.deterministic_checks["report_critic_grounded"])

        # Raw Apache HTML in evidence_snippet for exposed_server_status must not fail evidence_worthy
        raw_status_finding = VdpFinding(
            program_handle=prog.handle,
            program_name=prog.name,
            host="app.acme.example",
            finding_type="exposed_server_status",
            title="Exposed /server-status Apache Server Status Disclosure on app.acme.example",
            severity="medium",
            weakness_id="18",
            structured_scope_id="555",
            cname_target=None,
            a_records=[],
            http_status=200,
            http_url="https://app.acme.example/server-status",
            evidence_snippet="<!DOCTYPE HTML><html><body>Apache Server Status for app.acme.example</body></html>",
            remediation="Block public web access to /server-status.",
            captured_utc="2026-11-14T20:00:00+00:00",
        )
        gate_raw = evaluate_submission_quality_gate(
            prog, raw_status_finding, reverify_runs=2, critic_runs=3, skip_live_reverify=True
        )
        self.assertTrue(gate_raw.deterministic_checks["evidence_worthy"])
        self.assertTrue(gate_raw.passed, gate_raw.blocking_reasons)

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_end_to_end_dangling_referenced_bucket_and_firebase_quality_gate(self, _mock_doh, _mock_sleep):
        prog = self._program_with_all_cwe_weaknesses()

        # 1. Dangling referenced GCS bucket in HTML
        gcs_404_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>"
        )

        def _fake_fetch_gcs(url, headers=None, max_bytes=8192, timeout=5):
            if url == "https://portal.acme.example/":
                return (
                    200,
                    {"Content-Type": "text/html"},
                    '<html><body><img src="https://storage.googleapis.com/acme-dangling-assets/logo.png"></body></html>',
                )
            if url == "https://storage.googleapis.com/acme-dangling-assets/":
                return (404, {"Content-Type": "application/xml"}, gcs_404_xml)
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_fetch_gcs):
            finding_gcs = screen_host_non_destructively(prog, "portal.acme.example")
            self.assertIsNotNone(finding_gcs)
            self.assertEqual(finding_gcs.finding_type, "dangling_referenced_bucket")
            self.assertEqual(finding_gcs.host, "portal.acme.example")
            self.assertEqual(finding_gcs.structured_scope_id, "555")
            self.assertEqual(finding_gcs.http_url, "https://storage.googleapis.com/acme-dangling-assets/")
            gate_gcs = evaluate_submission_quality_gate(
                prog, finding_gcs, reverify_runs=2, critic_runs=3, skip_live_reverify=False
            )
        self.assertTrue(gate_gcs.passed, gate_gcs.blocking_reasons)
        self.assertEqual(gate_gcs.reverification_passes, 2)
        self.assertEqual(gate_gcs.critic_passes, 3)

        # 2. Exposed Firebase RTDB referenced from same-origin JS bundle
        def _fake_fetch_fb(url, headers=None, max_bytes=8192, timeout=5):
            if url == "https://app.acme.example/":
                return (200, {"Content-Type": "text/html"}, '<html><script src="/assets/bundle.js"></script></html>')
            if url == "https://app.acme.example/assets/bundle.js":
                return (200, {"Content-Type": "application/javascript"}, 'const db = "https://acme-prod-rtdb.firebaseio.com/users.json";')
            if url == "https://acme-prod-rtdb.firebaseio.com/.json?shallow=true":
                return (200, {"Content-Type": "application/json"}, '{"users": true, "sessions": true}')
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_fetch_fb):
            finding_fb = screen_host_non_destructively(prog, "app.acme.example")
            self.assertIsNotNone(finding_fb)
            self.assertEqual(finding_fb.finding_type, "exposed_firebase_db")
            self.assertEqual(finding_fb.host, "app.acme.example")
            self.assertEqual(finding_fb.structured_scope_id, "555")
            self.assertEqual(finding_fb.http_url, "https://acme-prod-rtdb.firebaseio.com/.json?shallow=true")
            gate_fb = evaluate_submission_quality_gate(
                prog, finding_fb, reverify_runs=2, critic_runs=3, skip_live_reverify=False
            )
        self.assertTrue(gate_fb.passed, gate_fb.blocking_reasons)
        self.assertEqual(gate_fb.reverification_passes, 2)
        self.assertEqual(gate_fb.critic_passes, 3)

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_end_to_end_cors_credentialed_reflection_quality_gate(self, _mock_doh, _mock_sleep):
        prog = self._program_with_all_cwe_weaknesses()
        seen_origins: list[str] = []

        def _fake_fetch_cors(url, headers=None, max_bytes=8192, timeout=5):
            if url == "https://api.acme.example/":
                origin = (headers or {}).get("Origin")
                if origin:
                    seen_origins.append(origin)
                    return (
                        200,
                        {
                            "Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true",
                            "Content-Type": "application/json",
                        },
                        '{"user_id": 42, "email": "alice@acme.example"}',
                    )
                return (200, {"Content-Type": "application/json"}, '{"user_id": 42, "email": "alice@acme.example"}')
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_fetch_cors):
            finding = screen_host_non_destructively(prog, "api.acme.example")
            self.assertIsNotNone(finding)
            self.assertEqual(finding.finding_type, "cors_credentialed_reflection")
            self.assertEqual(finding.http_url, "https://api.acme.example/")
            gate = evaluate_submission_quality_gate(
                prog, finding, reverify_runs=2, critic_runs=3, skip_live_reverify=False
            )
        self.assertTrue(gate.passed, gate.blocking_reasons)
        self.assertEqual(gate.reverification_passes, 2)
        self.assertEqual(gate.critic_passes, 3)
        self.assertEqual(len(seen_origins), 3)  # 1 initial screen + 2 live reverify runs

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_end_to_end_exposed_js_secret_quality_gate(self, _mock_doh, _mock_sleep):
        prog = self._program_with_all_cwe_weaknesses()
        raw_secret = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz987654"

        def _fake_fetch_secret(url, headers=None, max_bytes=8192, timeout=5):
            if url == "https://app.acme.example/":
                return (200, {"Content-Type": "text/html"}, '<html><script src="/static/main.js"></script></html>')
            if url == "https://app.acme.example/static/main.js":
                return (200, {"Content-Type": "application/javascript"}, f'window.STRIPE_KEY = "{raw_secret}";')
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_fetch_secret):
            finding = screen_host_non_destructively(prog, "app.acme.example")
            self.assertIsNotNone(finding)
            self.assertEqual(finding.finding_type, "exposed_js_secret")
            self.assertEqual(finding.severity, "high")
            self.assertEqual(finding.http_url, "https://app.acme.example/static/main.js")
            self.assertNotIn(raw_secret, finding.evidence_snippet)
            self.assertIn("<REDACTED>", finding.evidence_snippet)
            gate = evaluate_submission_quality_gate(
                prog, finding, reverify_runs=2, critic_runs=3, skip_live_reverify=False
            )
        self.assertTrue(gate.passed, gate.blocking_reasons)
        self.assertEqual(gate.reverification_passes, 2)
        self.assertEqual(gate.critic_passes, 3)
        md, _ = render_vdp_dossier(prog, finding)
        self.assertNotIn(raw_secret, md)

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_screen_host_spa_catchall_skips_sensitive_paths_except_server_status(self, _mock_doh, _mock_sleep):
        from urllib.parse import urlparse

        prog = self._program_with_all_cwe_weaknesses()

        # Sub-case A: SPA catch-all HTML on /.git/HEAD skips all remaining paths except /server-status
        requested_paths_clean: list[str] = []

        def _fake_spa_404(url, headers=None, max_bytes=8192, timeout=5):
            path = urlparse(url).path or "/"
            requested_paths_clean.append(path)
            if path == "/":
                return (200, {"Content-Type": "text/html"}, "<html><body>SPA App</body></html>")
            if path == "/.git/HEAD":
                return (200, {"Content-Type": "text/html"}, "<!doctype html><html><body>SPA Route</body></html>")
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_spa_404):
            finding = screen_host_non_destructively(prog, "app.acme.example")

        self.assertIsNone(finding)
        self.assertEqual(requested_paths_clean, ["/", "/.git/HEAD", "/server-status"])

        # Sub-case B: /server-status is still probed and detected despite SPA catch-all on /.git/HEAD
        requested_paths_status: list[str] = []

        def _fake_spa_with_server_status(url, headers=None, max_bytes=8192, timeout=5):
            path = urlparse(url).path or "/"
            requested_paths_status.append(path)
            if path == "/":
                return (200, {"Content-Type": "text/html"}, "<html><body>SPA App</body></html>")
            if path == "/.git/HEAD":
                return (200, {"Content-Type": "text/html"}, "<!doctype html><html><body>SPA Route</body></html>")
            if path == "/server-status":
                return (
                    200,
                    {"Content-Type": "text/html"},
                    (
                        "<!DOCTYPE HTML><html><body><h1>Apache Server Status for app.acme.example</h1>"
                        "<dt>Total Accesses: 42</dt><dt>Scoreboard: _W_</dt>"
                        "<table><tr><th>Client</th><th>VHost</th><th>Request</th></tr>"
                        "<tr><td>203.0.113.10</td><td>app.acme.example</td><td>GET /admin HTTP/1.1</td></tr>"
                        "</table></body></html>"
                    ),
                )
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_spa_with_server_status):
            status_finding = screen_host_non_destructively(prog, "app.acme.example")

        self.assertIsNotNone(status_finding)
        self.assertEqual(status_finding.finding_type, "exposed_server_status")
        self.assertEqual(requested_paths_status, ["/", "/.git/HEAD", "/server-status"])

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_screen_host_tarpit_timeout_breaks_sensitive_exposure_loop(self, _mock_doh, _mock_sleep):
        from urllib.parse import urlparse

        prog = self._program_with_all_cwe_weaknesses()
        requested_paths: list[str] = []

        def _fake_tarpit(url, headers=None, max_bytes=8192, timeout=5):
            path = urlparse(url).path or "/"
            requested_paths.append(path)
            if path == "/":
                return (200, {"Content-Type": "text/plain"}, "ok")
            if path == "/.git/HEAD":
                return (404, {}, "Not Found")
            if path == "/.git/config":
                return (0, {}, "")
            return (404, {}, "Not Found")

        with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_tarpit):
            finding = screen_host_non_destructively(prog, "app.acme.example")

        self.assertIsNone(finding)
        self.assertEqual(requested_paths, ["/", "/.git/HEAD", "/.git/config"])

    @patch("hunt_hackerone_vdps.time.sleep", return_value=None)
    @patch("hunt_hackerone_vdps.resolve_dns_doh", return_value={"Status": 0, "Answer": []})
    def test_screen_host_actuator_env_short_circuits_remaining_actuators(self, _mock_doh, _mock_sleep):
        from urllib.parse import urlparse

        prog = self._program_with_all_cwe_weaknesses()
        cases = [
            ("404", (404, {}, "Not Found")),
            ("200_html", (200, {"Content-Type": "text/html"}, "<html><body>Not Found</body></html>")),
        ]
        for label, env_response in cases:
            with self.subTest(case=label):
                requested_paths: list[str] = []

                def _fake_actuator(url, headers=None, max_bytes=8192, timeout=5):
                    path = urlparse(url).path or "/"
                    requested_paths.append(path)
                    if path == "/":
                        return (200, {"Content-Type": "text/plain"}, "ok")
                    if path == "/actuator/env":
                        return env_response
                    return (404, {}, "Not Found")

                with patch("hunt_hackerone_vdps.fetch_http_sample", side_effect=_fake_actuator):
                    finding = screen_host_non_destructively(prog, "app.acme.example")

                self.assertIsNone(finding)
                self.assertIn("/actuator/env", requested_paths)
                for skipped in ("/actuator/configprops", "/actuator/mappings", "/actuator/beans"):
                    self.assertNotIn(skipped, requested_paths)

    def test_run_vdp_hunt_caps_explicit_hosts_defaults_workers_12_and_logs_stderr(self):
        import contextlib
        import dataclasses
        import inspect
        import io

        self.assertEqual(inspect.signature(run_vdp_hunt).parameters["workers"].default, 12)
        with (
            patch("hunt_hackerone_vdps.run_vdp_hunt", return_value={"findings_count": 0, "findings": [], "submissions": []}) as mock_cli_run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli_rc = main(["--max-programs", "0", "--json"])
        self.assertEqual(cli_rc, 0)
        self.assertEqual(mock_cli_run.call_args.kwargs["workers"], 12)

        explicit_scopes = [
            {
                "id": f"80{i}",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": f"s{i}.explicit.example",
                    "eligible_for_submission": True,
                },
            }
            for i in range(1, 6)
        ]
        cap_prog = dataclasses.replace(
            self._program_with_all_cwe_weaknesses(),
            handle="explicit-cap",
            name="Explicit Cap VDP",
            structured_scopes=explicit_scopes,
        )
        raw_programs = [
            {
                "id": "1",
                "attributes": {
                    "handle": "explicit-cap",
                    "name": "Explicit Cap VDP",
                    "offers_bounties": False,
                    "submission_state": "open",
                },
            }
        ]
        screened_hosts: list[str] = []

        def _fake_fetch_h1(path, auth_header, **kwargs):
            if "/me/reports" in path:
                return []
            return raw_programs

        def _fake_screen(prog, host, detector=None):
            screened_hosts.append(host)
            if host == "s1.explicit.example":
                return VdpFinding(
                    program_handle=prog.handle,
                    program_name=prog.name,
                    host=host,
                    finding_type="exposed_git",
                    title=f"Exposed /.git/config Sensitive Configuration File on {host}",
                    severity="medium",
                    weakness_id="3002",
                    structured_scope_id="801",
                    cname_target=None,
                    a_records=["203.0.113.10"],
                    http_status=200,
                    http_url=f"https://{host}/.git/config",
                    evidence_snippet="[core]\n\trepositoryformatversion = 0",
                    remediation="Block /.git/config.",
                    captured_utc="2026-11-14T21:15:00Z",
                )
            return None

        stderr_buf = io.StringIO()
        with (
            patch("hunt_hackerone_vdps.load_hackerone_credentials", return_value=("user", "tok")),
            patch("hunt_hackerone_vdps.fetch_paginated_h1", side_effect=_fake_fetch_h1),
            patch("hunt_hackerone_vdps.hydrate_vdp_program", return_value=cap_prog),
            patch("hunt_hackerone_vdps.screen_host_non_destructively", side_effect=_fake_screen),
            patch("hunt_hackerone_vdps.submit_vdp_finding", return_value={"status": "QUALITY_GATE_BLOCKED"}),
            tempfile.TemporaryDirectory() as tmpdir,
            contextlib.redirect_stderr(stderr_buf),
        ):
            summary = run_vdp_hunt(
                max_programs=10,
                max_subdomains=1,
                program_handles="explicit-cap",
                vdp_ready_dir=Path(tmpdir) / "vdp_ready",
                manifest_path=Path(tmpdir) / "manifest.json",
            )

        self.assertEqual(summary["subdomains_screened"], 2)
        self.assertEqual(len(summary["explicit_hosts_scanned"]), 2)
        self.assertEqual(set(screened_hosts), {"s1.explicit.example", "s2.explicit.example"})
        stderr_out = stderr_buf.getvalue()
        self.assertIn(
            "[VDP-HUNT] FOUND [explicit-cap] s1.explicit.example -> exposed_git (https://s1.explicit.example/.git/config)",
            stderr_out,
        )
        self.assertIn(
            "[VDP-HUNT] DISPATCH [explicit-cap] s1.explicit.example -> QUALITY_GATE_BLOCKED",
            stderr_out,
        )

    def test_policy_exclusion_rejects_abbreviated_poc_requirement(self):
        import dataclasses

        prog = dataclasses.replace(
            self._program_with_all_cwe_weaknesses(),
            policy="Out of scope: Subdomain takeover without a full working PoC.",
        )
        finding = VdpFinding(
            program_handle=prog.handle,
            program_name=prog.name,
            host="app.acme.example",
            finding_type="dangling_cname",
            title="Dangling Heroku CNAME on app.acme.example",
            severity="medium",
            weakness_id="55",
            structured_scope_id="555",
            cname_target="old-app.herokuapp.com",
            a_records=["203.0.113.10"],
            http_status=404,
            http_url="https://app.acme.example/",
            evidence_snippet="No such app",
            remediation="Remove dangling DNS record.",
            captured_utc="2026-11-14T21:55:00Z",
            provider="Heroku",
        )
        gate = evaluate_submission_quality_gate(
            prog,
            finding,
            reverify_runs=2,
            critic_runs=3,
            skip_live_reverify=True,
        )
        self.assertFalse(gate.passed)
        self.assertFalse(gate.deterministic_checks["policy_not_excluded"])

    def test_vercel_cname_rejected_when_vercel_txt_lock_present(self):
        from hunt_hackerone_vdps import _reverify_finding_live

        with patch(
            "hunt_hackerone_vdps.resolve_dns_doh",
            return_value={"Status": 0, "Answer": [{"type": 16, "data": '"vc-domain-verify=good-vibes-preview.tictac.com,abc"'}]},
        ) as mock_doh:
            claimable, reason = check_takeover_claimability(
                "Vercel",
                "cname.vercel-dns.com",
                "The deployment could not be found on Vercel.",
                host="good-vibes-preview.tictac.com",
            )
        self.assertFalse(claimable)
        self.assertIn("_vercel.tictac.com", reason)
        mock_doh.assert_called_once_with("_vercel.tictac.com", "TXT", timeout=5)

        with patch(
            "hunt_hackerone_vdps.resolve_dns_doh",
            return_value={"Status": 0, "Answer": []},
        ):
            claimable_unlocked, _ = check_takeover_claimability(
                "Vercel",
                "cname.vercel-dns.com",
                "The deployment could not be found on Vercel.",
                host="good-vibes-preview.tictac.com",
            )
        self.assertTrue(claimable_unlocked)

        # Ensure _reverify_finding_live passes host=finding.host to check_takeover_claimability
        prog = self._program_with_all_cwe_weaknesses()
        finding = VdpFinding(
            program_handle=prog.handle,
            program_name=prog.name,
            host="good-vibes-preview.tictac.com",
            finding_type="dangling_cname",
            title="Dangling Vercel CNAME on good-vibes-preview.tictac.com",
            severity="medium",
            weakness_id="55",
            structured_scope_id="555",
            cname_target="cname.vercel-dns.com",
            a_records=["76.76.21.21"],
            http_status=404,
            http_url="https://good-vibes-preview.tictac.com/",
            evidence_snippet="The deployment could not be found on Vercel.",
            remediation="Remove dangling DNS record.",
            captured_utc="2026-11-14T21:55:00Z",
            provider="Vercel",
        )

        def _fake_doh(name, qtype="A", timeout=5):
            if name == "good-vibes-preview.tictac.com" and qtype == "CNAME":
                return {"Status": 0, "Answer": [{"type": 5, "data": "cname.vercel-dns.com."}]}
            if name == "_vercel.tictac.com" and qtype == "TXT":
                return {"Status": 0, "Answer": [{"type": 16, "data": '"vc-domain-verify=tictac"'}]}
            return {"Status": 0, "Answer": []}

        with (
            patch("hunt_hackerone_vdps.resolve_dns_doh", side_effect=_fake_doh),
            patch(
                "hunt_hackerone_vdps.fetch_http_sample",
                return_value=(404, {}, "The deployment could not be found on Vercel."),
            ),
        ):
            reverified, rev_reason = _reverify_finding_live(finding, prog)
        self.assertFalse(reverified)
        self.assertIn("_vercel.tictac.com", rev_reason)

    def test_defaults_use_subfinder_false_and_ollama_timeout_45(self):
        import contextlib
        import inspect
        import io
        from hunt_hackerone_vdps import discover_passive_subdomains

        self.assertEqual(
            inspect.signature(evaluate_submission_quality_gate).parameters["ollama_timeout"].default,
            45.0,
        )
        self.assertIs(
            inspect.signature(discover_passive_subdomains).parameters["use_subfinder"].default,
            False,
        )
        self.assertIs(
            inspect.signature(run_vdp_hunt).parameters["use_subfinder"].default,
            False,
        )
        with (
            patch("hunt_hackerone_vdps.run_vdp_hunt", return_value={"findings_count": 0, "findings": [], "submissions": []}) as mock_cli_run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["--max-programs", "0", "--json"]), 0)
            self.assertFalse(mock_cli_run.call_args.kwargs["use_subfinder"])
            self.assertEqual(main(["--max-programs", "0", "--use-subfinder", "--json"]), 0)
            self.assertTrue(mock_cli_run.call_args.kwargs["use_subfinder"])

    def test_fastly_cross_host_redirect_and_firebase_hosting_txt_guards(self):
        # 1. Fastly cross-host redirect guard rejects unknown domain mismatch
        ok_cross, reason_cross = check_takeover_claimability(
            "Fastly",
            "jetblue.map.fastly.net",
            "Fastly error: unknown domain: hola.jetblue.com",
            host="movil.jetblue.com",
        )
        self.assertFalse(ok_cross)
        self.assertIn("cross-host redirect", reason_cross)
        self.assertIn("movil.jetblue.com", reason_cross)

        # Matching host in Fastly unknown domain error does not trigger the cross-host guard
        ok_match, _ = check_takeover_claimability(
            "Fastly",
            "jetblue.map.fastly.net",
            "Fastly error: unknown domain: hola.jetblue.com",
            host="hola.jetblue.com",
        )
        self.assertTrue(ok_match)

        # 2. Firebase Hosting custom domains require TXT ownership verification
        ok_fb1, reason_fb1 = check_takeover_claimability(
            "Firebase Hosting",
            "codeium-staging.web.app",
            "Site Not Found",
            host="auth-staging.windsurf.com",
        )
        self.assertFalse(ok_fb1)
        self.assertIn("DNS TXT ownership verification", reason_fb1)

        ok_fb2, reason_fb2 = check_takeover_claimability(
            None,
            "legacy-portal.firebaseapp.com",
            "Site Not Found",
            host="portal.example.org",
        )
        self.assertFalse(ok_fb2)
        self.assertIn("DNS TXT ownership verification", reason_fb2)


if __name__ == "__main__":
    unittest.main()
