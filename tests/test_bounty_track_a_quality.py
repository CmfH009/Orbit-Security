"""TDD regression suite for Track A bounty readiness, PoC accuracy, false-positive gates, and egress compliance."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from orbit_security.ast_sentinel import audit_egress_guard_compliance
from orbit_security.bounty_active_prober import ActiveProbeFinding, BountyActiveProber
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyTakeoverSweeper,
    BountyVulnerability,
    HackerOneDisclosureGenerator,
    ResponsibleDisclosureDrafter,
)
from orbit_security.bounty_triage_copilot import GemmaTriageCopilot
from orbit_security.cloud_sentinels import CorsMisconfigurationSentinel
from orbit_security.models import Severity
from orbit_security.report_verifier import (
    EmpiricalEvidenceArtifact,
    ReportCriticVerifier,
    compute_evidence_digest,
)


def _sample_program(program_id: str = "acme", domain: str = "acme.com") -> BountyProgram:
    return BountyProgram(
        program_id=program_id,
        name=program_id.title(),
        platform="hackerone",
        policy_url=f"https://hackerone.com/{program_id}",
        in_scope=[f"*.{domain}", domain],
        out_of_scope=[],
        bounty_tier="cash",
        max_bounty=10000,
    )


class TestPoCFormatterConsistency:
    def test_cors_arbitrary_origin_matches_observed_evidence_and_endpoint(self):
        vuln = BountyVulnerability(
            program_id="mercadolibre",
            program_name="MercadoLibre",
            platform="hackerone",
            target_domain="api.mercadolibre.com",
            flaw_type="cors_arbitrary_origin_with_credentials",
            provider="API Gateway CORS",
            severity=Severity.HIGH,
            cvss_score=8.1,
            evidence=(
                "Vulnerable CORS policy on 'https://api.mercadolibre.com/v1/account': "
                "Server blindly reflects untrusted Origin 'https://untrusted-adversary.com' "
                "in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true."
            ),
        )
        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert 'Origin: https://untrusted-adversary.com' in h1
        assert "Access-Control-Allow-Origin: https://untrusted-adversary.com" in h1
        assert "https://api.mercadolibre.com/v1/account" in h1
        assert "Origin: https://evil.com" not in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Origin: https://untrusted-adversary.com" in bc
        assert "https://api.mercadolibre.com/v1/account" in bc

    def test_cors_null_and_wildcard_origin_poc_accuracy(self):
        null_vuln = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="hackerone",
            target_domain="auth.acme.com",
            flaw_type="cors_null_origin_with_credentials",
            provider="API Gateway CORS",
            severity=Severity.HIGH,
            cvss_score=7.1,
            evidence="Dangerous CORS policy on 'auth.acme.com': Server explicitly trusts Origin 'null'",
        )
        h1_null = HackerOneDisclosureGenerator.generate_h1_report(null_vuln)
        assert 'Origin: null' in h1_null
        assert "Access-Control-Allow-Origin: null" in h1_null
        assert "Origin: https://evil.com" not in h1_null

        bc_null = ResponsibleDisclosureDrafter.generate_bugcrowd_report(null_vuln)
        assert 'Origin: null' in bc_null

        wild_vuln = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="hackerone",
            target_domain="cdn.acme.com",
            flaw_type="cors_wildcard_origin",
            provider="API Gateway CORS",
            severity=Severity.LOW,
            cvss_score=3.7,
            evidence="Access-Control-Allow-Origin: *",
        )
        h1_wild = HackerOneDisclosureGenerator.generate_h1_report(wild_vuln)
        assert "Access-Control-Allow-Origin: *" in h1_wild
        assert "Access-Control-Allow-Credentials: true" not in h1_wild

    def test_graphql_poc_uses_observed_endpoint_path(self):
        vuln = BountyVulnerability(
            program_id="gitlab",
            program_name="GitLab",
            platform="hackerone",
            target_domain="gitlab.com",
            flaw_type="graphql_introspection",
            provider="GraphQL",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            evidence=(
                "Production GraphQL schema introspection is enabled at 'https://gitlab.com/api/graphql'. "
                "Root Query type 'Query' retrieved."
            ),
        )
        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "POST https://gitlab.com/api/graphql" in h1
        assert "POST https://gitlab.com/graphql " not in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "POST https://gitlab.com/api/graphql" in bc

    def test_cloud_storage_takeover_avoids_literal_output_none(self):
        vuln = BountyVulnerability(
            program_id="gitlab",
            program_name="GitLab",
            platform="hackerone",
            target_domain="assets.gitlab.com",
            cname_target=None,
            flaw_type="cloud_storage_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=8.6,
            evidence="NoSuchBucket signature match",
        )
        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# Output: None" not in h1


class TestCryptographicBundleArtifactDigest:
    def test_bundle_embeds_ev_digest_and_passes_strict_critic(self, tmp_path: Path):
        prog = _sample_program("spotify", "byspotify.com")
        vuln = BountyVulnerability(
            program_id="spotify",
            program_name="Spotify",
            platform="hackerone",
            target_domain="cdn.byspotify.com",
            flaw_type="open_cloud_bucket",
            provider="Cloud Storage",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            evidence="Public cloud storage bucket listing is exposed on 'https://cdn.byspotify.com/'. Signature match: '<ListBucketResult'.",
            bounty_viability="HIGH_CONFIDENCE",
        )

        res = ResponsibleDisclosureDrafter.export_cryptographic_bundle(
            vuln=vuln,
            program=prog,
            output_dir=tmp_path,
        )
        ev_id = res.get("evidence_artifact_id", "")
        assert re.match(r"^ev_[0-9a-f]{12}$", ev_id), f"Expected ev_<12-char-hex>, got {ev_id!r}"

        bundle_dir = res["bundle_dir"]
        meta = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
        manifest = json.loads((bundle_dir / "manifest_sha256.json").read_text(encoding="utf-8"))
        tech = (bundle_dir / "technical_evidence.txt").read_text(encoding="utf-8")

        assert meta.get("evidence_artifact_id") == ev_id
        assert manifest.get("evidence_artifact_id") == ev_id
        assert ev_id in tech

        # Verify all zip member hashes match manifest_sha256.json
        with zipfile.ZipFile(res["zip_path"], "r") as zf:
            for fname, digest in manifest["file_hashes_sha256"].items():
                assert hashlib.sha256(zf.read(fname)).hexdigest() == digest

        # End-to-end strict Critic check with matching EmpiricalEvidenceArtifact
        expected_art = EmpiricalEvidenceArtifact(
            artifact_id=ev_id,
            target="cdn.byspotify.com",
            flaw_type=vuln.flaw_type,
            evidence_snippet=vuln.evidence,
            provider=vuln.provider,
            endpoint_path="/",
        )
        h1_md = (bundle_dir / "hackerone_report.md").read_text(encoding="utf-8")
        verdict = ReportCriticVerifier.verify_briefing_pitch(
            pitch_text=h1_md,
            target_domain="cdn.byspotify.com",
            core_finding=vuln.flaw_type,
            artifacts=[expected_art],
            require_artifact_grounding=True,
        )
        assert verdict.passed is True, f"Bundle H1 report failed strict Critic: {verdict.reasons}"


class TestFalsePositiveAndSignalGates:
    def test_cloud_storage_takeover_suppressed_without_cname_while_open_bucket_kept(self):
        sweeper = BountyTakeoverSweeper()
        prog = BountyProgram(
            program_id="test_cloud",
            name="Test Cloud",
            platform="hackerone",
            in_scope=["assets.acme.com", "cdn.acme.com"],
            bounty_tier="cash",
        )

        vulns = sweeper.sweep_program(
            prog,
            audit_cloud_buckets=True,
            mock_cnames={},  # No CNAME record on either host
            mock_bodies={
                "assets.acme.com": "<Error><Code>NoSuchBucket</Code></Error>",
                "cdn.acme.com": "<ListBucketResult><Name>cdn-acme</Name></ListBucketResult>",
            },
        )
        flaws_by_host = {v.target_domain: v.flaw_type for v in vulns}
        assert "assets.acme.com" not in flaws_by_host, "Proxy NoSuchBucket without CNAME must be suppressed"
        assert flaws_by_host.get("cdn.acme.com") == "open_cloud_bucket"

    def test_graphql_introspection_without_sensitive_schema_is_conditional(self):
        sweeper = BountyTakeoverSweeper()
        prog = BountyProgram(
            program_id="gql_prog",
            name="GQL Prog",
            platform="hackerone",
            in_scope=["api.acme.com"],
            bounty_tier="cash",
        )
        vulns = sweeper.sweep_program(
            prog,
            audit_graphql=True,
            mock_graphql_responses={
                "api.acme.com": {
                    "/api/graphql": {"data": {"__schema": {"queryType": {"name": "Query"}}}}
                }
            },
        )
        assert len(vulns) == 1
        assert vulns[0].flaw_type == "graphql_introspection"
        assert vulns[0].bounty_viability == "CONDITIONAL"

    def test_cors_empty_body_suppressed_and_public_html_downgraded(self):
        sweeper = BountyTakeoverSweeper()
        prog = BountyProgram(
            program_id="cors_prog",
            name="CORS Prog",
            platform="hackerone",
            in_scope=["telemetry.acme.com", "www.acme.com"],
            bounty_tier="cash",
        )
        mock_cors = {
            "telemetry.acme.com": {
                CorsMisconfigurationSentinel.TEST_ORIGIN: {
                    "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                    "access-control-allow-credentials": "true",
                    "content-length": "0",
                }
            },
            "www.acme.com": {
                CorsMisconfigurationSentinel.TEST_ORIGIN: {
                    "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                    "access-control-allow-credentials": "true",
                    "content-type": "text/html; charset=utf-8",
                }
            },
        }
        vulns = sweeper.sweep_program(
            prog,
            audit_cors=True,
            mock_cors_responses=mock_cors,
            mock_bodies={
                "telemetry.acme.com": "",
                "www.acme.com": "<!doctype html><html><body>Welcome</body></html>",
            },
        )
        domains = {v.target_domain: v for v in vulns}
        assert "telemetry.acme.com" not in domains, "Empty 0-byte CORS response must be suppressed"
        assert "www.acme.com" in domains
        assert domains["www.acme.com"].bounty_viability == "CONDITIONAL"
        assert domains["www.acme.com"].severity == Severity.MEDIUM
        assert domains["www.acme.com"].cvss_score == 5.4

    def test_active_prober_downgrades_cors_wildcard_and_gates_advisory_packaging(self, tmp_path: Path):
        from orbit_security.tools.xh_probe import ProbeResult, SecurityHeaderAudit

        prober = BountyActiveProber(
            disclosures_dir=tmp_path / "disc",
            state_file=tmp_path / "state.json",
        )
        prog = _sample_program("acme", "acme.com")

        with patch.object(
            prober.xh_probe,
            "probe",
            return_value=ProbeResult(
                url="https://static.acme.com",
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Type": "text/html",
                },
                body="<html><body>Static</body></html>",
                security_audit=SecurityHeaderAudit(
                    grade="B",
                    score=80,
                    present_headers={"strict-transport-security": "max-age=31536000"},
                    missing_headers=[],
                    recommendations=[],
                ),
            ),
        ):
            findings = prober.probe_host_active(
                "static.acme.com",
                offline=False,
                mock_cloud_body="",
                mock_graphql_paths={},
                mock_cors_responses={},
            )

        wild = [f for f in findings if f.flaw_type == "cors_wildcard"]
        assert len(wild) == 1
        assert wild[0].severity == "LOW"
        assert wild[0].score <= 4.0

        cors_mock = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                "access-control-allow-credentials": "true",
            }
        }
        with patch.object(
            prober.xh_probe,
            "probe",
            return_value=ProbeResult(
                url="https://empty.acme.com",
                status_code=200,
                headers={"Content-Length": "0"},
                body="",
                security_audit=SecurityHeaderAudit(
                    grade="B",
                    score=80,
                    present_headers={"strict-transport-security": "max-age=31536000"},
                    missing_headers=[],
                    recommendations=[],
                ),
            ),
        ):
            empty_findings = prober.probe_host_active(
                "empty.acme.com",
                offline=False,
                mock_cloud_body="",
                mock_graphql_paths={},
                mock_cors_responses=cors_mock,
            )
        assert not [f for f in empty_findings if f.flaw_type == "cors_arbitrary_origin_with_credentials"]

        with patch.object(
            prober.xh_probe,
            "probe",
            return_value=ProbeResult(
                url="https://html.acme.com",
                status_code=200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                body="<html><body>Public Landing</body></html>",
                security_audit=SecurityHeaderAudit(
                    grade="B",
                    score=80,
                    present_headers={"strict-transport-security": "max-age=31536000"},
                    missing_headers=[],
                    recommendations=[],
                ),
            ),
        ):
            html_findings = prober.probe_host_active(
                "html.acme.com",
                offline=False,
                mock_cloud_body="",
                mock_graphql_paths={},
                mock_cors_responses=cors_mock,
            )
        html_cors = [f for f in html_findings if f.flaw_type == "cors_arbitrary_origin_with_credentials"]
        assert len(html_cors) == 1
        assert html_cors[0].severity == "MEDIUM"
        assert html_cors[0].score == 5.4
        assert "[PUBLIC_HTML_ONLY:" in html_cors[0].evidence

        # verify_and_package_finding must NOT write advisory-only flaws to disclosures_dir
        hsts_finding = ActiveProbeFinding(
            program_id="acme",
            target_domain="www.acme.com",
            flaw_type="missing_hsts",
            severity="MEDIUM",
            score=5.0,
            evidence="Strict-Transport-Security omitted",
        )
        assert prober.verify_and_package_finding(hsts_finding, prog) is None
        assert list((tmp_path / "disc").glob("*.md")) == []

    def test_triage_copilot_flags_unverified_cloud_cors_and_graphql(self):
        prog = _sample_program("acme", "acme.com")

        fp_s3 = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="hackerone",
            target_domain="assets.acme.com",
            cname_target=None,
            flaw_type="cloud_storage_takeover",
            severity=Severity.HIGH,
            evidence="Response body matches unallocated bucket signature: 'NoSuchBucket'.",
            bounty_viability="HIGH_CONFIDENCE",
        )
        assert GemmaTriageCopilot.audit_finding(fp_s3, prog).verdict == "REJECTED_LOW_SIGNAL"

        cond_cors = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="hackerone",
            target_domain="www.acme.com",
            flaw_type="cors_arbitrary_origin_with_credentials",
            severity=Severity.MEDIUM,
            cvss_score=5.4,
            evidence="CORS reflected with creds [CONDITIONAL: public HTML response; verify authenticated JSON/API]",
            bounty_viability="CONDITIONAL",
        )
        assert GemmaTriageCopilot.audit_finding(cond_cors, prog).verdict == "NEEDS_MORE_INFO"

        cond_gql = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="hackerone",
            target_domain="api.acme.com",
            flaw_type="graphql_introspection",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            evidence="Production GraphQL schema introspection is enabled at 'https://api.acme.com/api/graphql'.",
            bounty_viability="CONDITIONAL",
        )
        assert GemmaTriageCopilot.audit_finding(cond_gql, prog).verdict == "NEEDS_MORE_INFO"


class TestTrackAEgressCompliance:
    def test_owned_track_a_modules_have_zero_egress_violations(self):
        src_dir = Path(r"A:\projects\orbit-security\src\orbit_security")
        owned = [
            src_dir / "bounty_radar.py",
            src_dir / "bounty_active_prober.py",
            src_dir / "bounty_triage_copilot.py",
            src_dir / "bounty_dispatcher.py",
            src_dir / "bounty_graph.py",
            src_dir / "bounty_rolling_daemon.py",
            src_dir / "report_verifier.py",
            src_dir / "scanner.py",
        ]
        violations = audit_egress_guard_compliance(owned)
        assert violations == [], f"Track A owned modules have egress violations: {violations}"

    def test_ssl_cert_bound_blocks_loopback_ssrf(self):
        sweeper = BountyTakeoverSweeper()
        with patch("socket.create_connection", side_effect=AssertionError("Must block before socket connect")):
            assert sweeper.is_ssl_cert_bound_to_domain("127.0.0.1") is False
            assert sweeper.is_ssl_cert_bound_to_domain("localhost") is False


class TestRound3DisclosureVaultReadiness:
    """Read-only empirical checks on staged disclosures, false-positive archives, and program exclusions."""

    REPO_ROOT = Path(__file__).resolve().parent.parent

    def test_disclosures_vault_paired_19_and_tier3_archived(self):
        disc_dir = self.REPO_ROOT / "data" / "disclosures"
        fp_archive_dir = self.REPO_ROOT / "data" / "archive" / "false_positive_disclosures"

        mds = sorted(p.name for p in disc_dir.glob("*.md"))
        zips = sorted(p.name for p in disc_dir.glob("*_bundle.zip"))
        bdirs = sorted(p.name for p in disc_dir.iterdir() if p.is_dir() and p.name.endswith("_bundle"))
        dup_dirs = [p.name for p in disc_dir.iterdir() if p.is_dir() and "(1)" in p.name]

        assert len(mds) == 19
        assert len(zips) == 19
        assert len(bdirs) == 19
        assert dup_dirs == []
        assert [m[:-3] for m in mds] == [z[:-11] for z in zips] == [b[:-7] for b in bdirs]

        archived_tier3_stems = [
            "uber_cors_arbitrary_origin_with_credentials_fpbi8c1t_ubereats_com",
            "uber_cors_arbitrary_origin_with_credentials_fpfcpn2u_ubereats_com",
            "gitlab_cloud_storage_takeover_assets_gitlab_com",
            "khealth_cloud_storage_takeover_cdn_khealth-test_com",
            "gitlab_graphql_introspection_gitlab_com",
            "shopify_graphql_introspection_media_myshopify_com",
            "expediagroup_bbp_graphql_introspection_www_hotwire_com",
        ]
        assert fp_archive_dir.is_dir()
        for stem in archived_tier3_stems:
            assert (fp_archive_dir / f"{stem}.md").is_file()
            assert (fp_archive_dir / f"{stem}_bundle.zip").is_file()
            assert (fp_archive_dir / f"{stem}_bundle").is_dir()
            assert not (disc_dir / f"{stem}.md").exists()
        assert (
            fp_archive_dir / "xiaomi_cors_arbitrary_origin_with_credentials_mijiayoupin_com_bundle (1)"
        ).is_dir()

    def test_staged_19_bundles_have_deterministic_ev_digests_sha256_and_pass_critic(self):
        disc_dir = self.REPO_ROOT / "data" / "disclosures"
        bdirs = sorted(p for p in disc_dir.iterdir() if p.is_dir() and p.name.endswith("_bundle"))
        assert len(bdirs) == 19

        for bdir in bdirs:
            stem = bdir.name[: -len("_bundle")]
            standalone_md = (disc_dir / f"{stem}.md").read_text(encoding="utf-8")
            h1_md = (bdir / "hackerone_report.md").read_text(encoding="utf-8")
            bc_md = (bdir / "bugcrowd_report.md").read_text(encoding="utf-8")
            tech_txt = (bdir / "technical_evidence.txt").read_text(encoding="utf-8")
            meta = json.loads((bdir / "metadata.json").read_text(encoding="utf-8"))
            manifest = json.loads((bdir / "manifest_sha256.json").read_text(encoding="utf-8"))

            assert standalone_md == h1_md
            ev_id = meta.get("evidence_artifact_id", "")
            assert re.match(r"^ev_[0-9a-f]{12}$", ev_id), f"Missing ev_ digest in {stem}/metadata.json"
            assert manifest.get("evidence_artifact_id") == ev_id

            raw_evidence = tech_txt.split("OBSERVED RAW EVIDENCE:\n", 1)[1].split(
                "\n\nREMEDIATION GUIDANCE:", 1
            )[0]
            expected_ev = compute_evidence_digest(
                target=meta["target_domain"],
                status_code=None,
                flaw_type=meta["flaw_type"],
                evidence_snippet=raw_evidence,
                provider=meta.get("provider") or "",
            )
            assert ev_id == expected_ev

            for content in (standalone_md, h1_md, bc_md, tech_txt):
                assert ev_id in content
                assert "evil.com" not in content.lower()
                assert "# Output: None" not in content

            if stem == "spotify_open_cloud_bucket_cdn_byspotify_com":
                assert meta["severity"] == "MEDIUM"
                assert meta["cvss_score"] == 5.3
                assert meta["bounty_viability"] == "HIGH_CONFIDENCE"
                assert "Podsights Seed - Interview Version.pdf" in standalone_md
                assert "advisor/advisor-onboarding-demo.mp4" in standalone_md
                ep = "/interviews/Podsights%20Seed%20-%20Interview%20Version.pdf"
            else:
                assert meta["flaw_type"] == "cors_arbitrary_origin_with_credentials"
                assert meta["severity"] == "MEDIUM"
                assert meta["cvss_score"] == 5.4
                assert meta["bounty_viability"] == "CONDITIONAL"
                assert "[PUBLIC_HTML_ONLY:" in standalone_md
                assert "Origin: https://untrusted-adversary.com" in standalone_md
                ep = "/"

            zip_path = disc_dir / f"{bdir.name}.zip"
            with zipfile.ZipFile(zip_path, "r") as zf:
                assert zf.testzip() is None
                for member, expected_sha in manifest["file_hashes_sha256"].items():
                    assert hashlib.sha256(zf.read(member)).hexdigest() == expected_sha
                    assert hashlib.sha256((bdir / member).read_bytes()).hexdigest() == expected_sha

            art = EmpiricalEvidenceArtifact(
                artifact_id=ev_id,
                target=meta["target_domain"],
                status_code=200,
                flaw_type=meta["flaw_type"],
                evidence_snippet=raw_evidence,
                provider=meta.get("provider") or "",
                endpoint_path=ep,
            )
            for txt in (standalone_md, bc_md):
                verdict = ReportCriticVerifier.verify_briefing_pitch(
                    pitch_text=txt,
                    target_domain=meta["target_domain"],
                    core_finding=meta["flaw_type"],
                    artifacts=[art],
                    require_artifact_grounding=True,
                )
                assert verdict.passed is True, f"{stem} failed ReportCriticVerifier: {verdict.reasons}"
                assert ev_id in verdict.verified_artifact_ids

    def test_all_45_bounty_programs_populate_excluded_vulnerabilities(self):
        catalog_path = self.REPO_ROOT / "data" / "bounty_programs.json"
        programs = json.loads(catalog_path.read_text(encoding="utf-8")).get("programs", [])
        assert len(programs) == 45
        expected_baseline = {
            "mail_spoofing",
            "missing_dmarc",
            "spf",
            "missing_hsts",
            "cors_wildcard_origin",
            "clickjacking",
            "rate_limiting",
        }
        for prog in programs:
            excl = set(prog.get("excluded_vulnerabilities", []))
            assert expected_baseline.issubset(excl), (
                f"Program {prog.get('program_id')} missing baseline exclusions: {expected_baseline - excl}"
            )


def _build_test_jwt(payload_obj: dict) -> str:
    import base64 as _b64

    def _enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return _b64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = _enc({"alg": "HS256", "typ": "JWT"})
    payload = _enc(payload_obj)
    return f"{header}.{payload}.SigPart1234567890"


class TestRound4JsSecretFilterAndProgramHygiene:
    """Round 4 TDD verification for JS secret FP filtering, dedup, out_of_scope, and staging host downgrades."""

    REPO_ROOT = Path(__file__).resolve().parent.parent

    def test_onetrust_and_non_auth_jwt_rejected_while_auth_jwt_kept(self):
        from orbit_security.bounty_active_prober import (
            classify_js_secret_fp_reason,
            filter_and_deduplicate_js_secrets,
        )

        onetrust_jwt = _build_test_jwt({
            "otJwtVersion": 1,
            "tenantId": "42dec10d-7eac-4f9f-af3b-e0072302f8ff",
            "sub": None,
            "iss": None,
            "description": "Collection point for use with Consent Hub",
            "authenticationRequired": False,
        })
        unauth_jwt = _build_test_jwt({
            "iss": "https://cdn.example.com",
            "authenticationRequired": False,
            "sub": "anon",
        })
        claimsless_jwt = _build_test_jwt({
            "iss": "https://config.example.com",
            "iat": 1700000000,
            "appVersion": "2.4.1",
        })
        auth_jwt = _build_test_jwt({
            "sub": "usr_admin_42",
            "email": "admin@example.com",
            "role": "admin",
            "scope": "org:write",
        })

        assert classify_js_secret_fp_reason(
            pattern_name="JSON Web Token (JWT)",
            matched_value=onetrust_jwt,
            script_url="https://atl-onetrust-wrapper.atlassian.com/assets/atl-onetrust-wrapper.min.js",
        ) is not None
        assert classify_js_secret_fp_reason(
            pattern_name="JSON Web Token (JWT)",
            matched_value=unauth_jwt,
        ) == "jwt_authentication_not_required"
        assert classify_js_secret_fp_reason(
            pattern_name="JSON Web Token (JWT)",
            matched_value=claimsless_jwt,
        ) == "jwt_missing_sensitive_auth_claims"
        assert classify_js_secret_fp_reason(
            pattern_name="JSON Web Token (JWT)",
            matched_value=auth_jwt,
            script_url="https://app.example.com/bundle.js",
        ) is None

        kept = filter_and_deduplicate_js_secrets([
            {
                "target": "https://atlassian.com",
                "script_url": "https://atl-onetrust-wrapper.atlassian.com/assets/atl-onetrust-wrapper.min.js",
                "pattern_name": "JSON Web Token (JWT)",
                "matched_value": onetrust_jwt,
                "context_snippet": "",
            },
            {
                "target": "https://app.example.com",
                "script_url": "https://app.example.com/bundle.js",
                "pattern_name": "JSON Web Token (JWT)",
                "matched_value": auth_jwt,
                "context_snippet": "",
            },
        ])
        assert len(kept) == 1
        assert kept[0]["matched_value"] == auth_jwt

    def test_public_publishable_client_tokens_rejected_while_real_secrets_kept(self):
        from orbit_security.bounty_active_prober import (
            BountyActiveProber,
            classify_js_secret_fp_reason,
        )

        stripe_pk = "".join(["pk_", "live_", "51AbCdEfGhIjKlMnOpQrStUvWx"])
        stripe_pk_test = "".join(["pk_", "test_", "51AbCdEfGhIjKlMnOpQrStUvWx"])
        stripe_sk = "".join(["sk_", "live_", "51AbcDefGhIjKlMnOpQrStUvWxYz1234"])
        sentry_dsn = "https://0123456789abcdef0123456789abcdef@o12345.ingest.sentry.io/67890"
        sentry_auth = "".join(["sntrys_", "eyJpYXQiOjE3MDAwMDAwMDB9"])
        firebase_key = "AIza" + ("A" * 35)
        gcp_key = "AIza" + ("B" * 35)
        mapbox_payload_jwt = _build_test_jwt({"u": "mapboxuser", "a": "pk"})
        mapbox_full = f"pk.{mapbox_payload_jwt}"
        mapbox_secret = f"sk.{_build_test_jwt({'sub': 'svc_tiles', 'scope': 'tiles:write'})}"

        assert classify_js_secret_fp_reason("Stripe Key", stripe_pk) == "stripe_publishable_key"
        assert classify_js_secret_fp_reason("Stripe Key", stripe_pk_test) == "stripe_publishable_key"
        assert classify_js_secret_fp_reason("Stripe Live Secret Key", stripe_sk) is None

        assert classify_js_secret_fp_reason("Sentry DSN", sentry_dsn) == "sentry_public_dsn"
        assert classify_js_secret_fp_reason("Sentry Auth Token", sentry_auth) is None

        assert classify_js_secret_fp_reason(
            "Google Cloud API Key",
            firebase_key,
            context_snippet=f'const firebaseConfig = {{ apiKey: "{firebase_key}", authDomain: "demo.firebaseapp.com" }};',
        ) == "firebase_public_web_config"
        assert classify_js_secret_fp_reason(
            "Google Cloud API Key",
            gcp_key,
            context_snippet=f'const mapsKey = "{gcp_key}";',
        ) is None

        assert classify_js_secret_fp_reason(
            "Algolia API Key",
            "search1234567890abcdef",
            context_snippet='const client = algoliasearch("APPID1", "search1234567890abcdef");',
        ) == "algolia_search_only_key"
        assert classify_js_secret_fp_reason(
            "Algolia Admin Key",
            "adminkey1234567890abcd",
            context_snippet='const adminApiKey = "adminkey1234567890abcd";',
        ) is None

        # Validate both full pk.eyJ token and SecretHarvester substring match preceded by pk.
        assert classify_js_secret_fp_reason("Mapbox Token", mapbox_full) == "mapbox_public_token"
        assert classify_js_secret_fp_reason("Secret", mapbox_secret) is None

        prober = BountyActiveProber()
        js_bundle = (
            f'mapboxgl.accessToken = "{mapbox_full}";\n'
            f'const stripe = Stripe("{stripe_sk}");\n'
            f'const fb = {{ apiKey: "{firebase_key}", authDomain: "demo.firebaseapp.com" }};\n'
        )
        findings = prober.scan_js_for_actionable_secrets(
            js_bundle,
            script_url="https://app.example.com/static/main.js",
            target="https://app.example.com",
        )
        matched_vals = [f["matched_value"] for f in findings]
        assert matched_vals == [stripe_sk]

    def test_harvest_target_secrets_filters_fps_and_deduplicates_by_script_url(self, tmp_path):
        from scripts.mine_js_secrets import harvest_target_secrets

        onetrust_jwt = _build_test_jwt({
            "otJwtVersion": 1,
            "description": "Collection point for use with Consent Hub",
            "authenticationRequired": False,
            "sub": None,
        })
        real_sk = "".join(["sk_", "live_", "99XyZaBcDeFgHiJkLmNoPqRsTuVwXyZ1"])
        shared_js = "https://cdn.example.com/shared-bundle.js"
        out_path = tmp_path / "js_leaked_secrets.json"

        # Seed existing staged file with a stale OneTrust duplicate
        out_path.write_text(
            json.dumps([
                {
                    "target": "https://legacy.example.com",
                    "script_url": "https://atl-onetrust-wrapper.atlassian.com/assets/atl-onetrust-wrapper.min.js",
                    "pattern_name": "JSON Web Token (JWT)",
                    "matched_value": onetrust_jwt,
                    "redacted_value": "eyJh...w5c",
                    "confidence": "Medium",
                    "context_snippet": "",
                }
            ]),
            encoding="utf-8",
        )

        class _FakeResp:
            def __init__(self, status_code: int, text: str):
                self.status_code = status_code
                self.text = text

        class _FakeSession:
            def __init__(self):
                self.headers = {}

            def get(self, url, timeout=8, verify=False):
                if url == shared_js:
                    return _FakeResp(
                        200,
                        f'const consent = "{onetrust_jwt}"; const k = "{real_sk}";',
                    )
                return _FakeResp(200, f'<html><script src="{shared_js}"></script></html>')

        with patch("scripts.mine_js_secrets.create_guarded_requests_session", return_value=_FakeSession()):
            merged = harvest_target_secrets(
                targets=["https://a.example.com", "https://b.example.com"],
                output_path=out_path,
            )

        assert len(merged) == 1
        assert merged[0]["script_url"] == shared_js
        assert merged[0]["matched_value"] == real_sk
        assert b"\r" not in out_path.read_bytes()

    def test_staged_js_leaked_secrets_json_has_no_onetrust_false_positives(self):
        from orbit_security.bounty_active_prober import classify_js_secret_fp_reason

        staged_path = self.REPO_ROOT / "data" / "hackerone_staging" / "js_leaked_secrets.json"
        findings = json.loads(staged_path.read_text(encoding="utf-8"))
        assert findings == []
        for item in findings:
            assert classify_js_secret_fp_reason(
                pattern_name=item.get("pattern_name", ""),
                matched_value=item.get("matched_value", ""),
                context_snippet=item.get("context_snippet", ""),
                script_url=item.get("script_url", ""),
            ) is None

    def test_all_45_bounty_programs_populate_non_empty_out_of_scope(self):
        catalog_path = self.REPO_ROOT / "data" / "bounty_programs.json"
        programs = json.loads(catalog_path.read_text(encoding="utf-8")).get("programs", [])
        assert len(programs) == 45
        by_id = {p["program_id"]: p for p in programs}

        # Preserve existing custom non-empty out_of_scope entries
        assert by_id["shopify"]["out_of_scope"] == ["community.shopify.com"]
        assert "everynoise.com" in by_id["spotify"]["out_of_scope"]
        assert "*.betfair.com.au" in by_id["flutteruki"]["out_of_scope"]

        for prog in programs:
            oos = prog.get("out_of_scope", [])
            assert isinstance(oos, list) and len(oos) > 0, (
                f"Program {prog.get('program_id')} has empty out_of_scope"
            )
        assert b"\r" not in catalog_path.read_bytes()

    def test_is_staging_or_test_hostname_classifier_and_sweep_downgrade(self):
        from orbit_security.bounty_radar import (
            BountyProgram,
            BountyTakeoverSweeper,
            is_staging_or_test_hostname,
        )

        for staging_host in (
            "lhstage.example.com",
            "realtime-test.example.com",
            "test-vendedores.mercadolibre.com",
            "api.stage.example.com",
            "checkout-stage.shopify.com",
            "billing-test.stripe.com",
            "staging.gitlab.com",
        ):
            assert is_staging_or_test_hostname(staging_host) is True, staging_host

        for prod_host in (
            "api.example.com",
            "stagecoach.com",
            "latest.example.com",
            "attest.corp.com",
            "backstage.spotify.com",
            "sub.test.com",
            "test.com",
        ):
            assert is_staging_or_test_hostname(prod_host) is False, prod_host

        sweeper = BountyTakeoverSweeper()
        wildcard_prog = BountyProgram(
            program_id="wildcorp",
            name="Wild Corp",
            platform="hackerone",
            in_scope=["*.wildcorp.com"],
        )
        explicit_prog = BountyProgram(
            program_id="explicitcorp",
            name="Explicit Corp",
            platform="hackerone",
            in_scope=["lhstage.explicitcorp.com", "*.explicitcorp.com"],
        )

        # Avoid real DNS/HTTP by mocking sub-probes inside sweep_program
        with patch.object(sweeper, "expand_wildcards", return_value=["lhstage.wildcorp.com", "api.wildcorp.com"]):
            with patch.object(sweeper, "check_subdomain_takeover", return_value=None):
                with patch.object(
                    sweeper,
                    "audit_graphql_introspection",
                    return_value={
                        "vulnerable": True,
                        "has_sensitive_schema": True,
                        "evidence": "GraphQL mutation + user schema exposed",
                    },
                ):
                    wild_vulns = sweeper.sweep_program(wildcard_prog, audit_graphql=True)

        wild_by_host = {v.target_domain: v for v in wild_vulns}
        assert wild_by_host["lhstage.wildcorp.com"].bounty_viability == "CONDITIONAL"
        assert "[STAGING_OR_TEST_HOST:" in wild_by_host["lhstage.wildcorp.com"].evidence
        assert wild_by_host["api.wildcorp.com"].bounty_viability == "HIGH_CONFIDENCE"

        with patch.object(sweeper, "expand_wildcards", return_value=["lhstage.explicitcorp.com"]):
            with patch.object(sweeper, "check_subdomain_takeover", return_value=None):
                with patch.object(
                    sweeper,
                    "audit_graphql_introspection",
                    return_value={
                        "vulnerable": True,
                        "has_sensitive_schema": True,
                        "evidence": "GraphQL mutation + user schema exposed",
                    },
                ):
                    explicit_vulns = sweeper.sweep_program(explicit_prog, audit_graphql=True)

        assert explicit_vulns[0].bounty_viability == "HIGH_CONFIDENCE"
