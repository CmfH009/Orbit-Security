"""Unit tests for the Pre-KYC Remediation Vault & Submission Readiness Compiler."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
import pytest

from orbit_security.egress_guard import EgressViolationError
from orbit_security.scanner import PublicHostOnlyRoE
import scripts.bounty_vault_generator as bounty_vault_generator
from scripts.bounty_vault_generator import (
    UNTRUSTED_POC_ORIGIN,
    build_vault_manifest,
    classify_finding_tier,
    compute_cvss_profile,
    consolidate_program_findings,
    render_remediation_dossier,
    verify_live_targets,
)
from scripts.triage_hackerone_staging import classify_disclosure, triage_disclosures

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_classify_finding_tier_separates_ready_from_auth_needed_and_noise():
    bucket_finding = {
        "program": "AlphaCorp",
        "host": "cdn.alpha-example.com",
        "url": "https://cdn.alpha-example.com/",
        "code": 200,
        "verdict": "OPEN_BUCKET_LISTING",
        "score": 6,
    }
    assert classify_finding_tier(bucket_finding) == "TIER_1_READY"

    cors_html_finding = {
        "program": "BetaCommerce",
        "host": "checkout.beta-example.com",
        "url": "https://checkout.beta-example.com/",
        "code": 200,
        "cors_origin": "https://example.org",
        "cors_credentials": "true",
        "reflected": True,
        "verdict": "REFLECTED_PUBLIC_HTML",
        "score": 5,
    }
    assert classify_finding_tier(cors_html_finding) == "TIER_2_NEEDS_AUTH_PROOF"

    low_score_noise = {
        "program": "ExampleCorp",
        "host": "static.example.com",
        "url": "https://static.example.com/",
        "code": 200,
        "verdict": "SAFE_OR_DEAD",
        "score": 1,
    }
    assert classify_finding_tier(low_score_noise) == "TIER_3_SUPPRESSED"


def test_consolidate_program_findings_groups_same_program_and_verdict():
    raw_items = [
        {
            "program": "BetaCommerce",
            "host": "checkout-co.beta-example.com",
            "url": "https://checkout-co.beta-example.com/",
            "code": 200,
            "verdict": "REFLECTED_PUBLIC_HTML",
            "score": 5,
        },
        {
            "program": "BetaCommerce",
            "host": "checkout-mx.beta-example.com",
            "url": "https://checkout-mx.beta-example.com/",
            "code": 200,
            "verdict": "REFLECTED_PUBLIC_HTML",
            "score": 5,
        },
        {
            "program": "AlphaCorp",
            "host": "cdn.alpha-example.com",
            "url": "https://cdn.alpha-example.com/",
            "code": 200,
            "verdict": "OPEN_BUCKET_LISTING",
            "score": 6,
        },
    ]

    grouped = consolidate_program_findings(raw_items)
    assert len(grouped) == 2

    alpha_group = next(g for g in grouped if g["program"] == "AlphaCorp")
    assert alpha_group["tier"] == "TIER_1_READY"
    assert alpha_group["hosts"] == ["cdn.alpha-example.com"]

    beta_group = next(g for g in grouped if g["program"] == "BetaCommerce")
    assert beta_group["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
    assert len(beta_group["hosts"]) == 2
    assert "checkout-co.beta-example.com" in beta_group["hosts"]
    assert "checkout-mx.beta-example.com" in beta_group["hosts"]


def test_compute_cvss_profile_returns_standard_cwe_and_vector():
    bucket_cvss = compute_cvss_profile("OPEN_BUCKET_LISTING")
    assert bucket_cvss["cwe"] == "CWE-200"
    assert bucket_cvss["base_score"] == 5.3
    assert "CVSS:3.1/" in bucket_cvss["vector"]

    cors_cvss = compute_cvss_profile("REFLECTED_PUBLIC_HTML")
    assert cors_cvss["cwe"] == "CWE-942"
    assert cors_cvss["base_score"] >= 5.0


def test_render_remediation_dossier_contains_remediation_and_cwe():
    group = {
        "program": "AlphaCorp",
        "verdict": "OPEN_BUCKET_LISTING",
        "tier": "TIER_1_READY",
        "max_score": 6,
        "hosts": ["cdn.alpha-example.com"],
        "urls": ["https://cdn.alpha-example.com/"],
        "notes": ["S3/GCS bucket directory listing open."],
    }
    md = render_remediation_dossier(group)
    assert "# Remediation Dossier: AlphaCorp" in md
    assert "CWE-200" in md
    assert "cdn.alpha-example.com" in md
    assert "## Defensive Remediation Steps" in md


def test_build_vault_manifest_writes_queue_and_summary(tmp_path: Path):
    matrix_path = tmp_path / "live_verification_matrix.json"
    matrix_path.write_text(
        json.dumps(
            [
                {
                    "program": "AlphaCorp",
                    "host": "cdn.alpha-example.com",
                    "url": "https://cdn.alpha-example.com/",
                    "code": 200,
                    "verdict": "OPEN_BUCKET_LISTING",
                    "score": 6,
                    "notes": "Open storage listing",
                },
                {
                    "program": "BetaCommerce",
                    "host": "checkout.beta-example.com",
                    "url": "https://checkout.beta-example.com/",
                    "code": 200,
                    "verdict": "REFLECTED_PUBLIC_HTML",
                    "score": 5,
                    "cors_credentials": "true",
                    "reflected": True,
                    "notes": "CORS header reflection",
                },
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "vault_out"
    manifest = build_vault_manifest(matrix_path=matrix_path, output_dir=out_dir)

    assert manifest["tier_1_count"] == 1
    assert manifest["tier_2_count"] == 1
    assert (out_dir / "VAULT_LAUNCH_QUEUE.json").exists()
    assert (out_dir / "VAULT_READINESS_REPORT.md").exists()


def test_vault_synchronizes_19_ev_bundles_into_5_dossiers_with_zero_tier3(tmp_path: Path):
    disc_dir = REPO_ROOT / "data" / "disclosures"
    archive_fp_dir = REPO_ROOT / "data" / "archive" / "false_positive_disclosures"
    out_dir = tmp_path / "vault_out"

    manifest = build_vault_manifest(
        output_dir=out_dir,
        disclosures_dir=disc_dir,
        archive_fp_dir=archive_fp_dir,
    )

    assert manifest["source"] == "data/disclosures"
    assert manifest["verification_mode"] == "offline_static"
    assert manifest["total_raw_candidates"] == 19
    assert manifest["staged_bundle_count"] == 19
    assert manifest["evidence_digest_count"] == 19
    assert manifest["consolidated_dossiers"] == 5
    assert manifest["tier_1_count"] == 1
    assert manifest["tier_1_bundle_count"] == 1
    assert manifest["tier_2_count"] == 4
    assert manifest["tier_2_bundle_count"] == 18
    assert manifest["suppressed_count"] == 0
    assert manifest["tier3_false_positives_in_vault"] == 0
    assert manifest["archived_false_positives_count"] == 7

    by_prog = {g["program"]: g for g in manifest["launch_queue"]}
    assert list(by_prog.keys()) == ["Spotify", "MercadoLibre", "Xiaomi", "Superbet", "Playtika"]

    spotify = by_prog["Spotify"]
    assert spotify["tier"] == "TIER_1_READY"
    assert spotify["bounty_viability"] == "HIGH_CONFIDENCE"
    assert spotify["hosts"] == ["cdn.byspotify.com"]
    assert spotify["evidence_digests"] == ["ev_0bc4c77bfc5f"]
    assert spotify["evidence_keys"] == [
        "interviews/Podsights Seed - Interview Version.pdf",
        "interviews/AP Q4-2020 Podcast Adv. Rept_4Ww1Disc.Mtg.pdf",
        "reports/benchmarks/test-q3-podsights-conversion-report.pdf",
        "advisor/advisor-onboarding-demo.mp4",
    ]

    expected_tier2_counts = {"MercadoLibre": 9, "Xiaomi": 6, "Superbet": 2, "Playtika": 1}
    for prog_name, expected_n in expected_tier2_counts.items():
        grp = by_prog[prog_name]
        assert grp["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
        assert grp["bounty_viability"] == "CONDITIONAL"
        assert len(grp["hosts"]) == expected_n
        assert len(grp["evidence_digests"]) == expected_n
        assert all(re.match(r"^ev_[0-9a-f]{12}$", d) for d in grp["evidence_digests"])

    # Verify zero archived Tier-3 false positives or legacy evil.com strings leak anywhere
    all_written_text = [
        (out_dir / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8"),
        (out_dir / "VAULT_READINESS_REPORT.md").read_text(encoding="utf-8"),
    ]
    dossiers = sorted((out_dir / "consolidated_dossiers").glob("*.md"))
    assert len(dossiers) == 5
    for dossier_path in dossiers:
        all_written_text.append(dossier_path.read_text(encoding="utf-8"))

    joined = "\n".join(all_written_text)
    assert "evil.com" not in joined.lower()
    for forbidden in ("ubereats.com", "gitlab.com", "khealth-test.com", "myshopify.com", "hotwire.com"):
        assert forbidden not in joined

    for grp in manifest["launch_queue"]:
        slug = (
            f"{re.sub(r'[^a-z0-9_]+', '_', grp['program'].lower()).strip('_')}_"
            f"{re.sub(r'[^a-z0-9_]+', '_', grp['verdict'].lower()).strip('_')}.md"
        )
        dossier_md = (out_dir / "consolidated_dossiers" / slug).read_text(encoding="utf-8")
        for digest in grp["evidence_digests"]:
            assert digest in dossier_md
    for key in spotify["evidence_keys"]:
        assert key in (out_dir / "consolidated_dossiers" / "spotify_open_bucket_listing.md").read_text(
            encoding="utf-8"
        )

    # Verify checked-in staging vault matches the 19-bundle / 5-dossier compilation
    live_queue = json.loads(
        (REPO_ROOT / "data" / "hackerone_staging" / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8")
    )
    assert live_queue["staged_bundle_count"] == 19
    assert live_queue["evidence_digest_count"] == 19
    assert live_queue["consolidated_dossiers"] == 5
    assert live_queue["tier3_false_positives_in_vault"] == 0


def _write_synthetic_bundle(
    base_dir: Path,
    stem: str,
    *,
    program_id: str,
    program_name: str,
    domain: str,
    flaw_type: str,
    viability: str,
    ev_id: str,
    raw_evidence: str,
) -> None:
    bdir = base_dir / f"{stem}_bundle"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "metadata.json").write_text(
        json.dumps(
            {
                "program_id": program_id,
                "program_name": program_name,
                "platform": "hackerone",
                "target_domain": domain,
                "flaw_type": flaw_type,
                "bounty_viability": viability,
                "evidence_artifact_id": ev_id,
            }
        ),
        encoding="utf-8",
    )
    (bdir / "technical_evidence.txt").write_text(
        f"TARGET DOMAIN: {domain}\nEVIDENCE ARTIFACT ID: {ev_id}\n\n"
        f"OBSERVED RAW EVIDENCE:\n{raw_evidence}\n\nREMEDIATION GUIDANCE:\n1. Fix.\n",
        encoding="utf-8",
    )
    (base_dir / f"{stem}.md").write_text(
        f"# Report on {domain}\n**Evidence Artifact ID:** `{ev_id}`\n",
        encoding="utf-8",
    )


def test_ev_digest_propagation_and_tier3_archive_exclusion(tmp_path: Path):
    disc_dir = tmp_path / "disclosures"
    archive_dir = tmp_path / "archive_fp"
    disc_dir.mkdir()
    archive_dir.mkdir()

    _write_synthetic_bundle(
        disc_dir,
        "alpha_open_cloud_bucket_cdn_alpha_example_com",
        program_id="alpha",
        program_name="Alpha",
        domain="cdn.alpha-example.com",
        flaw_type="open_cloud_bucket",
        viability="HIGH_CONFIDENCE",
        ev_id="ev_112233445566",
        raw_evidence="Open bucket listing (1) docs/internal.pdf (1 MB).",
    )
    _write_synthetic_bundle(
        disc_dir,
        "beta_cors_arbitrary_origin_with_credentials_api_beta_example_com",
        program_id="beta",
        program_name="Beta",
        domain="api.beta-example.com",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_aabbccddeeff",
        raw_evidence="Reflected https://untrusted-adversary.com [PUBLIC_HTML_ONLY]",
    )
    # Tier-3 bundle referenced in archive_dir must be strictly excluded
    fp_stem = "gamma_cors_fp_noise_example_com"
    _write_synthetic_bundle(
        disc_dir,
        fp_stem,
        program_id="gamma",
        program_name="Gamma",
        domain="noise.example.com",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_999999999999",
        raw_evidence="Empty body probe",
    )
    (archive_dir / f"{fp_stem}.md").write_text("archived", encoding="utf-8")

    manifest = build_vault_manifest(
        output_dir=tmp_path / "out",
        disclosures_dir=disc_dir,
        archive_fp_dir=archive_dir,
    )
    assert manifest["staged_bundle_count"] == 2
    assert manifest["evidence_digest_count"] == 2
    assert manifest["archived_false_positives_count"] == 1
    assert [g["program"] for g in manifest["launch_queue"]] == ["Alpha", "Beta"]

    # Missing or malformed ev_ digest fails closed
    _write_synthetic_bundle(
        disc_dir,
        "broken_missing_ev",
        program_id="broken",
        program_name="Broken",
        domain="broken.example.com",
        flaw_type="open_cloud_bucket",
        viability="HIGH_CONFIDENCE",
        ev_id="invalid_digest",
        raw_evidence="No valid digest",
    )
    with pytest.raises(ValueError, match="Malformed|Missing or malformed"):
        build_vault_manifest(
            output_dir=tmp_path / "out_fail",
            disclosures_dir=disc_dir,
            archive_fp_dir=archive_dir,
        )


def test_verify_live_cli_uses_guarded_httpx_client_and_default_is_offline(tmp_path: Path, monkeypatch):
    disc_dir = tmp_path / "disclosures"
    archive_dir = tmp_path / "archive_fp"
    disc_dir.mkdir()
    archive_dir.mkdir()

    _write_synthetic_bundle(
        disc_dir,
        "spotify_open_cloud_bucket_cdn_byspotify_com",
        program_id="spotify",
        program_name="Spotify",
        domain="cdn.byspotify.com",
        flaw_type="open_cloud_bucket",
        viability="HIGH_CONFIDENCE",
        ev_id="ev_0bc4c77bfc5f",
        raw_evidence="Open bucket (1) interviews/Podsights Seed - Interview Version.pdf (2.1 MB).",
    )
    _write_synthetic_bundle(
        disc_dir,
        "playtika_cors_arbitrary_origin_with_credentials_slotomania_com",
        program_id="playtika",
        program_name="Playtika",
        domain="slotomania.com",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_1bb2538c79aa",
        raw_evidence="Reflected Origin 'https://untrusted-adversary.com' [PUBLIC_HTML_ONLY]",
    )
    _write_synthetic_bundle(
        disc_dir,
        "blocked_cors_arbitrary_origin_with_credentials_localhost",
        program_id="BlockedLocal",
        program_name="BlockedLocal",
        domain="127.0.0.1",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_abcdef012345",
        raw_evidence="Localhost blocked test",
    )

    # 1. Default invocation without --verify-live must remain 100% offline/static
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("create_guarded_httpx_client must NOT be called without --verify-live")

    monkeypatch.setattr(bounty_vault_generator, "create_guarded_httpx_client", _fail_if_called)
    offline_out = tmp_path / "offline_out"
    rc_off = bounty_vault_generator.main(
        ["--disclosures-dir", str(disc_dir), "--out", str(offline_out)]
    )
    assert rc_off == 0
    offline_json = json.loads((offline_out / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8"))
    assert offline_json["verification_mode"] == "offline_static"
    assert "live_verification" not in offline_json

    # 2. With --verify-live, verify PublicHostOnlyRoE-guarded httpx client usage
    seen_roe_types = []
    seen_requests = []

    class _MockGuardedClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None):
            seen_requests.append((url, dict(headers or {})))
            if "127.0.0.1" in url:
                raise EgressViolationError("ROE_BOGON_BLOCKED", url, "Loopback blocked by RoE")
            if "cdn.byspotify.com" in url:
                return SimpleNamespace(
                    status_code=200,
                    headers={"Content-Type": "application/xml"},
                    text="<ListBucketResult><Name>cdn</Name></ListBucketResult>",
                )
            return SimpleNamespace(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": UNTRUSTED_POC_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                },
                text="<html></html>",
            )

    def _mock_factory(*, roe_engine, timeout=10.0, **kwargs):
        seen_roe_types.append(type(roe_engine))
        return _MockGuardedClient()

    monkeypatch.setattr(bounty_vault_generator, "create_guarded_httpx_client", _mock_factory)
    live_out = tmp_path / "live_out"
    rc_live = bounty_vault_generator.main(
        ["--disclosures-dir", str(disc_dir), "--out", str(live_out), "--verify-live"]
    )
    assert rc_live == 0
    assert seen_roe_types == [PublicHostOnlyRoE]
    assert len(seen_requests) == 3

    cors_headers = dict(seen_requests[1][1])
    assert cors_headers.get("Origin") == UNTRUSTED_POC_ORIGIN

    live_json = json.loads((live_out / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8"))
    assert live_json["verification_mode"] == "live_verified"
    lv = live_json["live_verification"]
    assert lv["targets_checked"] == 3
    assert lv["confirmed_live_count"] == 2
    assert lv["roe_blocked_count"] == 1
    assert lv["error_count"] == 0

    report_md = (live_out / "VAULT_READINESS_REPORT.md").read_text(encoding="utf-8")
    assert "Live Pre-Submission Verification Summary" in report_md
    spotify_md = (live_out / "consolidated_dossiers" / "spotify_open_bucket_listing.md").read_text(
        encoding="utf-8"
    )
    assert "CONFIRMED_LIVE" in spotify_md


def test_triage_hackerone_staging_handles_spotify_cwe200_and_conditional_cors():
    spotify_md = REPO_ROOT / "data" / "disclosures" / "spotify_open_cloud_bucket_cdn_byspotify_com.md"
    spotify_meta = json.loads(
        (
            REPO_ROOT
            / "data"
            / "disclosures"
            / "spotify_open_cloud_bucket_cdn_byspotify_com_bundle"
            / "metadata.json"
        ).read_text(encoding="utf-8")
    )
    bucket, reason = classify_disclosure(spotify_md, metadata=spotify_meta)
    assert bucket == "ready"
    assert "ev_0bc4c77bfc5f" in reason

    summary = triage_disclosures(data_dir=REPO_ROOT / "data", dry_run=True)
    assert summary["total_disclosures"] == 19
    assert len(summary["ready"]) == 1
    assert len(summary["verify"]) == 18
    assert len(summary["archive"]) == 0


def test_verify_live_real_guarded_client_blocks_loopback_without_network():
    """Real egress_guard hook blocks loopback targets before any socket connection."""
    loopback_group = [
        {
            "program": "LoopbackGuardTest",
            "verdict": "REFLECTED_PUBLIC_HTML",
            "tier": "TIER_2_NEEDS_AUTH_PROOF",
            "hosts": ["127.0.0.1"],
            "urls": ["http://127.0.0.1/"],
            "bundles": [
                {
                    "host": "127.0.0.1",
                    "url": "http://127.0.0.1/",
                    "evidence_artifact_id": "ev_000000000000",
                }
            ],
        }
    ]
    live_summary = verify_live_targets(loopback_group, timeout=1.0)
    assert live_summary["targets_checked"] == 1
    assert live_summary["confirmed_live_count"] == 0
    assert live_summary["roe_blocked_count"] == 1
    assert live_summary["results"][0]["status"] == "ROE_BLOCKED"

