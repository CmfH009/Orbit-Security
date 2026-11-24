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

    conditional_bucket_finding = {
        "program": "GammaHotel",
        "host": "portal.wifi.gamma-example.com",
        "url": "https://portal.wifi.gamma-example.com/",
        "code": 200,
        "verdict": "OPEN_BUCKET_LISTING",
        "bounty_viability": "CONDITIONAL",
        "score": 5,
    }
    assert classify_finding_tier(conditional_bucket_finding) == "TIER_2_NEEDS_AUTH_PROOF"

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


def test_vault_synchronizes_ev_bundles_into_dossiers_with_zero_tier3(tmp_path: Path):
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
    assert manifest["total_raw_candidates"] >= 19
    assert manifest["staged_bundle_count"] == manifest["total_raw_candidates"]
    assert manifest["evidence_digest_count"] == manifest["total_raw_candidates"]
    assert manifest["consolidated_dossiers"] >= 5
    assert manifest["tier_1_count"] >= 1
    assert manifest["tier_2_count"] >= 4
    assert manifest["tier_2_bundle_count"] >= 18
    assert manifest["suppressed_count"] == 0
    assert manifest["tier3_false_positives_in_vault"] == 0
    assert manifest["archived_false_positives_count"] >= 15

    by_prog = {(g["program"], g["verdict"]): g for g in manifest["launch_queue"]}
    prog_names = {g["program"] for g in manifest["launch_queue"]}
    assert {"Starbucks", "Spotify", "MercadoLibre", "Xiaomi", "Superbet", "Playtika"}.issubset(prog_names)

    spotify = by_prog[("Spotify", "OPEN_BUCKET_LISTING")]
    assert spotify["tier"] == "TIER_1_READY"
    assert spotify["bounty_viability"] == "HIGH_CONFIDENCE"
    assert "cdn.byspotify.com" in spotify["hosts"]
    assert len(spotify["evidence_digests"]) == len(spotify["hosts"])
    assert all(re.match(r"^ev_[0-9a-f]{12}$", d) for d in spotify["evidence_digests"])

    # Hyatt open bucket has no offline sensitive key proofs and must stay downgraded to Tier 2
    hyatt = by_prog[("Hyatt Hotels", "OPEN_BUCKET_LISTING")]
    assert hyatt["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
    assert hyatt["bounty_viability"] == "CONDITIONAL"
    assert hyatt["hosts"] == ["portal.wifi.hyatt.com"]

    # Ensure archived CloudFront, PKI, and static/CDN/telemetry FPs are absent from the vault
    expected_tier2_counts = {"MercadoLibre": 9, "Xiaomi": 6, "Superbet": 2, "Playtika": 1}
    for prog_name, expected_n in expected_tier2_counts.items():
        grp = by_prog[(prog_name, "REFLECTED_PUBLIC_HTML")]
        assert grp["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
        assert grp["bounty_viability"] == "CONDITIONAL"
        assert len(grp["hosts"]) >= expected_n
        assert len(grp["evidence_digests"]) == len(grp["hosts"])
        assert all(re.match(r"^ev_[0-9a-f]{12}$", d) for d in grp["evidence_digests"])

    # Verify zero archived Tier-3 false positives or legacy evil.com strings leak anywhere
    all_written_text = [
        (out_dir / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8"),
        (out_dir / "VAULT_READINESS_REPORT.md").read_text(encoding="utf-8"),
    ]
    dossiers = sorted((out_dir / "consolidated_dossiers").glob("*.md"))
    assert len(dossiers) == manifest["consolidated_dossiers"]
    for dossier_path in dossiers:
        all_written_text.append(dossier_path.read_text(encoding="utf-8"))

    joined = "\n".join(all_written_text)
    assert "evil.com" not in joined.lower()
    for forbidden in (
        "ubereats.com",
        "gitlab.com",
        "khealth-test.com",
        "myshopify.com",
        "hotwire.com",
        "www.cdn.amazon.ca",
        "cdn4.epicgames.com",
        "i.nintendo.net",
        "helm.elastic.co",
        "crl.pki.uberinternal.com",
        "prod-pki-cloud.uberinternal.com",
        "prod-pki-cloud-staging.uberinternal.com",
        "assets.yelp.com",
        "media.yelp.com",
        "static.yelp.com",
        "static1.yelp.com",
        "images.mercadolibre.com.co",
        "files.trello.com",
        "files.stripe.com",
        "fp.coinbase.com",
        "fpbi8c1t.uber.com",
        "fpfcpn2u.uber.com",
        "tracking.ibi.uber.com",
        "analytics.query.yahoo.com",
    ):
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

    # Verify checked-in staging vault matches the latest staging compilation
    live_queue_path = REPO_ROOT / "data" / "hackerone_staging" / "VAULT_LAUNCH_QUEUE.json"
    if live_queue_path.exists():
        live_queue = json.loads(live_queue_path.read_text(encoding="utf-8"))
        assert live_queue["staged_bundle_count"] >= 19
        assert live_queue["evidence_digest_count"] == live_queue["staged_bundle_count"]
        assert live_queue["consolidated_dossiers"] >= 5
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


def test_triage_hackerone_staging_handles_spotify_cwe200_and_conditional_cors(tmp_path: Path):
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
    assert spotify_meta["evidence_artifact_id"] in reason

    disc_dir = tmp_path / "data" / "disclosures"
    disc_dir.mkdir(parents=True)

    # 1. Ready: Verified open cloud bucket (even if CWE-200 is mentioned)
    ready_md = disc_dir / "spotify_open_cloud_bucket_cdn_byspotify_com.md"
    ready_md.write_text(spotify_md.read_text(encoding="utf-8"), encoding="utf-8")
    ready_bundle = disc_dir / "spotify_open_cloud_bucket_cdn_byspotify_com_bundle"
    ready_bundle.mkdir()
    (ready_bundle / "metadata.json").write_text(json.dumps(spotify_meta), encoding="utf-8")

    # 2. Verify: Conditional CORS reflection on public HTML
    verify_md = disc_dir / "example_cors_conditional.md"
    verify_md.write_text(
        "# Cors Arbitrary Origin With Credentials\nCWE-942 [PUBLIC_HTML_ONLY]\n",
        encoding="utf-8",
    )
    verify_bundle = disc_dir / "example_cors_conditional_bundle"
    verify_bundle.mkdir()
    (verify_bundle / "metadata.json").write_text(
        json.dumps({"flaw_type": "cors_arbitrary_origin_with_credentials", "bounty_viability": "CONDITIONAL"}),
        encoding="utf-8",
    )

    # 3. Archive: Informational CWE-200 without exploit proof
    archive_md = disc_dir / "example_info_cwe200.md"
    archive_md.write_text("# Informational Observation\nCWE-200\n", encoding="utf-8")

    summary = triage_disclosures(data_dir=tmp_path / "data", dry_run=True)
    assert summary["total_disclosures"] == 3
    assert len(summary["ready"]) == 1
    assert len(summary["verify"]) == 1
    assert len(summary["archive"]) == 1


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


def test_verify_live_authenticated_cors_poc_replay_local_http_server(tmp_path: Path, monkeypatch):
    """End-to-end offline test of --verify-live authenticated session-cookie CORS PoC replay."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    import httpx

    received_requests = []

    class _CorsTestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            cookie = self.headers.get("Cookie", "")
            received_requests.append((self.path, origin, cookie))
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            if "session=valid_tok" in cookie:
                payload = json.dumps({"user_id": 42, "email": "alice@example.com", "csrf": "tok123"}).encode()
                self.send_header("Content-Type", "application/json")
            else:
                payload = b"<html><body>Public landing page</body></html>"
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _CorsTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Point create_guarded_httpx_client at a real httpx.Client for the local test server
        monkeypatch.setattr(
            bounty_vault_generator,
            "create_guarded_httpx_client",
            lambda *, roe_engine, timeout=10.0, **kwargs: httpx.Client(timeout=timeout),
        )

        cookies_file = tmp_path / "auth_cookies.json"
        cookies_file.write_text(json.dumps({"beta": "session=valid_tok"}), encoding="utf-8")

        groups = [
            {
                "program": "BetaCommerce",
                "program_id": "beta",
                "verdict": "REFLECTED_PUBLIC_HTML",
                "tier": "TIER_2_NEEDS_AUTH_PROOF",
                "hosts": ["api.beta-example.com"],
                "urls": [f"http://127.0.0.1:{port}/api/me"],
                "bundles": [
                    {
                        "bundle_stem": "beta_cors",
                        "host": "api.beta-example.com",
                        "url": f"http://127.0.0.1:{port}/api/me",
                        "evidence_artifact_id": "ev_aabbccddeeff",
                    }
                ],
            },
            {
                "program": "GammaPortal",
                "program_id": "gamma",
                "verdict": "REFLECTED_PUBLIC_HTML",
                "tier": "TIER_2_NEEDS_AUTH_PROOF",
                "hosts": ["www.gamma-example.com"],
                "urls": [f"http://127.0.0.1:{port}/public"],
                "bundles": [
                    {
                        "bundle_stem": "gamma_cors",
                        "host": "www.gamma-example.com",
                        "url": f"http://127.0.0.1:{port}/public",
                        "evidence_artifact_id": "ev_112233445566",
                    }
                ],
            },
        ]

        live_summary = verify_live_targets(groups, timeout=5.0, auth_cookies=cookies_file)
        assert live_summary["targets_checked"] == 2
        assert live_summary["confirmed_live_count"] == 2
        poc_sum = live_summary["cors_poc_summary"]
        assert poc_sum["cors_bundles_checked"] == 2
        assert poc_sum["cors_reflected_count"] == 2
        assert poc_sum["authenticated_replays_count"] == 1
        assert poc_sum["exploitable_auth_cors_count"] == 1

        beta_res = next(r for r in live_summary["results"] if r["program"] == "BetaCommerce")
        assert beta_res["cors_poc_replay"]["auth_mode"] == "authenticated_cookie_replay"
        assert beta_res["cors_poc_replay"]["exploitable_auth_cors"] is True
        assert "email" in beta_res["cors_poc_replay"]["sensitive_indicators"]
        assert "user_id" in beta_res["cors_poc_replay"]["sensitive_indicators"]
        # Ensure raw cookie secret is never leaked into evidence output
        assert "valid_tok" not in json.dumps(live_summary)

        gamma_res = next(r for r in live_summary["results"] if r["program"] == "GammaPortal")
        assert gamma_res["cors_poc_replay"]["auth_mode"] == "unauthenticated_baseline"
        assert gamma_res["cors_poc_replay"]["exploitable_auth_cors"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_triage_classifies_subdomain_takeover_and_prunes_stale_tier_files(tmp_path: Path):
    data_dir = tmp_path / "data"
    disc_dir = data_dir / "disclosures"
    staging_dir = data_dir / "hackerone_staging"
    disc_dir.mkdir(parents=True)

    # Seed a stale file in 03_out_of_scope_archive to verify cleanup on re-triage
    stale_archive = staging_dir / "03_out_of_scope_archive"
    stale_archive.mkdir(parents=True)
    stale_md = stale_archive / "starbucks_subdomain_takeover_trace_dev_starbucks_com.md"
    stale_md.write_text("stale", encoding="utf-8")

    _write_synthetic_bundle(
        disc_dir,
        "starbucks_subdomain_takeover_trace_dev_starbucks_com",
        program_id="starbucks",
        program_name="Starbucks",
        domain="trace-dev.starbucks.com",
        flaw_type="subdomain_takeover",
        viability="HIGH_CONFIDENCE",
        ev_id="ev_387efa7fba69",
        raw_evidence="Dangling CNAME confirmed.",
    )
    _write_synthetic_bundle(
        disc_dir,
        "acme_subdomain_takeover_dev_acme_com",
        program_id="acme",
        program_name="Acme",
        domain="dev.acme.com",
        flaw_type="subdomain_takeover",
        viability="CONDITIONAL",
        ev_id="ev_1234567890ab",
        raw_evidence="Needs CNAME check.",
    )

    bucket_ready, _ = classify_disclosure(
        disc_dir / "starbucks_subdomain_takeover_trace_dev_starbucks_com.md",
        metadata={"flaw_type": "subdomain_takeover", "bounty_viability": "HIGH_CONFIDENCE", "evidence_artifact_id": "ev_387efa7fba69"},
    )
    bucket_verify, _ = classify_disclosure(
        disc_dir / "acme_subdomain_takeover_dev_acme_com.md",
        metadata={"flaw_type": "subdomain_takeover", "bounty_viability": "CONDITIONAL", "evidence_artifact_id": "ev_1234567890ab"},
    )
    assert bucket_ready == "ready"
    assert bucket_verify == "verify"

    summary = triage_disclosures(data_dir=data_dir, dry_run=False)
    assert len(summary["ready"]) == 1
    assert len(summary["verify"]) == 1
    assert not stale_md.exists()
    assert (staging_dir / "01_ready_for_submission" / "starbucks_subdomain_takeover_trace_dev_starbucks_com.md").is_file()
    assert (staging_dir / "02_needs_session_verification" / "acme_subdomain_takeover_dev_acme_com.md").is_file()


def test_verify_live_targets_dangling_takeover_uses_dns_not_cors(monkeypatch):
    groups = [
        {
            "program": "TakeoverTest",
            "verdict": "DANGLING_TAKEOVER_VERIFIED",
            "tier": "TIER_1_READY",
            "hosts": ["dangling.example.com", "mitigated.example.com", "127.0.0.1"],
            "urls": ["https://dangling.example.com/", "https://mitigated.example.com/", "http://127.0.0.1/"],
            "bundles": [
                {"host": "dangling.example.com", "url": "https://dangling.example.com/", "evidence_artifact_id": "ev_111111111111"},
                {"host": "mitigated.example.com", "url": "https://mitigated.example.com/", "evidence_artifact_id": "ev_222222222222"},
                {"host": "127.0.0.1", "url": "http://127.0.0.1/", "evidence_artifact_id": "ev_333333333333"},
            ],
        }
    ]

    class _NoHttpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None):
            raise AssertionError(f"HTTP GET should not be called for {url}")

    monkeypatch.setattr(bounty_vault_generator, "create_guarded_httpx_client", lambda **kw: _NoHttpClient())
    monkeypatch.setattr(
        bounty_vault_generator,
        "_resolve_live_cname",
        lambda host, timeout=10.0: "orphan.trafficmanager.net" if host == "dangling.example.com" else None,
    )
    monkeypatch.setattr(
        bounty_vault_generator,
        "_cname_target_is_nxdomain",
        lambda cname, timeout=10.0: cname == "orphan.trafficmanager.net",
    )

    summary = verify_live_targets(groups, timeout=5.0)
    assert summary["targets_checked"] == 3
    assert summary["confirmed_live_count"] == 1
    assert summary["roe_blocked_count"] == 1
    assert summary["cors_poc_summary"]["cors_bundles_checked"] == 0

    by_host = {r["host"]: r for r in summary["results"]}
    assert by_host["dangling.example.com"]["status"] == "CONFIRMED_LIVE"
    assert by_host["dangling.example.com"]["verified_live"] is True
    assert "cors_poc_replay" not in by_host["dangling.example.com"]

    assert by_host["mitigated.example.com"]["status"] == "CHANGED_OR_MITIGATED"
    assert by_host["mitigated.example.com"]["verified_live"] is False
    assert "cors_poc_replay" not in by_host["mitigated.example.com"]

    assert by_host["127.0.0.1"]["status"] == "ROE_BLOCKED"
    assert by_host["127.0.0.1"]["verified_live"] is False


def test_verify_live_program_filter_per_host_headers_and_endpoints(tmp_path: Path, monkeypatch):
    seen_requests = []

    class _MockClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None):
            seen_requests.append((url, dict(headers or {})))
            return SimpleNamespace(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": UNTRUSTED_POC_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                    "Content-Type": "application/json",
                },
                text='{"user_id": 7, "email": "qa@example.com"}',
            )

    monkeypatch.setattr(bounty_vault_generator, "create_guarded_httpx_client", lambda **kw: _MockClient())

    groups = [
        {
            "program": "Alpha",
            "program_id": "alpha",
            "verdict": "REFLECTED_PUBLIC_HTML",
            "tier": "TIER_2_NEEDS_AUTH_PROOF",
            "hosts": ["api.alpha-example.com"],
            "urls": ["https://api.alpha-example.com/"],
            "bundles": [
                {"host": "api.alpha-example.com", "url": "https://api.alpha-example.com/", "evidence_artifact_id": "ev_111111111111"}
            ],
        },
        {
            "program": "Beta",
            "program_id": "beta",
            "verdict": "REFLECTED_PUBLIC_HTML",
            "tier": "TIER_2_NEEDS_AUTH_PROOF",
            "hosts": ["api.beta-example.com"],
            "urls": ["https://api.beta-example.com/"],
            "bundles": [
                {"host": "api.beta-example.com", "url": "https://api.beta-example.com/", "evidence_artifact_id": "ev_222222222222"}
            ],
        },
    ]

    # 1. program_filter=["alpha"] probes only alpha, rewrites endpoint, and attaches researcher header
    summary = verify_live_targets(
        groups,
        auth_header={"api.alpha-example.com": "Bearer secret_alpha"},
        endpoints={"api.alpha-example.com": "/api/me"},
        researcher_header="X-Bug-Bounty: HackerOne-tester",
        program_filter=["alpha"],
    )
    assert summary["targets_checked"] == 1
    assert summary["program_filter"] == ["alpha"]
    assert len(seen_requests) == 1
    req_url, req_headers = seen_requests[0]
    assert req_url == "https://api.alpha-example.com/api/me"
    assert req_headers["Authorization"] == "Bearer secret_alpha"
    assert req_headers["X-Bug-Bounty"] == "HackerOne-tester"
    assert "secret_alpha" not in json.dumps(summary)

    # 2. Without program_filter, beta never receives alpha's host-scoped Authorization header
    seen_requests.clear()
    summary_all = verify_live_targets(
        groups,
        auth_header={"api.alpha-example.com": "Bearer secret_alpha"},
    )
    assert summary_all["targets_checked"] == 2
    beta_req = next(h for u, h in seen_requests if "beta-example.com" in u)
    assert "Authorization" not in beta_req

    # 3. Cross-host endpoint override and CR/LF researcher header fail closed
    with pytest.raises(ValueError, match="Cross-host"):
        verify_live_targets(groups, endpoints={"api.alpha-example.com": "https://evil.other.com/steal"})
    with pytest.raises(ValueError, match="CR/LF"):
        verify_live_targets(groups, researcher_header="X-Bug-Bounty: bad\r\nInjected: 1")


def test_auth_config_and_write_auth_template(tmp_path: Path, monkeypatch):
    disc_dir = tmp_path / "disclosures"
    disc_dir.mkdir()
    _write_synthetic_bundle(
        disc_dir,
        "playtika_cors_arbitrary_origin_with_credentials_slotomania_com",
        program_id="playtika",
        program_name="Playtika",
        domain="slotomania.com",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_e09a813dc2f2",
        raw_evidence="Reflected Origin [PUBLIC_HTML_ONLY]",
    )
    _write_synthetic_bundle(
        disc_dir,
        "alpha_cors_arbitrary_origin_with_credentials_api_alpha_com",
        program_id="alpha",
        program_name="Alpha",
        domain="api.alpha.com",
        flaw_type="cors_arbitrary_origin_with_credentials",
        viability="CONDITIONAL",
        ev_id="ev_aabbccddeeff",
        raw_evidence="Reflected Origin [PUBLIC_HTML_ONLY]",
    )

    out_dir = tmp_path / "staging"
    rc_tpl = bounty_vault_generator.main(
        ["--disclosures-dir", str(disc_dir), "--out", str(out_dir), "--write-auth-template"]
    )
    assert rc_tpl == 0
    tpl_path = out_dir / "auth_verify.template.json"
    assert tpl_path.is_file()
    tpl = json.loads(tpl_path.read_text(encoding="utf-8"))
    assert tpl["auth_cookies"] == {"api.alpha.com": "", "slotomania.com": ""}
    assert tpl["auth_headers"] == {"api.alpha.com": "", "slotomania.com": ""}
    assert tpl["endpoints"] == {"api.alpha.com": "/", "slotomania.com": "/"}
    assert tpl["researcher_header"] == ""

    seen = []

    class _MockClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None):
            seen.append((url, dict(headers or {})))
            return SimpleNamespace(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": UNTRUSTED_POC_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                    "Content-Type": "application/json",
                },
                text='{"email": "test@example.com"}',
            )

    monkeypatch.setattr(bounty_vault_generator, "create_guarded_httpx_client", lambda **kw: _MockClient())
    cfg_path = out_dir / "auth_verify.local.json"
    cfg_path.write_text(
        json.dumps(
            {
                "researcher_header": "X-Bug-Bounty: HackerOne-user",
                "auth_cookies": {"slotomania.com": "sid=supersecret_cookie"},
                "auth_headers": {},
                "endpoints": {"slotomania.com": "/api/profile"},
            }
        ),
        encoding="utf-8",
    )

    rc_live = bounty_vault_generator.main(
        [
            "--disclosures-dir",
            str(disc_dir),
            "--out",
            str(out_dir),
            "--verify-live",
            "--program",
            "playtika",
            "--auth-config",
            str(cfg_path),
        ]
    )
    assert rc_live == 0
    assert len(seen) == 1
    assert seen[0][0] == "https://slotomania.com/api/profile"
    assert seen[0][1]["Cookie"] == "sid=supersecret_cookie"
    assert seen[0][1]["X-Bug-Bounty"] == "HackerOne-user"

    queue_text = (out_dir / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8")
    assert "supersecret_cookie" not in queue_text
    queue = json.loads(queue_text)
    assert len(queue["launch_queue"]) == 2
    assert queue["live_verification"]["targets_checked"] == 1
    assert queue["live_verification"]["cors_poc_summary"]["exploitable_auth_cors_count"] == 1



