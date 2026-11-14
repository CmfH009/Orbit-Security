"""Tests for scripts/orbit_readiness_audit.py (Option C Track A & Track B ground-truth audit)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "orbit_readiness_audit.py"


def _load_audit_module():
    spec = importlib.util.spec_from_file_location("orbit_readiness_audit", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_disclosure_pair(
    disc_dir: Path,
    stem: str,
    md_body: str = "# PoC\n\nEvidence Digest: ev_a1b2c3d4e5f6\n",
    meta_digest: str | None = "ev_a1b2c3d4e5f6",
) -> Path:
    (disc_dir / f"{stem}.md").write_text(md_body, encoding="utf-8")
    zip_path = disc_dir / f"{stem}_bundle.zip"
    report_bytes = md_body.encode("utf-8")
    manifest = {
        "version": "1.0",
        "bundle_name": f"{stem}_bundle",
        "file_hashes_sha256": {
            "hackerone_report.md": hashlib.sha256(report_bytes).hexdigest(),
        },
    }
    if meta_digest is not None:
        bundle_dir = disc_dir / f"{stem}_bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        meta_obj = {"bundle_name": f"{stem}_bundle", "evidence_digest": meta_digest}
        (bundle_dir / "metadata.json").write_text(json.dumps(meta_obj), encoding="utf-8")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("hackerone_report.md", report_bytes)
        zf.writestr("manifest_sha256.json", json.dumps(manifest))
    return zip_path


def _seed_clean_repo(repo_root: Path, mod) -> None:
    for rel in mod.TRACK_B_REQUIRED_SCRIPTS:
        p = repo_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('"""stub script"""\n', encoding="utf-8")

    for rel in mod.TRACK_B_REQUIRED_MODULES:
        p = repo_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('"""stub module"""\n', encoding="utf-8")

    for tree in ("landing", "docs"):
        for rel in mod.TRACK_B_REQUIRED_WEB_PAGES:
            p = repo_root / tree / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if rel == "signup.html":
                p.write_text('<form action="/create-checkout-session" method="POST"></form>', encoding="utf-8")
            else:
                p.write_text(f"<h1>Orbit {rel}</h1>", encoding="utf-8")
        portal_path = repo_root / tree / "portals" / "eastside-co.html"
        portal_path.parent.mkdir(parents=True, exist_ok=True)
        portal_path.write_text("<h1>Eastside Portal</h1>", encoding="utf-8")

    data_dir = repo_root / "data"
    (data_dir / "disclosures").mkdir(parents=True, exist_ok=True)
    (data_dir / "archive" / "legacy_passive_disclosures").mkdir(parents=True, exist_ok=True)
    (data_dir / "subscribers.json").write_text('{"subscribers": []}', encoding="utf-8")
    (data_dir / "clients.json").write_text(
        json.dumps({"clients": [{"client_id": "client-velvetcraft-com", "apex_domain": "velvetcraft.com"}]}),
        encoding="utf-8",
    )
    (data_dir / "agency_retainers.json").write_text(
        json.dumps({"agencies": [{"agency_id": "eastside-co", "agency_name": "Eastside Co"}]}),
        encoding="utf-8",
    )
    programs = [{"program_id": f"prog_{i}", "bounty_tier": "cash"} for i in range(45)]
    (data_dir / "bounty_programs.json").write_text(json.dumps({"programs": programs}), encoding="utf-8")
    _write_disclosure_pair(data_dir / "disclosures", "uber_subdomain_takeover_dev_uber_com")
    (data_dir / "bounty_radar_state.json").write_text(
        json.dumps({"total_sweeps": 1, "total_submittable_findings": 1, "total_advisory_observations": 0}),
        encoding="utf-8",
    )


def test_readiness_audit_reports_clean_floor_and_pending_id(tmp_path, monkeypatch):
    mod = _load_audit_module()
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("ORBIT_KYC_STATUS", "PENDING_PHYSICAL_ID")

    _seed_clean_repo(tmp_path, mod)

    report = mod.run_readiness_audit(repo_root=tmp_path)
    assert report["technical_floor_clean"] is True
    assert report["track_a_disclosures_ready"] is True
    assert report["track_b_offline_ready"] is True
    assert report["track_b_live_checkout_ready"] is False
    assert report["kyc_payout_status"] == "PENDING_PHYSICAL_ID"
    assert "KYC_PAYOUT_PENDING_PHYSICAL_ID" in report["blockers"]
    assert "STRIPE_KEYS_UNCONFIGURED" in report["blockers"]
    assert report["clients_hygiene"]["hygiene_clean"] is True
    assert report["disclosures_and_radar"]["active_submittable_reports"] == 1
    assert report["disclosures_and_radar"]["paired_bundle_count"] == 1
    assert report["disclosures_and_radar"]["bundle_pairing_ok"] is True
    assert report["disclosures_and_radar"]["ev_digest_coverage"]["coverage_ok"] is True
    assert report["disclosures_and_radar"]["ev_digest_coverage"]["covered_count"] == 1
    assert report["disclosures_and_radar"]["advisory_lingering_reports"] == 0
    assert report["track_b_funnel"]["ready"] is True


def test_readiness_audit_flags_synthetic_leaks_and_advisory_reports(tmp_path):
    mod = _load_audit_module()
    (tmp_path / "landing").mkdir()
    (tmp_path / "docs").mkdir()
    data_dir = tmp_path / "data"
    (data_dir / "disclosures").mkdir(parents=True)
    (data_dir / "clients.json").write_text(
        json.dumps({"clients": [{"client_id": "c1", "apex_domain": "t.com"}]}),
        encoding="utf-8",
    )
    (data_dir / "bounty_programs.json").write_text(json.dumps({"programs": []}), encoding="utf-8")
    (data_dir / "disclosures" / "acme_mail_spoofing_mail_acme_com.md").write_text("# DMARC", encoding="utf-8")

    report = mod.run_readiness_audit(repo_root=tmp_path)
    assert report["technical_floor_clean"] is False
    assert "CLIENT_REGISTRY_SYNTHETIC_LEAKS" in report["blockers"]
    assert "UNARCHIVED_ADVISORY_DISCLOSURES" in report["blockers"]
    assert "BOUNTY_CATALOG_INTEGRITY" in report["blockers"]


def test_readiness_audit_flags_disclosure_bundle_parity_mismatch(tmp_path, monkeypatch):
    mod = _load_audit_module()
    monkeypatch.setenv("ORBIT_KYC_STATUS", "PENDING_PHYSICAL_ID")
    _seed_clean_repo(tmp_path, mod)
    disc_dir = tmp_path / "data" / "disclosures"

    # Case 1: Missing _bundle.zip for an extra .md report
    (disc_dir / "gitlab_graphql_introspection_gitlab_com.md").write_text("# GraphQL", encoding="utf-8")
    report_missing = mod.run_readiness_audit(repo_root=tmp_path)
    assert report_missing["technical_floor_clean"] is False
    assert report_missing["disclosures_and_radar"]["bundle_pairing_ok"] is False
    assert report_missing["disclosures_and_radar"]["missing_bundle_zips"] == [
        "gitlab_graphql_introspection_gitlab_com.md"
    ]
    assert "DISCLOSURE_BUNDLE_PARITY_MISMATCH" in report_missing["blockers"]

    # Case 2: Orphan _bundle.zip with no .md
    (disc_dir / "gitlab_graphql_introspection_gitlab_com.md").unlink()
    with zipfile.ZipFile(disc_dir / "orphan_finding_bundle.zip", "w") as zf:
        zf.writestr("manifest_sha256.json", "{}")
    report_orphan = mod.run_readiness_audit(repo_root=tmp_path)
    assert report_orphan["disclosures_and_radar"]["orphan_bundle_zips"] == ["orphan_finding_bundle.zip"]
    assert report_orphan["disclosures_and_radar"]["bundle_pairing_ok"] is False
    assert "DISCLOSURE_BUNDLE_PARITY_MISMATCH" in report_orphan["blockers"]
    (disc_dir / "orphan_finding_bundle.zip").unlink()

    # Case 3: Corrupt/tampered SHA-256 manifest in _bundle.zip
    bad_zip = disc_dir / "uber_subdomain_takeover_dev_uber_com_bundle.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("hackerone_report.md", b"tampered")
        zf.writestr(
            "manifest_sha256.json",
            json.dumps({"file_hashes_sha256": {"hackerone_report.md": "0" * 64}}),
        )
    report_corrupt = mod.run_readiness_audit(repo_root=tmp_path)
    assert report_corrupt["disclosures_and_radar"]["corrupt_bundle_zips"] == [bad_zip.name]
    assert report_corrupt["disclosures_and_radar"]["bundle_pairing_ok"] is False
    assert "DISCLOSURE_BUNDLE_PARITY_MISMATCH" in report_corrupt["blockers"]


def test_readiness_audit_boundary_aware_flaw_classification(tmp_path):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)
    disc_dir = tmp_path / "data" / "disclosures"

    # Domain contains 'spf' substring inside 'spfhub', but flaw is submittable subdomain_takeover
    _write_disclosure_pair(disc_dir, "uber_subdomain_takeover_app_spfhub_com")
    report_ok = mod.run_readiness_audit(repo_root=tmp_path)
    assert report_ok["disclosures_and_radar"]["advisory_lingering_reports"] == 0
    assert report_ok["disclosures_and_radar"]["active_submittable_reports"] == 2
    assert report_ok["disclosures_and_radar"]["unclassified_disclosures"] == []

    # Unclassified .md report should be caught explicitly rather than assumed submittable
    _write_disclosure_pair(disc_dir, "custom_unknown_vector_example_com")
    report_unclassified = mod.run_readiness_audit(repo_root=tmp_path)
    assert report_unclassified["disclosures_and_radar"]["unclassified_disclosures"] == [
        "custom_unknown_vector_example_com.md"
    ]
    assert "UNCLASSIFIED_DISCLOSURES" in report_unclassified["blockers"]
    assert report_unclassified["technical_floor_clean"] is False


def test_readiness_audit_flags_track_b_funnel_gaps(tmp_path):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)

    # Remove required checkout script, retainer portal, and break signup checkout form hook
    (tmp_path / "scripts" / "run_stripe_checkout.py").unlink()
    (tmp_path / "docs" / "portals" / "eastside-co.html").unlink()
    (tmp_path / "landing" / "signup.html").write_text("<h1>No checkout form</h1>", encoding="utf-8")
    (tmp_path / "src" / "orbit_security" / "stripe_webhook.py").write_text("def broken(:\n", encoding="utf-8")

    report = mod.run_readiness_audit(repo_root=tmp_path)
    tb = report["track_b_funnel"]
    assert tb["ready"] is False
    assert "scripts/run_stripe_checkout.py" in tb["missing_scripts"]
    assert "docs/portals/eastside-co.html" in tb["missing_agency_portals"]
    assert tb["checkout_form_hook_present"] is False
    assert any("stripe_webhook.py" in err for err in tb["syntax_errors"])
    assert "TRACK_B_FUNNEL_INCOMPLETE" in report["blockers"]
    assert report["track_b_offline_ready"] is False
    assert report["technical_floor_clean"] is False


def test_readiness_audit_cli_json_and_verified_gate(tmp_path, monkeypatch, capsys):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_stub")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_stub")
    monkeypatch.setenv("ORBIT_KYC_STATUS", "VERIFIED")

    rc = mod.main(["--repo-root", str(tmp_path), "--json"])
    assert rc == 0
    captured = json.loads(capsys.readouterr().out)
    assert captured["technical_floor_clean"] is True
    assert captured["track_a_disclosures_ready"] is True
    assert captured["track_b_offline_ready"] is True
    assert captured["track_b_live_checkout_ready"] is True
    assert captured["blockers"] == []


def test_readiness_audit_flags_missing_ev_digest_in_md_and_metadata(tmp_path):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)
    disc_dir = tmp_path / "data" / "disclosures"

    # Replace clean fixture with a report missing ev_ digest in .md (even if metadata has it)
    _write_disclosure_pair(
        disc_dir,
        "uber_subdomain_takeover_dev_uber_com",
        md_body="# PoC without digest\n",
        meta_digest="ev_a1b2c3d4e5f6",
    )
    report_missing_md = mod.run_readiness_audit(repo_root=tmp_path)
    ev_md = report_missing_md["disclosures_and_radar"]["ev_digest_coverage"]
    assert ev_md["coverage_ok"] is False
    assert ev_md["covered_count"] == 0
    assert ev_md["missing_ev_digests"] == ["uber_subdomain_takeover_dev_uber_com.md"]
    assert "MISSING_EV_DIGESTS" in report_missing_md["blockers"]
    assert report_missing_md["technical_floor_clean"] is False
    assert report_missing_md["track_a_disclosures_ready"] is False

    # Valid .md digest, but metadata.json lacks ev_ digest
    _write_disclosure_pair(
        disc_dir,
        "uber_subdomain_takeover_dev_uber_com",
        md_body="# PoC\n\nEvidence Digest: ev_1234567890ab\n",
        meta_digest="",
    )
    report_missing_meta = mod.run_readiness_audit(repo_root=tmp_path)
    ev_meta = report_missing_meta["disclosures_and_radar"]["ev_digest_coverage"]
    assert ev_meta["coverage_ok"] is False
    assert ev_meta["md_covered_count"] == 1
    assert ev_meta["metadata_checked_count"] == 1
    assert ev_meta["metadata_covered_count"] == 0
    assert "MISSING_EV_DIGESTS" in report_missing_meta["blockers"]


def test_readiness_audit_counts_false_positive_archive_alongside_legacy(tmp_path):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)

    legacy_dir = tmp_path / "data" / "archive" / "legacy_passive_disclosures"
    for i in range(3):
        (legacy_dir / f"legacy_{i}.md").write_text("# Legacy\n", encoding="utf-8")

    fp_dir = tmp_path / "data" / "archive" / "false_positive_disclosures"
    fp_dir.mkdir(parents=True, exist_ok=True)
    for stem in ("uber_cors_fp1", "gitlab_graphql_fp2"):
        (fp_dir / f"{stem}.md").write_text("# False positive\n", encoding="utf-8")
        (fp_dir / f"{stem}_bundle.zip").write_bytes(b"zip")
        (fp_dir / f"{stem}_bundle").mkdir()
    (fp_dir / "duplicate_bundle (1)").mkdir()

    report = mod.run_readiness_audit(repo_root=tmp_path)
    disc = report["disclosures_and_radar"]
    assert disc["archived_legacy_artifacts"] == 3
    assert disc["archived_false_positive_disclosures"] == 2
    assert disc["archived_false_positive_items"] == 7
    assert disc["archived_total_count"] == 5

    rendered = mod._render_human_report(report)
    assert "2 false_positive_disclosures + 3 legacy_passive_disclosures" in rendered
