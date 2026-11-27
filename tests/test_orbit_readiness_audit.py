"""Tests for scripts/orbit_readiness_audit.py (Option C Track A & Track B ground-truth audit)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
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
    assert report["track_a_disclosures_ready"] is False
    assert report["track_b_offline_ready"] is True
    assert report["track_b_live_checkout_ready"] is False
    assert report["kyc_payout_status"] == "PENDING_PHYSICAL_ID"
    assert "STRIPE_KEYS_UNCONFIGURED" in report["blockers"]
    assert report["clients_hygiene"]["hygiene_clean"] is True
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

    report = mod.run_readiness_audit(repo_root=tmp_path)
    assert report["technical_floor_clean"] is False
    assert "CLIENT_REGISTRY_SYNTHETIC_LEAKS" in report["blockers"]


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
    assert captured["track_a_disclosures_ready"] is False
    assert captured["track_b_offline_ready"] is True
    assert captured["track_b_live_checkout_ready"] is True
    assert captured["blockers"] == []


def test_verify_stripe_cutover_hermetic_and_redacts_secrets(tmp_path, monkeypatch, capsys):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)

    secret_marker_sk = "sk_live_FAKE_DO_NOT_LEAK_999999"
    secret_marker_wh = "whsec_FAKE_DO_NOT_LEAK_888888"
    monkeypatch.setenv("STRIPE_SECRET_KEY", secret_marker_sk)
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", secret_marker_wh)
    monkeypatch.setenv("ORBIT_KYC_STATUS", "VERIFIED")

    rc_json = mod.main(["--repo-root", str(tmp_path), "--verify-cutover", "--json"])
    assert rc_json == 0
    raw_json_out = capsys.readouterr().out
    assert "FAKE_DO_NOT_LEAK" not in raw_json_out
    assert os.environ.get("STRIPE_SECRET_KEY") == secret_marker_sk
    assert os.environ.get("STRIPE_WEBHOOK_SECRET") == secret_marker_wh

    payload = json.loads(raw_json_out)
    assert payload["technical_floor_clean"] is True
    assert payload["blockers"] == []
    cutover = payload["stripe_cutover_dry_run"]
    assert cutover["ok"] is True
    assert cutover["duration_ms"] < 5000.0
    assert cutover["stripe_key_mode"] == "live"
    assert cutover["env_key_prefixes"] == {
        "STRIPE_SECRET_KEY": "sk_live_*",
        "STRIPE_API_KEY": "unset",
        "STRIPE_WEBHOOK_SECRET": "whsec_*",
    }
    assert cutover["checkout_session_fields_verified"] is True
    assert cutover["webhook_status"] == "PROVISIONED"
    assert cutover["subscriber_provisioned"] is True
    assert cutover["sla_pdf_valid"] is True
    assert cutover["bundle_zip_sha256_valid"] is True
    assert cutover["portal_html_generated"] is True
    assert cutover["isolated_paths_verified"] is True
    assert cutover["live_data_untouched"] is True

    rc_human = mod.main(["--repo-root", str(tmp_path), "--verify-cutover"])
    assert rc_human == 0
    human_out = capsys.readouterr().out
    assert "FAKE_DO_NOT_LEAK" not in human_out
    assert "Stripe Cutover Dry-Run" in human_out
    assert "ok=True" in human_out
    assert "secret=sk_live_*" in human_out
    assert "webhook=whsec_*" in human_out
    assert "live_untouched=True" in human_out


def test_verify_stripe_cutover_leaves_live_track_b_paths_untouched():
    mod = _load_audit_module()
    repo_root = mod.REPO_ROOT

    def _snapshot_tree(root: Path):
        if not root.exists():
            return {}
        return {
            str(p.relative_to(repo_root)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(root.rglob("*"))
            if p.is_file()
        }

    def _read_max_event_id(db_path: Path) -> int:
        if not db_path.exists():
            return 0
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
            ).fetchone()
            if row is None:
                return 0
            max_row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            return int(max_row[0] or 0) if max_row else 0
        finally:
            conn.close()

    def _read_new_non_hook_events(db_path: Path, after_id: int):
        if not db_path.exists():
            return []
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
            ).fetchone()
            if row is None:
                return []
            rows = conn.execute(
                "SELECT id, event_type, topic, source, payload FROM events WHERE id > ? ORDER BY id ASC",
                (after_id,),
            ).fetchall()
            return [
                {
                    "id": r[0],
                    "event_type": r[1],
                    "topic": r[2],
                    "source": r[3],
                    "payload": r[4],
                }
                for r in rows
                if str(r[3] or "") != "orbit_hook"
                or ("cutover" in str(r[4] or "").lower() and str(r[3] or "") != "orbit_hook")
            ]
        finally:
            conn.close()

    tracked_files = [
        repo_root / "data" / "subscribers.json",
        repo_root / "data" / "clients.json",
        repo_root / "data" / "agency_retainers.json",
    ]
    events_db = repo_root / "data" / "orbit_events.db"
    before_max_event_id = _read_max_event_id(events_db)
    before_files = {
        str(p.relative_to(repo_root)): (p.stat().st_size, p.stat().st_mtime_ns) if p.exists() else None
        for p in tracked_files
    }
    before_trees = {
        "certificates": _snapshot_tree(repo_root / "data" / "certificates"),
        "client_bundles": _snapshot_tree(repo_root / "data" / "client_bundles"),
        "docs_portals": _snapshot_tree(repo_root / "docs" / "portals"),
        "landing_portals": _snapshot_tree(repo_root / "landing" / "portals"),
    }

    res = mod.verify_stripe_cutover()
    assert res["ok"] is True
    assert res["live_data_untouched"] is True

    after_files = {
        str(p.relative_to(repo_root)): (p.stat().st_size, p.stat().st_mtime_ns) if p.exists() else None
        for p in tracked_files
    }
    after_trees = {
        "certificates": _snapshot_tree(repo_root / "data" / "certificates"),
        "client_bundles": _snapshot_tree(repo_root / "data" / "client_bundles"),
        "docs_portals": _snapshot_tree(repo_root / "docs" / "portals"),
        "landing_portals": _snapshot_tree(repo_root / "landing" / "portals"),
    }

    assert after_files == before_files
    assert after_trees == before_trees
    assert _read_new_non_hook_events(events_db, before_max_event_id) == []
    for artifact_dir in (repo_root / "data", repo_root / "docs", repo_root / "landing"):
        if artifact_dir.exists():
            assert not list(artifact_dir.rglob("*cutover-dryrun*"))


def test_readiness_audit_dotenv_fallback_clears_stripe_blocker_hermetically(tmp_path, monkeypatch):
    mod = _load_audit_module()
    _seed_clean_repo(tmp_path, mod)

    for key in (
        "STRIPE_SECRET_KEY",
        "STRIPE_API_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_STARTER",
        "STRIPE_PRICE_SCALE",
        "STRIPE_PRICE_ENTERPRISE",
        "ORBIT_KYC_STATUS",
    ):
        monkeypatch.delenv(key, raising=False)

    without_dotenv = mod.run_readiness_audit(repo_root=tmp_path)
    assert without_dotenv["stripe_config"]["live_checkout_ready"] is False
    assert "STRIPE_KEYS_UNCONFIGURED" in without_dotenv["blockers"]

    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "# synthetic local .env",
                'STRIPE_API_KEY="rk_live_DOTENV_SECRET_DO_NOT_LEAK"',
                "STRIPE_PRICE_STARTER=price_starter_dotenv",
                "STRIPE_PRICE_SCALE=price_scale_dotenv # inline comment",
                "STRIPE_PRICE_ENTERPRISE=price_enterprise_dotenv",
                "STRIPE_WEBHOOK_SECRET='whsec_DOTENV_SECRET_DO_NOT_LEAK'",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with_dotenv = mod.run_readiness_audit(repo_root=tmp_path, verify_cutover=True)
    assert "STRIPE_API_KEY" not in os.environ
    assert "STRIPE_WEBHOOK_SECRET" not in os.environ
    assert with_dotenv["stripe_config"]["api_key_configured"] is True
    assert with_dotenv["stripe_config"]["webhook_secret_configured"] is True
    assert with_dotenv["stripe_config"]["live_checkout_ready"] is True
    assert all(with_dotenv["stripe_config"]["price_overrides_configured"].values())
    assert "STRIPE_KEYS_UNCONFIGURED" not in with_dotenv["blockers"]
    assert with_dotenv["blockers"] == []
    assert with_dotenv["track_b_live_checkout_ready"] is True

    cutover = with_dotenv["stripe_cutover_dry_run"]
    assert cutover["ok"] is True
    assert cutover["stripe_key_mode"] == "live"
    assert cutover["env_key_prefixes"] == {
        "STRIPE_SECRET_KEY": "unset",
        "STRIPE_API_KEY": "rk_live_*",
        "STRIPE_WEBHOOK_SECRET": "whsec_*",
    }
    rendered = mod._render_human_report(with_dotenv)
    assert "DOTENV_SECRET_DO_NOT_LEAK" not in json.dumps(with_dotenv)
    assert "DOTENV_SECRET_DO_NOT_LEAK" not in rendered
    assert "api=rk_live_*" in rendered
    assert "webhook=whsec_*" in rendered

    monkeypatch.setenv("ORBIT_KYC_STATUS", "VERIFIED")
    verified_report = mod.run_readiness_audit(repo_root=tmp_path)
    assert verified_report["blockers"] == []
    assert verified_report["track_b_live_checkout_ready"] is True
