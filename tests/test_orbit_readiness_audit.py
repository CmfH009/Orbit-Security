"""Tests for scripts/orbit_readiness_audit.py (Step 4 ground-truth audit)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "orbit_readiness_audit.py"


def _load_audit_module():
    spec = importlib.util.spec_from_file_location("orbit_readiness_audit", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_readiness_audit_reports_clean_floor_and_pending_id(tmp_path, monkeypatch):
    mod = _load_audit_module()
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("ORBIT_KYC_STATUS", "PENDING_PHYSICAL_ID")

    (tmp_path / "landing").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "landing" / "index.html").write_text("<h1>Orbit</h1>", encoding="utf-8")
    (tmp_path / "docs" / "index.html").write_text("<h1>Orbit</h1>", encoding="utf-8")

    data_dir = tmp_path / "data"
    (data_dir / "disclosures").mkdir(parents=True)
    (data_dir / "archive" / "legacy_passive_disclosures").mkdir(parents=True)
    (data_dir / "subscribers.json").write_text('{"subscribers": []}', encoding="utf-8")
    (data_dir / "clients.json").write_text(
        json.dumps({"clients": [{"client_id": "client-velvetcraft-com", "apex_domain": "velvetcraft.com"}]}),
        encoding="utf-8",
    )
    programs = [{"program_id": f"prog_{i}", "bounty_tier": "cash"} for i in range(45)]
    (data_dir / "bounty_programs.json").write_text(json.dumps({"programs": programs}), encoding="utf-8")
    (data_dir / "disclosures" / "uber_subdomain_takeover_dev_uber_com.md").write_text("# PoC", encoding="utf-8")
    (data_dir / "bounty_radar_state.json").write_text(
        json.dumps({"total_sweeps": 1, "total_submittable_findings": 1, "total_advisory_observations": 0}),
        encoding="utf-8",
    )

    report = mod.run_readiness_audit(repo_root=tmp_path)
    assert report["technical_floor_clean"] is True
    assert report["kyc_payout_status"] == "PENDING_PHYSICAL_ID"
    assert "KYC_PAYOUT_PENDING_PHYSICAL_ID" in report["blockers"]
    assert "STRIPE_KEYS_UNCONFIGURED" in report["blockers"]
    assert report["clients_hygiene"]["hygiene_clean"] is True
    assert report["disclosures_and_radar"]["active_submittable_reports"] == 1
    assert report["disclosures_and_radar"]["advisory_lingering_reports"] == 0


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
