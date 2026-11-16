"""Tests for master briefing Section 1-4 parsing, HyperDB + CognitiveMatrix wiring, and nova_email_daemon hardening."""

import base64
import datetime
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

HYPERNOTE_ROOT = Path("A:/projects/hypernote") if Path("A:/projects/hypernote").exists() else Path(r"C:\AgyHut\projects\hypernote")
SYSTEM_ROOT = Path("A:/system") if Path("A:/system").exists() else Path(r"C:\AgyHut\system")
SYSTEM_SCRIPTS = SYSTEM_ROOT / "scripts"
for p in (HYPERNOTE_ROOT, SYSTEM_ROOT, SYSTEM_SCRIPTS):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))


def _make_substack_redirect(target_url: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"e": target_url}).encode("utf-8")).decode("ascii").rstrip("=")
    return f"https://substack.com/redirect/2/{payload}"


def test_master_briefing_parses_sections_past_line_200_and_8_bullets():
    from scripts.daily_briefing import _render_master_briefing_block
    from scripts.unified_morning_cockpit import _extract_master_briefing_delta

    sub_url = _make_substack_redirect("https://github.com/baidu/Unlimited-OCR?utm_source=substack")
    google_url = "https://www.google.com/url?q=https%3A%2F%2Fhuggingface.co%2FMemTensor%2FMemT-1.0-Nano%26utm_campaign%3Dbriefing&sa=D"
    arxiv_url = "https://www.google.com/url?q=https%3A%2F%2Farxiv.org%2Fabs%2F2611.13946"

    filler = "\n".join(f"- Historical item filler line #{i}" for i in range(1, 215))
    body = (
        "COMBINED DAILY MASTER BRIEFING — NOVEMBER 14, 2026\n"
        "SECTION 1: 24h Personal Delta & Account Alerts\n"
        "- 2 Google AI Studio projects hit monthly spend cap and paused\n"
        "- Freebuff account suspended for 3rd-party proxy access\n"
        f"{filler}\n"
        "SECTION 2: AI News & Ecosystem Releases\n"
        "- EmbeddingGemma 2 (~310 MB multimodal embedder on Ollama)\n"
        "- llama.cpp v1.0.0 strict C ABI & OCP-FP8 KV-cache\n"
        f"- Unlimited-OCR constant KV cache ({sub_url})\n"
        "- OpenRouter Fusion 8-model :free router\n"
        "SECTION 3: Technical YouTube Digest (AI Search)\n"
        f"- AI Search: MemT-1.0-Nano memory-native LLM ({google_url})\n"
        f"- TreeAgent continual memory paper ({arxiv_url})\n"
        "- Edge0-145B skipped (requires CUDA 13 and 16 GiB VRAM)\n"
        "SECTION 4: 30-Day Deprecations & Upcoming Deadlines\n"
        "- Nov 17: Google Opal closes — export custom prompts from My Drive > Opal\n"
        "- Jan 14, 2027: GPT-4o and GPT-4.1 retirements on OpenRouter\n"
    )
    msg = SimpleNamespace(
        id="mb-long",
        subject="Combined Daily Master Briefing — November 14, 2026: 24h Delta, AI News, YouTube & Deprecations",
        date=datetime.datetime(2026, 11, 14, 11, 0, tzinfo=datetime.timezone.utc),
        body_text=body,
    )

    res = _extract_master_briefing_delta([msg])
    assert res["found"] is True
    sections = res["sections"]
    assert any("monthly spend cap" in x for x in sections["personal_delta"])
    assert any("Unlimited-OCR" in x for x in sections["ai_news"])
    assert any("llama.cpp v1.0.0" in x for x in sections["ai_news"])
    assert any("MemT-1.0-Nano" in x for x in sections["youtube_digest"])
    assert any("Edge0-145B" in x for x in sections["youtube_digest"])
    assert any("Nov 17" in x and "Opal" in x for x in sections["deprecations"])
    assert any("Jan 14, 2027" in x for x in sections["deprecations"])
    assert len(res["extracted_urls"]) >= 3

    rendered = _render_master_briefing_block(res)
    assert "AI News & Releases" in rendered
    assert "Technical YouTube Digest" in rendered
    assert "30-Day Deprecations & Deadlines" in rendered
    assert "Unlimited-OCR" in rendered
    assert "Google Opal closes" in rendered


def test_hypernote_briefing_unwraps_tracking_urls_and_writes_hyperdb_and_matrix(tmp_path):
    pytest.importorskip("hypernote")
    pytest.importorskip("raven_matrix")
    from hypernote.core.db import HyperDB
    from orbit_security.hypernote_briefing import (
        HyperNoteBriefingEngine,
        ingest_briefing_to_stores,
        unwrap_tracking_url,
    )
    from raven_matrix.engine import CognitiveMatrix

    sub_url = _make_substack_redirect("https://github.com/baidu/Unlimited-OCR?utm_source=substack")
    assert unwrap_tracking_url(sub_url) == "https://github.com/baidu/Unlimited-OCR"

    g_url = "https://www.google.com/url?q=https%3A%2F%2Fhuggingface.co%2FMemTensor%2FMemT-1.0-Nano%3Futm_medium%3Demail&sa=D"
    assert unwrap_tracking_url(g_url) == "https://huggingface.co/MemTensor/MemT-1.0-Nano"

    master_briefing = {
        "found": True,
        "subject": "Combined Daily Master Briefing — November 14, 2026",
        "date": "2026-11-14 11:00",
        "highlights": [
            "EmbeddingGemma 2 270M GGUF via Ollama",
            "2 Google AI Studio projects hit monthly spend cap and paused",
            "Nov 17: Google Opal closes — export custom workflow prompts",
        ],
        "sections": {
            "personal_delta": [
                "2 Google AI Studio projects hit monthly spend cap and paused",
                "Freebuff account suspended due to 3rd-party proxy access",
            ],
            "ai_news": [
                "EmbeddingGemma 2 (~310 MB multimodal embedder on Ollama)",
                "Edge0-145B needs CUDA 13 and 16 GiB VRAM",
                "OpenRouter Fusion :free 8-model panel",
            ],
            "youtube_digest": [
                "AI Search: Unlimited-OCR constant KV cache",
            ],
            "deprecations": [
                "Nov 17: Google Opal closes — export custom prompts from My Drive > Opal",
                "Jan 14, 2027: GPT-4o / GPT-4.1 retirements",
            ],
        },
        "extracted_urls": [
            sub_url,
            g_url,
            "https://www.google.com/url?q=https%3A%2F%2Farxiv.org%2Fabs%2F2611.13946",
        ],
    }

    hdb_path = tmp_path / "notebook.db"
    mx_path = tmp_path / "matrix.db"
    engine = HyperNoteBriefingEngine(output_dir=tmp_path / "out")
    res = engine.ingest_master_briefing(
        master_briefing,
        hyperdb_path=hdb_path,
        matrix_db_path=mx_path,
    )

    assert res["status"] == "ingested"
    assert res["errors"] == []
    assert "https://github.com/baidu/Unlimited-OCR" in res["unwrapped_urls"]
    assert "https://huggingface.co/MemTensor/MemT-1.0-Nano" in res["unwrapped_urls"]
    assert "https://arxiv.org/abs/2611.13946" in res["unwrapped_urls"]
    assert res["hyperdb_written"] > 0
    assert res["matrix_written"] > 0

    hdb = HyperDB(db_path=str(hdb_path))
    try:
        assert hdb.get_stats()["sources"] == 1
        entities = {(e["name"], e["category"]) for e in hdb.get_all_entities()}
        assert ("baidu/Unlimited-OCR", "GitHubRepo") in entities
        assert ("MemTensor/MemT-1.0-Nano", "HuggingFaceModel") in entities
        assert ("arXiv:2611.13946", "ResearchPaper") in entities
        assert ("LOCAL_CPU_FIT", "HardwareFit") in entities
        assert ("GPU_SKIP", "HardwareFit") in entities
        assert ("CLOUD_FREE_OR_CHEAP", "HardwareFit") in entities

        timeline = hdb.get_timeline()
        assert any("Opal" in row["description"] for row in timeline)
    finally:
        hdb.close()

    mx = CognitiveMatrix(db_path=mx_path, json_mirror_path=None, attach_graph=False)
    try:
        dep_invariants = mx.get_all_invariants(domain="ai_deprecations")
        assert any("Opal" in inv["rule"] for inv in dep_invariants)
        recalled_alerts = mx.recall("monthly spend cap paused", limit=5)
        assert any("spend cap" in r["body"].lower() for r in recalled_alerts)
        recalled_susp = mx.recall("Freebuff account suspended", limit=5)
        assert any("freebuff" in r["body"].lower() for r in recalled_susp)
    finally:
        mx.close()

    skipped = ingest_briefing_to_stores({"found": False})
    assert skipped["status"] == "skipped"


def test_daily_briefing_dry_run_vs_live_store_ingestion(monkeypatch, tmp_path):
    import scripts.daily_briefing as db

    ingested_calls = []
    monkeypatch.setattr(db, "DEFAULT_BRIEFINGS_DIR", tmp_path / "briefings")
    monkeypatch.setattr(db, "compute_and_save_daily_deltas", lambda **kwargs: {"today": {}, "yesterday": {}, "deltas": {}, "formatted": ""})
    monkeypatch.setattr(db, "query_stripe_telemetry", lambda: {"available_usd": 0.0, "pending_usd": 0.0, "active_subscriptions": 0})
    monkeypatch.setattr(db, "query_daemon_health", lambda: {"live_verified_active": True, "supervisor_pid": 100, "sentinel_live_verified": True, "sentinel_pid": 200, "services_live_active": 1, "services_total": 1, "sentinel_restarts": 0})
    monkeypatch.setattr(db, "query_inbox_pipeline", lambda: {"total_threads": 0, "escalations": 0})
    monkeypatch.setattr(db, "query_campaign_outreach", lambda: {"frozen": True, "dispatched_count": 0, "recent_dispatched": []})
    monkeypatch.setattr(db, "query_option_c_readiness", lambda: {"kyc_payout_status": "PENDING_PHYSICAL_ID", "tier_1_items": ["Spotify"], "tier_2_items": []})
    monkeypatch.setattr(db, "query_live_github_ci_status", lambda: {"status": "ok", "head_sha": "abc1234", "all_green": True, "failing_workflows": [], "passing_workflows": ["CI"]})
    monkeypatch.setattr(db, "query_geo_panel_telemetry", lambda: {"has_data": True, "total_records": 12, "latest": {"citation_rate_pct": 16.7, "mention_rate_pct": 16.7, "composite_authority_score": 16.7}, "summary_markdown": "- **GEO:** ok"})
    monkeypatch.setattr(db, "query_system_telemetry", lambda: {"temp_c": 42.0, "ram_pct": 50.0, "drives": {"A:\\": {"free_gb": 135.2, "total_gb": 443.2, "pct_free": 30.5}}})
    monkeypatch.setattr(db, "query_projects_radar", lambda: {"recently_active": [], "workspace_root_commits_48h": [], "inbox_queues": {}})
    monkeypatch.setattr(db, "query_calendar_and_tasks", lambda: {"configured": True, "feed_status": "OK", "fallback_used": False, "fallback_events_count": 0, "events": [], "events_today": [], "events_week": [], "birthdays": []})
    monkeypatch.setattr(db, "query_intel_and_world_news", lambda: {"ai_innovations": ["Test AI"], "tech_and_security": [], "world_news": [], "ai_takeaway": "", "world_takeaway": ""})
    monkeypatch.setattr(
        db,
        "query_live_email_telemetry",
        lambda: {
            "scanned": 1,
            "unread": 0,
            "unread_non_ci_count": 0,
            "unread_list": [],
            "urgent": 0,
            "urgent_list": [],
            "historical_alerts_count": 0,
            "ci_alerts": [],
            "deal_threads": [],
            "email_hygiene": {
                "master_briefing": {
                    "found": True,
                    "subject": "Combined Daily Master Briefing — Nov 14",
                    "date": "2026-11-14 10:00",
                    "highlights": ["EmbeddingGemma 2"],
                }
            },
        },
    )
    monkeypatch.setattr(db, "dispatch_email_briefing", lambda *a, **kw: None)
    monkeypatch.setattr(db, "archive_superseded_ci_alerts_in_imap", lambda *a, **kw: 0)

    import orbit_security.hypernote_briefing as hb
    monkeypatch.setattr(hb, "ingest_briefing_to_stores", lambda mb, **kw: ingested_calls.append(mb) or {"status": "ingested"})

    db.generate_briefing(dry_run=True, speak=False, email=False)
    assert len(ingested_calls) == 0

    db.generate_briefing(dry_run=False, speak=False, email=False)
    assert len(ingested_calls) == 1
    assert ingested_calls[0]["subject"] == "Combined Daily Master Briefing — Nov 14"


def test_nova_email_daemon_readonly_peek_dotenv_fallback_and_lockfile_guard(tmp_path):
    pytest.importorskip("nova_email_daemon")
    import nova_email_daemon as ned

    env_path = tmp_path / ".env"
    env_path.write_text("IMAP_USER=carsonmail009@gmail.com\nIMAP_PASS=mock_app_password_16\n", encoding="utf-8")

    raw_msg = (
        b"From: carsonmail009@gmail.com\r\n"
        b"Subject: [TASK] Verify Read-Only IMAP\r\n"
        b"Message-ID: <ro-peek-1@example.com>\r\n"
        b"\r\n"
        b"Confirm BODY.PEEK is used."
    )

    mock_mail = MagicMock()
    mock_mail.select.return_value = ("OK", [b"1"])
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1 (BODY[] {99})", raw_msg), b")"])

    daemon = ned.NovaEmailDaemon(
        state_file=str(tmp_path / "state.json"),
        queue_dir=str(tmp_path / "queue"),
        pending_inbox_dir=str(tmp_path / "pending"),
        health_port=0,
        env_file=str(env_path),
    )
    assert daemon.account == "carsonmail009@gmail.com"

    with patch.dict(os.environ, {}, clear=True), patch("nova_email_daemon.imaplib.IMAP4_SSL", return_value=mock_mail):
        results = daemon.poll_imap()

    mock_mail.login.assert_called_once_with("carsonmail009@gmail.com", "mock_app_password_16")
    mock_mail.select.assert_called_once_with("INBOX", readonly=True)
    mock_mail.fetch.assert_called_once_with(b"1", "(BODY.PEEK[])")
    assert len(results) == 1
    assert results[0]["category"] == ned.EmailCategory.TASK_DIRECTIVE.value

    pid_file = tmp_path / "daemon.pid"
    lock_file = tmp_path / "daemon.lock"
    assert ned.acquire_instance_guard(pid_file=pid_file, lock_file=lock_file, use_mutex=False) is True
    assert ned.is_daemon_running(pid_file=pid_file, lock_file=lock_file) is True
    assert ned.acquire_instance_guard(pid_file=pid_file, lock_file=lock_file, use_mutex=False) is False

    ned.release_instance_guard(pid_file=pid_file, lock_file=lock_file, release_mutex=False)
    assert not pid_file.exists()
    assert ned.acquire_instance_guard(pid_file=pid_file, lock_file=lock_file, use_mutex=False) is True
    ned.release_instance_guard(pid_file=pid_file, lock_file=lock_file, release_mutex=False)
