"""Unit tests for Daily Briefing GitHub Actions HEAD status reconciliation."""

from __future__ import annotations

import json
import pytest

from scripts.daily_briefing import (
    query_live_github_ci_status,
    reconcile_ci_alerts_with_live_status,
)


def test_reconcile_ci_alerts_marks_stale_email_alerts_resolved_when_head_is_green():
    stale_email_alerts = [
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (42a8f0d)",
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (cf922c4)",
    ]
    live_ci = {
        "status": "ok",
        "head_sha": "717b2aa",
        "all_green": True,
        "failing_workflows": [],
        "passing_workflows": ["Orbit Security CI", "Orbit Security Perimeter Sentinel"],
    }

    reconciled = reconcile_ci_alerts_with_live_status(stale_email_alerts, live_ci)
    assert reconciled["active_failures"] == 0
    assert len(reconciled["resolved_alerts"]) == 2
    assert "717b2aa" in reconciled["summary_markdown"]
    assert "RESOLVED on HEAD 717b2aa" in reconciled["summary_markdown"]
    assert "green on HEAD" in reconciled["spoken_note"]


def test_reconcile_ci_alerts_surfaces_active_failures_when_head_is_failing():
    email_alerts = [
        "[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (717b2aa)",
    ]
    live_ci = {
        "status": "ok",
        "head_sha": "717b2aa",
        "all_green": False,
        "failing_workflows": ["Orbit Security CI"],
        "passing_workflows": ["Orbit Security Perimeter Sentinel"],
    }

    reconciled = reconcile_ci_alerts_with_live_status(email_alerts, live_ci)
    assert reconciled["active_failures"] == 1
    assert "Orbit Security CI" in reconciled["summary_markdown"]
    assert "failing on HEAD" in reconciled["spoken_note"]


def test_query_live_github_ci_status_parses_workflow_runs(monkeypatch):
    sample_api_payload = {
        "workflow_runs": [
            {
                "name": "Orbit Security CI",
                "head_sha": "717b2aa9999999",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Orbit Security Perimeter Sentinel",
                "head_sha": "717b2aa9999999",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Orbit Security CI",
                "head_sha": "42a8f0d1111111",
                "status": "completed",
                "conclusion": "failure",
            },
        ]
    }

    class DummyResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(sample_api_payload).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=6.0: DummyResp())

    res = query_live_github_ci_status()
    assert res["status"] == "ok"
    assert res["head_sha"] == "717b2aa"
    assert res["all_green"] is True
    assert res["failing_workflows"] == []
    assert "Orbit Security CI" in res["passing_workflows"]


def test_query_geo_panel_telemetry_surfaces_summary_and_delta(tmp_path):
    from orbit_security.geo_panel import GeoPromptPanel
    from scripts.daily_briefing import query_geo_panel_telemetry

    log_file = tmp_path / "geo_panels.jsonl"
    panel = GeoPromptPanel(log_file=log_file)
    panel.run_panel(engines=["mock"], dry_run=False)
    panel.run_panel(engines=["mock"], dry_run=False)

    geo = query_geo_panel_telemetry(log_file=str(log_file))
    assert geo["has_data"] is True
    assert geo["has_previous_run"] is True
    assert geo["total_records"] == 24
    assert "Latest 12-Query Panel" in geo["summary_markdown"]
    assert "Panel Run-over-Run Delta" in geo["summary_markdown"]


def test_query_option_c_readiness_surfaces_track_a_and_track_b(tmp_path):
    import hashlib
    import shutil
    import zipfile
    from pathlib import Path
    from scripts.daily_briefing import query_option_c_readiness
    from scripts.orbit_readiness_audit import TRACK_B_REQUIRED_MODULES, TRACK_B_REQUIRED_SCRIPTS

    repo_root = Path(__file__).resolve().parent.parent
    (tmp_path / "data" / "disclosures").mkdir(parents=True)
    (tmp_path / "data" / "hackerone_staging").mkdir(parents=True)

    for rel_json in ("data/bounty_programs.json", "data/agency_retainers.json"):
        src = repo_root / rel_json
        dst = tmp_path / rel_json
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    for tree in ("landing", "docs"):
        tree_root = repo_root / tree
        for html_file in tree_root.rglob("*.html"):
            rel = html_file.relative_to(tree_root)
            dst = tmp_path / tree / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(html_file, dst)

    for rel_py in (*TRACK_B_REQUIRED_SCRIPTS, *TRACK_B_REQUIRED_MODULES):
        src = repo_root / rel_py
        dst = tmp_path / rel_py
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    stem = "spotify_open_cloud_bucket_cdn_byspotify_com"
    md_bytes = b"# Synthetic Track A Disclosure\n\nEvidence Digest: ev_0123456789ab\n"
    (tmp_path / "data" / "disclosures" / f"{stem}.md").write_bytes(md_bytes)
    manifest = json.dumps({"file_hashes_sha256": {"report.md": hashlib.sha256(md_bytes).hexdigest()}})
    with zipfile.ZipFile(tmp_path / "data" / "disclosures" / f"{stem}_bundle.zip", "w") as zf:
        zf.writestr("report.md", md_bytes)
        zf.writestr("manifest_sha256.json", manifest)

    (tmp_path / "data" / "hackerone_staging" / "VAULT_LAUNCH_QUEUE.json").write_text(
        json.dumps(
            {
                "consolidated_dossiers": 1,
                "launch_queue": [
                    {
                        "program": "Spotify",
                        "tier": "TIER_1_READY",
                        "hosts": ["cdn.byspotify.com"],
                        "evidence_digests": ["ev_0123456789ab"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    res = query_option_c_readiness(repo_root=tmp_path)
    assert res["commercial_outreach_frozen"] is True
    assert res["unique_programs"] >= 45
    assert res["staged_reports"] >= 1
    assert res["track_b_ready"] is True
    assert res["landing_docs_in_sync"] is True
    assert any("Spotify" in item for item in res["tier_1_items"])


def test_query_campaign_outreach_sorts_newest_first(tmp_path):
    from scripts.daily_briefing import query_campaign_outreach

    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "dispatched_campaigns.json").write_text(
        json.dumps(
            {
                "northstar-web.example.com": {
                    "agency_name": "Northstar Web",
                    "dispatched_at": "2026-11-10",
                },
                "apex-studio.example.com": {
                    "agency_name": "Apex Studio",
                    "dispatched_at": "2026-11-13",
                },
                "cascade-digital.example.com": {
                    "agency_name": "Cascade Digital",
                    "dispatched_at": "2026-11-12",
                },
            }
        ),
        encoding="utf-8",
    )

    res = query_campaign_outreach(repo_root=tmp_path)
    assert res["frozen"] is True
    assert res["dispatched_count"] > 0
    recent = res["recent_dispatched"]
    assert len(recent) >= 2
    dates = [entry.rsplit(" - ", 1)[-1] for entry in recent]
    assert dates == sorted(dates, reverse=True)
    assert dates[0].startswith("2026-11-")


def test_triage_email_messages_filters_self_ci_and_deduplicates_threads():
    import datetime
    from types import SimpleNamespace
    from scripts.daily_briefing import triage_email_messages

    now = datetime.datetime(2026, 11, 14, 17, 0, tzinfo=datetime.timezone.utc)
    messages = [
        SimpleNamespace(
            id="m1",
            subject="Google AI Daily Briefing — November 8, 2026",
            sender="carsonmail009@gmail.com",
            date=now - datetime.timedelta(days=6),
            is_read=True,
        ),
        SimpleNamespace(
            id="m2",
            subject="[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (d2b986f)",
            sender="notifications@github.com",
            date=now - datetime.timedelta(hours=3),
            is_read=False,
        ),
        SimpleNamespace(
            id="m3",
            subject="Orbit Security Daily Operational Briefing - 2026-11-14",
            sender="carsonmail009@gmail.com",
            date=now - datetime.timedelta(hours=1),
            is_read=False,
        ),
        SimpleNamespace(
            id="m4",
            subject="Re: Dispute of Unauthorized Account",
            sender="support@atlasfin.com",
            date=now - datetime.timedelta(days=3),
            is_read=True,
        ),
        SimpleNamespace(
            id="m5",
            subject="Dispute of Unauthorized Account",
            sender="support@atlasfin.com",
            date=now - datetime.timedelta(days=4),
            is_read=True,
        ),
        SimpleNamespace(
            id="m6",
            subject="Urgent: Client Domain Verification Needed",
            sender="ops@clientagency.com",
            date=now - datetime.timedelta(hours=2),
            is_read=False,
        ),
    ]

    urgent_items = [
        SimpleNamespace(message_id=m.id, subject=m.subject, sender=m.sender, date_str="2026-11-14 08:00")
        for m in messages
        if m.id != "m2"
    ]
    work_items = [
        SimpleNamespace(message_id="m2", subject=messages[1].subject, sender=messages[1].sender),
    ]
    digest = SimpleNamespace(
        total_scanned=6,
        unread_count=3,
        urgent_items=urgent_items,
        work_items=work_items,
        financial_totals={},
        hygiene_stats={},
    )

    triaged = triage_email_messages(messages=messages, digest=digest, now_ts=now.timestamp())
    assert triaged["urgent"] == 1
    assert "Client Domain Verification Needed" in triaged["urgent_list"][0]
    assert triaged["historical_alerts_count"] == 1
    assert triaged["unread_non_ci_count"] == 1
    assert len(triaged["ci_alerts"]) == 1


def test_compute_and_save_daily_deltas_day_over_day_and_idempotent_dry_run(tmp_path):
    from scripts.daily_briefing import compute_and_save_daily_deltas

    snap_day1 = {
        "disk_free_gb": 136.5,
        "commits_24h": 3,
        "unread_count": 5,
        "urgent_count": 1,
        "tier1_ready": 1,
        "tier2_queued": 4,
        "geo_citation_share_pct": 16.7,
        "kyc_gate": "PENDING_PHYSICAL_ID",
    }
    first = compute_and_save_daily_deltas("2026-11-13", snap_day1, state_dir=tmp_path)
    assert first["has_previous"] is False
    assert first["geo_unchanged"] is False
    assert (tmp_path / "briefing_state_2026-11-13.json").is_file()
    assert (tmp_path / "briefing_state_latest.json").is_file()

    snap_day2 = {
        "disk_free_gb": 135.2,
        "commits_24h": 6,
        "unread_count": 7,
        "urgent_count": 2,
        "tier1_ready": 1,
        "tier2_queued": 4,
        "geo_citation_share_pct": 16.7,
        "kyc_gate": "PENDING_PHYSICAL_ID",
    }
    second = compute_and_save_daily_deltas("2026-11-14", snap_day2, state_dir=tmp_path)
    assert second["has_previous"] is True
    assert second["previous_date"] == "2026-11-13"
    assert second["deltas"]["disk_free_gb"] == -1.3
    assert second["deltas"]["commits_24h"] == 3
    assert second["deltas"]["unread_count"] == 2
    assert second["deltas"]["urgent_count"] == 1
    assert second["deltas"]["geo_citation_share_pct"] == 0.0
    assert second["geo_unchanged"] is True

    # Repeated --dry-run on same date must still compare against 2026-11-13, not today's run
    snap_day2_rerun = dict(snap_day2, unread_count=8)
    rerun = compute_and_save_daily_deltas("2026-11-14", snap_day2_rerun, state_dir=tmp_path)
    assert rerun["has_previous"] is True
    assert rerun["previous_date"] == "2026-11-13"
    assert rerun["deltas"]["disk_free_gb"] == -1.3
    assert rerun["deltas"]["unread_count"] == 3


def test_generate_markdown_top3_banner_and_geo_collapse():
    from scripts.daily_briefing import generate_markdown

    md = generate_markdown(
        today="2026-11-14 10:00",
        agenda_items=[
            "First critical action",
            "Second important action",
            "Third priority action",
            "Fourth lower-priority action",
        ],
        deltas={
            "has_previous": True,
            "previous_date": "2026-11-13",
            "geo_unchanged": True,
            "current": {"geo_citation_share_pct": 16.7},
            "summary_line": "vs 2026-11-13: Disk -1.3 GB | Commits +3",
        },
        geo_panel={
            "has_data": True,
            "total_records": 24,
            "latest": {
                "citation_rate_pct": 16.7,
                "mention_rate_pct": 16.7,
                "composite_authority_score": 16.7,
            },
            "summary_markdown": "- **Latest 12-Query Panel:** Full block\n- **Panel Run-over-Run Delta:** Extra line",
        },
    )

    assert "**24h Delta (Δ):** vs 2026-11-13: Disk -1.3 GB | Commits +3" in md
    top3_idx = md.index("## ⚡ TOP 3 PRIORITY ACTIONS TODAY")
    sec1_idx = md.index("### 1. Orbit Security Daemon & Sentinel Health")
    header_idx = md.index("**24h Delta (Δ):**")
    assert header_idx < top3_idx < sec1_idx

    banner_slice = md[top3_idx:sec1_idx]
    assert "1. First critical action" in banner_slice
    assert "2. Second important action" in banner_slice
    assert "3. Third priority action" in banner_slice
    assert "Fourth lower-priority action" not in banner_slice

    # Static GEO collapsed into 1-line UNCHANGED summary
    geo_start = md.index("### 7. GEO Visibility & AI Citation Panel")
    geo_end = md.index("### 8. Host Hardware")
    geo_block = md[geo_start:geo_end]
    assert "UNCHANGED vs 2026-11-13" in geo_block
    assert "16.7%" in geo_block
    assert "Full block" not in geo_block


def test_generate_markdown_master_briefing_hygiene_news_takeaways_and_calendar():
    from scripts.daily_briefing import generate_markdown

    md = generate_markdown(
        today="2026-11-14 10:00",
        email_data={"scanned": 50},
        email_hygiene={
            "archived_count": 3,
            "trashed_count": 2,
            "unsubscribed_count": 5,
            "received_24h": 14,
            "read_or_cleared_24h": 11,
            "auto_hygiene_candidates": 4,
            "master_briefing": {
                "found": True,
                "subject": "Combined Daily Master Briefing — November 14, 2026",
                "date": "2026-11-14 08:00",
                "highlights": ["Atlas FTC Affidavit", "LinkedIn Restored", "Antigravity v2.32.0"],
            },
        },
        intel_news={
            "ai_innovations": ["Ggml v1.0.0 [372 pts]"],
            "tech_and_security": ["PyPI security signals"],
            "world_news": ["Macro rate outlook - Reuters"],
            "ai_takeaway": "Local GGML 1.0 stabilizes inference stacks for autonomous security agents.",
            "world_takeaway": "Central bank volatility raises demand for cost-predictable local infra.",
        },
        cal_tasks={
            "configured": True,
            "feed_status": "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)",
            "vevent_count": 0,
            "ical_bytes": 189,
            "fallback_used": True,
            "fallback_events_count": 1,
            "events": [
                {
                    "summary": "Security Architecture Sync",
                    "when": "2:00 PM",
                    "source": "gmail_invite",
                    "sender": "team@example.com",
                    "subject": "Invitation: Security Architecture Sync @ 2:00 PM",
                    "is_today": True,
                }
            ],
            "events_today": ["📩 Security Architecture Sync (2:00 PM)"],
            "events_week": [],
            "birthdays": [],
        },
    )

    assert "`14 received` | `11 read/cleared` | `4 auto-hygiene candidates`" in md
    assert "**Eligible Inbox Zero Archiving:** 3" in md
    assert "**Marketing Promos & Spam Purged:** 2" in md
    assert "**Active Unsubscribe Targets Extracted:** 5" in md
    assert "Combined Daily Master Briefing" in md
    assert "Atlas FTC Affidavit" in md
    assert "LinkedIn Restored" in md
    assert "> 💡 **Why It Matters**: Local GGML 1.0 stabilizes inference stacks for autonomous security agents." in md
    assert "> 💡 **Why It Matters**: Central bank volatility raises demand for cost-predictable local infra." in md
    assert "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)" in md
    assert "Gmail invite fallback active: `1` invite(s) surfaced" in md
    assert "Security Architecture Sync (2:00 PM)" in md


def test_generate_markdown_calendar_synthesizes_gmail_invites_when_lists_empty():
    from scripts.daily_briefing import generate_markdown

    md = generate_markdown(
        today="2026-11-14 10:00",
        cal_tasks={
            "configured": True,
            "feed_status": "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)",
            "fallback_used": True,
            "fallback_events_count": 1,
            "events": [
                {
                    "summary": "Client Kickoff",
                    "when": "2026-11-16",
                    "source": "gmail_invite",
                    "sender": "client@example.com",
                    "subject": "Invitation: Client Kickoff",
                    "is_today": False,
                }
            ],
            "events_today": [],
            "events_week": [],
            "birthdays": [],
        },
    )
    assert "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)" in md
    assert "📩 Client Kickoff (2026-11-16)" in md


def test_generate_markdown_handles_missing_master_briefing_gracefully():
    from scripts.daily_briefing import generate_markdown

    md = generate_markdown(
        today="2026-11-14 10:00",
        email_hygiene={"master_briefing": {"found": False, "subject": "", "date": "", "highlights": []}},
    )
    assert "No Combined Daily Master Briefing found" in md


def test_generate_briefing_dry_run_skips_email_and_imap_mutation(tmp_path, monkeypatch):
    import scripts.daily_briefing as db

    monkeypatch.setattr(db, "DEFAULT_BRIEFINGS_DIR", tmp_path)
    monkeypatch.setattr(db, "query_stripe_telemetry", lambda: {"available_usd": 0.0, "pending_usd": 0.0, "active_subscriptions": 0})
    monkeypatch.setattr(db, "query_daemon_health", lambda: {"live_verified_active": True, "supervisor_pid": 100, "sentinel_live_verified": True, "sentinel_pid": 200, "services_live_active": 1, "services_total": 1, "sentinel_restarts": 0})
    monkeypatch.setattr(db, "query_inbox_pipeline", lambda: {"total_threads": 0, "escalations": 0})
    monkeypatch.setattr(db, "query_campaign_outreach", lambda: {"frozen": True, "dispatched_count": 0, "recent_dispatched": []})
    monkeypatch.setattr(db, "query_option_c_readiness", lambda: {"kyc_payout_status": "PENDING_PHYSICAL_ID", "tier_1_items": ["Spotify"], "tier_2_items": []})
    monkeypatch.setattr(db, "query_live_email_telemetry", lambda: {"scanned": 10, "unread": 2, "unread_non_ci_count": 1, "unread_list": ["Hello (a@b.com)"], "urgent": 0, "urgent_list": [], "historical_alerts_count": 0, "ci_alerts": ["Run failed"], "deal_threads": [], "email_hygiene": {"received_24h": 4, "read_or_cleared_24h": 3, "auto_hygiene_candidates": 1, "master_briefing": {"found": False, "subject": "", "date": "", "highlights": []}}})
    monkeypatch.setattr(db, "query_live_github_ci_status", lambda: {"status": "ok", "head_sha": "abc1234", "all_green": True, "failing_workflows": [], "passing_workflows": ["CI"]})
    monkeypatch.setattr(db, "query_geo_panel_telemetry", lambda: {"has_data": True, "total_records": 12, "latest": {"citation_rate_pct": 16.7, "mention_rate_pct": 16.7, "composite_authority_score": 16.7}, "summary_markdown": "- **GEO:** ok"})
    monkeypatch.setattr(db, "query_system_telemetry", lambda: {"temp_c": 42.0, "ram_pct": 50.0, "drives": {"A:\\": {"free_gb": 135.2, "total_gb": 443.2, "pct_free": 30.5}}})
    monkeypatch.setattr(db, "query_projects_radar", lambda: {"total_projects": 1, "recently_active": [], "workspace_root_commits_48h": [], "inbox_queues": {}})
    monkeypatch.setattr(db, "query_calendar_and_tasks", lambda: {"configured": True, "feed_status": "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)", "fallback_used": True, "fallback_events_count": 0, "events": [], "events_today": [], "events_week": [], "birthdays": []})
    monkeypatch.setattr(db, "query_intel_and_world_news", lambda: {"ai_innovations": ["Test AI"], "tech_and_security": ["Test Sec"], "world_news": ["Test World"], "ai_takeaway": "AI matters.", "world_takeaway": "World matters."})

    called = {"email": False, "archive": False}
    monkeypatch.setattr(db, "dispatch_email_briefing", lambda *a, **kw: called.__setitem__("email", True))
    monkeypatch.setattr(db, "archive_superseded_ci_alerts_in_imap", lambda *a, **kw: called.__setitem__("archive", True) or 0)

    db.generate_briefing(speak=False, email=True, dry_run=True)

    assert called["email"] is False
    assert called["archive"] is False
    assert (tmp_path / "briefing_state_latest.json").is_file()
    md_files = list(tmp_path.glob("briefing_*.md"))
    assert len(md_files) == 1
    content = md_files[0].read_text(encoding="utf-8")
    assert "## ⚡ TOP 3 PRIORITY ACTIONS TODAY" in content
    assert "**24h Delta (Δ):**" in content
    assert "> 💡 **Why It Matters**: AI matters." in content
    assert "EMPTY_ICAL_FEED (0 VEVENTs, 189 bytes)" in content


def test_build_agenda_items_surfaces_urgent_emails_when_unread_is_zero():
    from scripts.daily_briefing import _build_agenda_items

    items = _build_agenda_items(
        ci_count=1,
        live_ci={"failing_workflows": ["Orbit Security CI"]},
        option_c={"kyc_payout_status": "PENDING_PHYSICAL_ID"},
        email_data={"unread_non_ci_count": 0, "urgent": 2},
        daemon={"live_verified_active": True},
        inbox_q={"failed": 0},
    )
    assert len(items) == 3
    assert "2 actionable urgent email item(s)" in items[2]


def test_triage_email_messages_moves_self_replied_thread_to_awaiting_external_reply():
    import datetime
    from types import SimpleNamespace
    from scripts.daily_briefing import triage_email_messages

    inbound_dt = datetime.datetime(2026, 11, 13, 22, 48, tzinfo=datetime.timezone.utc)
    reply_dt = datetime.datetime(2026, 11, 14, 1, 15, tzinfo=datetime.timezone.utc)
    open_dt = datetime.datetime(2026, 11, 14, 2, 0, tzinfo=datetime.timezone.utc)
    now_dt = datetime.datetime(2026, 11, 14, 10, 0, tzinfo=datetime.timezone.utc)

    messages = [
        SimpleNamespace(
            id="m1",
            subject="Account Verification Required",
            sender="support@atlasfin.com",
            date=inbound_dt,
            is_read=False,
            labels=["INBOX"],
        ),
        SimpleNamespace(
            id="m2",
            subject="Re: Account Verification Required",
            sender="carsonmail009@gmail.com",
            date=reply_dt,
            is_read=True,
            labels=["Sent"],
        ),
        SimpleNamespace(
            id="m3",
            subject="Contract Signature Needed",
            sender="legal@partner.io",
            date=open_dt,
            is_read=False,
            labels=["INBOX"],
        ),
    ]
    digest = SimpleNamespace(
        total_scanned=3,
        unread_count=2,
        financial_totals={},
        work_items=[],
        urgent_items=[
            SimpleNamespace(
                message_id="m1",
                subject="Account Verification Required",
                sender="support@atlasfin.com",
                date_str="2026-11-13 22:48",
            ),
            SimpleNamespace(
                message_id="m3",
                subject="Contract Signature Needed",
                sender="legal@partner.io",
                date_str="2026-11-14 02:00",
            ),
        ],
    )

    triaged = triage_email_messages(messages=messages, digest=digest, now_ts=now_dt.timestamp())

    assert triaged["urgent"] == 1
    assert len(triaged["urgent_list"]) == 1
    assert "Contract Signature Needed" in triaged["urgent_list"][0]
    assert "legal@partner.io" in triaged["urgent_list"][0]
    assert triaged["awaiting_external_reply_count"] == 1
    assert len(triaged["awaiting_external_reply"]) == 1
    assert "support@atlasfin.com" in triaged["awaiting_external_reply"][0]
    assert "[outbound reply in thread]" in triaged["awaiting_external_reply"][0]


def test_triage_email_messages_master_briefing_and_newer_inbound_stays_urgent():
    import datetime
    from types import SimpleNamespace
    from scripts.daily_briefing import triage_email_messages

    atlas_dt = datetime.datetime(2026, 11, 13, 22, 48, tzinfo=datetime.timezone.utc)
    cloud_dt = datetime.datetime(2026, 11, 14, 9, 30, tzinfo=datetime.timezone.utc)
    now_dt = datetime.datetime(2026, 11, 14, 10, 0, tzinfo=datetime.timezone.utc)

    messages = [
        SimpleNamespace(
            id="m1",
            subject="Account Closure Prevention",
            sender="support@atlasfin.com",
            date=atlas_dt,
            is_read=False,
            labels=["INBOX"],
        ),
        SimpleNamespace(
            id="m2",
            subject="Invoice Hold Follow-up",
            sender="billing@cloudhost.io",
            date=cloud_dt,
            is_read=False,
            labels=["INBOX"],
        ),
    ]
    digest = SimpleNamespace(
        total_scanned=2,
        unread_count=2,
        financial_totals={},
        work_items=[],
        urgent_items=[
            SimpleNamespace(
                message_id="m1",
                subject="Account Closure Prevention",
                sender="support@atlasfin.com",
                date_str="2026-11-13 22:48",
            ),
            SimpleNamespace(
                message_id="m2",
                subject="Invoice Hold Follow-up",
                sender="billing@cloudhost.io",
                date_str="2026-11-14 09:30",
            ),
        ],
    )
    master_briefing = {
        "found": True,
        "date": "2026-11-14 07:00",
        "highlights": [
            "Submitted verification appeal to Atlasfin support at 2026-11-14 00:15 UTC.",
        ],
    }

    triaged = triage_email_messages(
        messages=messages,
        digest=digest,
        now_ts=now_dt.timestamp(),
        sent_replied_subjects=["invoice hold follow-up"],
        sent_replied_timestamps={
            "invoice hold follow-up": datetime.datetime(
                2026, 11, 14, 7, 0, tzinfo=datetime.timezone.utc
            ).timestamp()
        },
        master_briefing=master_briefing,
    )

    assert triaged["awaiting_external_reply_count"] == 1
    assert "support@atlasfin.com" in triaged["awaiting_external_reply"][0]
    assert "[confirmed in Master Briefing]" in triaged["awaiting_external_reply"][0]
    assert triaged["urgent"] == 1
    assert "billing@cloudhost.io" in triaged["urgent_list"][0]


def test_triage_email_messages_aligns_with_cockpit_sent_metadata_and_folded_headers():
    import datetime
    from types import SimpleNamespace
    from scripts.daily_briefing import triage_email_messages

    inbound_dt = datetime.datetime(2026, 11, 13, 22, 48, tzinfo=datetime.timezone.utc)
    sent_epoch = datetime.datetime(2026, 11, 14, 2, 49, 14, tzinfo=datetime.timezone.utc).timestamp()
    now_dt = datetime.datetime(2026, 11, 14, 10, 0, tzinfo=datetime.timezone.utc)

    messages = [
        SimpleNamespace(
            id="m_in",
            subject="Dispute of Unauthorized Account &\r\n\tStatement ($35.94) - Immediate Account Closure Request",
            sender="support@atlasfin.com",
            date=inbound_dt,
            is_read=False,
            labels=["INBOX"],
        ),
        SimpleNamespace(
            id="m_out_shadow",
            subject="Re: Dispute of Unauthorized Account & Statement ($35.94) - Immediate Account Closure Request",
            sender="carsonmail009@gmail.com",
            date=datetime.datetime.fromtimestamp(sent_epoch, tz=datetime.timezone.utc),
            is_read=True,
            labels=["Sent"],
        ),
    ]
    digest = SimpleNamespace(
        total_scanned=2,
        unread_count=1,
        financial_totals={},
        work_items=[],
        urgent_items=[
            SimpleNamespace(
                message_id="m_out_shadow",
                subject="Re: Dispute of Unauthorized Account & Statement ($35.94) - Immediate Account Closure Request",
                sender="carsonmail009@gmail.com",
                date_str="2026-11-14 02:49",
            ),
            SimpleNamespace(
                message_id="m_in",
                subject="Dispute of Unauthorized Account &\r\n\tStatement ($35.94) - Immediate Account Closure Request",
                sender="support@atlasfin.com",
                date_str="2026-11-13 22:48",
            ),
        ],
    )

    triaged = triage_email_messages(
        messages=messages,
        digest=digest,
        now_ts=now_dt.timestamp(),
        sent_replied_subjects=[
            "dispute of unauthorized account & statement ($35.94) - immediate account closure request",
        ],
        sent_replied_timestamps={
            "dispute of unauthorized account & statement ($35.94) - immediate account closure request": sent_epoch,
        },
    )

    assert triaged["urgent"] == 0
    assert triaged["urgent_list"] == []
    assert triaged["awaiting_external_reply_count"] == 1
    assert "support@atlasfin.com" in triaged["awaiting_external_reply"][0]
    assert "outbound reply" in triaged["awaiting_external_reply"][0]


def test_awaiting_reply_excluded_from_top3_and_rendered_in_section4():
    from scripts.daily_briefing import _build_agenda_items, generate_markdown

    email_data = {
        "status": "connected",
        "scanned": 50,
        "unread": 0,
        "unread_non_ci_count": 0,
        "unread_list": [],
        "urgent": 0,
        "urgent_list": [],
        "awaiting_external_reply_count": 1,
        "awaiting_external_reply": [
            "Account Verification — support@atlasfin.com (2026-11-13 22:48) [outbound reply in thread]"
        ],
        "historical_alerts_count": 0,
        "ci_alerts": [],
        "deal_threads": [],
        "financial_total": 0.0,
    }
    agenda_items = _build_agenda_items(
        ci_count=0,
        live_ci={"failing_workflows": []},
        option_c={"kyc_payout_status": "VERIFIED"},
        email_data=email_data,
        daemon={"live_verified_active": True},
        inbox_q={"failed": 0},
    )
    assert all("urgent email item" not in item for item in agenda_items)

    md = generate_markdown(today="2026-11-14", email_data=email_data, agenda_items=agenda_items)
    top3_section = md.split("## 1.", 1)[0]
    sec4 = md.split("## 4.", 1)[1].split("## 5.", 1)[0]

    assert "support@atlasfin.com" not in top3_section
    assert "- **⏳ Awaiting External Reply:** 1" in sec4
    assert "  - ⏳ Account Verification — support@atlasfin.com (2026-11-13 22:48) [outbound reply in thread]" in sec4
    assert "No new or unread urgent action items today." in sec4


def test_generate_markdown_deduplicates_section9_agenda_items():
    from scripts.daily_briefing import generate_markdown

    md_exact3 = generate_markdown(
        today="2026-11-14",
        agenda_items=["Alpha task", "Beta task", "Gamma task"],
    )
    top3_exact = md_exact3.split("## 1.", 1)[0]
    sec9_exact = md_exact3.split("**Recommended Engineering Agenda Today:**", 1)[1].split("## 10.", 1)[0]

    assert "1. Alpha task" in top3_exact
    assert "2. Beta task" in top3_exact
    assert "3. Gamma task" in top3_exact
    assert "Alpha task" not in sec9_exact
    assert "Beta task" not in sec9_exact
    assert "Gamma task" not in sec9_exact
    assert "Top 3 priorities surfaced in executive banner above (0 overflow backlog items)." in sec9_exact

    md_five = generate_markdown(
        today="2026-11-14",
        agenda_items=["Alpha task", "Beta task", "Gamma task", "Delta overflow", "Epsilon overflow"],
    )
    top3_five = md_five.split("## 1.", 1)[0]
    sec9_five = md_five.split("**Recommended Engineering Agenda Today:**", 1)[1].split("## 10.", 1)[0]

    assert "Delta overflow" not in top3_five
    assert "Epsilon overflow" not in top3_five
    assert "Alpha task" not in sec9_five
    assert "Beta task" not in sec9_five
    assert "Gamma task" not in sec9_five
    assert "4. Delta overflow" in sec9_five
    assert "5. Epsilon overflow" in sec9_five




