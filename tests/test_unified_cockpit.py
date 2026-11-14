"""Unit tests for the Unified Morning Cockpit integrations."""

from __future__ import annotations

import os
import pytest
from scripts.unified_morning_cockpit import (
    query_system_telemetry,
    query_projects_radar,
    query_calendar_and_tasks,
    query_intel_and_world_news,
)


def test_query_system_telemetry_returns_valid_structure():
    telemetry = query_system_telemetry()
    assert isinstance(telemetry, dict)
    assert "cpu_name" in telemetry
    assert "temp_c" in telemetry
    assert isinstance(telemetry["temp_c"], (int, float))
    assert "uptime" in telemetry
    assert "ram_used_gb" in telemetry
    assert "ram_total_gb" in telemetry
    assert "drives" in telemetry
    assert "open_ports" in telemetry
    assert isinstance(telemetry["open_ports"], list)


def test_query_projects_radar_discovers_repositories(tmp_path):
    import subprocess

    projects_root = tmp_path / "projects"
    repo_dir = projects_root / "orbit-security"
    repo_dir.mkdir(parents=True)
    inbox_root = tmp_path / "inbox"
    (inbox_root / "expansion_queue").mkdir(parents=True)

    (repo_dir / "ROADMAP.md").write_text("# Roadmap\n", encoding="utf-8")
    subprocess.run(["git", "init", str(repo_dir)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        ["git", "-C", str(repo_dir), "checkout", "-B", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "ROADMAP.md"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_dir),
            "-c",
            "user.name=Orbit CI",
            "-c",
            "user.email=ci@orbit.local",
            "commit",
            "-m",
            "feat: initial roadmap",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    radar = query_projects_radar(
        projects_root=str(projects_root),
        workspace_root="",
        inbox_root=str(inbox_root),
    )
    assert isinstance(radar, dict)
    assert "total_projects" in radar
    assert radar["total_projects"] > 0
    assert "projects" in radar
    assert "recently_active" in radar
    assert len(radar["recently_active"]) == 1
    # Verify project item structure
    first = radar["projects"][0]
    assert first["name"] == "orbit-security"
    assert first["branch"] == "main"
    assert first["last_commit"]
    assert first["roadmap"] == "ROADMAP.md"
    assert first["repo_kind"] == "standalone"


def test_query_calendar_and_tasks_handles_unconfigured(monkeypatch):
    monkeypatch.delenv("GOOGLE_CALENDAR_ICAL_URL", raising=False)
    cal = query_calendar_and_tasks()
    assert isinstance(cal, dict)
    assert "configured" in cal
    assert "events_today" in cal
    assert "birthdays" in cal


def test_query_intel_and_world_news_returns_content():
    news = query_intel_and_world_news()
    assert isinstance(news, dict)
    assert "ai_innovations" in news
    assert "tech_and_security" in news
    assert "world_news" in news
    assert len(news["ai_innovations"]) > 0 or len(news["world_news"]) > 0


def test_query_projects_radar_ignores_skeleton_dot_git_and_counts_inbox(tmp_path):
    projects_dir = tmp_path / "projects"
    skeleton_proj = projects_dir / "aevum"
    (skeleton_proj / ".git" / "objects").mkdir(parents=True)

    inbox_dir = tmp_path / "inbox"
    for q in ("pending", "in_progress", "failed", "expansion_queue", "completed"):
        (inbox_dir / q).mkdir(parents=True)
    (inbox_dir / "pending" / ".gitkeep").write_text("", encoding="utf-8")
    (inbox_dir / "failed" / "task_bad.json").write_text("{}", encoding="utf-8")
    (inbox_dir / "completed" / "task_done.json").write_text("{}", encoding="utf-8")

    radar = query_projects_radar(
        projects_root=str(projects_dir),
        workspace_root="",
        inbox_root=str(inbox_dir),
    )
    assert radar["total_projects"] == 1
    assert radar["recently_active"] == []
    assert radar["projects"][0]["repo_kind"] == "untracked"
    assert radar["inbox_queues"]["pending"] == 0
    assert radar["inbox_queues"]["failed"] == 1
    assert radar["inbox_queues"]["completed_24h"] == 1


def test_classify_intel_feeds_prevents_substring_ai_false_positives():
    from scripts.unified_morning_cockpit import classify_intel_feeds

    hits = [
        {
            "title": "Brazil's Caixa insurer breach exposes names and tax IDs of 7.6M customers",
            "url": "https://example.com/caixa",
            "points": 190,
        },
        {
            "title": "Ggml v1.0.0",
            "url": "https://github.com/ggml-org/ggml/releases/tag/v1.0.0",
            "points": 370,
        },
        {
            "title": "Building autonomous AI coding agents with local inference",
            "url": "https://example.com/agents",
            "points": 240,
        },
    ]
    rss = ["Global supply chain briefing - Reuters", "Federal Reserve rate outlook - Bloomberg"]

    res = classify_intel_feeds(hn_hits=hits, rss_headlines=rss)
    assert len(res["ai_innovations"]) == 2
    assert not any("Caixa" in item for item in res["ai_innovations"])
    assert any("Caixa" in item for item in res["tech_and_security"])
    assert res["world_news"] == rss


def test_extract_master_briefing_delta_extracts_newest_and_highlights():
    import datetime
    from types import SimpleNamespace
    from scripts.unified_morning_cockpit import _extract_master_briefing_delta

    older = SimpleNamespace(
        id="m-old",
        subject="Combined Daily Master Briefing — November 13, 2026: 24h Personal Delta, Gemini 4 Hydrogen",
        date=datetime.datetime(2026, 11, 13, 9, 30, tzinfo=datetime.timezone.utc),
        body_text="- Older bullet that should not win",
    )
    newer = SimpleNamespace(
        id="m-new",
        subject=(
            "Combined Daily Master Briefing — November 14, 2026: "
            "24h Personal Delta (Atlas FTC Affidavit, LinkedIn Restored), "
            "Antigravity v2.32.0, Edge0-145B & Full Dossier"
        ),
        date=datetime.datetime(2026, 11, 14, 11, 16, tzinfo=datetime.timezone.utc),
        body_text=(
            "COMBINED DAILY MASTER BRIEFING — SATURDAY, NOVEMBER 14, 2026\n"
            "Prepared for Carson Haynes\n"
            "EXECUTIVE TABLE OF CONTENTS\n"
            "- Atlas FTC identity theft affidavit filed\n"
            "- LinkedIn account access restored\n"
        ),
    )
    unrelated = SimpleNamespace(
        id="m-other",
        subject="Weekly Security Digest",
        date=datetime.datetime(2026, 11, 14, 12, 0, tzinfo=datetime.timezone.utc),
        body_text="- Unrelated item",
    )

    res = _extract_master_briefing_delta([older, unrelated, newer])
    assert res["found"] is True
    assert "November 14, 2026" in res["subject"]
    assert res["date"] == "2026-11-14 11:16"
    assert "24h Personal Delta (Atlas FTC Affidavit, LinkedIn Restored)" in res["highlights"]
    assert "Antigravity v2.32.0" in res["highlights"]
    assert "Atlas FTC identity theft affidavit filed" in res["highlights"]
    assert not any("Older bullet" in h for h in res["highlights"])

    missing = _extract_master_briefing_delta([unrelated])
    assert missing == {"found": False, "subject": "", "date": "", "highlights": []}


def test_query_email_hygiene_computes_24h_flow_and_safe_candidates():
    import datetime
    from types import SimpleNamespace
    from scripts.unified_morning_cockpit import query_email_hygiene

    now = datetime.datetime(2026, 11, 14, 17, 0, tzinfo=datetime.timezone.utc)
    messages = [
        # 1. Recent 24h master briefing (unread) -> NOT an auto-hygiene candidate
        SimpleNamespace(
            id="m1",
            subject="Combined Daily Master Briefing — November 14, 2026: 24h Personal Delta (Atlas), Antigravity v2.32.0",
            sender="carsonmail009@gmail.com",
            date=now - datetime.timedelta(hours=1),
            body_text="- Atlas filing complete",
            is_read=False,
            is_in_inbox=True,
        ),
        # 2. Recent 24h safe newsletter (unread, in inbox) -> auto-hygiene candidate
        SimpleNamespace(
            id="m2",
            subject="Python Weekly Issue #700",
            sender="digest@pythonweekly.com",
            date=now - datetime.timedelta(hours=3),
            body_text="Weekly curated Python links.",
            list_unsubscribe="<https://pythonweekly.com/unsub>",
            is_read=False,
            is_in_inbox=True,
        ),
        # 3. Recent 24h automated CI alert (read) -> read_or_cleared + auto-hygiene candidate
        SimpleNamespace(
            id="m3",
            subject="[CmfH009/Orbit-Security] Run failed: Orbit Security CI - main (d2b986f)",
            sender="notifications@github.com",
            date=now - datetime.timedelta(hours=4),
            body_text="Workflow run failed on main.",
            is_read=True,
            is_in_inbox=True,
        ),
        # 4. Recent 24h financial dispute (unread) -> MUST NOT be auto-hygiene candidate
        SimpleNamespace(
            id="m4",
            subject="Re: Dispute of Unauthorized Account & Statement ($35.94)",
            sender="support@atlasfin.com",
            date=now - datetime.timedelta(hours=5),
            body_text="Please review your $35.94 statement dispute.",
            is_read=False,
            is_in_inbox=True,
        ),
        # 5. Recent 24h cleared personal email -> read_or_cleared, NOT auto-hygiene candidate
        SimpleNamespace(
            id="m5",
            subject="Coffee next week?",
            sender="alex@gmail.com",
            to=["carsonmail009@gmail.com"],
            date=now - datetime.timedelta(hours=6),
            body_text="Hey, want to grab coffee Tuesday?",
            is_read=False,
            is_in_inbox=False,
        ),
        # 6. Old read receipt (45 days old) -> Inbox Zero archive candidate
        SimpleNamespace(
            id="m6",
            subject="Receipt for Order #9981",
            sender="billing@vendor.com",
            date=now - datetime.timedelta(days=45),
            body_text="Total billed: $19.00",
            is_read=True,
            is_in_inbox=True,
        ),
        # 7. Old expired promo (10 days old) -> Trash + unsubscribe candidate
        SimpleNamespace(
            id="m7",
            subject="FLASH SALE 60% OFF: 24 Hours Only!",
            sender="deals@promo-shop.com",
            date=now - datetime.timedelta(days=10),
            body_text="Flash sale ends tonight.",
            list_unsubscribe="<https://promo-shop.com/unsub>",
            is_read=True,
            is_in_inbox=True,
        ),
    ]

    class FakeClient:
        def __init__(self, items):
            self.items = items
            self.calls = []

        def fetch_messages(self, folder="INBOX", limit=50):
            self.calls.append((folder, limit))
            return self.items

    fake_client = FakeClient(messages)
    hygiene = query_email_hygiene(client=fake_client, limit=50, now_ts=now.timestamp())

    assert fake_client.calls == [("INBOX", 50)]
    assert hygiene["status"] == "connected"
    assert hygiene["total_scanned"] == 7
    assert hygiene["received_24h"] == 5
    assert hygiene["read_or_cleared_24h"] == 2  # m3 (read) + m5 (not in inbox)
    assert hygiene["archived"] >= 1
    assert hygiene["trashed"] >= 1
    assert hygiene["unsubscribed"] >= 1
    # m2 (24h newsletter), m3 (24h CI alert), m6 (triage archive), m7 (triage trash) = 4
    assert hygiene["auto_hygiene_candidates"] == 4
    assert hygiene["master_briefing"]["found"] is True
    assert "Antigravity v2.32.0" in hygiene["master_briefing"]["highlights"]


def test_synthesize_news_takeaway_ollama_success_fallback_and_offline(monkeypatch):
    import json
    import urllib.error
    from scripts.unified_morning_cockpit import _synthesize_news_takeaway, query_intel_and_world_news
    import scripts.unified_morning_cockpit as cockpit

    ai_news = [{"title": "Ggml v1.0.0 released with faster local quantization", "points": 370}]
    world_news = [{"title": "Nationwide airline ground stop triggers cloud ops delays - AP News"}]

    class FakeResp:
        def __init__(self, payload: dict):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

    # 1. Warm VRAM model returned by /api/ps is reused first (8.0s timeout)
    seen_warm_calls = []

    def fake_urlopen_warm(req, timeout=8.0):
        if req.full_url.endswith("/api/ps"):
            seen_warm_calls.append(("ps", timeout))
            return FakeResp({"models": [{"name": "orbit-thinker:latest"}]})
        body = json.loads(req.data.decode("utf-8"))
        seen_warm_calls.append((body["model"], body["stream"], timeout))
        return FakeResp(
            {
                "response": json.dumps(
                    {
                        "ai_takeaway": "Ggml v1.0.0 cuts local inference latency for on-device security pipelines.",
                        "world_takeaway": "Infrastructure ground stops highlight single-point operational continuity risks.",
                    }
                )
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen_warm)
    res_warm = _synthesize_news_takeaway(ai_news, world_news)
    assert seen_warm_calls == [("ps", 1.5), ("orbit-thinker:latest", False, 8.0)]
    assert "Ggml v1.0.0" in res_warm["ai_takeaway"]
    assert "continuity risks" in res_warm["world_takeaway"]

    # 2. Empty /api/ps cascades qwen2.5-coder:7b -> orbit-critic:latest -> gemma4:12b on 404
    cascade_models = []

    def fake_urlopen_cold_cascade(req, timeout=8.0):
        if req.full_url.endswith("/api/ps"):
            return FakeResp({"models": []})
        body = json.loads(req.data.decode("utf-8"))
        cascade_models.append((body["model"], timeout))
        if body["model"] in ("qwen2.5-coder:7b", "orbit-critic:latest"):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        return FakeResp(
            {
                "response": json.dumps(
                    {
                        "ai_takeaway": "Local quantization upgrades lower zero-token security triage cost.",
                        "world_takeaway": "Transit outages reinforce resilient failover planning.",
                    }
                )
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen_cold_cascade)
    res_cascade = _synthesize_news_takeaway(ai_news, world_news)
    assert cascade_models == [
        ("qwen2.5-coder:7b", 8.0),
        ("orbit-critic:latest", 8.0),
        ("gemma4:12b", 8.0),
    ]
    assert "zero-token security triage cost" in res_cascade["ai_takeaway"]

    # 3. ConnectionRefused on /api/ps short-circuits immediately without hitting /api/generate
    generate_called = []

    def fake_urlopen_refused(req, timeout=8.0):
        if req.full_url.endswith("/api/ps"):
            raise urllib.error.URLError(ConnectionRefusedError("connection refused"))
        generate_called.append(req.full_url)
        raise AssertionError("/api/generate should not run when daemon refuses connection")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen_refused)
    res_refused = _synthesize_news_takeaway(ai_news, world_news)
    assert generate_called == []
    assert "Ggml v1.0.0" in res_refused["ai_takeaway"]

    # 4. Timeout deterministic fallback + query_intel_and_world_news integration
    def fake_urlopen_offline(req, timeout=8.0):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen_offline)
    res_offline = _synthesize_news_takeaway(ai_news, world_news)
    assert "Ggml v1.0.0" in res_offline["ai_takeaway"]
    assert len(res_offline["world_takeaway"]) > 20
    assert "\n" not in res_offline["ai_takeaway"]

    monkeypatch.setattr(cockpit, "_fetch_hn_algolia_hits", lambda: [{"title": "Ggml v1.0.0", "url": "https://ex.com", "points": 300}])
    monkeypatch.setattr(cockpit, "_fetch_google_news_rss", lambda: ["Global grid resilience update - Reuters"])
    intel = query_intel_and_world_news()
    assert "ai_takeaway" in intel and intel["ai_takeaway"]
    assert "world_takeaway" in intel and intel["world_takeaway"]


def test_query_google_calendar_zero_vevent_and_gmail_invite_fallback(monkeypatch):
    import datetime
    from types import SimpleNamespace
    import scripts.unified_morning_cockpit as cockpit
    from scripts.unified_morning_cockpit import query_google_calendar, query_calendar_and_tasks

    empty_ical = b"BEGIN:VCALENDAR\r\nPRODID:-//Google Inc//Google Calendar 70.9054//EN\r\nVERSION:2.0\r\nCALSCALE:GREGORIAN\r\nMETHOD:PUBLISH\r\nEND:VCALENDAR\r\n"

    class DummyIcalResp:
        def __init__(self, raw: bytes):
            self._raw = raw

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._raw

    monkeypatch.setenv("GOOGLE_CALENDAR_ICAL_URL", "https://calendar.google.com/calendar/ical/example/basic.ics")
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=5: DummyIcalResp(empty_ical))

    today = datetime.date.today()
    today_token = today.strftime("%Y%m%d")
    next_week_token = (today + datetime.timedelta(days=3)).strftime("%Y%m%d")

    invite_messages = [
        SimpleNamespace(
            id="inv1",
            subject=f"Invitation: Security Architecture Sync @ {today.strftime('%b %d, %Y')} 2pm",
            sender="calendar-notification@google.com",
            date=datetime.datetime.now(datetime.timezone.utc),
            headers={"Content-Type": "text/calendar; charset=UTF-8; method=REQUEST"},
            body_text=f"BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART:{today_token}T140000Z\nSUMMARY:Security Architecture Sync\nEND:VEVENT\nEND:VCALENDAR",
        ),
        SimpleNamespace(
            id="inv2",
            subject="Updated invitation: Client Kickoff Call @ 2026-11-20 10:00",
            sender="partner@agency.io",
            date=datetime.datetime.now(datetime.timezone.utc),
            headers={"Content-Type": "multipart/mixed"},
            body_text=f"Please find invite.ics attached.\nBEGIN:VEVENT\nDTSTART:{next_week_token}T160000Z\nSUMMARY:Client Kickoff Call\nEND:VEVENT",
        ),
        SimpleNamespace(
            id="noise1",
            subject="Weekly newsletter",
            sender="news@example.com",
            date=datetime.datetime.now(datetime.timezone.utc),
            headers={"Content-Type": "text/plain"},
            body_text="Regular newsletter.",
        ),
    ]

    monkeypatch.setattr(cockpit, "_fetch_imap_messages", lambda folder="INBOX", query=None, limit=25: (invite_messages, "connected"))

    cal = query_google_calendar()
    assert cal["configured"] is True
    assert cal["vevent_count"] == 0
    assert cal["ical_bytes"] == len(empty_ical)
    assert cal["feed_status"].startswith("EMPTY_ICAL_FEED (0 VEVENTs")
    assert cal["fallback_used"] is True
    assert cal["fallback_events_count"] == 2
    assert len(cal["events"]) == 2
    assert any("Security Architecture Sync" in e for e in cal["events_today"])
    assert any("Client Kickoff Call" in e for e in cal["events_week"])

    # Companion wrapper returns identical structured metadata
    cal2 = query_calendar_and_tasks(messages=invite_messages)
    assert cal2["feed_status"] == cal["feed_status"]
    assert cal2["fallback_used"] is True

    # Non-empty iCal skips fallback
    populated_ical = (
        f"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Live Sync\r\nDTSTART:{today_token}T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    ).encode("utf-8")
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=5: DummyIcalResp(populated_ical))
    cal_ok = query_google_calendar()
    assert cal_ok["vevent_count"] == 1
    assert cal_ok["feed_status"].startswith("OK (1 VEVENTs")
    assert cal_ok["fallback_used"] is False
    assert any("Live Sync" in e for e in cal_ok["events_today"])


def test_extract_master_briefing_delta_strips_tracking_urls_before_truncating():
    import datetime
    from types import SimpleNamespace
    from scripts.unified_morning_cockpit import _extract_master_briefing_delta

    msg = SimpleNamespace(
        id="mb-urls",
        subject="Combined Daily Master Briefing — November 14, 2026: 24h Personal Delta (Atlas & LinkedIn)",
        date=datetime.datetime(2026, 11, 14, 11, 16, tzinfo=datetime.timezone.utc),
        body_text=(
            "COMBINED DAILY MASTER BRIEFING\n"
            "- Atlas Financial unauthorized account — FTC identity theft affidavit submitted via portal "
            "(https://www.google.com/url?q=https://reportfraud.ftc.gov/confirmation/very-long-tracking-token-that-previously-clipped-the-rest-of-this-sentence&sa=D&source=editors) "
            "and response receipt archived (359,020 bytes, https://www.google.com/url?q=https://drive.google.com/file/d/abc123def456/view&ust=999999) "
            "at 2026-11-14 02:49 UTC.\n"
            "- LinkedIn Identity Verification — appeal accepted [support case](https://www.google.com/url?q=https://www.linkedin.com/help/linkedin/answer/a1339724&sa=D) "
            "and 2FA access fully restored.\n"
        ),
    )

    res = _extract_master_briefing_delta([msg])
    assert res["found"] is True
    joined = "\n".join(res["highlights"])
    assert "https://" not in joined
    assert "google.com/url" not in joined
    assert "FTC identity theft affidavit submitted via portal" in joined
    assert "(359,020 bytes)" in joined
    assert "2026-11-14 02:49 UTC" in joined
    assert "support case and 2FA access fully restored" in joined


def test_query_email_hygiene_and_sent_reply_metadata(monkeypatch):
    import datetime
    from types import SimpleNamespace
    import scripts.unified_morning_cockpit as cockpit
    from scripts.unified_morning_cockpit import (
        _fetch_sent_mail_headers,
        query_email_hygiene,
        query_sent_reply_metadata,
    )

    now = datetime.datetime(2026, 11, 14, 12, 0, tzinfo=datetime.timezone.utc)
    atlas_sent_dt = datetime.datetime(2026, 11, 14, 2, 49, 14, tzinfo=datetime.timezone.utc)
    linkedin_sent_dt = datetime.datetime(2026, 11, 14, 4, 21, 9, tzinfo=datetime.timezone.utc)

    sent_msgs = [
        SimpleNamespace(
            subject="Re: Dispute of Unauthorized Account & Statement ($35.94) - Immediate Account Closure Request",
            sender="carsonmail009@gmail.com",
            date=atlas_sent_dt,
        ),
        SimpleNamespace(
            subject="Fwd: Re: Your recent request",
            sender="carsonmail009@gmail.com",
            date=linkedin_sent_dt,
        ),
        SimpleNamespace(
            subject="Combined Daily Master Briefing — November 14, 2026: Ignore Self",
            sender="carsonmail009@gmail.com",
            date=now,
        ),
    ]

    meta = query_sent_reply_metadata(sent_messages=sent_msgs)
    assert meta["sent_scanned"] == 3
    assert "dispute of unauthorized account & statement ($35.94) - immediate account closure request" in meta["sent_replied_subjects"]
    assert "your recent request" in meta["sent_replied_subjects"]
    assert not any("combined daily master briefing" in s for s in meta["sent_replied_subjects"])
    assert meta["sent_replied_timestamps"]["dispute of unauthorized account & statement ($35.94) - immediate account closure request"] == atlas_sent_dt.timestamp()

    # query_email_hygiene combines sent_messages and any outbound owner emails in INBOX messages
    inbox_msgs = [
        SimpleNamespace(
            id="in1",
            subject="Re: Dispute of Unauthorized Account & Statement ($35.94) - Immediate Account Closure Request",
            sender="support@atlasfin.com",
            date=datetime.datetime(2026, 11, 13, 22, 48, tzinfo=datetime.timezone.utc),
            body_text="Please see attached notice.",
            is_read=False,
            is_in_inbox=True,
        ),
        SimpleNamespace(
            id="out-in-thread",
            subject="Re: Follow-up on Security Audit Scope",
            sender="Carson Haynes <carsonmail009@gmail.com>",
            date=datetime.datetime(2026, 11, 14, 5, 0, tzinfo=datetime.timezone.utc),
            body_text="Sent updated scope.",
            is_read=True,
            is_in_inbox=True,
        ),
    ]
    hygiene = query_email_hygiene(
        messages=inbox_msgs,
        now_ts=now.timestamp(),
        sent_messages=sent_msgs,
    )
    assert "dispute of unauthorized account & statement ($35.94) - immediate account closure request" in hygiene["sent_replied_subjects"]
    assert "follow-up on security audit scope" in hygiene["sent_replied_subjects"]
    assert hygiene["sent_replied_timestamps"]["follow-up on security audit scope"] == datetime.datetime(
        2026, 11, 14, 5, 0, tzinfo=datetime.timezone.utc
    ).timestamp()

    # _fetch_sent_mail_headers uses readonly IMAP select and BODY.PEEK header fetch
    imap_calls = []

    class FakeIMAP:
        def __init__(self, host, port, timeout=None):
            imap_calls.append(("init", host, port, timeout))

        def login(self, user, pw):
            imap_calls.append(("login", user))
            return "OK", [b"Logged in"]

        def select(self, folder, readonly=False):
            imap_calls.append(("select", folder, readonly))
            return "OK", [b"2"]

        def search(self, charset, criteria):
            imap_calls.append(("search", criteria))
            return "OK", [b"1 2"]

        def fetch(self, seq_set, spec):
            imap_calls.append(("fetch", seq_set, spec))
            hdr = (
                b"Subject: Re: Dispute of Unauthorized Account\r\n"
                b"From: Carson Haynes <carsonmail009@gmail.com>\r\n"
                b"To: support@atlasfin.com\r\n"
                b"Date: Fri, 13 Nov 2026 18:49:14 -0800\r\n\r\n"
            )
            return "OK", [(b"1 (BODY[HEADER.FIELDS (SUBJECT FROM TO DATE)] {140}", hdr), b")"]

        def logout(self):
            imap_calls.append(("logout",))
            return "BYE", [b"Logout"]

    monkeypatch.setattr(cockpit, "_load_imap_credentials", lambda: ("carsonmail009@gmail.com", "secret-pass"))
    monkeypatch.setattr(cockpit.imaplib, "IMAP4_SSL", FakeIMAP)
    fetched = _fetch_sent_mail_headers(limit=10, timeout=3.0)
    assert len(fetched) == 1
    assert fetched[0]["subject"] == "Re: Dispute of Unauthorized Account"
    assert fetched[0]["sender"] == "carsonmail009@gmail.com"
    assert fetched[0]["date"] is not None
    assert ("select", '"[Gmail]/Sent Mail"', True) in imap_calls
    assert any(c[0] == "fetch" and "BODY.PEEK[HEADER.FIELDS" in c[2] for c in imap_calls)
    assert ("logout",) in imap_calls
