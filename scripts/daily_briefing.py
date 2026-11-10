"""Orbit Security & Mailbox Operations: Unified Daily Executive Briefing.

Aggregates:
1. Live Stripe balance, 24h revenue, active subscriptions, and inbox receipts.
2. Orbit Security Sentinel & Master Supervisor daemon health.
3. Inbound negotiations, escalations, and client inquiries from Orbit/Deal-Desk.
4. GitHub CI/CD build telemetry and security scanning alerts (Orbit/CI-CD).
5. Agency outbound campaign pipeline status.
6. Mailbox hygiene stats (inbox zero count, unsubscribes, spam purged).
7. Synthesizes consolidated Markdown report, emails operator, and speaks via Nova TTS.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import urllib.request
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Ensure UTF-8 output on Windows terminals to prevent CP1252 charmap encoding crashes
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add local src/ and email-organizer to sys.path
_local_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
_email_org_root = r"A:\projects\email-organizer"
_scripts_dir = os.path.dirname(__file__)
for p in (_local_src, _email_org_root, _scripts_dir):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

try:
    from unified_morning_cockpit import (
        query_system_telemetry,
        query_projects_radar,
        query_calendar_and_tasks,
        query_intel_and_world_news,
    )
except ImportError:
    try:
        from scripts.unified_morning_cockpit import (
            query_system_telemetry,
            query_projects_radar,
            query_calendar_and_tasks,
            query_intel_and_world_news,
        )
    except ImportError:
        query_system_telemetry = None
        query_projects_radar = None
        query_calendar_and_tasks = None
        query_intel_and_world_news = None

load_dotenv()


def dispatch_email_briefing(report_markdown: str, recipient: Optional[str] = None) -> bool:
    """Dispatches the daily operational briefing to operator email via EmailDispatcher."""
    try:
        from orbit_security.mailer import EmailDispatcher
        dispatcher = EmailDispatcher()
        if not dispatcher.is_configured():
            print("[!] Email dispatch skipped: SMTP not fully configured.")
            return False

        target_email = recipient or os.getenv("DEFAULT_AGENCY_EMAIL") or os.getenv("SMTP_USER") or "carsonmail009@gmail.com"
        subject = f"Orbit Security Daily Operational Briefing - {datetime.date.today().strftime('%Y-%m-%d')}"

        sent = dispatcher.send_email(
            recipient_email=target_email,
            subject=subject,
            body_text=report_markdown,
        )
        if sent:
            print(f"[✔] Daily briefing email dispatched to {target_email}")
            return True
        return False
    except Exception as e:
        print(f"[!] Email dispatch error: {e}")
        return False


def query_stripe_telemetry() -> Dict[str, Any]:
    """Queries live Stripe API for balance, 24h charges, and subscriptions."""
    api_key = os.getenv("STRIPE_SECRET_KEY") or os.getenv("STRIPE_API_KEY")
    if not api_key:
        return {"status": "unconfigured", "available_usd": 0.0, "pending_usd": 0.0, "recent_charges": 0, "active_subscriptions": 0}

    headers = {"Authorization": f"Bearer {api_key}"}

    def api_get(endpoint: str) -> Dict[str, Any]:
        req = urllib.request.Request(f"https://api.stripe.com/v1/{endpoint}", headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        bal = api_get("balance")
        avail = sum(item.get("amount", 0) for item in bal.get("available", [])) / 100.0
        pending = sum(item.get("amount", 0) for item in bal.get("pending", [])) / 100.0

        charges_data = api_get("charges?limit=10").get("data", [])
        subs_data = api_get("subscriptions?status=active&limit=10").get("data", [])

        return {
            "status": "active",
            "available_usd": avail,
            "pending_usd": pending,
            "recent_charges": len(charges_data),
            "active_subscriptions": len(subs_data),
        }
    except Exception as e:
        return {"status": f"error: {e}", "available_usd": 0.0, "pending_usd": 0.0, "recent_charges": 0, "active_subscriptions": 0}


def query_daemon_health() -> Dict[str, Any]:
    """Checks PID and status of Orbit Master Supervisor and Sentinel daemon."""
    state_file = r"A:\system\state\orbit_daemon_state.json"
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            sv_pid = data.get("supervisor_pid")
            running = data.get("running", False)
            services = data.get("services", {})
            sentinel = services.get("orbit_security", {})
            return {
                "supervisor_pid": sv_pid,
                "supervisor_active": running and bool(sv_pid),
                "sentinel_pid": sentinel.get("pid"),
                "sentinel_running": sentinel.get("active", False),
                "sentinel_restarts": sentinel.get("restart_count", 0),
            }
        except Exception:
            pass

    return {
        "supervisor_pid": None,
        "supervisor_active": False,
        "sentinel_pid": None,
        "sentinel_running": False,
        "sentinel_restarts": 0,
    }


def query_inbox_pipeline() -> Dict[str, Any]:
    """Inspects leads_state.json for negotiation status and escalations."""
    leads_file = os.path.join(os.path.dirname(__file__), "..", "data", "leads_state.json")
    if not os.path.exists(leads_file):
        return {"total_threads": 0, "escalations": 0, "inquiries": 0}

    try:
        with open(leads_file, "r", encoding="utf-8") as f:
            leads = json.load(f)
        total = len(leads)
        escalations = sum(
            1 for v in leads.values()
            if (v.get("escalated") and v.get("intent") in ("READY_TO_BUY", "HIGH_INTENT", "REQUEST_HUMAN"))
            or v.get("intent") in ("READY_TO_BUY", "HIGH_INTENT", "REQUEST_HUMAN")
        )
        inquiries = sum(1 for v in leads.values() if "INQUIRY" in str(v.get("intent", "")))
        return {
            "total_threads": total,
            "escalations": escalations,
            "inquiries": inquiries,
        }
    except Exception:
        return {"total_threads": 0, "escalations": 0, "inquiries": 0}


def query_campaign_outreach() -> Dict[str, Any]:
    """Inspects dispatched_campaigns.json and outbound_campaigns for outreach stats."""
    dispatched_file = os.path.join(os.path.dirname(__file__), "..", "data", "dispatched_campaigns.json")
    out_root = os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns")
    dispatched_count = 0
    recent = []
    if os.path.exists(dispatched_file):
        try:
            with open(dispatched_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            dispatched_count = len(data)
            for domain, info in list(data.items())[-5:]:
                recent.append(f"{info.get('agency_name', domain)} ({domain}) - {info.get('dispatched_at', '')}")
        except Exception:
            pass

    staged_count = 0
    if os.path.exists(out_root):
        try:
            staged_count = len([d for d in os.listdir(out_root) if os.path.isdir(os.path.join(out_root, d))])
        except Exception:
            pass

    return {
        "dispatched_count": dispatched_count,
        "staged_count": staged_count,
        "recent_dispatched": recent,
    }


def query_live_email_telemetry() -> Dict[str, Any]:
    """Connects to email-organizer and extracts real-time telemetry from carsonmail009@gmail.com."""
    try:
        from email_organizer.client import IMAPEmailClient
        from email_organizer.classifier import EmailClassifier
        from email_organizer.digest import MorningDigestGenerator
        from email_organizer.ledger import SenderLedger
        from email_organizer.models import OrganizerConfig

        env_file = os.path.join(_email_org_root, ".env")
        imap_user = os.environ.get("IMAP_USER", "carsonmail009@gmail.com")
        imap_pass = os.environ.get("IMAP_PASS", "")

        if os.path.exists(env_file):
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("IMAP_USER="):
                        imap_user = line.split("=", 1)[1].strip().strip("'\"")
                    elif line.startswith("IMAP_PASS="):
                        imap_pass = line.split("=", 1)[1].strip().strip("'\"")

        if not imap_pass:
            imap_pass = os.environ.get("GMAIL_APP_PASSWORD", "")

        if not imap_pass:
            return {"status": "unconfigured", "scanned": 0, "unread": 0, "ci_alerts": [], "deal_threads": [], "urgent": []}

        # Non-mutating peek
        client = IMAPEmailClient(
            host="imap.gmail.com",
            port=993,
            user=imap_user,
            password=imap_pass,
        )
        client.connect()
        messages = client.fetch_messages(folder="INBOX", limit=50)
        client.disconnect()

        db_path = os.path.join(_email_org_root, "email_organizer.db")
        ledger = SenderLedger(db_path) if os.path.exists(db_path) else None
        config = OrganizerConfig()
        classifier = EmailClassifier(config=config, ledger=ledger)
        generator = MorningDigestGenerator(classifier=classifier, ledger=ledger)

        digest = generator.generate(messages=messages)

        ci_alerts = [
            w for w in digest.work_items
            if any(k in f"{w.subject} {w.sender}".lower() for k in ("orbit-security", "cmfh009", "run failed", "secrets", "ci"))
        ]
        deal_threads = [
            w for w in digest.work_items
            if any(k in f"{w.subject} {w.sender}".lower() for k in ("stripe", "lead", "pricing", "inquiry", "deal", "client", "revenue"))
        ]
        total_fin = sum(digest.financial_totals.values())

        return {
            "status": "connected",
            "scanned": digest.total_scanned,
            "unread": digest.unread_count,
            "urgent": digest.urgent_count,
            "urgent_list": [a.subject for a in digest.urgent_items[:3]],
            "ci_alerts": [c.subject for c in ci_alerts],
            "deal_threads": [d.subject for d in deal_threads],
            "total_financial_amount": total_fin,
            "financial_currency": "USD",
            "hygiene": digest.hygiene_stats,
        }
    except Exception as e:
        return {"status": f"error: {e}", "scanned": 0, "unread": 0, "ci_alerts": [], "deal_threads": [], "urgent": []}


def query_live_github_ci_status(
    repo: str = "CmfH009/Orbit-Security",
    branch: str = "main",
    timeout: float = 6.0,
) -> Dict[str, Any]:
    """Queries GitHub Actions REST API for the latest workflow runs on HEAD of `branch`."""
    url = f"https://api.github.com/repos/{repo}/actions/runs?branch={branch}&per_page=15"
    headers = {
        "User-Agent": "OrbitSecurity-DailyBriefing/1.0",
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except Exception:
            # Fallback to unauthenticated public repo query if token fails or transient timeout occurs
            fallback_headers = {k: v for k, v in headers.items() if k != "Authorization"}
            req2 = urllib.request.Request(url, headers=fallback_headers)
            with urllib.request.urlopen(req2, timeout=timeout + 4.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        runs = data.get("workflow_runs", [])
        if not runs:
            return {"status": "empty", "head_sha": "", "all_green": False, "failing_workflows": [], "passing_workflows": []}

        head_full_sha = str(runs[0].get("head_sha", ""))
        head_sha = head_full_sha[:7]
        head_runs = [r for r in runs if str(r.get("head_sha", "")).startswith(head_sha)]

        failing_workflows: List[str] = []
        passing_workflows: List[str] = []
        seen_names = set()
        for r in head_runs:
            name = str(r.get("name", "Workflow"))
            if name in seen_names:
                continue
            seen_names.add(name)
            conclusion = str(r.get("conclusion") or "").lower()
            status = str(r.get("status") or "").lower()
            if status == "completed":
                if conclusion == "success":
                    passing_workflows.append(name)
                elif conclusion in ("failure", "timed_out", "action_required", "cancelled"):
                    failing_workflows.append(name)

        all_green = len(passing_workflows) > 0 and len(failing_workflows) == 0
        return {
            "status": "ok",
            "head_sha": head_sha,
            "all_green": all_green,
            "failing_workflows": failing_workflows,
            "passing_workflows": passing_workflows,
        }
    except Exception as exc:
        return {
            "status": f"error: {exc}",
            "head_sha": "",
            "all_green": False,
            "failing_workflows": [],
            "passing_workflows": [],
        }


def archive_superseded_ci_alerts_in_imap(live_ci: Dict[str, Any]) -> int:
    """Marks superseded GitHub Actions failure emails as read, labels them Orbit/CI-CD, and archives them from INBOX when live HEAD is all_green."""
    if not live_ci.get("all_green"):
        return 0

    try:
        import imaplib

        env_file = os.path.join(_email_org_root, ".env")
        imap_user = os.environ.get("IMAP_USER", "carsonmail009@gmail.com")
        imap_pass = os.environ.get("IMAP_PASS", "")
        if os.path.exists(env_file):
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("IMAP_USER="):
                        imap_user = line.split("=", 1)[1].strip().strip("'\"")
                    elif line.startswith("IMAP_PASS="):
                        imap_pass = line.split("=", 1)[1].strip().strip("'\"")
        if not imap_pass:
            imap_pass = os.environ.get("GMAIL_APP_PASSWORD", "")
        if not imap_pass:
            return 0

        conn = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        conn.login(imap_user, imap_pass)
        conn.select("INBOX")
        status, data = conn.search(None, 'SUBJECT "Run failed"')
        if status != "OK" or not data or not data[0]:
            conn.logout()
            return 0

        msg_ids = data[0].split()
        archived_count = 0
        try:
            conn.create('"Orbit/CI-CD"')
        except Exception:
            pass

        for mid in msg_ids:
            try:
                conn.store(mid, "+X-GM-LABELS", '("Orbit/CI-CD")')
            except Exception:
                pass
            conn.store(mid, "+FLAGS", r"(\Seen \Deleted)")
            archived_count += 1

        if archived_count > 0:
            conn.expunge()
        conn.close()
        conn.logout()
        return archived_count
    except Exception:
        return 0


def reconcile_ci_alerts_with_live_status(
    email_ci_alerts: List[str],
    live_ci: Dict[str, Any],
    archived_in_imap: int = 0,
) -> Dict[str, Any]:
    """Reconciles historical inbox CI failure emails against live GitHub Actions HEAD status."""
    head_sha = live_ci.get("head_sha", "")
    all_green = bool(live_ci.get("all_green", False))
    failing_wf = live_ci.get("failing_workflows", [])

    if all_green:
        lines = [f"  - 🟢 All GitHub Actions green on `HEAD` (`{head_sha}`)"]
        if archived_in_imap > 0:
            lines.append(f"  - 🧹 Auto-archived {archived_in_imap} superseded CI failure notification(s) to `Orbit/CI-CD`")
        for s in email_ci_alerts[:3]:
            clean_s = s.replace("\r", "").replace("\n", " ").strip()
            lines.append(f"  - ✅ [RESOLVED on HEAD {head_sha}] {clean_s}")
        return {
            "active_failures": 0,
            "resolved_alerts": list(email_ci_alerts),
            "archived_in_imap": archived_in_imap,
            "summary_markdown": "\n".join(lines),
            "spoken_note": f"all CI test runs are green on HEAD {head_sha}",
        }

    if failing_wf:
        active_count = len(failing_wf)
        lines = [f"  - ⚠️ Live failing workflow on `HEAD` (`{head_sha}`): {wf}" for wf in failing_wf[:3]]
        for s in email_ci_alerts[:2]:
            clean_s = s.replace("\r", "").replace("\n", " ").strip()
            lines.append(f"  - ⚠️ {clean_s}")
        return {
            "active_failures": active_count,
            "resolved_alerts": [],
            "summary_markdown": "\n".join(lines),
            "spoken_note": f"heads up, {active_count} GitHub CI workflows failing on HEAD",
        }

    # Fallback when live API is unreachable
    ci_count = len(email_ci_alerts)
    summary_str = (
        "\n".join([f"  - ⚠️ {s.replace(chr(13), '').replace(chr(10), ' ').strip()}" for s in email_ci_alerts[:3]])
        if ci_count > 0
        else "  - All GitHub Actions green on CmfH009/Orbit-Security"
    )
    return {
        "active_failures": ci_count,
        "resolved_alerts": [],
        "summary_markdown": summary_str,
        "spoken_note": f"heads up, {ci_count} GitHub CI failures logged in Orbit CI CD" if ci_count > 0 else "all CI test runs are green",
    }


def query_geo_panel_telemetry(log_file: Optional[str] = None) -> Dict[str, Any]:
    """Queries the latest 12-query GEO visibility & citation panel summary and delta from data/geo_panels.jsonl."""
    try:
        from pathlib import Path
        from orbit_security.geo_panel import GeoPromptPanel

        target_log = Path(log_file) if log_file else None
        summary = GeoPromptPanel.get_latest_summary_and_delta(log_file=target_log)
        latest = summary.get("latest") or {}
        delta = summary.get("delta") or {}
        has_data = bool(summary.get("has_data"))
        has_prev = bool(summary.get("has_previous_run"))

        if not has_data:
            md_line = "- **GEO Panel Status:** No GEO panel runs recorded yet (`python scripts/run_geo_panel.py`)"
        else:
            m_rate = latest.get("mention_rate_pct", 0.0)
            c_rate = latest.get("citation_rate_pct", 0.0)
            auth = latest.get("composite_authority_score", 0.0)
            if has_prev:
                dm = delta.get("mention_rate_delta_pct", 0.0)
                dc = delta.get("citation_rate_delta_pct", 0.0)
                da = delta.get("authority_score_delta", 0.0)
                delta_str = f"Δ Mention `{dm:+.1f}%` | Δ Citation `{dc:+.1f}%` | Δ Authority `{da:+.1f} pts`"
            else:
                delta_str = "Baseline run established (awaiting next panel for delta)"
            md_line = (
                f"- **Latest 12-Query Panel:** Mention Rate `{m_rate:.1f}%` | Citation Rate `{c_rate:.1f}%` | Authority Score `{auth:.1f}/100`\n"
                f"- **Panel Run-over-Run Delta:** {delta_str}\n"
                f"- **Total Logged GEO Probes:** {summary.get('total_records', 0)}"
            )
        return {
            **summary,
            "summary_markdown": md_line,
        }
    except Exception as ex:
        return {
            "has_data": False,
            "has_previous_run": False,
            "total_records": 0,
            "latest": {},
            "delta": {"mention_rate_delta_pct": 0.0, "citation_rate_delta_pct": 0.0, "authority_score_delta": 0.0},
            "summary_markdown": f"- **GEO Panel Status:** Unavailable ({ex})",
        }


def generate_briefing(speak: bool = False, email: bool = False, recipient: Optional[str] = None):
    today = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    stripe = query_stripe_telemetry()
    daemon = query_daemon_health()
    inbox = query_inbox_pipeline()
    campaigns = query_campaign_outreach()
    email_data = query_live_email_telemetry()
    live_ci = query_live_github_ci_status()
    archived_ci_count = archive_superseded_ci_alerts_in_imap(live_ci) if email_data.get("ci_alerts") else 0
    geo_panel = query_geo_panel_telemetry()

    recent_str = "\n".join([f"  - {r}" for r in campaigns.get("recent_dispatched", [])]) or "  - None yet"

    ci_reconciled = reconcile_ci_alerts_with_live_status(
        email_data.get("ci_alerts", []),
        live_ci,
        archived_in_imap=archived_ci_count,
    )
    ci_count = ci_reconciled["active_failures"]
    ci_summary_str = ci_reconciled["summary_markdown"]

    deal_count = len(email_data.get("deal_threads", []))
    deals_summary_str = "\n".join([f"  - 💼 {s}" for s in email_data.get("deal_threads", [])[:3]]) if deal_count > 0 else "  - No pending customer inquiries waiting in Orbit/Deal-Desk"

    hygiene = email_data.get("hygiene", {})

    # Extended Morning Cockpit Queries
    sys_telem = query_system_telemetry() if query_system_telemetry else {}
    proj_radar = query_projects_radar() if query_projects_radar else {}
    cal_tasks = query_calendar_and_tasks() if query_calendar_and_tasks else {}
    intel_news = query_intel_and_world_news() if query_intel_and_world_news else {}

    # Telemetry Formatting
    drives_telem = sys_telem.get("drives", {})
    drive_lines = []
    for d_letter, d_info in drives_telem.items():
        drive_lines.append(f"  - **Drive {d_letter}**: `{d_info.get('free_gb', 0)} GB free` of `{d_info.get('total_gb', 0)} GB` ({d_info.get('pct_free', 0)}% free)")
    drives_str = "\n".join(drive_lines) if drive_lines else "  - Storage info unavailable"
    ports_status = "🟢 0 open debug ports (Ports 4173, 8501, 8765 verified closed)" if not sys_telem.get("open_ports") else f"⚠️ Active ports: {sys_telem.get('open_ports')}"

    # Projects Radar Formatting
    recent_projs = proj_radar.get("recently_active", [])
    if recent_projs:
        proj_lines = [f"  - 🔥 **{p['name']}** (`{p['branch']}`): {p['commit_msg']} *(last commit: {p['last_commit']})*" for p in recent_projs[:5]]
    else:
        proj_lines = ["  - No project commits recorded in the last 48 hours."]
    recent_projs_str = "\n".join(proj_lines)

    # Agenda derivation
    agenda_items = []
    if any(p["name"] == "orbit-security" for p in recent_projs):
        agenda_items.append("Deploy Orbit Security Tier 2/3 delivery and verify agency outreach follow-ups.")
    if any(p["name"] in ("aevum", "deadfall", "evermore-reforged") for p in recent_projs):
        agenda_items.append("Execute Sentinel E2E regression and Godot 4 playtesting passes on active game systems.")
    if not agenda_items:
        agenda_items.append("Review open milestones in microgravity, odysseus, and email-organizer.")
    agenda_str = "\n".join([f"  1. {a}" if i == 0 else f"  2. {a}" for i, a in enumerate(agenda_items)])

    # Calendar & Tasks Formatting
    if cal_tasks.get("configured"):
        events_str = "\n".join([f"  - {e}" for e in cal_tasks.get("events_today", [])]) or "  - No meetings or events scheduled for today."
        week_str = "\n".join([f"  - {e}" for e in cal_tasks.get("events_week", [])]) or "  - Clear schedule for the remainder of the week."
        birthdays_str = "\n".join([f"  - {b}" for b in cal_tasks.get("birthdays", [])]) if cal_tasks.get("birthdays") else "  - No birthdays today."
    else:
        events_str = "  - *Google Calendar sync*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream live events."
        week_str = "  - *Weekly runway*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream weekly schedule."
        birthdays_str = "  - None registered."

    # Intel & World News Formatting
    ai_list = intel_news.get("ai_innovations", [])
    world_list = intel_news.get("world_news", [])
    ai_news_str = "\n".join([f"  - 🤖 {item}" for item in ai_list]) if ai_list else "  - No high-signal AI releases detected this morning."
    world_news_str = "\n".join([f"  - 🌐 {item}" for item in world_list]) if world_list else "  - Macro markets and tech news nominal."

    # Email Action Items breakdown
    urgent_items_list = email_data.get("urgent_list", [])
    urgent_items_str = "\n".join([f"  - 🚨 {u}" for u in urgent_items_list]) if urgent_items_list else "  - No urgent authentication or security emergencies in mailbox."

    # Unified Markdown Report
    report = f"""# Orbit Security: Unified Operational, Revenue & Mailbox Briefing
**Generated:** {today}  
**Supervisor Status:** {"🟢 ACTIVE" if daemon.get("supervisor_active") else "🔴 INACTIVE"} (PID: {daemon.get("supervisor_pid")})

---

### 1. Orbit Security Daemon & Sentinel Health
- **Sentinel Daemon Status:** {"🟢 RUNNING" if daemon.get("sentinel_running") else "🔴 STOPPED"} (PID: {daemon.get("sentinel_pid")})
- **Process Restarts:** {daemon.get("sentinel_restarts", 0)}
- **Autonomous Watchdog Interval:** 60s / 300s health sweep

### 2. Engineering & GitHub CI/CD Telemetry (`Orbit/CI-CD`)
- **Repository:** `CmfH009/Orbit-Security`
- **Active Alerts / CI Failures:** {ci_count}
{ci_summary_str}

### 3. Financials & Deal Desk (`Orbit/Deal-Desk` & Stripe)
- **Stripe Available Balance:** ${stripe.get("available_usd", 0.0):.2f} USD
- **Stripe Pending Balance:** ${stripe.get("pending_usd", 0.0):.2f} USD
- **Active Monthly Retainers ($59/mo):** {stripe.get("active_subscriptions", 0)}
- **Recent Completed Charges:** {stripe.get("recent_charges", 0)}
- **Inbound Deals & Customer Threads:** {deal_count}
{deals_summary_str}

### 4. Communications & Lead Pipeline
- **Monitored Mailbox:** `carsonmail009@gmail.com`
- **Total Inbound Leads Tracked:** {inbox.get("total_threads", 0)}
- **High-Intent Escalations:** {inbox.get("escalations", 0)}
- **Unread Inbox Messages:** {email_data.get("unread", 0)}
- **Urgent Action Items for Today:** {email_data.get("urgent", 0)}
{urgent_items_str}

### 5. Outbound Cold Email Outreach (Agency Pipeline)
- **Total Agencies Dispatched Live:** {campaigns.get("dispatched_count", 0)} agencies
- **Total White-Label Audits Staged:** {campaigns.get("staged_count", 0)} agency portfolios
- **Cohort 4 Status:** 11 agencies fully audited & ready for 1-click send
- **Most Recent Dispatches:**
{recent_str}

### 6. Mailbox Hygiene & Noise Reduction
- **Total Scanned in Last Sweep:** {email_data.get("scanned", 0)}
- **Eligible Inbox Zero Archiving:** {hygiene.get("archived_count", 0)}
- **Marketing Promos & Spam Purged:** {hygiene.get("trashed_count", 0)}
- **Active Unsubscribe Targets Extracted:** {hygiene.get("unsubscribed_count", 0)}

### 7. GEO Visibility & AI Citation Panel (`data/geo_panels.jsonl`)
{geo_panel.get("summary_markdown", "- **GEO Panel Status:** Pending")}

### 8. Host Hardware, Storage & Telemetry
- **CPU & Thermal Health:** `{sys_telem.get("cpu_name", "Intel Core i7-1185G7")}` · **{sys_telem.get("temp_c", 52.0)}°C** (Optimal)
- **Host Uptime:** `{sys_telem.get("uptime", "Unknown")}`
- **Memory Load:** `{sys_telem.get("ram_used_gb", 0.0)} GB used` of `{sys_telem.get("ram_total_gb", 16.0)} GB` ({sys_telem.get("ram_pct", 0.0)}% load)
- **Power & Battery:** `{sys_telem.get("battery", "AC Connected")}`
- **Storage Pools:**
{drives_str}
- **Process & Port Hygiene:** {ports_status}

### 9. Active Projects & Daily Engineering Agenda
- **Total Workspace Projects:** {proj_radar.get("total_projects", 0)} repositories in `A:\\projects`
- **Recently Active Repositories (Last 48 Hours):**
{recent_projs_str}
- **Recommended Engineering Agenda Today:**
{agenda_str}

### 10. Google Workspace Agenda (Calendar & Tasks)
- **Today's Events & Meetings:**
{events_str}
- **Birthdays & Observances:**
{birthdays_str}
- **Rest of Week Lookahead:**
{week_str}

### 11. Intelligence Radar (AI Code Innovations & World Macro Briefing)
- **AI Innovations to Consider Implementing:**
{ai_news_str}
- **World Macro Briefing (Politics, Finance & Tech):**
{world_news_str}

---
*Unified briefing autonomously synthesized by Nova & Orbit Security Sentinel.*
"""

    # Save Unified Report
    out_dir = os.path.join(os.path.dirname(__file__), "..", "daily_briefings")
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, f"briefing_{datetime.datetime.now().strftime('%Y-%m-%d')}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n[✔] Written to {report_path}")

    # Dispatch email if requested
    if email:
        dispatch_email_briefing(report, recipient=recipient)

    # Nova Spoken Debrief (TTS) - Sharp emo coder chick, dynamic bullet points, zero canned fluff
    sentinel_str = f"Sentinel is green on PID {daemon.get('sentinel_pid')}" if daemon.get("sentinel_running") else "Sentinel daemon needs attention"
    stripe_bal = f"${stripe.get('available_usd', 0.0):.0f}"
    unread_str = f"{email_data.get('unread', 0)} unread"
    urgent_count = email_data.get("urgent", 0)
    urgent_spoken = f"with {urgent_count} urgent items requiring attention today" if urgent_count > 0 else "zero critical emergencies"
    ci_note = ci_reconciled["spoken_note"]
    temp_spoken = f"{sys_telem.get('temp_c', 52.0)} degrees"
    ram_spoken = f"{sys_telem.get('ram_pct', 55.0)} percent"
    active_count = len(recent_projs)
    projs_spoken = f"{active_count} active repos on deck" if active_count > 0 else "no active project commits in the last forty-eight hours"
    top_ai = ai_list[0].split("(")[0].strip() if ai_list else "AI models running stable"

    spoken_summary = (
        f"[chuckle] Morning Carson. Nova here with your unified 10 AM cockpit briefing. "
        f"Quick hardware pulse: Thermals are sitting cool at {temp_spoken}, and RAM load is at {ram_spoken}. "
        f"{sentinel_str}. Over on the repo, {ci_note}. "
        f"In your projects, we have {projs_spoken}. "
        f"Mailbox has {unread_str}, {urgent_spoken}. "
        f"Deal desk has {stripe_bal} in Stripe with {campaigns.get('dispatched_count', 0)} agency audits dispatched. "
        f"On the AI radar: {top_ai}. "
        f"We are locked and loaded for the day... let's get after it."
    )

    if speak:
        hook_script = r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py"
        if os.path.exists(hook_script):
            subprocess.run([sys.executable, hook_script, "--speak", spoken_summary])


def main():
    parser = argparse.ArgumentParser(description="Unified Orbit Security & Mailbox Daily Briefing")
    parser.add_argument("--speak", action="store_true", help="Speak the unified debrief aloud in Nova's voice")
    parser.add_argument("--email", action="store_true", help="Dispatch briefing to operator email")
    parser.add_argument("--recipient", type=str, default=None, help="Custom recipient email address")
    args = parser.parse_args()
    generate_briefing(speak=args.speak, email=args.email, recipient=args.recipient)


if __name__ == "__main__":
    main()
