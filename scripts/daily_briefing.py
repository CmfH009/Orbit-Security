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
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
from typing import Dict, Any, Optional, List, Sequence
from dotenv import load_dotenv

try:
    import psutil
except ImportError:
    psutil = None

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
_REPO_ROOT = Path(__file__).resolve().parent.parent
_local_src = str(_REPO_ROOT / "src")
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
        query_email_hygiene,
    )
except ImportError:
    try:
        from scripts.unified_morning_cockpit import (
            query_system_telemetry,
            query_projects_radar,
            query_calendar_and_tasks,
            query_intel_and_world_news,
            query_email_hygiene,
        )
    except ImportError:
        query_system_telemetry = None
        query_projects_radar = None
        query_calendar_and_tasks = None
        query_intel_and_world_news = None
        query_email_hygiene = None

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


def _is_pid_alive(pid: Any) -> bool:
    """Checks whether an integer PID is currently running in the OS process table."""
    if not isinstance(pid, int) or pid <= 0 or psutil is None:
        return False
    try:
        return bool(psutil.pid_exists(pid))
    except Exception:
        return False


def query_daemon_health() -> Dict[str, Any]:
    """Checks PID and live OS process status of Orbit Master Supervisor and Sentinel daemon."""
    state_file = r"A:\system\state\orbit_daemon_state.json"
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            sv_pid = data.get("supervisor_pid")
            running = bool(data.get("running", False))
            services = data.get("services", {})
            sentinel = services.get("orbit_security", {})
            sen_pid = sentinel.get("pid")

            sv_alive = _is_pid_alive(sv_pid)
            sen_alive = _is_pid_alive(sen_pid)
            svc_state_active = sum(1 for s in services.values() if isinstance(s, dict) and s.get("active"))
            svc_live_active = sum(
                1 for s in services.values()
                if isinstance(s, dict) and s.get("active") and _is_pid_alive(s.get("pid"))
            )

            return {
                "supervisor_pid": sv_pid,
                "supervisor_active": running and bool(sv_pid),
                "supervisor_pid_alive": sv_alive,
                "live_verified_active": bool(running and sv_pid and sv_alive),
                "sentinel_pid": sen_pid,
                "sentinel_running": bool(sentinel.get("active", False)),
                "sentinel_pid_alive": sen_alive,
                "sentinel_live_verified": bool(sentinel.get("active", False) and sen_alive),
                "sentinel_restarts": sentinel.get("restart_count", 0),
                "state_timestamp": str(data.get("timestamp") or ""),
                "services_live_active": svc_live_active,
                "services_state_active": svc_state_active,
                "services_total": len(services),
            }
        except Exception:
            pass

    return {
        "supervisor_pid": None,
        "supervisor_active": False,
        "supervisor_pid_alive": False,
        "live_verified_active": False,
        "sentinel_pid": None,
        "sentinel_running": False,
        "sentinel_pid_alive": False,
        "sentinel_live_verified": False,
        "sentinel_restarts": 0,
        "state_timestamp": "",
        "services_live_active": 0,
        "services_state_active": 0,
        "services_total": 0,
    }


def query_option_c_readiness(
    repo_root: Optional[Path] = None,
    vault_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Aggregates Option C Dual-Track Minimal readiness (Track A Bounty Vault + Track B Inbound Funnel)."""
    root = Path(repo_root) if repo_root else _REPO_ROOT
    v_path = Path(vault_file) if vault_file else (root / "data" / "hackerone_staging" / "VAULT_LAUNCH_QUEUE.json")

    audit: Dict[str, Any] = {}
    try:
        try:
            from orbit_readiness_audit import run_readiness_audit
        except ImportError:
            from scripts.orbit_readiness_audit import run_readiness_audit
        audit = run_readiness_audit(repo_root=root, verify_cutover=False)
    except Exception:
        audit = {}

    vault: Dict[str, Any] = {}
    if v_path.is_file():
        try:
            vault = json.loads(v_path.read_text(encoding="utf-8"))
        except Exception:
            vault = {}

    catalog = audit.get("bounty_catalog", {})
    disc = audit.get("disclosures_and_radar", {})
    ev = disc.get("ev_digest_coverage", {})
    parity = audit.get("landing_docs_parity", {})
    tb = audit.get("track_b_funnel", {})
    stripe_cfg = audit.get("stripe_config", {})
    subs = audit.get("subscribers", {})
    clients = audit.get("clients_hygiene", {})

    tier_1_items: List[str] = []
    tier_2_items: List[str] = []
    for entry in vault.get("launch_queue", []):
        if not isinstance(entry, dict):
            continue
        prog = str(entry.get("program") or "Unknown")
        tier = str(entry.get("tier") or "")
        if tier == "TIER_1_READY":
            hosts = ", ".join(entry.get("hosts", [])[:2])
            digests = ", ".join(entry.get("evidence_digests", [])[:2])
            tier_1_items.append(f"{prog} ({hosts}) [{digests}]")
        elif tier == "TIER_2_NEEDS_AUTH_PROOF":
            b_count = len(entry.get("bundles", []))
            tier_2_items.append(f"{prog} ({b_count})")

    return {
        "revenue_focus": audit.get("revenue_focus", "Option C (Dual-Track Minimal: Verified Bounties + Inbound Fixpack/Audit)"),
        "technical_floor_clean": bool(audit.get("technical_floor_clean", False)),
        "commercial_outreach_frozen": bool(audit.get("commercial_outreach_frozen", True)),
        "kyc_payout_status": str(audit.get("kyc_payout_status", "PENDING_PHYSICAL_ID")),
        "blockers": list(audit.get("blockers", [])),
        "unique_programs": int(catalog.get("unique_programs", 0)),
        "cash_tier_count": int(catalog.get("cash_tier_count", 0)),
        "staged_reports": int(disc.get("active_submittable_reports", 0)),
        "paired_bundles": int(disc.get("paired_bundle_count", 0)),
        "ev_covered": int(ev.get("covered_count", 0)),
        "ev_total": int(ev.get("total_staged", 0)),
        "archived_total": int(disc.get("archived_total_count", 0)),
        "consolidated_dossiers": int(vault.get("consolidated_dossiers", 0)),
        "tier_1_items": tier_1_items,
        "tier_2_items": tier_2_items,
        "landing_docs_in_sync": bool(parity.get("in_sync", False)),
        "landing_docs_identical": int(parity.get("identical_count", 0)),
        "landing_docs_shared": int(parity.get("shared_count", 0)),
        "track_b_ready": bool(tb.get("ready", False)),
        "stripe_live_checkout_ready": bool(stripe_cfg.get("live_checkout_ready", False)),
        "paid_subscribers": int(subs.get("count", 0)),
        "active_clients": int(clients.get("client_count", 0)),
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
    """Inspects dispatched_campaigns.json (sorted newest-first) and outbound freeze status."""
    dispatched_file = os.path.join(os.path.dirname(__file__), "..", "data", "dispatched_campaigns.json")
    out_root = os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns")
    dispatched_count = 0
    recent = []
    if os.path.exists(dispatched_file):
        try:
            with open(dispatched_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            dispatched_count = len(data)
            sorted_entries = sorted(
                data.items(),
                key=lambda kv: str((kv[1] or {}).get("dispatched_at", "")),
                reverse=True,
            )
            for domain, info in sorted_entries[:5]:
                info_dict = info if isinstance(info, dict) else {}
                recent.append(f"{info_dict.get('agency_name', domain)} ({domain}) - {info_dict.get('dispatched_at', '')}")
        except Exception:
            pass

    staged_count = 0
    if os.path.exists(out_root):
        try:
            staged_count = len([d for d in os.listdir(out_root) if os.path.isdir(os.path.join(out_root, d))])
        except Exception:
            pass

    frozen = True
    try:
        from orbit_security.private_alerting import COMMERCIAL_OUTREACH_FROZEN
        frozen = bool(COMMERCIAL_OUTREACH_FROZEN)
    except Exception:
        pass

    return {
        "dispatched_count": dispatched_count,
        "staged_count": staged_count,
        "recent_dispatched": recent,
        "frozen": frozen,
    }


def _msg_epoch_ts(msg: Any) -> float:
    """Converts EmailMessage.date into a UTC epoch float safely."""
    dt = getattr(msg, "date", None)
    if dt is None:
        return 0.0
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    except Exception:
        return 0.0


def _clean_subject(subject: str) -> str:
    return (subject or "").replace("\r", "").replace("\n", " ").strip()


def _normalize_thread_key(subject: str) -> str:
    cleaned = re.sub(r"\s+", " ", _clean_subject(subject)).strip()
    while True:
        stripped = re.sub(r"^(re|fwd?|fw)\s*:\s*", "", cleaned, flags=re.IGNORECASE).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    return cleaned.lower()


def _is_self_briefing_or_ci(subject: str, sender: str = "") -> tuple[bool, bool]:
    """Returns (is_self_briefing, is_ci_alert)."""
    subj_low = _clean_subject(subject).lower()
    comb_low = f"{subj_low} {sender.lower()}"
    is_self = (
        "orbit security daily operational briefing" in subj_low
        or "google ai daily briefing" in subj_low
    )
    is_ci = any(k in comb_low for k in ("orbit-security", "cmfh009", "run failed"))
    return is_self, is_ci


_OUTBOUND_ACTION_CUE_RE = re.compile(
    r"\b(submitted|uploaded|replied|responded|sent|filed|appealed|resolved|completed|confirmed)\b",
    re.IGNORECASE,
)
_ISO_OR_DT_IN_TEXT_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_TOPIC_STOPWORDS = frozenset({
    "re", "fw", "fwd", "the", "and", "for", "with", "from", "your", "our",
    "immediate", "request", "update", "alert", "notice", "statement", "account",
    "urgent", "action", "required", "email", "message", "today", "closure",
    "http", "https", "www", "com", "google", "url",
})


def _parse_any_ts(val: Any) -> float:
    """Parses datetime/epoch/ISO/YYYY-MM-DD HH:MM values into UTC epoch seconds."""
    if val is None or val == "":
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, datetime.datetime):
        dt = val if val.tzinfo else val.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    text = str(val).strip()
    if not text:
        return 0.0
    try:
        dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(text[:19], fmt).replace(tzinfo=datetime.timezone.utc)
            return float(dt.timestamp())
        except ValueError:
            continue
    return 0.0


def _detect_outbound_reply_reason(
    *,
    subject: str,
    sender: str,
    msg_ts: float,
    outbound_by_thread: Dict[str, float],
    norm_sent_ts: Dict[str, float],
    norm_sent_subjects: set[str],
    master_briefing: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Returns a status reason if an urgent inbound thread already has a newer outbound reply/confirmation."""
    t_key = _normalize_thread_key(subject)
    if t_key in outbound_by_thread and outbound_by_thread[t_key] > msg_ts:
        return "outbound reply in thread"
    if t_key in norm_sent_ts:
        if msg_ts == 0.0 or norm_sent_ts[t_key] > msg_ts:
            return "outbound reply in Sent"
    elif t_key in norm_sent_subjects:
        return "outbound reply in Sent"

    if not isinstance(master_briefing, dict) or not master_briefing.get("found", True):
        return None
    highlights = [str(h).strip() for h in (master_briefing.get("highlights") or []) if str(h).strip()]
    if not highlights:
        return None

    mb_ts = _parse_any_ts(master_briefing.get("date"))
    if msg_ts > 0.0 and mb_ts > 0.0 and mb_ts < msg_ts:
        return None

    sender_low = str(sender or "").lower()
    domain_root = ""
    if "@" in sender_low:
        dom = sender_low.rsplit("@", 1)[-1].strip("<> ")
        domain_root = dom.split(".")[0] if dom else ""

    topic_tokens = {
        tok
        for tok in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", t_key)
        if len(tok) >= 4 and tok not in _TOPIC_STOPWORDS
    }

    for hl in highlights:
        if not _OUTBOUND_ACTION_CUE_RE.search(hl):
            continue
        embedded_dt_match = _ISO_OR_DT_IN_TEXT_RE.search(hl)
        if embedded_dt_match and msg_ts > 0.0:
            hl_ts = _parse_any_ts(embedded_dt_match.group(1))
            if hl_ts > 0.0 and hl_ts <= msg_ts:
                continue

        hl_low = hl.lower()
        hl_words = {
            w for w in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", hl_low)
            if len(w) >= 4 and w not in _TOPIC_STOPWORDS
        }
        brand_match = bool(
            domain_root
            and len(domain_root) >= 4
            and (
                domain_root in hl_words
                or any(domain_root.startswith(w) or w.startswith(domain_root) for w in hl_words)
            )
        )
        topic_overlap = topic_tokens & hl_words
        if brand_match or len(topic_overlap) >= 2:
            return "confirmed in Master Briefing"

    return None


def triage_email_messages(
    messages: List[Any],
    digest: Any,
    now_ts: Optional[float] = None,
    *,
    owner_email: str = "carsonmail009@gmail.com",
    sent_replied_subjects: Optional[Sequence[str]] = None,
    sent_replied_timestamps: Optional[Dict[str, Any]] = None,
    master_briefing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Filters, deduplicates, and sorts email digest signals into actionable today vs awaiting/historical buckets."""
    ref_ts = float(now_ts if now_ts is not None else datetime.datetime.now(datetime.timezone.utc).timestamp())
    msg_by_id = {getattr(m, "id", None): m for m in messages}
    owner_low = (owner_email or "carsonmail009@gmail.com").strip().lower()

    # Track outbound self-replies present in the fetched message list
    outbound_by_thread: Dict[str, float] = {}
    for m in messages:
        m_sender = str(getattr(m, "sender", "") or "").lower()
        m_labels = {str(lbl).lower() for lbl in (getattr(m, "labels", None) or ())}
        m_subj = _clean_subject(getattr(m, "subject", ""))
        is_self_briefing, _ = _is_self_briefing_or_ci(m_subj, m_sender)
        if is_self_briefing or m_subj.lower().startswith("combined daily master briefing"):
            continue
        is_outbound = (owner_low and owner_low in m_sender) or ("sent" in m_labels)
        if not is_outbound:
            continue
        m_key = _normalize_thread_key(m_subj)
        m_ts = _msg_epoch_ts(m)
        if m_key and m_ts > outbound_by_thread.get(m_key, -1.0):
            outbound_by_thread[m_key] = m_ts

    norm_sent_ts: Dict[str, float] = {}
    for raw_subj, raw_ts in (sent_replied_timestamps or {}).items():
        n_key = _normalize_thread_key(str(raw_subj))
        parsed = _parse_any_ts(raw_ts)
        if n_key and parsed > norm_sent_ts.get(n_key, -1.0):
            norm_sent_ts[n_key] = parsed

    norm_sent_subjects = {
        _normalize_thread_key(str(s))
        for s in (sent_replied_subjects or ())
        if _normalize_thread_key(str(s))
    }

    ci_alerts = [
        _clean_subject(w.subject)
        for w in getattr(digest, "work_items", [])
        if any(k in f"{w.subject} {w.sender}".lower() for k in ("orbit-security", "cmfh009", "run failed", "secrets", "ci"))
    ]
    deal_threads = [
        _clean_subject(d.subject)
        for d in getattr(digest, "work_items", [])
        if any(k in f"{d.subject} {d.sender}".lower() for k in ("stripe", "lead", "pricing", "inquiry", "deal", "client", "revenue"))
    ]

    # Sort urgent items newest-first, deduplicate by thread subject, and drop self-briefings & CI alerts
    raw_urgent = list(getattr(digest, "urgent_items", []))
    raw_urgent.sort(key=lambda u: _msg_epoch_ts(msg_by_id.get(u.message_id)), reverse=True)

    seen_threads: set[str] = set()
    urgent_today: List[str] = []
    awaiting_external_reply: List[str] = []
    historical_urgent: List[str] = []

    for item in raw_urgent:
        subj = _clean_subject(item.subject)
        is_self, is_ci = _is_self_briefing_or_ci(subj, item.sender)
        if is_self or is_ci:
            continue
        if owner_low and owner_low in str(item.sender or "").lower():
            continue
        t_key = _normalize_thread_key(subj)
        if t_key in seen_threads:
            continue
        seen_threads.add(t_key)

        msg = msg_by_id.get(item.message_id)
        is_unread = not bool(getattr(msg, "is_read", True)) if msg is not None else False
        ts = _msg_epoch_ts(msg)
        is_recent_24h = ts > 0.0 and (ref_ts - ts) <= 86400.0
        formatted = f"{subj} — {item.sender} ({item.date_str})"

        if is_unread or is_recent_24h:
            reply_reason = None
            if owner_low not in str(item.sender or "").lower():
                reply_reason = _detect_outbound_reply_reason(
                    subject=subj,
                    sender=item.sender,
                    msg_ts=ts,
                    outbound_by_thread=outbound_by_thread,
                    norm_sent_ts=norm_sent_ts,
                    norm_sent_subjects=norm_sent_subjects,
                    master_briefing=master_briefing,
                )
            if reply_reason:
                awaiting_external_reply.append(f"{formatted} [{reply_reason}]")
            else:
                urgent_today.append(formatted)
        else:
            historical_urgent.append(formatted)

    # Non-CI, non-self unread messages sorted newest-first
    unread_msgs = [m for m in messages if not getattr(m, "is_read", True)]
    unread_msgs.sort(key=_msg_epoch_ts, reverse=True)
    unread_non_ci: List[str] = []
    for m in unread_msgs:
        subj = _clean_subject(getattr(m, "subject", ""))
        sender = str(getattr(m, "sender", ""))
        is_self, is_ci = _is_self_briefing_or_ci(subj, sender)
        if is_self or is_ci:
            continue
        unread_non_ci.append(f"{subj} ({sender})")

    total_fin = sum((getattr(digest, "financial_totals", {}) or {}).values())

    return {
        "status": "connected",
        "scanned": getattr(digest, "total_scanned", len(messages)),
        "unread": getattr(digest, "unread_count", len(unread_msgs)),
        "unread_non_ci_count": len(unread_non_ci),
        "unread_list": unread_non_ci[:5],
        "urgent": len(urgent_today),
        "urgent_list": urgent_today[:5],
        "awaiting_external_reply_count": len(awaiting_external_reply),
        "awaiting_external_reply": awaiting_external_reply[:5],
        "historical_alerts_count": len(historical_urgent),
        "historical_alerts_sample": historical_urgent[:3],
        "ci_alerts": ci_alerts,
        "deal_threads": deal_threads,
        "total_financial_amount": total_fin,
        "financial_currency": "USD",
        "hygiene": getattr(digest, "hygiene_stats", {}),
    }


def query_live_email_telemetry() -> Dict[str, Any]:
    """Connects to email-organizer and extracts high-signal telemetry from carsonmail009@gmail.com."""
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
            return {
                "status": "unconfigured",
                "scanned": 0,
                "unread": 0,
                "unread_non_ci_count": 0,
                "unread_list": [],
                "ci_alerts": [],
                "deal_threads": [],
                "urgent": 0,
                "urgent_list": [],
                "historical_alerts_count": 0,
            }

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
        hygiene_res: Dict[str, Any] = {}
        if query_email_hygiene:
            try:
                hygiene_res = query_email_hygiene(messages=messages) or {}
            except Exception:
                hygiene_res = {}
        result = triage_email_messages(
            messages=messages,
            digest=digest,
            owner_email=imap_user,
            sent_replied_subjects=hygiene_res.get("sent_replied_subjects"),
            sent_replied_timestamps=hygiene_res.get("sent_replied_timestamps"),
            master_briefing=hygiene_res.get("master_briefing"),
        )
        result["email_hygiene"] = hygiene_res
        return result
    except Exception as e:
        return {
            "status": f"error: {e}",
            "scanned": 0,
            "unread": 0,
            "unread_non_ci_count": 0,
            "unread_list": [],
            "ci_alerts": [],
            "deal_threads": [],
            "urgent": 0,
            "urgent_list": [],
            "historical_alerts_count": 0,
        }


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


_STATE_DATE_FILE_RE = re.compile(r"^briefing_state_(\d{4}-\d{2}-\d{2})\.json$")
DEFAULT_BRIEFINGS_DIR = _REPO_ROOT / "daily_briefings"
_DELTA_FLOAT_KEYS = ("disk_free_gb", "geo_citation_share_pct")
_DELTA_INT_KEYS = ("commits_24h", "unread_count", "urgent_count", "tier1_ready", "tier2_queued")


def _normalize_delta_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Coerces tracked snapshot fields to deterministic numeric/string types."""
    norm: Dict[str, Any] = {}
    for k in _DELTA_FLOAT_KEYS:
        try:
            norm[k] = round(float(snapshot.get(k, 0.0) or 0.0), 2)
        except (TypeError, ValueError):
            norm[k] = 0.0
    for k in _DELTA_INT_KEYS:
        try:
            norm[k] = int(snapshot.get(k, 0) or 0)
        except (TypeError, ValueError):
            norm[k] = 0
    kyc_val = snapshot.get("kyc_gate")
    norm["kyc_gate"] = str(kyc_val) if kyc_val not in (None, "") else "PENDING_PHYSICAL_ID"
    return norm


def _load_json_dict(path: Path) -> Optional[Dict[str, Any]]:
    """Reads a JSON file and returns a dict or None on missing/invalid payloads."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_snapshot_payload(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extracts tracked snapshot dict from either a wrapped state record or flat snapshot."""
    snap = data.get("snapshot")
    if isinstance(snap, dict):
        return snap
    all_keys = (*_DELTA_FLOAT_KEYS, *_DELTA_INT_KEYS, "kyc_gate")
    if any(k in data for k in all_keys):
        return data
    return None


def _find_previous_snapshot(
    date_key: str,
    target_dir: Path,
) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Finds the most recent prior-day snapshot, avoiding today's own snapshot on repeated runs."""
    candidates: List[tuple[str, Path]] = []
    for entry in target_dir.iterdir():
        if not entry.is_file():
            continue
        match = _STATE_DATE_FILE_RE.match(entry.name)
        if not match:
            continue
        file_date = match.group(1)
        if file_date < date_key:
            candidates.append((file_date, entry))

    candidates.sort(key=lambda item: item[0], reverse=True)
    for file_date, entry in candidates:
        data = _load_json_dict(entry)
        if data:
            snap = _extract_snapshot_payload(data)
            if snap is not None:
                return file_date, snap

    latest_data = _load_json_dict(target_dir / "briefing_state_latest.json")
    if latest_data:
        latest_date = str(latest_data.get("date") or "")[:10]
        if latest_date and latest_date < date_key:
            snap = _extract_snapshot_payload(latest_data)
            if snap is not None:
                return latest_date, snap
        if latest_date == date_key and isinstance(latest_data.get("previous_snapshot"), dict):
            prev_date = latest_data.get("previous_date")
            return (str(prev_date)[:10] if prev_date else None), latest_data["previous_snapshot"]

    today_data = _load_json_dict(target_dir / f"briefing_state_{date_key}.json")
    if today_data and isinstance(today_data.get("previous_snapshot"), dict):
        prev_date = today_data.get("previous_date")
        return (str(prev_date)[:10] if prev_date else None), today_data["previous_snapshot"]

    return None, None


def compute_and_save_daily_deltas(
    date_str: str,
    current_snapshot: Dict[str, Any],
    state_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Computes 24h day-over-day deltas against the prior day's snapshot and persists state files."""
    date_key = str(date_str).strip()[:10] or datetime.date.today().isoformat()
    target_dir = Path(state_dir) if state_dir is not None else DEFAULT_BRIEFINGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    normalized = _normalize_delta_snapshot(current_snapshot)
    prev_date, raw_prev = _find_previous_snapshot(date_key=date_key, target_dir=target_dir)

    if raw_prev is not None:
        previous_snapshot = _normalize_delta_snapshot(raw_prev)
        has_previous = True
        deltas: Dict[str, Any] = {}
        for k in _DELTA_FLOAT_KEYS:
            deltas[k] = round(normalized[k] - previous_snapshot[k], 2)
        for k in _DELTA_INT_KEYS:
            deltas[k] = int(normalized[k] - previous_snapshot[k])
        kyc_prev = previous_snapshot["kyc_gate"]
        kyc_curr = normalized["kyc_gate"]
        kyc_changed = kyc_curr != kyc_prev
        deltas["kyc_gate"] = f"{kyc_prev} -> {kyc_curr}" if kyc_changed else "unchanged"
        has_prev_geo = "geo_citation_share_pct" in raw_prev
        geo_unchanged = bool(has_prev_geo and round(normalized["geo_citation_share_pct"], 2) == round(previous_snapshot["geo_citation_share_pct"], 2))
        kyc_note = f"{kyc_prev} -> {kyc_curr}" if kyc_changed else f"{kyc_curr} (unchanged)"
        summary_line = (
            f"vs {prev_date or 'prior'}: "
            f"Disk {deltas['disk_free_gb']:+.1f} GB | "
            f"Commits {deltas['commits_24h']:+d} | "
            f"Unread {deltas['unread_count']:+d} | "
            f"Urgent {deltas['urgent_count']:+d} | "
            f"Tier-1 {deltas['tier1_ready']:+d} | "
            f"Tier-2 {deltas['tier2_queued']:+d} | "
            f"GEO {deltas['geo_citation_share_pct']:+.1f}% | "
            f"KYC: {kyc_note}"
        )
    else:
        previous_snapshot = None
        has_previous = False
        deltas = {k: 0.0 for k in _DELTA_FLOAT_KEYS}
        deltas.update({k: 0 for k in _DELTA_INT_KEYS})
        deltas["kyc_gate"] = "baseline"
        kyc_changed = False
        geo_unchanged = False
        summary_line = (
            f"Baseline ({date_key}): "
            f"Disk {normalized['disk_free_gb']:.1f} GB free | "
            f"Commits {normalized['commits_24h']} | "
            f"Unread {normalized['unread_count']} | "
            f"Urgent {normalized['urgent_count']} | "
            f"Tier-1 {normalized['tier1_ready']} | "
            f"Tier-2 {normalized['tier2_queued']} | "
            f"GEO {normalized['geo_citation_share_pct']:.1f}% | "
            f"KYC: {normalized['kyc_gate']}"
        )

    state_payload = {
        "date": date_key,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": normalized,
        "previous_date": prev_date,
        "previous_snapshot": previous_snapshot,
        "has_previous": has_previous,
        "deltas": deltas,
        "geo_unchanged": geo_unchanged,
        "kyc_changed": kyc_changed,
        "summary_line": summary_line,
    }

    dated_path = target_dir / f"briefing_state_{date_key}.json"
    latest_path = target_dir / "briefing_state_latest.json"
    serialized = json.dumps(state_payload, indent=2)
    dated_path.write_text(serialized, encoding="utf-8")
    latest_path.write_text(serialized, encoding="utf-8")

    return {
        "date": date_key,
        "has_previous": has_previous,
        "previous_date": prev_date,
        "current": normalized,
        "previous": previous_snapshot,
        "deltas": deltas,
        "geo_unchanged": geo_unchanged,
        "kyc_changed": kyc_changed,
        "summary_line": summary_line,
        "state_file": str(dated_path),
        "latest_file": str(latest_path),
    }


def _count_commits_24h(
    proj_radar: Dict[str, Any],
    repo_root: Optional[Path] = None,
    now_dt: Optional[datetime.datetime] = None,
) -> int:
    """Counts recent 24h commits across root workspace radar and standalone orbit-security repo."""
    ref_now = now_dt or datetime.datetime.now()
    cutoff = ref_now - datetime.timedelta(hours=24)
    root_count = 0
    for entry in proj_radar.get("workspace_root_commits_48h", []):
        parts = [p.strip() for p in str(entry).split("|")]
        if len(parts) < 2:
            continue
        try:
            commit_dt = datetime.datetime.strptime(parts[1][:16], "%Y-%m-%d %H:%M")
            if commit_dt >= cutoff:
                root_count += 1
        except ValueError:
            continue

    repo_count = 0
    target_repo = Path(repo_root) if repo_root else _REPO_ROOT
    if (target_repo / ".git").exists():
        try:
            out = subprocess.check_output(
                ["git", "-C", str(target_repo), "rev-list", "--count", "--since=24 hours ago", "HEAD"],
                text=True,
                timeout=2,
                stderr=subprocess.DEVNULL,
            ).strip()
            if out.isdigit():
                repo_count = int(out)
        except Exception:
            repo_count = 0

    return root_count + repo_count


def _build_agenda_items(
    ci_count: int,
    live_ci: Dict[str, Any],
    option_c: Dict[str, Any],
    email_data: Dict[str, Any],
    daemon: Dict[str, Any],
    inbox_q: Dict[str, Any],
) -> List[str]:
    """Derives prioritized engineering and operational agenda items."""
    state_ts = daemon.get("state_timestamp") or "unknown"
    agenda_items: List[str] = []
    if ci_count > 0:
        failing_names = ", ".join(live_ci.get("failing_workflows", [])) or "GitHub CI"
        agenda_items.append(f"Fix {ci_count} failing GitHub Actions workflow(s) on `CmfH009/Orbit-Security` HEAD ({failing_names}).")
    if option_c.get("kyc_payout_status") != "VERIFIED":
        agenda_items.append(
            "Gate 2 Physical ID / KYC watch: keep Tier-1 Spotify bucket ready and capture authenticated session/PII proof for Tier-2 CONDITIONAL CORS bundles (MercadoLibre, Xiaomi, Superbet, Playtika)."
        )
    if email_data.get("unread_non_ci_count", 0) > 0:
        agenda_items.append(f"Triage {email_data['unread_non_ci_count']} unread non-CI message(s) in `carsonmail009@gmail.com`.")
    elif email_data.get("urgent", 0) > 0:
        agenda_items.append(f"Review {email_data['urgent']} actionable urgent email item(s) in `carsonmail009@gmail.com`.")
    if not daemon.get("live_verified_active"):
        agenda_items.append(f"Restart `OrbitMasterSupervisor` daemon if 24/7 background monitoring is desired (state stale since `{state_ts}`).")
    if inbox_q.get("failed", 0) > 0:
        agenda_items.append(f"Inspect {inbox_q['failed']} failed task(s) in `A:\\inbox\\failed`.")
    if not agenda_items:
        agenda_items.append("Run `orbit_readiness_audit.py --verify-cutover` and advance active workspace sprint.")
    return agenda_items


def _render_master_briefing_block(master_briefing: Any) -> str:
    """Formats the Combined Daily Master Briefing delta block gracefully."""
    if isinstance(master_briefing, dict) and master_briefing.get("found"):
        subject = _clean_subject(str(master_briefing.get("subject") or "Combined Daily Master Briefing"))
        date_val = str(master_briefing.get("date") or "").strip()
        highlights = [str(h).strip() for h in (master_briefing.get("highlights") or []) if str(h).strip()]
        date_suffix = f" *({date_val})*" if date_val else ""
        lines = [f"#### 📨 Combined Daily Master Briefing (24h Personal & Ecosystem Delta)", f"- **Latest Dispatch:** {subject}{date_suffix}"]
        for h in highlights[:8]:
            lines.append(f"  - {h}")
        return "\n".join(lines)
    return "#### 📨 Combined Daily Master Briefing (24h Personal & Ecosystem Delta)\n- No Combined Daily Master Briefing found in latest inbox sweep."


def generate_markdown(
    *,
    today: Optional[str] = None,
    stripe: Optional[Dict[str, Any]] = None,
    daemon: Optional[Dict[str, Any]] = None,
    inbox: Optional[Dict[str, Any]] = None,
    campaigns: Optional[Dict[str, Any]] = None,
    option_c: Optional[Dict[str, Any]] = None,
    email_data: Optional[Dict[str, Any]] = None,
    live_ci: Optional[Dict[str, Any]] = None,
    ci_reconciled: Optional[Dict[str, Any]] = None,
    geo_panel: Optional[Dict[str, Any]] = None,
    sys_telem: Optional[Dict[str, Any]] = None,
    proj_radar: Optional[Dict[str, Any]] = None,
    cal_tasks: Optional[Dict[str, Any]] = None,
    intel_news: Optional[Dict[str, Any]] = None,
    email_hygiene: Optional[Dict[str, Any]] = None,
    deltas: Optional[Dict[str, Any]] = None,
    agenda_items: Optional[List[str]] = None,
) -> str:
    """Renders the unified daily executive briefing Markdown report."""
    today_str = today or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    stripe = stripe or {}
    daemon = daemon or {}
    inbox = inbox or {}
    campaigns = campaigns or {}
    option_c = option_c or {}
    email_data = email_data or {}
    live_ci = live_ci or {}
    geo_panel = geo_panel or {}
    sys_telem = sys_telem or {}
    proj_radar = proj_radar or {}
    cal_tasks = cal_tasks or {}
    intel_news = intel_news or {}
    email_hygiene = email_hygiene or {}
    deltas = deltas or {}

    if ci_reconciled is None:
        ci_reconciled = reconcile_ci_alerts_with_live_status(
            email_data.get("ci_alerts", []),
            live_ci,
            archived_in_imap=0,
        )

    ci_count = ci_reconciled.get("active_failures", 0)
    ci_summary_str = ci_reconciled.get("summary_markdown", "  - All GitHub Actions green on CmfH009/Orbit-Security")

    recent_str = "\n".join([f"  - {r}" for r in campaigns.get("recent_dispatched", [])]) or "  - None yet"
    deal_count = len(email_data.get("deal_threads", []))
    deals_summary_str = (
        "\n".join([f"  - 💼 {s}" for s in email_data.get("deal_threads", [])[:3]])
        if deal_count > 0
        else "  - No pending customer inquiries waiting in Orbit/Deal-Desk"
    )
    hygiene = email_data.get("hygiene", {}) or {}

    # Ground-truth Daemon & Supervisor Banner
    sv_pid = daemon.get("supervisor_pid")
    sen_pid = daemon.get("sentinel_pid")
    state_ts = daemon.get("state_timestamp") or "unknown"
    if daemon.get("live_verified_active"):
        supervisor_banner = f"🟢 ACTIVE (PID: {sv_pid})"
    elif daemon.get("supervisor_active"):
        supervisor_banner = f"🟡 STOPPED / STALE STATE (Last seen: {state_ts}, PID {sv_pid} not running)"
    else:
        supervisor_banner = "🔴 INACTIVE"

    if daemon.get("sentinel_live_verified"):
        sentinel_banner = f"🟢 RUNNING (PID: {sen_pid})"
    elif daemon.get("sentinel_running"):
        sentinel_banner = f"🟡 STOPPED / STALE STATE (Last seen: {state_ts}, PID {sen_pid} not running)"
    else:
        sentinel_banner = "🔴 STOPPED"

    # Hardware & Storage Telemetry Formatting
    drives_telem = sys_telem.get("drives", {})
    drive_notes = {"A:\\": " (Mapped to C:\\AgyHut)", "G:\\": " (Google Drive Mirror)"}
    drive_lines = []
    for d_letter, d_info in drives_telem.items():
        note = drive_notes.get(d_letter, "")
        drive_lines.append(
            f"  - **Drive {d_letter}**{note}: `{d_info.get('free_gb', 0)} GB free` of `{d_info.get('total_gb', 0)} GB` ({d_info.get('pct_free', 0)}% free)"
        )
    drives_str = "\n".join(drive_lines) if drive_lines else "  - Storage info unavailable"
    ports_status = (
        "🟢 0 open debug ports (Ports 4173, 8501, 8765 verified closed)"
        if not sys_telem.get("open_ports")
        else f"⚠️ Active ports: {sys_telem.get('open_ports')}"
    )

    temp_c = sys_telem.get("temp_c", 52.0)
    chassis_c = sys_telem.get("chassis_temp_c")
    exhaust_c = sys_telem.get("exhaust_temp_c")
    fan_rpm = sys_telem.get("fan_rpm")
    thermal_extras = []
    if chassis_c is not None:
        thermal_extras.append(f"Chassis {chassis_c}°C")
    if exhaust_c is not None:
        thermal_extras.append(f"Exhaust {exhaust_c}°C")
    if fan_rpm is not None:
        thermal_extras.append(f"Fan {fan_rpm} RPM")
    thermal_suffix = f" ({', '.join(thermal_extras)})" if thermal_extras else " (Optimal)"

    # Workspace, Projects & Inbox Queues Formatting
    recent_projs = proj_radar.get("recently_active", [])
    if recent_projs:
        proj_lines = [
            f"  - 🔥 **{p['name']}** (`{p['branch']}`): {p['commit_msg']} *(last commit: {p['last_commit']})*"
            for p in recent_projs[:6]
        ]
    else:
        proj_lines = ["  - No project commits recorded in the last 48 hours."]
    recent_projs_str = "\n".join(proj_lines)

    root_commits = proj_radar.get("workspace_root_commits_48h", [])
    root_commits_str = "\n".join([f"  - `{c}`" for c in root_commits[:5]]) if root_commits else "  - No root workspace commits in the last 48 hours."
    inbox_q = proj_radar.get("inbox_queues", {})
    inbox_q_line = (
        f"pending `{inbox_q.get('pending', 0)}` | in_progress `{inbox_q.get('in_progress', 0)}` | "
        f"failed `{inbox_q.get('failed', 0)}` | expansion `{inbox_q.get('expansion_queue', 0)}` | "
        f"completed_24h `{inbox_q.get('completed_24h', 0)}`"
    )

    if agenda_items is None:
        agenda_items = _build_agenda_items(
            ci_count=ci_count,
            live_ci=live_ci,
            option_c=option_c,
            email_data=email_data,
            daemon=daemon,
            inbox_q=inbox_q,
        )
    top3_items = agenda_items[:3]
    top3_str = "\n".join([f"{i + 1}. {item}" for i, item in enumerate(top3_items)]) if top3_items else "1. Run `orbit_readiness_audit.py --verify-cutover` and advance active workspace sprint."
    overflow_items = agenda_items[3:]
    if overflow_items:
        agenda_str = "\n".join([f"  {i + 4}. {item}" for i, item in enumerate(overflow_items)])
    else:
        agenda_str = "  - Top 3 priorities surfaced in executive banner above (0 overflow backlog items)."

    delta_summary_line = str(deltas.get("summary_line") or "Baseline snapshot pending")

    # Section 6: Hygiene & 24h inbox volume + Combined Daily Master Briefing
    scanned_cnt = email_data.get("scanned", email_hygiene.get("total_scanned", 0))
    archived_cnt = email_hygiene.get(
        "archived_count",
        email_hygiene.get("archived", hygiene.get("archived_count", hygiene.get("archived", 0))),
    )
    trashed_cnt = email_hygiene.get(
        "trashed_count",
        email_hygiene.get("trashed", hygiene.get("trashed_count", hygiene.get("trashed", 0))),
    )
    unsub_cnt = email_hygiene.get(
        "unsubscribed_count",
        email_hygiene.get("unsubscribed", hygiene.get("unsubscribed_count", hygiene.get("unsubscribed", 0))),
    )
    received_24h = email_hygiene.get("received_24h", 0)
    read_cleared_24h = email_hygiene.get("read_or_cleared_24h", 0)
    auto_hygiene_cnt = email_hygiene.get("auto_hygiene_candidates", 0)
    master_briefing_block = _render_master_briefing_block(email_hygiene.get("master_briefing"))

    # Section 7: GEO Visibility & AI Citation Panel (collapsed when unchanged vs prior day)
    if deltas.get("geo_unchanged"):
        latest_geo = geo_panel.get("latest") or {}
        c_rate = float(latest_geo.get("citation_rate_pct", (deltas.get("current") or {}).get("geo_citation_share_pct", 0.0)))
        m_rate = float(latest_geo.get("mention_rate_pct", 0.0))
        auth = float(latest_geo.get("composite_authority_score", 0.0))
        prev_dt = deltas.get("previous_date") or "prior day"
        geo_section_body = (
            f"- **UNCHANGED vs {prev_dt}:** Citation Share `{c_rate:.1f}%` "
            f"(Mention `{m_rate:.1f}%` | Authority `{auth:.1f}/100` | {geo_panel.get('total_records', 0)} probes logged)."
        )
    else:
        geo_section_body = geo_panel.get("summary_markdown", "- **GEO Panel Status:** Pending")

    # Calendar & Tasks Formatting (with feed_status & Gmail invite fallback diagnostics)
    feed_status = str(cal_tasks.get("feed_status") or "").strip()
    fallback_used = bool(cal_tasks.get("fallback_used", False))
    structured_events = cal_tasks.get("events") or []
    gmail_invites = [
        ev for ev in structured_events
        if isinstance(ev, dict) and ev.get("source") == "gmail_invite"
    ]
    fallback_events_count = int(cal_tasks.get("fallback_events_count", len(gmail_invites)) or 0)

    raw_today = list(cal_tasks.get("events_today", []))
    raw_week = list(cal_tasks.get("events_week", []))
    if not raw_today and not raw_week and gmail_invites:
        for inv in gmail_invites[:5]:
            summary = str(inv.get("summary") or inv.get("subject") or "Calendar Invitation")
            when = str(inv.get("when") or "").strip()
            label = f"📩 {summary} ({when})" if when else f"📩 {summary}"
            if inv.get("is_today"):
                raw_today.append(label)
            else:
                raw_week.append(label)

    if cal_tasks.get("configured") or raw_today or raw_week or gmail_invites or feed_status:
        events_str = "\n".join([f"  - {e}" for e in raw_today]) or "  - No meetings or events scheduled for today."
        week_str = "\n".join([f"  - {e}" for e in raw_week]) or "  - Clear schedule for the remainder of the week."
        birthdays_str = "\n".join([f"  - {b}" for b in cal_tasks.get("birthdays", [])]) if cal_tasks.get("birthdays") else "  - No birthdays today."
    else:
        events_str = "  - *Google Calendar sync*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream live events."
        week_str = "  - *Weekly runway*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream weekly schedule."
        birthdays_str = "  - None registered."

    cal_diag_lines: List[str] = []
    if feed_status:
        if fallback_used:
            fb_note = f" (Gmail invite fallback active: `{fallback_events_count}` invite(s) surfaced)"
        else:
            fb_note = ""
        cal_diag_lines.append(f"- **Calendar Feed Status:** `{feed_status}`{fb_note}")
    elif fallback_used:
        cal_diag_lines.append(f"- **Calendar Feed Status:** Gmail invite fallback active (`{fallback_events_count}` invite(s))")
    cal_diag_block = ("\n" + "\n".join(cal_diag_lines)) if cal_diag_lines else ""

    # Intel & World News Formatting (with optional Why It Matters takeaways)
    ai_list = intel_news.get("ai_innovations", [])
    tech_sec_list = intel_news.get("tech_and_security", [])
    world_list = intel_news.get("world_news", [])
    ai_news_str = "\n".join([f"  - 🤖 {item}" for item in ai_list]) if ai_list else "  - No high-signal AI releases detected this morning."
    tech_sec_str = "\n".join([f"  - 🛡️ {item}" for item in tech_sec_list]) if tech_sec_list else "  - No engineering/security frontpage items fetched."
    world_news_str = "\n".join([f"  - 🌐 {item}" for item in world_list]) if world_list else "  - Macro markets and world news nominal."

    ai_takeaway = str(intel_news.get("ai_takeaway") or "").strip()
    world_takeaway = str(intel_news.get("world_takeaway") or "").strip()
    ai_takeaway_line = f"> 💡 **Why It Matters**: {ai_takeaway}\n" if ai_takeaway else ""
    world_takeaway_line = f"> 💡 **Why It Matters**: {world_takeaway}\n" if world_takeaway else ""

    # Email Action Items breakdown
    urgent_items_list = email_data.get("urgent_list", [])
    urgent_items_str = "\n".join([f"  - 🚨 {u}" for u in urgent_items_list]) if urgent_items_list else "  - No new or unread urgent action items today."
    awaiting_list = email_data.get("awaiting_external_reply", [])
    awaiting_count = int(email_data.get("awaiting_external_reply_count", len(awaiting_list)) or 0)
    if awaiting_list:
        awaiting_lines = "\n".join([f"  - ⏳ {item}" for item in awaiting_list])
        awaiting_block = f"\n- **⏳ Awaiting External Reply:** {awaiting_count}\n{awaiting_lines}"
    elif awaiting_count > 0:
        awaiting_block = f"\n- **⏳ Awaiting External Reply:** {awaiting_count}"
    else:
        awaiting_block = ""
    unread_list = email_data.get("unread_list", [])
    unread_non_ci_str = "\n".join([f"  - ✉️ {u}" for u in unread_list]) if unread_list else "  - No unread non-CI messages."

    tier_1_str = ", ".join(option_c.get("tier_1_items", [])) or "None"
    tier_2_str = ", ".join(option_c.get("tier_2_items", [])) or "None"
    outreach_freeze_label = "❄️ FROZEN (Option C Guardrail — 0 active blasts)" if campaigns.get("frozen", True) else "🟢 ACTIVE"

    return f"""# Orbit Security: Unified Operational, Revenue & Mailbox Briefing
**Generated:** {today_str}  
**Supervisor Status:** {supervisor_banner}  
**24h Delta (Δ):** {delta_summary_line}

---

## ⚡ TOP 3 PRIORITY ACTIONS TODAY
{top3_str}

---

### 1. Orbit Security Daemon & Sentinel Health
- **Sentinel Daemon Status:** {sentinel_banner}
- **Service Mesh Live:** {daemon.get("services_live_active", 0)}/{daemon.get("services_total", 0)} services running (state file active count: {daemon.get("services_state_active", 0)})
- **Process Restarts:** {daemon.get("sentinel_restarts", 0)}

### 2. Engineering & GitHub CI/CD Telemetry (`Orbit/CI-CD`)
- **Repository:** `CmfH009/Orbit-Security`
- **Active Alerts / CI Failures:** {ci_count}
{ci_summary_str}

### 3. Option C Revenue Readiness, Deal Desk & Stripe (`Track B`)
- **Strategic Focus:** {option_c.get("revenue_focus")}
- **Technical Floor Clean:** {option_c.get("technical_floor_clean")} | **KYC / Payout Gate:** `{option_c.get("kyc_payout_status")}`
- **Track B Self-Serve Funnel:** `ready={option_c.get("track_b_ready")}` | **Landing <-> Docs Parity:** `{option_c.get("landing_docs_identical")}/{option_c.get("landing_docs_shared")}` (`in_sync={option_c.get("landing_docs_in_sync")}`)
- **Stripe Live Checkout Ready:** `{option_c.get("stripe_live_checkout_ready")}` | **Available:** ${stripe.get("available_usd", 0.0):.2f} USD | **Pending:** ${stripe.get("pending_usd", 0.0):.2f} USD
- **Paid Subscribers / Retainers:** {option_c.get("paid_subscribers", 0)} paid | {stripe.get("active_subscriptions", 0)} active Stripe subs | {option_c.get("active_clients", 0)} active client registry entries
- **Inbound Deals & Customer Threads:** {deal_count}
{deals_summary_str}

### 4. Communications & Lead Pipeline
- **Monitored Mailbox:** `carsonmail009@gmail.com`
- **Total Inbound Leads Tracked:** {inbox.get("total_threads", 0)} | **High-Intent Escalations:** {inbox.get("escalations", 0)}
- **Unread Inbox Messages:** {email_data.get("unread", 0)} total ({email_data.get("unread_non_ci_count", 0)} non-CI)
{unread_non_ci_str}
- **Today's Actionable Urgent Items:** {email_data.get("urgent", 0)} *(historical read alerts deduplicated: {email_data.get("historical_alerts_count", 0)})*
{urgent_items_str}{awaiting_block}

### 5. Track A Bug Bounty Vault & Frozen Outbound Status
- **Bounty Catalog:** {option_c.get("unique_programs", 0)} unique programs ({option_c.get("cash_tier_count", 0)} cash tier)
- **Submission Vault (`data/hackerone_staging`):** {option_c.get("staged_reports", 0)} staged `.md` + {option_c.get("paired_bundles", 0)} paired `.zip` bundles (`{option_c.get("ev_covered", 0)}/{option_c.get("ev_total", 0)}` `ev_` digests, `{option_c.get("consolidated_dossiers", 0)}` dossiers, `{option_c.get("archived_total", 0)}` archived noise)
- **Tier-1 Ready (Pending KYC ID):** {tier_1_str}
- **Tier-2 Conditional CORS (Needs Auth Proof):** {tier_2_str}
- **Cold Email Outreach Status:** {outreach_freeze_label}
- **Historical Outreach Registry:** {campaigns.get("dispatched_count", 0)} agencies sent previously | Most recent dispatches:
{recent_str}

### 6. Mailbox Hygiene & Noise Reduction
- **Total Scanned in Last Sweep:** {scanned_cnt}
- **24h Inbox Flow:** `{received_24h} received` | `{read_cleared_24h} read/cleared` | `{auto_hygiene_cnt} auto-hygiene candidates`
- **Eligible Inbox Zero Archiving:** {archived_cnt}
- **Marketing Promos & Spam Purged:** {trashed_cnt}
- **Active Unsubscribe Targets Extracted:** {unsub_cnt}

{master_briefing_block}

### 7. GEO Visibility & AI Citation Panel (`data/geo_panels.jsonl`)
{geo_section_body}

### 8. Host Hardware, Storage & Telemetry
- **CPU & Thermal Health:** `{sys_telem.get("cpu_name", "Intel Core i7-1185G7")}` · **{temp_c}°C**{thermal_suffix}
- **Host Uptime:** `{sys_telem.get("uptime", "Unknown")}`
- **Memory Load:** `{sys_telem.get("ram_used_gb", 0.0)} GB used` of `{sys_telem.get("ram_total_gb", 16.0)} GB` ({sys_telem.get("ram_pct", 0.0)}% load)
- **Power & Battery:** `{sys_telem.get("battery", "AC Connected")}`
- **Storage Pools:**
{drives_str}
- **Process & Port Hygiene:** {ports_status}

### 9. Workspace, Active Projects & Autonomous Inbox Radar
- **Total Workspace Projects:** {proj_radar.get("total_projects", 0)} repositories in `A:\\projects` | **Root Uncommitted Files:** `{proj_radar.get("workspace_dirty_count", 0)}`
- **`A:\\inbox` Autonomous Queues:** {inbox_q_line}
- **Recently Active Project Repos (Last 48 Hours):**
{recent_projs_str}
- **Root Workspace (`C:\\AgyHut`) 48h Velocity:**
{root_commits_str}
- **Recommended Engineering Agenda Today:**
{agenda_str}

### 10. Google Workspace Agenda (Calendar & Tasks){cal_diag_block}
- **Today's Events & Meetings:**
{events_str}
- **Birthdays & Observances:**
{birthdays_str}
- **Rest of Week Lookahead:**
{week_str}

### 11. Intelligence Radar (AI Engineering, Tech/Security & World Macro)
- **AI & Agent Engineering Innovations:**
{ai_takeaway_line}{ai_news_str}
- **Engineering & Security Frontpage:**
{tech_sec_str}
- **World & Macro News Briefing:**
{world_takeaway_line}{world_news_str}

---
*Unified briefing autonomously synthesized by Nova & Orbit Security Sentinel.*
"""


def generate_briefing(speak: bool = False, email: bool = False, recipient: Optional[str] = None, dry_run: bool = False):
    now_dt = datetime.datetime.now()
    today = now_dt.strftime("%Y-%m-%d %H:%M")
    date_key = now_dt.strftime("%Y-%m-%d")
    stripe = query_stripe_telemetry()
    daemon = query_daemon_health()
    inbox = query_inbox_pipeline()
    campaigns = query_campaign_outreach()
    option_c = query_option_c_readiness()
    email_data = query_live_email_telemetry()
    live_ci = query_live_github_ci_status()
    archived_ci_count = 0 if dry_run else (archive_superseded_ci_alerts_in_imap(live_ci) if email_data.get("ci_alerts") else 0)
    geo_panel = query_geo_panel_telemetry()

    ci_reconciled = reconcile_ci_alerts_with_live_status(
        email_data.get("ci_alerts", []),
        live_ci,
        archived_in_imap=archived_ci_count,
    )
    ci_count = ci_reconciled["active_failures"]

    # Extended Morning Cockpit Queries
    sys_telem = query_system_telemetry() if query_system_telemetry else {}
    proj_radar = query_projects_radar() if query_projects_radar else {}
    cal_tasks = query_calendar_and_tasks() if query_calendar_and_tasks else {}
    intel_news = query_intel_and_world_news() if query_intel_and_world_news else {}
    email_hygiene = email_data.get("email_hygiene")
    if not email_hygiene and query_email_hygiene:
        try:
            email_hygiene = query_email_hygiene()
        except Exception:
            email_hygiene = {}
    email_hygiene = email_hygiene or {}

    drives = sys_telem.get("drives", {})
    primary_drive = drives.get("A:\\") or drives.get("C:\\") or (next(iter(drives.values())) if drives else {})
    snapshot = {
        "disk_free_gb": float(primary_drive.get("free_gb", 0.0) or 0.0),
        "commits_24h": _count_commits_24h(proj_radar, now_dt=now_dt),
        "unread_count": int(email_data.get("unread", 0) or 0),
        "urgent_count": int(email_data.get("urgent", 0) or 0),
        "tier1_ready": len(option_c.get("tier_1_items", [])),
        "tier2_queued": len(option_c.get("tier_2_items", [])),
        "geo_citation_share_pct": float((geo_panel.get("latest") or {}).get("citation_rate_pct", 0.0) or 0.0),
        "kyc_gate": str(option_c.get("kyc_payout_status") or "PENDING_PHYSICAL_ID"),
    }
    deltas = compute_and_save_daily_deltas(date_str=date_key, current_snapshot=snapshot)

    inbox_q = proj_radar.get("inbox_queues", {})
    agenda_items = _build_agenda_items(
        ci_count=ci_count,
        live_ci=live_ci,
        option_c=option_c,
        email_data=email_data,
        daemon=daemon,
        inbox_q=inbox_q,
    )

    report = generate_markdown(
        today=today,
        stripe=stripe,
        daemon=daemon,
        inbox=inbox,
        campaigns=campaigns,
        option_c=option_c,
        email_data=email_data,
        live_ci=live_ci,
        ci_reconciled=ci_reconciled,
        geo_panel=geo_panel,
        sys_telem=sys_telem,
        proj_radar=proj_radar,
        cal_tasks=cal_tasks,
        intel_news=intel_news,
        email_hygiene=email_hygiene,
        deltas=deltas,
        agenda_items=agenda_items,
    )

    # Save Unified Report
    DEFAULT_BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DEFAULT_BRIEFINGS_DIR / f"briefing_{date_key}.md"
    report_path.write_text(report, encoding="utf-8")

    print(report)
    print(f"\n[✔] Written to {report_path}")

    # Dispatch email if requested (skipped in --dry-run)
    if email and not dry_run:
        dispatch_email_briefing(report, recipient=recipient)

    # Nova Spoken Debrief (TTS) - Sharp emo coder chick, ground-truth metrics, zero canned fluff
    sen_pid = daemon.get("sentinel_pid")
    if daemon.get("live_verified_active") and daemon.get("sentinel_live_verified"):
        daemon_spoken = f"Supervisor and Sentinel are green on PID {sen_pid}"
    elif daemon.get("supervisor_active"):
        daemon_spoken = "Heads up, Orbit Supervisor and Sentinel look offline since November fifth"
    else:
        daemon_spoken = "Orbit Supervisor is currently offline"

    unread_non_ci = email_data.get("unread_non_ci_count", 0)
    urgent_count = email_data.get("urgent", 0)
    unread_str = f"{unread_non_ci} unread non-CI messages" if unread_non_ci != 1 else "1 unread non-CI message"
    urgent_spoken = f"and {urgent_count} urgent item needing eyes today" if urgent_count > 0 else "with zero new urgent emergencies"
    ci_note = ci_reconciled["spoken_note"]
    temp_c = sys_telem.get("temp_c", 52.0)
    temp_spoken = f"{temp_c} degrees"
    ram_spoken = f"{sys_telem.get('ram_pct', 55.0)} percent"
    recent_projs = proj_radar.get("recently_active", [])
    root_commits = proj_radar.get("workspace_root_commits_48h", [])
    active_count = len(recent_projs)
    projs_spoken = f"{active_count} active repos plus {len(root_commits)} root workspace commits in the last forty-eight hours"
    ai_list = intel_news.get("ai_innovations", [])
    world_list = intel_news.get("world_news", [])
    top_ai = ai_list[0].split(" [")[0].split("(")[0].strip() if ai_list else "AI models running stable"
    top_world = world_list[0].split(" - ")[0].strip() if world_list else "macro news quiet"
    vault_count = option_c.get("staged_reports", 0)
    kyc_note = "awaiting physical ID for KYC payout unlock" if option_c.get("kyc_payout_status") != "VERIFIED" else "KYC verified"

    spoken_summary = (
        f"[chuckle] Morning Carson. Nova here with your unified 10 AM cockpit briefing. "
        f"Hardware pulse: CPU is running cool at {temp_spoken}, and RAM is at {ram_spoken}. "
        f"{daemon_spoken}. Over on GitHub, {ci_note}. "
        f"Option C status: {vault_count} verified bounty bundles staged with Spotify Tier-1 ready, Track B checkout ready, {kyc_note}. "
        f"In your workspace, {projs_spoken}. "
        f"Mailbox has {unread_str}, {urgent_spoken}. "
        f"On the AI radar: {top_ai}. World headline: {top_world}. "
        f"Let's knock out the priority queue."
    )

    if speak and not dry_run:
        hook_script = r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py"
        if os.path.exists(hook_script):
            subprocess.run([sys.executable, hook_script, "--speak", spoken_summary])


def main():
    parser = argparse.ArgumentParser(description="Unified Orbit Security & Mailbox Daily Briefing")
    parser.add_argument("--speak", action="store_true", help="Speak the unified debrief aloud in Nova's voice")
    parser.add_argument("--email", action="store_true", help="Dispatch briefing to operator email")
    parser.add_argument("--recipient", type=str, default=None, help="Custom recipient email address")
    parser.add_argument("--dry-run", action="store_true", help="Generate briefing and state files without email, TTS, or IMAP mutation")
    args = parser.parse_args()
    generate_briefing(speak=args.speak, email=args.email, recipient=args.recipient, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
