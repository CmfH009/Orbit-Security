"""Unified Morning Cockpit: Telemetry, Project Radar, Calendar, and News Integrations.

Powers the expanded morning intelligence briefing for Nova and Orbit Security.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import datetime
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
import imaplib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import psutil
except ImportError:
    psutil = None

AI_KEYWORD_RE = re.compile(
    r"\b(ai|llm|llms|gpt|claude|gemini|ollama|ggml|mcp|agent|agents|rag|transformer|inference|openai|anthropic|deepmind|neural|vllm|diffusion)\b",
    re.IGNORECASE,
)

SECURITY_TECH_RE = re.compile(
    r"\b(security|cve|breach|vuln|vulnerability|zero-day|0day|exploit|ransomware|kernel|linux|rust|compiler|wasm|sqlite|postgres|github|python|typescript|browser|dns|tls|ssl)\b",
    re.IGNORECASE,
)


def _query_hardware_thermals() -> Dict[str, Any]:
    """Queries live CPU/chassis/exhaust thermals and fan RPM via HP InstrumentedBIOS COM first."""
    thermals: Dict[str, Any] = {
        "cpu_temp": None,
        "chassis_temp": None,
        "exhaust_temp": None,
        "fan_rpm": None,
    }

    try:
        import pythoncom

        pythoncom.CoInitialize()
    except Exception:
        pass

    # 1. Primary: Direct COM query to HP InstrumentedBIOS (<50ms)
    try:
        import win32com.client

        wmi = win32com.client.GetObject("winmgmts://./root/HP/InstrumentedBIOS")
        sensors = wmi.ExecQuery("SELECT Name, CurrentReading FROM HP_BIOSNumericSensor")
        for s in sensors:
            name = str(s.Name).strip()
            val = float(s.CurrentReading)
            if name == "CPU Temperature":
                thermals["cpu_temp"] = round(val, 1)
            elif name == "Local Temperature":
                thermals["chassis_temp"] = round(val, 1)
            elif name == "Remote Temperature":
                thermals["exhaust_temp"] = round(val, 1)
            elif name == "CPU Fan":
                thermals["fan_rpm"] = int(val)
    except Exception:
        pass

    # 2. Secondary: Direct COM query to standard Windows ACPI thermal zones
    if thermals["cpu_temp"] is None:
        try:
            import win32com.client

            wmi = win32com.client.GetObject("winmgmts://./root/WMI")
            zones = wmi.ExecQuery("SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature")
            for z in zones:
                tc = round(float(z.CurrentTemperature) / 10.0 - 273.15, 1)
                iname = str(z.InstanceName)
                if "CPUZ" in iname and thermals["cpu_temp"] is None:
                    thermals["cpu_temp"] = tc
                elif "LOCZ" in iname and thermals["chassis_temp"] is None:
                    thermals["chassis_temp"] = tc
                elif "EXTZ" in iname and thermals["exhaust_temp"] is None:
                    thermals["exhaust_temp"] = tc
                elif thermals["cpu_temp"] is None:
                    thermals["cpu_temp"] = tc
        except Exception:
            pass

    # 3. Fallback: PowerShell CIM query
    if thermals["cpu_temp"] is None:
        try:
            out = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue).CurrentTemperature[0]",
                ],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).strip()
            if out and out.isdigit():
                thermals["cpu_temp"] = round((int(out) - 2732) / 10.0, 1)
        except Exception:
            pass

    return thermals


def _get_cpu_name() -> str:
    """Reads CPU model string from Windows Registry with safe default."""
    default_cpu = "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz"
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            if isinstance(val, str) and val.strip():
                return val.strip()
    except Exception:
        pass
    return default_cpu


def query_system_telemetry() -> Dict[str, Any]:
    """Queries live hardware sensors, CPU, thermals, uptime, RAM, and storage health."""
    cpu_name = _get_cpu_name()
    cores = os.cpu_count() or 4
    thermals = _query_hardware_thermals()
    temp_c = thermals.get("cpu_temp")

    # Uptime & Memory via psutil
    uptime_str = "Unknown"
    ram_used_gb = 0.0
    ram_total_gb = 16.0
    ram_pct = 0.0
    battery_info = "AC / Desktop"

    if psutil:
        try:
            boot_ts = psutil.boot_time()
            uptime_sec = time.time() - boot_ts
            days = int(uptime_sec // 86400)
            hours = int((uptime_sec % 86400) // 3600)
            mins = int((uptime_sec % 3600) // 60)
            uptime_str = f"{days}d {hours}h {mins}m"

            vmem = psutil.virtual_memory()
            ram_used_gb = round(vmem.used / (1024 ** 3), 2)
            ram_total_gb = round(vmem.total / (1024 ** 3), 2)
            ram_pct = round(vmem.percent, 1)

            bat = psutil.sensors_battery()
            if bat:
                status = "AC Connected" if bat.power_plugged else "Battery"
                battery_info = f"{bat.percent}% ({status})"
        except Exception:
            pass

    # Storage
    drives: Dict[str, Dict[str, Any]] = {}
    for d in ("A:\\", "C:\\", "G:\\"):
        if os.path.exists(d):
            try:
                usage = shutil.disk_usage(d)
                drives[d] = {
                    "total_gb": round(usage.total / (1024 ** 3), 1),
                    "free_gb": round(usage.free / (1024 ** 3), 1),
                    "used_gb": round(usage.used / (1024 ** 3), 1),
                    "pct_free": round((usage.free / usage.total) * 100, 1),
                }
            except Exception:
                pass

    # Port state check (verify test servers are cleanly shut down)
    open_ports = []
    for port in (4173, 8501, 8765):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass

    return {
        "cpu_name": cpu_name,
        "cores": cores,
        "temp_c": temp_c if temp_c is not None else 52.0,
        "chassis_temp_c": thermals.get("chassis_temp"),
        "exhaust_temp_c": thermals.get("exhaust_temp"),
        "fan_rpm": thermals.get("fan_rpm"),
        "uptime": uptime_str,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "ram_pct": ram_pct,
        "battery": battery_info,
        "drives": drives,
        "open_ports": open_ports,
    }


def _is_within_48h(iso_date_str: str, now: datetime.datetime) -> bool:
    if not iso_date_str:
        return False
    try:
        dt = datetime.datetime.fromisoformat(iso_date_str.replace("Z", "+00:00"))
        if dt.tzinfo:
            diff = datetime.datetime.now(dt.tzinfo) - dt
        else:
            diff = now - dt
        return diff.total_seconds() <= 172800
    except Exception:
        return False


def _query_git_last_commit(repo_path: str, pathspec: Optional[str] = None) -> tuple[str, str, str]:
    """Returns (last_commit_iso[:16], commit_subject, branch) scoped cleanly to repo_path/pathspec."""
    args_base = ["git", "-C", repo_path]
    tail = ["--", pathspec] if pathspec else ["--", "."]
    try:
        out = subprocess.check_output(
            [*args_base, "log", "-1", "--format=%cd\x1f%s", "--date=iso", *tail],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).strip()
        if not out:
            return "", "", "N/A"
        parts = out.split("\x1f", 1)
        c_date = parts[0].strip()
        c_msg = parts[1].strip() if len(parts) > 1 else ""
        if pathspec:
            c_branch = "master"
        else:
            c_branch = subprocess.check_output(
                [*args_base, "branch", "--show-current"],
                text=True,
                timeout=2,
                stderr=subprocess.DEVNULL,
            ).strip()
        return c_date, c_msg, (c_branch or "HEAD")
    except Exception:
        return "", "", "N/A"


def _query_inbox_queues(inbox_root: str) -> Dict[str, int]:
    """Counts active, failed, expansion, and recent 24h completed task files in A:\\inbox."""
    queues = {
        "pending": 0,
        "in_progress": 0,
        "failed": 0,
        "expansion_queue": 0,
        "completed_24h": 0,
        "completed_total": 0,
    }
    if not os.path.isdir(inbox_root):
        return queues

    cutoff_ts = time.time() - 86400.0
    for q_name in ("pending", "in_progress", "failed", "expansion_queue", "completed"):
        q_dir = os.path.join(inbox_root, q_name)
        if not os.path.isdir(q_dir):
            continue
        try:
            for entry in os.scandir(q_dir):
                if not entry.is_file() or entry.name.startswith("."):
                    continue
                if q_name == "completed":
                    queues["completed_total"] += 1
                    try:
                        if entry.stat().st_mtime >= cutoff_ts:
                            queues["completed_24h"] += 1
                    except OSError:
                        pass
                else:
                    queues[q_name] += 1
        except OSError:
            pass
    return queues


def query_projects_radar(
    projects_root: str = r"A:\projects",
    workspace_root: Optional[str] = None,
    inbox_root: Optional[str] = None,
) -> Dict[str, Any]:
    r"""Surveys standalone and monorepo projects in A:\projects, root workspace 48h commits, and A:\inbox queues."""
    if not os.path.exists(projects_root) and os.path.exists(r"C:\AgyHut\projects"):
        projects_root = r"C:\AgyHut\projects"

    if workspace_root is None:
        if os.path.isfile(r"C:\AgyHut\.git\HEAD"):
            workspace_root = r"C:\AgyHut"
        elif os.path.isfile(r"A:\.git\HEAD"):
            workspace_root = r"A:\\"
        else:
            workspace_root = ""

    if inbox_root is None:
        inbox_root = r"A:\inbox" if os.path.isdir(r"A:\inbox") else r"C:\AgyHut\inbox"

    projects: List[Dict[str, Any]] = []
    recently_active: List[Dict[str, Any]] = []
    now = datetime.datetime.now()

    if os.path.exists(projects_root):
        for name in sorted(os.listdir(projects_root)):
            p = os.path.join(projects_root, name)
            if not os.path.isdir(p) or name.startswith("."):
                continue

            dot_git = os.path.join(p, ".git")
            # A bare skeleton .git directory without HEAD (e.g. only objects/) is NOT a standalone repo.
            has_standalone_git = os.path.isfile(os.path.join(dot_git, "HEAD")) or os.path.isfile(dot_git)

            last_commit_date = ""
            commit_msg = ""
            branch = "N/A"
            is_active_48h = False
            repo_kind = "untracked"

            if has_standalone_git:
                repo_kind = "standalone"
                c_date, c_msg, c_branch = _query_git_last_commit(p)
                if c_date:
                    branch = c_branch
                    commit_msg = c_msg
                    last_commit_date = c_date[:16]
                    is_active_48h = _is_within_48h(c_date, now)
            elif workspace_root:
                c_date, c_msg, c_branch = _query_git_last_commit(workspace_root, f"projects/{name}")
                if c_date:
                    repo_kind = "monorepo"
                    branch = f"{c_branch} (monorepo)"
                    commit_msg = c_msg
                    last_commit_date = c_date[:16]
                    is_active_48h = _is_within_48h(c_date, now)

            roadmap = "None"
            for r_name in ("ROADMAP.md", "FUTURE_ROADMAP.md", "HANDOFF_NOVA_FEATURE_ROADMAP.md", "HANDOFF.md"):
                if os.path.exists(os.path.join(p, r_name)):
                    roadmap = r_name
                    break

            item = {
                "name": name,
                "branch": branch,
                "last_commit": last_commit_date,
                "commit_msg": commit_msg,
                "roadmap": roadmap,
                "is_active_48h": is_active_48h,
                "repo_kind": repo_kind,
            }
            projects.append(item)
            if is_active_48h:
                recently_active.append(item)

    workspace_root_commits_48h: List[str] = []
    workspace_dirty_count = 0
    if workspace_root and os.path.exists(workspace_root):
        try:
            root_log = subprocess.check_output(
                [
                    "git",
                    "-C",
                    workspace_root,
                    "log",
                    "--since=48 hours ago",
                    "-n",
                    "8",
                    "--pretty=format:%h | %cd | %s",
                    "--date=format:%Y-%m-%d %H:%M",
                ],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).strip()
            if root_log:
                workspace_root_commits_48h = [line.strip() for line in root_log.splitlines() if line.strip()]
        except Exception:
            pass

        try:
            status_out = subprocess.check_output(
                ["git", "-C", workspace_root, "status", "--porcelain"],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
            workspace_dirty_count = sum(1 for line in status_out.splitlines() if line.strip())
        except Exception:
            pass

    inbox_queues = _query_inbox_queues(inbox_root)

    return {
        "total_projects": len(projects),
        "projects": projects,
        "recently_active": recently_active,
        "workspace_root_commits_48h": workspace_root_commits_48h,
        "workspace_dirty_count": workspace_dirty_count,
        "inbox_queues": inbox_queues,
    }


_EMAIL_ORG_FALLBACK_DIR = Path(r"A:\projects\email-organizer")
_DEFAULT_OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
_MASTER_BRIEFING_PREFIX = "combined daily master briefing"

_SAFE_AUTO_HYGIENE_SENDER_RE = re.compile(
    r"(noreply|no-reply|notifications?@|alerts?@|mailer-daemon|automated|digest|newsletter|github\.com)",
    re.IGNORECASE,
)
_SAFE_AUTO_HYGIENE_ALERT_RE = re.compile(
    r"(run failed|build failed|verification code|one-time\s*(?:password|passcode|code)|\botp\b|login\s*code|cron)",
    re.IGNORECASE,
)
_FINANCIAL_OR_LEGAL_GUARD_RE = re.compile(
    r"(\$\s*\d+|€\s*\d+|£\s*\d+|\b(?:invoice|receipt|dispute|statement|affidavit|escrow|tax|billing|refund|chargeback|payment\s+received)\b)",
    re.IGNORECASE,
)
_CALENDAR_INVITE_SUBJECT_RE = re.compile(
    r"^\s*(?:updated\s+invitation|invitation|canceled\s+event|cancelled\s+event|accepted|declined|tentative)\s*:",
    re.IGNORECASE,
)
_CALENDAR_INVITE_MARKER_RE = re.compile(
    r"(text/calendar|\.ics\b|BEGIN:VCALENDAR|BEGIN:VEVENT|METHOD:REQUEST|\binvited you to\b)",
    re.IGNORECASE,
)


def _ensure_email_organizer_on_path() -> bool:
    """Adds A:\\projects\\email-organizer (or sibling repo) to sys.path when available."""
    sibling_dir = Path(__file__).resolve().parent.parent.parent / "email-organizer"
    for candidate in (sibling_dir, _EMAIL_ORG_FALLBACK_DIR):
        if candidate.is_dir():
            cand_str = str(candidate)
            if cand_str not in sys.path:
                sys.path.insert(0, cand_str)
            return True
    return False


def _load_imap_credentials() -> Tuple[str, str]:
    """Loads IMAP credentials from email-organizer/.env and environment variables."""
    imap_user = os.environ.get("IMAP_USER", "carsonmail009@gmail.com")
    imap_pass = os.environ.get("IMAP_PASS", "")
    sibling_env = Path(__file__).resolve().parent.parent.parent / "email-organizer" / ".env"
    env_candidates = (sibling_env, _EMAIL_ORG_FALLBACK_DIR / ".env")
    for env_path in env_candidates:
        if not env_path.is_file():
            continue
        try:
            for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                clean_key = key.strip()
                clean_val = val.strip().strip("'\"")
                if clean_key == "IMAP_USER" and clean_val:
                    imap_user = clean_val
                elif clean_key == "IMAP_PASS" and clean_val and not imap_pass:
                    imap_pass = clean_val
        except Exception:
            pass
    if not imap_pass:
        imap_pass = os.environ.get("GMAIL_APP_PASSWORD", "")
    return imap_user, imap_pass


def _fetch_imap_messages(
    folder: str = "INBOX",
    query: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[Any], str]:
    """Fetches recent messages via IMAPEmailClient without mutating \\Seen flags."""
    if not _ensure_email_organizer_on_path():
        return [], "unconfigured"
    imap_user, imap_pass = _load_imap_credentials()
    if not imap_pass:
        return [], "unconfigured"

    try:
        from email_organizer.client import IMAPEmailClient
    except Exception as exc:
        return [], f"error: {exc}"

    client = IMAPEmailClient(host="imap.gmail.com", port=993, user=imap_user, password=imap_pass)
    try:
        client.connect()
        messages = client.fetch_messages(folder=folder, query=query, limit=limit)
        return list(messages or []), "connected"
    except Exception as exc:
        return [], f"error: {exc}"
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def _msg_field(msg: Any, key: str, default: Any = None) -> Any:
    """Reads a field from either an object attribute or a mapping."""
    if isinstance(msg, dict):
        return msg.get(key, default)
    return getattr(msg, key, default)


def _parse_msg_datetime(raw_date: Any) -> Optional[datetime.datetime]:
    """Parses datetime/epoch/ISO/RFC822 message timestamps into UTC-aware datetimes."""
    if raw_date is None:
        return None
    if isinstance(raw_date, datetime.datetime):
        return raw_date if raw_date.tzinfo else raw_date.replace(tzinfo=datetime.timezone.utc)
    if isinstance(raw_date, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(float(raw_date), tz=datetime.timezone.utc)
        except Exception:
            return None
    if isinstance(raw_date, str):
        text = raw_date.strip()
        if not text:
            return None
        try:
            dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            pass
        try:
            dt = parsedate_to_datetime(text)
            if dt is not None:
                return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            pass
    return None


def _clean_single_line(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("\r", " ").replace("\n", " ")).strip()


def _split_top_level_topics(text: str) -> List[str]:
    """Splits comma/semicolon topic lists without breaking parenthesized sub-clauses."""
    topics: List[str] = []
    buf: List[str] = []
    paren_depth = 0
    bracket_depth = 0
    for ch in text:
        if ch == "(":
            paren_depth += 1
        elif ch == ")" and paren_depth > 0:
            paren_depth -= 1
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]" and bracket_depth > 0:
            bracket_depth -= 1

        if ch in (",", ";") and paren_depth == 0 and bracket_depth == 0:
            item = _clean_single_line("".join(buf))
            if item:
                topics.append(item)
            buf = []
        else:
            buf.append(ch)
    tail = _clean_single_line("".join(buf))
    if tail:
        topics.append(tail)
    return topics


def _strip_html_to_lines(raw_html: str) -> List[str]:
    """Extracts readable lines and list items from HTML email bodies."""
    if not raw_html:
        return []
    text = re.sub(r"(?i)<li[^>]*>", "\n- ", raw_html)
    text = re.sub(r"(?i)<(?:br|p|div|h[1-6]|tr)[^>]*>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = (
        text.replace("&amp;", "&")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
        .replace("&nbsp;", " ")
        .replace("&#39;", "'")
        .replace("&quot;", '"')
    )
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _strip_tracking_urls(text: str) -> str:
    """Removes Google redirect wrappers and long tracking URLs before bullet truncation."""
    cleaned = re.sub(r"\[([^\]]+)\]\(\s*https?://[^)\s]+\s*\)", r"\1", text or "")
    cleaned = re.sub(r"<\s*https?://[^>\s]+\s*>", "", cleaned)
    cleaned = re.sub(r"\(\s*https?://[^)]*(?:\)|$)", "", cleaned)
    cleaned = re.sub(r"\s*[,;|—–-]\s*https?://[^\s)\]>]+(?=\s*\))", "", cleaned)
    cleaned = re.sub(r"https?://[^\s)\]>]+", "", cleaned)
    cleaned = re.sub(r"\(\s*\)", "", cleaned)
    cleaned = re.sub(r"\(\s*[,;|]\s*", "(", cleaned)
    cleaned = re.sub(r"\s*[,;|]\s*\)", ")", cleaned)
    cleaned = re.sub(r"\s+([,.;:!?])", r"\1", cleaned)
    return _clean_single_line(cleaned)


def _extract_master_briefing_delta(messages: Sequence[Any]) -> Dict[str, Any]:
    """Extracts the latest 'Combined Daily Master Briefing' subject, date, and topic highlights."""
    candidates: List[Tuple[float, int, Any, str, Optional[datetime.datetime]]] = []
    for idx, msg in enumerate(messages or []):
        subj = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
        if not subj.lower().startswith(_MASTER_BRIEFING_PREFIX):
            continue
        dt = _parse_msg_datetime(_msg_field(msg, "date"))
        ts = dt.timestamp() if dt else 0.0
        candidates.append((ts, idx, msg, subj, dt))

    if not candidates:
        return {"found": False, "subject": "", "date": "", "highlights": []}

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    _, _, best_msg, subject, dt = candidates[0]

    raw_date = _msg_field(best_msg, "date")
    if dt is not None:
        date_str = dt.strftime("%Y-%m-%d %H:%M")
    elif raw_date:
        date_str = _clean_single_line(str(raw_date))
    else:
        date_str = ""

    highlights: List[str] = []
    seen_lower: set[str] = set()

    def _add_highlight(candidate_text: str) -> None:
        cleaned = _strip_tracking_urls(candidate_text).lstrip("-*• ").strip()
        if not cleaned or len(cleaned) < 4:
            return
        if len(cleaned) > 280:
            truncated = cleaned[:277].rstrip()
            if " " in truncated and len(truncated) > 140:
                truncated = truncated.rsplit(" ", 1)[0].rstrip(" ,;:")
            cleaned = truncated + "..."
        key = cleaned.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            highlights.append(cleaned)

    if ":" in subject:
        _, suffix = subject.split(":", 1)
        for topic in _split_top_level_topics(suffix):
            _add_highlight(topic)

    body_text = str(_msg_field(best_msg, "body_text", "") or "")
    body_html = str(_msg_field(best_msg, "body_html", "") or "")
    snippet = str(_msg_field(best_msg, "snippet", "") or "")

    lines: List[str] = []
    if body_text.strip():
        lines = [ln.strip() for ln in body_text.splitlines() if ln.strip()]
    elif body_html.strip():
        lines = _strip_html_to_lines(body_html)
    elif snippet.strip():
        lines = [ln.strip() for ln in snippet.splitlines() if ln.strip()]

    skip_line_re = re.compile(
        r"^(?:combined daily master briefing|prepared for|self-healing status|executive table of contents|here is your\b|[=\-_]{3,})",
        re.IGNORECASE,
    )
    bullet_lines: List[str] = []
    numbered_lines: List[str] = []
    for ln in lines[:200]:
        if skip_line_re.match(ln):
            continue
        if ln.startswith(("- ", "* ", "• ")):
            bullet_lines.append(ln[2:].strip())
        elif re.match(r"^\d+\.\s+", ln):
            numbered_lines.append(re.sub(r"^\d+\.\s+", "", ln).strip())

    for b in bullet_lines:
        if len(highlights) >= 8:
            break
        _add_highlight(b)

    if not bullet_lines:
        for n in numbered_lines:
            if len(highlights) >= 6:
                break
            _add_highlight(n)

    if not highlights and snippet.strip():
        _add_highlight(snippet)

    return {
        "found": True,
        "subject": subject,
        "date": date_str,
        "highlights": highlights[:8],
    }


def _coerce_email_message(msg: Any, idx: int = 0) -> Any:
    """Normalizes EmailMessage, SimpleNamespace, or dict into an EmailMessage instance when available."""
    _ensure_email_organizer_on_path()
    try:
        from email_organizer.models import EmailMessage
    except Exception:
        return msg

    if isinstance(msg, EmailMessage):
        return msg

    sender = str(_msg_field(msg, "sender", "") or "")
    sender_domain = str(_msg_field(msg, "sender_domain", "") or "")
    if not sender_domain and "@" in sender:
        sender_domain = sender.rsplit("@", 1)[-1].strip("<> ").lower()

    raw_labels = _msg_field(msg, "labels", set())
    labels = set(raw_labels) if raw_labels else set()
    raw_headers = _msg_field(msg, "headers", {})
    headers = dict(raw_headers) if isinstance(raw_headers, dict) else {}

    return EmailMessage(
        id=str(_msg_field(msg, "id", f"msg-{idx}") or f"msg-{idx}"),
        subject=str(_msg_field(msg, "subject", "") or ""),
        sender=sender,
        sender_name=str(_msg_field(msg, "sender_name", "") or ""),
        sender_domain=sender_domain,
        to=list(_msg_field(msg, "to", []) or []),
        cc=list(_msg_field(msg, "cc", []) or []),
        date=_parse_msg_datetime(_msg_field(msg, "date")),
        body_text=str(_msg_field(msg, "body_text", "") or _msg_field(msg, "snippet", "") or ""),
        body_html=str(_msg_field(msg, "body_html", "") or ""),
        list_unsubscribe=_msg_field(msg, "list_unsubscribe"),
        list_unsubscribe_post=_msg_field(msg, "list_unsubscribe_post"),
        list_id=_msg_field(msg, "list_id"),
        is_read=bool(_msg_field(msg, "is_read", False)),
        is_starred=bool(_msg_field(msg, "is_starred", False)),
        is_in_inbox=bool(_msg_field(msg, "is_in_inbox", True)),
        labels=labels,
        headers=headers,
        thread_id=_msg_field(msg, "thread_id"),
        raw_size=int(_msg_field(msg, "raw_size", 0) or 0),
    )


def _is_safe_auto_hygiene_candidate(
    msg: Any,
    category_val: str,
    triage_flagged: bool,
) -> bool:
    """Identifies safe newsletter/automated alert hygiene targets while protecting personal/financial mail."""
    if bool(_msg_field(msg, "is_starred", False)):
        return False

    subject = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
    subj_low = subject.lower()
    if subj_low.startswith(_MASTER_BRIEFING_PREFIX) or "orbit security daily operational briefing" in subj_low:
        return False

    # EmailOrganizerEngine already enforces strict archive/purge safeguards (VIP, starred, <30d receipts/work/personal).
    if triage_flagged:
        return True

    body_preview = str(_msg_field(msg, "body_text", "") or _msg_field(msg, "snippet", "") or "")[:500]
    combined = f"{subject} {body_preview}"
    if _FINANCIAL_OR_LEGAL_GUARD_RE.search(combined):
        return False
    if category_val in ("Receipts", "Personal"):
        return False

    if category_val in ("Subscriptions/Newsletters", "Promotions"):
        return True

    if _msg_field(msg, "list_unsubscribe") or _msg_field(msg, "list_id"):
        return True

    sender = str(_msg_field(msg, "sender", "") or "").lower()
    is_automated_sender = bool(_SAFE_AUTO_HYGIENE_SENDER_RE.search(sender))
    is_automated_alert_body = bool(_SAFE_AUTO_HYGIENE_ALERT_RE.search(combined))

    if category_val == "System Alerts" and (is_automated_sender or is_automated_alert_body):
        return True

    # Catch automated CI / workflow notifications even if repo keywords matched Work classification
    if is_automated_sender and is_automated_alert_body:
        return True

    return False


def _normalize_thread_key(subject: str) -> str:
    """Strips leading Re:/Fwd:/Fw: prefixes and lowercases for outbound reply matching."""
    cleaned = _clean_single_line(subject)
    while True:
        stripped = re.sub(r"^(re|fwd?|fw)\s*:\s*", "", cleaned, flags=re.IGNORECASE).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    return cleaned.lower()


def _decode_mime_header(raw_val: str) -> str:
    """Decodes RFC 2047 encoded email header values into a clean single-line string."""
    parts: List[str] = []
    for chunk, encoding in decode_header(raw_val or ""):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(encoding or "utf-8", errors="replace"))
        else:
            parts.append(str(chunk))
    return _clean_single_line("".join(parts))


def _fetch_sent_mail_headers(
    limit: int = 30,
    timeout: float = 4.0,
) -> List[Dict[str, Any]]:
    """Fetches headers-only from [Gmail]/Sent Mail (readonly, no body download or \\Seen mutation)."""
    imap_user, imap_pass = _load_imap_credentials()
    if not imap_pass or limit <= 0:
        return []

    conn: Optional[imaplib.IMAP4_SSL] = None
    try:
        conn = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=timeout)
        conn.login(imap_user, imap_pass)

        selected = False
        for folder in ('"[Gmail]/Sent Mail"', "[Gmail]/Sent Mail", "Sent"):
            typ, _ = conn.select(folder, readonly=True)
            if typ == "OK":
                selected = True
                break
        if not selected:
            return []

        typ, search_data = conn.search(None, "ALL")
        if typ != "OK" or not search_data or not search_data[0]:
            return []

        seq_nums = search_data[0].split()[-int(limit) :]
        if not seq_nums:
            return []

        seq_set = b",".join(seq_nums).decode("ascii", errors="ignore")
        typ, fetch_data = conn.fetch(seq_set, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])")
        if typ != "OK" or not fetch_data:
            return []

        results: List[Dict[str, Any]] = []
        for item in fetch_data:
            if not isinstance(item, tuple) or len(item) < 2 or not isinstance(item[1], (bytes, bytearray)):
                continue
            parsed_hdr = email.message_from_bytes(bytes(item[1]))
            subject = _decode_mime_header(str(parsed_hdr.get("Subject", "") or ""))
            from_raw = _decode_mime_header(str(parsed_hdr.get("From", "") or ""))
            _, from_addr = parseaddr(from_raw)
            to_raw = _decode_mime_header(str(parsed_hdr.get("To", "") or ""))
            dt = _parse_msg_datetime(str(parsed_hdr.get("Date", "") or ""))
            results.append(
                {
                    "subject": subject,
                    "sender": (from_addr or from_raw).strip(),
                    "to": [to_raw] if to_raw else [],
                    "date": dt,
                    "labels": {"SENT"},
                    "is_sent": True,
                }
            )
        return results
    except Exception:
        return []
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass


def _extract_sent_reply_metadata(
    messages: Sequence[Any],
    sent_messages: Sequence[Any] = (),
    owner_email: str = "carsonmail009@gmail.com",
) -> Tuple[List[str], Dict[str, float]]:
    """Extracts normalized outbound thread subjects and latest UTC epochs for reply suppression."""
    owner_low = (owner_email or "carsonmail009@gmail.com").strip().lower()
    sent_ts_by_thread: Dict[str, float] = {}
    seen_threads: set[str] = set()

    def _scan_batch(batch: Sequence[Any], assume_outbound: bool) -> None:
        for msg in batch or ():
            subject = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
            if not subject:
                continue
            subj_low = subject.lower()
            if (
                subj_low.startswith(_MASTER_BRIEFING_PREFIX)
                or "orbit security daily operational briefing" in subj_low
                or "google ai daily briefing" in subj_low
            ):
                continue

            if not assume_outbound:
                sender = str(_msg_field(msg, "sender", "") or "").lower()
                labels_low = {str(lbl).lower() for lbl in (_msg_field(msg, "labels", set()) or set())}
                is_sent_flag = bool(_msg_field(msg, "is_sent", False))
                is_outbound = is_sent_flag or ("sent" in labels_low) or (bool(owner_low) and owner_low in sender)
                if not is_outbound:
                    continue

            t_key = _normalize_thread_key(subject)
            if not t_key:
                continue
            seen_threads.add(t_key)
            dt = _parse_msg_datetime(_msg_field(msg, "date"))
            if dt is not None:
                ts = float(dt.timestamp())
                if ts > sent_ts_by_thread.get(t_key, -1.0):
                    sent_ts_by_thread[t_key] = ts

    _scan_batch(sent_messages, assume_outbound=True)
    _scan_batch(messages, assume_outbound=False)

    sent_subjects = sorted(
        seen_threads,
        key=lambda key: (-sent_ts_by_thread.get(key, 0.0), key),
    )
    return sent_subjects, sent_ts_by_thread


def query_sent_reply_metadata(
    limit: int = 30,
    sent_messages: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Queries lightweight outbound reply metadata from [Gmail]/Sent Mail headers."""
    sent_list = list(sent_messages) if sent_messages is not None else _fetch_sent_mail_headers(limit=limit)
    owner_email, _ = _load_imap_credentials()
    subjects, timestamps = _extract_sent_reply_metadata(
        (),
        sent_messages=sent_list,
        owner_email=owner_email or "carsonmail009@gmail.com",
    )
    return {
        "sent_replied_subjects": subjects,
        "sent_replied_timestamps": timestamps,
        "sent_scanned": len(sent_list),
    }


def query_email_hygiene(
    messages: Optional[Sequence[Any]] = None,
    limit: int = 50,
    now_ts: Optional[float] = None,
    client: Optional[Any] = None,
    sent_messages: Optional[Sequence[Any]] = None,
    include_sent: bool = True,
) -> Dict[str, Any]:
    """Runs read-only EmailOrganizerEngine hygiene triage, 24h inbox flow counts, and Master Briefing extraction."""
    empty_master = {"found": False, "subject": "", "date": "", "highlights": []}
    ref_ts = float(now_ts if now_ts is not None else datetime.datetime.now(datetime.timezone.utc).timestamp())
    ref_dt = datetime.datetime.fromtimestamp(ref_ts, tz=datetime.timezone.utc)

    fetch_status = "connected"
    if messages is None:
        if client is not None:
            try:
                messages = list(client.fetch_messages(folder="INBOX", limit=limit) or [])
            except Exception as exc:
                messages = []
                fetch_status = f"error: {exc}"
        else:
            messages, fetch_status = _fetch_imap_messages(folder="INBOX", limit=limit)

    msg_list = list(messages or [])
    master_briefing = _extract_master_briefing_delta(msg_list)
    owner_email, _ = _load_imap_credentials()

    if sent_messages is not None:
        sent_list = list(sent_messages)
    elif include_sent and client is None:
        sent_list = _fetch_sent_mail_headers(limit=min(30, max(10, int(limit))))
    else:
        sent_list = []

    if not msg_list and fetch_status != "connected":
        sent_subjects, sent_timestamps = _extract_sent_reply_metadata(
            (),
            sent_messages=sent_list,
            owner_email=owner_email or "carsonmail009@gmail.com",
        )
        return {
            "status": fetch_status,
            "total_scanned": 0,
            "archived": 0,
            "trashed": 0,
            "unsubscribed": 0,
            "archived_count": 0,
            "trashed_count": 0,
            "unsubscribed_count": 0,
            "received_24h": 0,
            "read_or_cleared_24h": 0,
            "auto_hygiene_candidates": 0,
            "master_briefing": empty_master,
            "sent_replied_subjects": sent_subjects,
            "sent_replied_timestamps": sent_timestamps,
        }

    coerced = [_coerce_email_message(m, idx=i) for i, m in enumerate(msg_list)]
    archived_count = 0
    trashed_count = 0
    unsubscribed_count = 0
    triage_flagged_ids: set[str] = set()
    classifier = None

    if _ensure_email_organizer_on_path():
        try:
            from email_organizer.client import MockEmailClient
            from email_organizer.models import ActionType, OrganizerConfig
            from email_organizer.triage import EmailOrganizerEngine

            mock_client = MockEmailClient(initial_messages=coerced)
            config = OrganizerConfig(
                dry_run=True,
                enable_ledger=False,
                enable_auto_unsubscribe=False,
            )
            engine = EmailOrganizerEngine(client=mock_client, config=config, ledger=None)
            summary = engine.run_triage(folder="INBOX", limit=limit, reference_time=ref_dt)
            archived_count = int(summary.archived_count)
            trashed_count = int(summary.trashed_count)
            unsubscribed_count = int(summary.unsubscribed_count)
            classifier = engine.classifier
            for act in summary.actions:
                if act.action_type in (ActionType.ARCHIVE, ActionType.TRASH):
                    triage_flagged_ids.add(str(act.message_id))
        except Exception:
            classifier = None

    received_24h = 0
    read_or_cleared_24h = 0
    auto_hygiene_candidates = 0

    for msg in coerced:
        msg_id = str(_msg_field(msg, "id", "") or "")
        dt = _parse_msg_datetime(_msg_field(msg, "date"))
        is_24h = dt is not None and -3600.0 <= (ref_ts - dt.timestamp()) <= 86400.0

        labels_upper = {str(lbl).upper() for lbl in (_msg_field(msg, "labels", set()) or set())}
        is_read = bool(_msg_field(msg, "is_read", False))
        is_in_inbox = bool(_msg_field(msg, "is_in_inbox", True))
        is_cleared = (not is_in_inbox) or bool({"TRASH", "ARCHIVED"} & labels_upper)

        if is_24h:
            received_24h += 1
            if is_read or is_cleared:
                read_or_cleared_24h += 1

        triage_flagged = msg_id in triage_flagged_ids
        cat_val = ""
        if classifier is not None:
            try:
                cat_val = classifier.classify(msg).value
            except Exception:
                cat_val = ""

        if (is_24h or triage_flagged) and (is_in_inbox or triage_flagged):
            if _is_safe_auto_hygiene_candidate(msg, cat_val, triage_flagged):
                auto_hygiene_candidates += 1

    sent_replied_subjects, sent_replied_timestamps = _extract_sent_reply_metadata(
        coerced,
        sent_messages=sent_list,
        owner_email=owner_email or "carsonmail009@gmail.com",
    )

    return {
        "status": fetch_status,
        "total_scanned": len(coerced),
        "archived": archived_count,
        "trashed": trashed_count,
        "unsubscribed": unsubscribed_count,
        "archived_count": archived_count,
        "trashed_count": trashed_count,
        "unsubscribed_count": unsubscribed_count,
        "received_24h": received_24h,
        "read_or_cleared_24h": read_or_cleared_24h,
        "auto_hygiene_candidates": auto_hygiene_candidates,
        "master_briefing": master_briefing,
        "sent_replied_subjects": sent_replied_subjects,
        "sent_replied_timestamps": sent_replied_timestamps,
    }


def _unfold_ical_lines(content: str) -> List[str]:
    """Unfolds RFC 5545 continuation lines starting with space or tab."""
    unfolded: List[str] = []
    for raw_line in (content or "").splitlines():
        if raw_line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += raw_line[1:]
        else:
            unfolded.append(raw_line)
    return unfolded


def _extract_ical_dtstart_date(dtstart: str) -> str:
    """Extracts YYYYMMDD date token from an iCal DTSTART value."""
    match = re.search(r"(\d{8})", dtstart or "")
    return match.group(1) if match else ""


def _is_invite_event_today(
    when_str: str,
    dt_token: str,
    msg_dt: Optional[datetime.datetime],
    today_str: str,
) -> bool:
    """Determines whether a Gmail calendar invitation corresponds to today without false positives on future invites."""
    if dt_token:
        return dt_token == today_str
    ymd_match = re.search(r"(\d{4})-(\d{2})-(\d{2})", when_str or "")
    if ymd_match:
        return "".join(ymd_match.groups()) == today_str
    text_date_match = re.search(r"\b([A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})\b", when_str or "")
    if text_date_match:
        date_text = text_date_match.group(1).replace(",", "")
        for fmt in ("%b %d %Y", "%B %d %Y"):
            try:
                return datetime.datetime.strptime(date_text, fmt).strftime("%Y%m%d") == today_str
            except ValueError:
                continue
    if "today" in (when_str or "").lower():
        return True
    if msg_dt is not None and not (when_str or "").strip():
        return msg_dt.strftime("%Y%m%d") == today_str
    return False


def _scan_gmail_calendar_invites(
    messages: Sequence[Any],
    today_str: str,
) -> List[Dict[str, Any]]:
    """Scans recent Gmail messages for calendar invitation markers as a fallback when iCal has 0 VEVENTs."""
    invites: List[Dict[str, Any]] = []
    seen_keys: set[str] = set()

    for msg in messages or []:
        subject = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
        sender = _clean_single_line(str(_msg_field(msg, "sender", "") or ""))
        headers = _msg_field(msg, "headers", {}) or {}
        content_type = str(headers.get("Content-Type", "") or "") if isinstance(headers, dict) else ""
        body_text = str(_msg_field(msg, "body_text", "") or "")
        body_html = str(_msg_field(msg, "body_html", "") or "")
        combined = f"{content_type}\n{body_text[:2000]}\n{body_html[:1000]}"

        is_subj_invite = bool(_CALENDAR_INVITE_SUBJECT_RE.search(subject))
        is_marker_invite = bool(_CALENDAR_INVITE_MARKER_RE.search(combined))
        is_google_cal = "calendar-notification@google.com" in sender.lower()
        if not (is_subj_invite or is_marker_invite or (is_google_cal and subject)):
            continue

        # Prefer embedded VEVENT summary/dtstart when available
        summary = ""
        dtstart = ""
        if "BEGIN:VEVENT" in combined:
            for block in combined.split("BEGIN:VEVENT")[1:]:
                if "END:VEVENT" not in block:
                    continue
                for ln in _unfold_ical_lines(block):
                    if ln.startswith("SUMMARY:"):
                        summary = ln[8:].strip()
                    elif ln.startswith("DTSTART"):
                        dtstart = ln.split(":", 1)[-1].strip()
                if summary or dtstart:
                    break

        if not summary:
            summary = _CALENDAR_INVITE_SUBJECT_RE.sub("", subject).strip() or subject or "Calendar Invitation"
            if "@" in summary:
                summary = summary.split("@", 1)[0].strip()

        parsed_dt = _parse_msg_datetime(_msg_field(msg, "date"))
        when = ""
        dt_token = _extract_ical_dtstart_date(dtstart)
        if dt_token:
            when = f"{dt_token[:4]}-{dt_token[4:6]}-{dt_token[6:8]}"
        elif "@" in subject:
            when = subject.split("@", 1)[-1].strip()
        elif parsed_dt is not None:
            when = parsed_dt.strftime("%Y-%m-%d %H:%M")
        else:
            when = "Recent invite"

        is_today = _is_invite_event_today(when, dt_token, parsed_dt, today_str)

        dedup_key = f"{summary.lower()}|{when.lower()}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        invites.append(
            {
                "summary": summary,
                "when": when,
                "source": "gmail_invite",
                "sender": sender,
                "subject": subject,
                "is_today": is_today,
            }
        )

    return invites


def query_google_calendar(
    ical_url: Optional[str] = None,
    messages: Optional[Sequence[Any]] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """Queries Google Calendar iCal feed with empty-feed diagnostics and Gmail invite fallback."""
    resolved_url = ical_url if ical_url is not None else os.getenv("GOOGLE_CALENDAR_ICAL_URL")
    events_today: List[str] = []
    events_week: List[str] = []
    birthdays: List[str] = []
    tasks: List[str] = []
    structured_events: List[Dict[str, Any]] = []

    today_str = datetime.date.today().strftime("%Y%m%d")
    vevent_count = 0
    ical_bytes = 0
    feed_status = "UNCONFIGURED"
    fallback_used = False
    fallback_events_count = 0
    has_http_url = bool(resolved_url and str(resolved_url).startswith("http"))

    if has_http_url:
        try:
            req = urllib.request.Request(str(resolved_url), headers={"User-Agent": "OrbitBriefing/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw_bytes = resp.read()
            ical_bytes = len(raw_bytes)
            content = raw_bytes.decode("utf-8", errors="ignore")
            blocks = [b for b in content.split("BEGIN:VEVENT")[1:] if "END:VEVENT" in b]
            vevent_count = len(blocks)

            for block in blocks:
                summary = "Untitled Event"
                dtstart = ""
                for line in _unfold_ical_lines(block):
                    if line.startswith("SUMMARY:"):
                        summary = line[8:].strip()
                    elif line.startswith("DTSTART"):
                        dtstart = line.split(":", 1)[-1].strip()

                dt_token = _extract_ical_dtstart_date(dtstart)
                is_birthday = "birthday" in summary.lower()
                is_today = bool(today_str in dtstart or dt_token == today_str)

                if is_birthday:
                    birthdays.append(f"🎂 {summary}")
                elif is_today:
                    events_today.append(f"📅 {summary}")
                elif dtstart:
                    events_week.append(f"🗓️ {summary} ({dtstart[:8]})")

                structured_events.append(
                    {
                        "summary": summary,
                        "when": dtstart[:16] if dtstart else "",
                        "source": "ical",
                        "sender": "",
                        "subject": summary,
                        "is_today": is_today,
                    }
                )

            if vevent_count == 0:
                feed_status = f"EMPTY_ICAL_FEED (0 VEVENTs, {ical_bytes} bytes)"
            else:
                feed_status = f"OK ({vevent_count} VEVENTs, {ical_bytes} bytes)"
        except Exception as exc:
            feed_status = f"ICAL_FETCH_ERROR ({exc})"
            events_today.append(f"Calendar sync note: {exc}")

    # Trigger Gmail invite fallback when configured feed has 0 VEVENTs (or failed),
    # or when explicit messages were passed by caller/test with no iCal events found.
    should_run_fallback = (has_http_url and vevent_count == 0) or (messages is not None and vevent_count == 0)
    if should_run_fallback:
        invite_msgs: List[Any] = []
        fallback_scan_ok = False
        if messages is not None:
            invite_msgs = list(messages)
            fallback_scan_ok = True
        else:
            fetched_msgs, fetch_status = _fetch_imap_messages(
                folder="INBOX",
                query='OR SUBJECT "Invitation" TEXT ".ics"',
                limit=limit,
            )
            if fetch_status == "connected":
                invite_msgs = fetched_msgs
                fallback_scan_ok = True
            elif fetch_status.startswith("error:"):
                # Retry broad recent peek in case IMAP server rejects compound OR search
                fetched_msgs, fetch_status2 = _fetch_imap_messages(folder="INBOX", query=None, limit=min(limit, 15))
                if fetch_status2 == "connected":
                    invite_msgs = fetched_msgs
                    fallback_scan_ok = True

        if fallback_scan_ok:
            fallback_used = True
            invites = _scan_gmail_calendar_invites(invite_msgs, today_str=today_str)
            fallback_events_count = len(invites)
            for inv in invites:
                structured_events.append(inv)
                label = f"📩 {inv['summary']} ({inv['when']})" if inv["when"] else f"📩 {inv['summary']}"
                if inv["is_today"]:
                    events_today.append(label)
                else:
                    events_week.append(label)

    is_configured = bool(has_http_url or events_today or events_week or structured_events)

    return {
        "configured": is_configured,
        "feed_status": feed_status,
        "vevent_count": vevent_count,
        "ical_bytes": ical_bytes,
        "fallback_used": fallback_used,
        "fallback_events_count": fallback_events_count,
        "events": structured_events[:10],
        "events_today": events_today[:5],
        "events_week": events_week[:5],
        "birthdays": birthdays,
        "tasks": tasks,
    }


def query_calendar_and_tasks(
    ical_url: Optional[str] = None,
    messages: Optional[Sequence[Any]] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """Extracts today's and this week's events, birthdays, and tasks from Google Workspace."""
    return query_google_calendar(ical_url=ical_url, messages=messages, limit=limit)


def _fetch_hn_algolia_hits(timeout: float = 3.5) -> List[Dict[str, Any]]:
    req = urllib.request.Request(
        "https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=30",
        headers={"User-Agent": "OrbitBriefing/2.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    hits = data.get("hits", [])
    return hits if isinstance(hits, list) else []


def _fetch_google_news_rss(timeout: float = 3.5) -> List[str]:
    req = urllib.request.Request(
        "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en",
        headers={"User-Agent": "OrbitBriefing/2.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw_xml = resp.read()
    root = ET.fromstring(raw_xml)
    headlines: List[str] = []
    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        if title:
            headlines.append(title)
    return headlines


def classify_intel_feeds(
    hn_hits: List[Dict[str, Any]],
    rss_headlines: List[str],
) -> Dict[str, List[str]]:
    """Classifies HN frontpage hits and world news RSS headlines cleanly without substring noise."""
    ai_innovations: List[str] = []
    tech_and_security: List[str] = []
    fallback_hn_world: List[str] = []

    for hit in hn_hits:
        title = str(hit.get("title") or "").strip()
        if not title:
            continue
        url = str(hit.get("url") or "").strip()
        points = hit.get("points")
        pts_tag = f" [{points} pts]" if isinstance(points, int) else ""
        formatted = f"{title}{pts_tag} ({url})" if url else f"{title}{pts_tag}"

        if AI_KEYWORD_RE.search(title):
            if len(ai_innovations) < 3:
                ai_innovations.append(formatted)
        elif SECURITY_TECH_RE.search(title):
            if len(tech_and_security) < 3:
                tech_and_security.append(formatted)
        else:
            fallback_hn_world.append(formatted)

    # Top up tech_and_security from remaining high-point HN engineering stories if under 3
    for item in fallback_hn_world:
        if len(tech_and_security) >= 3:
            break
        tech_and_security.append(item)

    world_news = [h for h in rss_headlines if h][:4]
    if not world_news:
        world_news = [item.split(" (http")[0] for item in fallback_hn_world[:4]]

    return {
        "ai_innovations": ai_innovations,
        "tech_and_security": tech_and_security,
        "world_news": world_news,
    }


def _headline_text(item: Any) -> str:
    """Extracts clean headline text from either a dict item or formatted news string."""
    if isinstance(item, dict):
        raw = str(item.get("title") or item.get("headline") or item.get("summary") or "").strip()
    else:
        raw = str(item or "").strip()
    if not raw:
        return ""
    raw = re.sub(r"\s*\(https?://[^)]+\)\s*$", "", raw)
    raw = re.sub(r"\s*\[\d+\s*pts\]\s*$", "", raw)
    return _clean_single_line(raw)


def _clamp_single_sentence(text: str, max_len: int = 220) -> str:
    """Normalizes LLM output into a clean single-line 1-sentence takeaway."""
    cleaned = _clean_single_line(text).strip("\"'` ")
    if not cleaned:
        return ""
    # Keep first complete sentence if multiple sentences were returned
    sent_match = re.match(r"^(.+?[.!?])(?:\s+[A-Z0-9]|$)", cleaned)
    if sent_match:
        cleaned = sent_match.group(1).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3].rstrip() + "..."
    return cleaned


def _deterministic_news_takeaway(
    ai_headlines: List[str],
    world_headlines: List[str],
) -> Dict[str, str]:
    """Provides fast deterministic 1-sentence builder takeaways when Ollama is unavailable."""
    top_ai = ai_headlines[0] if ai_headlines else ""
    if not top_ai or "temporarily unavailable" in top_ai.lower():
        ai_takeaway = (
            "Live AI headlines are temporarily offline; focus on deterministic local model verification and test coverage."
        )
    elif re.search(r"\b(ggml|ollama|vllm|inference|gpu|quant|local|llama)\b", top_ai, re.IGNORECASE):
        ai_takeaway = (
            f"{top_ai} directly impacts local inference throughput, hardware efficiency, and zero-token security automation."
        )
    elif re.search(r"\b(agent|agents|mcp|coding|llm|rag|claude|gemini|openai)\b", top_ai, re.IGNORECASE):
        ai_takeaway = (
            f"{top_ai} shapes how autonomous coding agents, tool protocols, and verification loops are engineered."
        )
    else:
        ai_takeaway = (
            f"Tracking {top_ai} helps prioritize Orbit Security's AI tooling roadmap and competitive telemetry."
        )

    top_world = world_headlines[0] if world_headlines else ""
    if not top_world or "temporarily unavailable" in top_world.lower():
        world_takeaway = (
            "Macro feeds are temporarily offline; keep cloud infrastructure resilient and monitor client perimeter baselines."
        )
    elif re.search(r"\b(outage|flight|canceled|ground stop|grid|network|cyber|breach|hack|dns|cloud)\b", top_world, re.IGNORECASE):
        world_takeaway = (
            f"{top_world} underscores infrastructure blast radius, vendor resilience, and client continuity risk."
        )
    elif re.search(r"\b(fed|rate|market|tariff|economy|budget|funding|recession|stock)\b", top_world, re.IGNORECASE):
        world_takeaway = (
            f"{top_world} influences enterprise security budgets, SaaS procurement velocity, and pricing strategy."
        )
    else:
        world_takeaway = (
            f"{top_world} signals shifting geopolitical and regulatory risk that affects enterprise perimeter priorities."
        )

    return {
        "ai_takeaway": _clamp_single_sentence(ai_takeaway),
        "world_takeaway": _clamp_single_sentence(world_takeaway),
    }


def _parse_ollama_takeaways(raw_response: str) -> Tuple[str, str]:
    """Parses JSON or labeled-line takeaways from an Ollama /api/generate response string."""
    clean = (raw_response or "").strip()
    if not clean:
        return "", ""
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean)
        clean = re.sub(r"\s*```$", "", clean)

    try:
        parsed = json.loads(clean)
        if isinstance(parsed, dict):
            return (
                _clamp_single_sentence(str(parsed.get("ai_takeaway", "") or "")),
                _clamp_single_sentence(str(parsed.get("world_takeaway", "") or "")),
            )
    except Exception:
        m = re.search(r"\{.*\}", clean, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
                if isinstance(parsed, dict):
                    return (
                        _clamp_single_sentence(str(parsed.get("ai_takeaway", "") or "")),
                        _clamp_single_sentence(str(parsed.get("world_takeaway", "") or "")),
                    )
            except Exception:
                pass

    ai_val = ""
    world_val = ""
    for line in clean.splitlines():
        ln = line.strip()
        if re.match(r"^(?:ai_takeaway|ai)\s*:", ln, re.IGNORECASE):
            ai_val = _clamp_single_sentence(ln.split(":", 1)[1])
        elif re.match(r"^(?:world_takeaway|world)\s*:", ln, re.IGNORECASE):
            world_val = _clamp_single_sentence(ln.split(":", 1)[1])
    return ai_val, world_val


def _derive_ollama_ps_url(ollama_url: str) -> str:
    """Derives the Ollama /api/ps endpoint URL from an /api/generate URL."""
    parsed = urllib.parse.urlsplit(ollama_url or _DEFAULT_OLLAMA_GENERATE_URL)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/api/ps"
    return "http://localhost:11434/api/ps"


def _query_warm_ollama_models(
    ps_url: str,
    ps_timeout: float = 1.5,
) -> Tuple[List[str], bool]:
    """Queries Ollama /api/ps to reuse models already loaded in VRAM.

    Returns (warm_model_names, daemon_offline).
    """
    req = urllib.request.Request(ps_url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=ps_timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
        models = body.get("models", []) if isinstance(body, dict) else []
        warm: List[str] = []
        for entry in models:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or entry.get("model") or "").strip()
            if name and name not in warm:
                warm.append(name)
        return warm, False
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ConnectionRefusedError) or "connection refused" in str(exc).lower():
            return [], True
        return [], False
    except ConnectionRefusedError:
        return [], True
    except Exception:
        return [], False


def _synthesize_news_takeaway(
    ai_news: Sequence[Any],
    world_news: Sequence[Any],
    ollama_url: str = _DEFAULT_OLLAMA_GENERATE_URL,
    timeout: float = 8.0,
) -> Dict[str, str]:
    """Queries local Ollama (warm VRAM model first, else fast local models) for 1-sentence takeaways."""
    ai_headlines = [h for h in (_headline_text(x) for x in (ai_news or [])) if h][:3]
    world_headlines = [h for h in (_headline_text(x) for x in (world_news or [])) if h][:3]
    fallback = _deterministic_news_takeaway(ai_headlines, world_headlines)

    has_live_ai = any("temporarily unavailable" not in h.lower() for h in ai_headlines)
    has_live_world = any("temporarily unavailable" not in h.lower() for h in world_headlines)
    if not (has_live_ai or has_live_world):
        return fallback

    ps_url = _derive_ollama_ps_url(ollama_url)
    warm_models, daemon_offline = _query_warm_ollama_models(
        ps_url,
        ps_timeout=min(1.5, float(timeout)),
    )
    if daemon_offline:
        return fallback

    default_order = ("qwen2.5-coder:7b", "orbit-critic:latest", "gemma4:12b")
    candidate_models: List[str] = []
    for candidate in list(warm_models) + list(default_order):
        if candidate and candidate not in candidate_models:
            candidate_models.append(candidate)

    prompt = (
        "You are an AI and cybersecurity engineering advisor. "
        "Given the top AI and World headlines below, return strict JSON with keys "
        '"ai_takeaway" and "world_takeaway". Each value must be exactly 1 concise sentence '
        "(under 28 words) explaining why those headlines matter to an AI/cybersecurity builder.\n"
        f"AI headlines: {ai_headlines}\n"
        f"World headlines: {world_headlines}\n"
        "JSON:"
    )

    for idx, model_name in enumerate(candidate_models):
        has_next = idx + 1 < len(candidate_models)
        payload = json.dumps(
            {
                "model": model_name,
                "prompt": prompt,
                "format": "json",
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 140},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            ollama_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if isinstance(body, dict) and body.get("error"):
                err_msg = str(body.get("error", "")).lower()
                if has_next and ("not found" in err_msg or "model" in err_msg):
                    continue
                break
            ai_out, world_out = _parse_ollama_takeaways(str(body.get("response", "") if isinstance(body, dict) else ""))
            if ai_out or world_out:
                return {
                    "ai_takeaway": ai_out or fallback["ai_takeaway"],
                    "world_takeaway": world_out or fallback["world_takeaway"],
                }
            break
        except urllib.error.HTTPError as exc:
            if has_next and exc.code == 404:
                continue
            break
        except Exception:
            break

    return fallback


def query_intel_and_world_news() -> Dict[str, Any]:
    """Pulls top AI innovations, engineering/security frontpage items, world macro news, and 1-line takeaways."""
    hn_hits: List[Dict[str, Any]] = []
    rss_headlines: List[str] = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        hn_future = pool.submit(_fetch_hn_algolia_hits)
        rss_future = pool.submit(_fetch_google_news_rss)
        try:
            hn_hits = hn_future.result(timeout=4.5)
        except Exception:
            hn_hits = []
        try:
            rss_headlines = rss_future.result(timeout=4.5)
        except Exception:
            rss_headlines = []

    if not hn_hits and not rss_headlines:
        fallback_news = {
            "ai_innovations": [
                "Live AI news feed temporarily unavailable (network timeout)",
            ],
            "tech_and_security": [
                "Engineering & security feed temporarily unavailable (network timeout)",
            ],
            "world_news": [
                "World macro RSS feed temporarily unavailable (network timeout)",
            ],
        }
        takeaways = _synthesize_news_takeaway(
            fallback_news["ai_innovations"],
            fallback_news["world_news"],
        )
        return {**fallback_news, **takeaways}

    classified = classify_intel_feeds(hn_hits=hn_hits, rss_headlines=rss_headlines)
    takeaways = _synthesize_news_takeaway(
        classified.get("ai_innovations", []),
        classified.get("world_news", []),
    )
    return {**classified, **takeaways}
