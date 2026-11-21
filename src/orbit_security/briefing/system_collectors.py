"""Hardware, Ports, Workspace/Git, Stripe, Daemon, GitHub CI, GEO, and News Collectors."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    import psutil
except ImportError:
    psutil = None

from .email_cockpit import (
    _clean_single_line,
    archive_superseded_ci_alerts_in_imap,
    query_calendar_and_tasks,
    query_email_hygiene,
    query_live_email_telemetry,
)
from .models import CollectorAdapters, EmailCollectRequest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"

AI_KEYWORD_RE = re.compile(
    r"\b(ai|llm|llms|gpt|claude|gemini|ollama|ggml|mcp|agent|agents|rag|transformer|inference|openai|anthropic|deepmind|neural|vllm|diffusion)\b",
    re.IGNORECASE,
)

SECURITY_TECH_RE = re.compile(
    r"\b(security|cve|breach|vuln|vulnerability|zero-day|0day|exploit|ransomware|kernel|linux|rust|compiler|wasm|sqlite|postgres|github|python|typescript|browser|dns|tls|ssl)\b",
    re.IGNORECASE,
)

KNOWN_EXPECTED_PORTS: Dict[int, str] = {
    4064: "Patch Desktop App",
    4173: "Vite Preview Test Server (ephemeral dev)",
    8088: "Orbit Stripe Webhook / Local Cockpit",
    8200: "Nova Brain HTTP Server",
    8201: "Nova Brain Telemetry / WebSocket",
    8203: "Orbit MCP / Sidekick Bridge",
    8501: "Streamlit Test Server (ephemeral dev)",
    8765: "Browser Companion",
    8989: "Orbit Multi-Adapter Proxy",
    9008: "Orbit Sidekick Health",
    9010: "Orbit Inbox Worker Health",
    9012: "Nova Email Daemon Health",
    9090: "Orbit Sentinel Health",
    11434: "Ollama Local LLM",
    28894: "OpenCode Server",
}

_EPHEMERAL_DEV_PORTS = frozenset({4173, 8501})
_IGNORED_OS_SYNC_PROCESSES = frozenset(
    {
        "svchost",
        "svchost.exe",
        "system",
        "googledrivefs",
        "googledrivefs.exe",
        "onedrive.sync.service",
        "onedrive.sync.service.exe",
        "lsass",
        "lsass.exe",
    }
)

CORE_ACTIVE_REPOS: Tuple[str, ...] = (
    "orbit-security",
    "microgravity",
    "nova-brain",
    "hypernote",
    "canine-sanctuary",
    "browser-companion",
    "email-organizer",
)


def _find_workspace_root(explicit_root: Optional[Path] = None) -> Path:
    if explicit_root is not None:
        return Path(explicit_root)
    if Path(r"C:\AgyHut\projects").is_dir():
        return Path(r"C:\AgyHut")
    if Path(r"A:\projects").is_dir():
        return Path(r"A:\\")
    return _REPO_ROOT.parent.parent


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


def _triage_listening_ports() -> Dict[str, Any]:
    """Scans local listening TCP ports and classifies expected Orbit/ecosystem services vs unexpected listeners."""
    open_ports: List[int] = []
    for port in (4173, 8501, 8765):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # roe-exempt: hardcoded 127.0.0.1 local port triage probe
                s.settimeout(0.2)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass

    seen_ports: Dict[int, Dict[str, Any]] = {}
    if psutil is not None:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if str(getattr(conn, "status", "")) != "LISTEN":
                    continue
                laddr = getattr(conn, "laddr", None)
                if not laddr:
                    continue
                ip = str(getattr(laddr, "ip", "") or "")
                port = int(getattr(laddr, "port", 0) or 0)
                if port < 1024 or port > 49151:
                    continue
                if ip not in ("127.0.0.1", "0.0.0.0", "::", "::1", ""):
                    continue
                pid = getattr(conn, "pid", None)
                proc_name = ""
                if isinstance(pid, int) and pid > 0:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except Exception:
                        proc_name = ""
                if proc_name.lower() in _IGNORED_OS_SYNC_PROCESSES:
                    continue
                if port not in seen_ports:
                    seen_ports[port] = {"port": port, "addr": ip, "pid": pid, "process": proc_name or "unknown"}
        except Exception:
            pass

    for port in (4173, 8088, 8200, 8203, 8501, 8765, 8989, 11434):
        if port in seen_ports:
            continue
        if port in open_ports:
            seen_ports[port] = {"port": port, "addr": "127.0.0.1", "pid": None, "process": "detected"}
            continue
        if port not in (4173, 8501, 8765):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # roe-exempt: hardcoded 127.0.0.1 local port triage probe
                    s.settimeout(0.15)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        seen_ports[port] = {"port": port, "addr": "127.0.0.1", "pid": None, "process": "detected"}
            except Exception:
                pass

    expected_listeners: List[Dict[str, Any]] = []
    unexpected_listeners: List[Dict[str, Any]] = []
    for port in sorted(seen_ports):
        entry = dict(seen_ports[port])
        known_svc = KNOWN_EXPECTED_PORTS.get(port)
        if known_svc and port not in _EPHEMERAL_DEV_PORTS:
            entry["service"] = known_svc
            entry["status"] = "expected"
            expected_listeners.append(entry)
        else:
            entry["service"] = known_svc or "Unknown Listener"
            entry["status"] = "ephemeral_dev" if port in _EPHEMERAL_DEV_PORTS else "unexpected"
            unexpected_listeners.append(entry)

    if unexpected_listeners:
        unexp_desc = ", ".join(f"{e['port']} ({e['service']}/{e['process']})" for e in unexpected_listeners)
        summary = f"ALERT: {len(unexpected_listeners)} unexpected/dev listener(s): {unexp_desc} | {len(expected_listeners)} expected ecosystem listener(s)"
    elif expected_listeners:
        exp_desc = ", ".join(f"{e['port']}={e['service']}" for e in expected_listeners[:5])
        if len(expected_listeners) > 5:
            exp_desc += f" (+{len(expected_listeners) - 5} more)"
        summary = f"0 unexpected listeners; {len(expected_listeners)} expected local service(s) [{exp_desc}]"
    else:
        summary = "0 open debug/ecosystem listeners detected"

    return {
        "open_ports": open_ports,
        "port_triage": {
            "expected_listeners": expected_listeners,
            "unexpected_listeners": unexpected_listeners,
            "total_listening": len(seen_ports),
            "summary": summary,
        },
    }


def query_system_telemetry() -> Dict[str, Any]:
    """Queries live hardware sensors, CPU, thermals, uptime, RAM, storage health, and open-port triage."""
    cpu_name = _get_cpu_name()
    cores = os.cpu_count() or 4
    thermals = _query_hardware_thermals()
    temp_c = thermals.get("cpu_temp")

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

    port_info = _triage_listening_ports()

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
        "open_ports": port_info["open_ports"],
        "port_triage": port_info["port_triage"],
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


def _query_git_repo_details(repo_path: str, pathspec: Optional[str] = None) -> Dict[str, Any]:
    """Queries last commit, short SHA, branch, 48h commit count, and dirty-tree file count."""
    args_base = ["git", "-C", repo_path]
    tail = ["--", pathspec] if pathspec else ["--", "."]
    result: Dict[str, Any] = {
        "last_commit": "",
        "head_sha": "",
        "commit_msg": "",
        "branch": "N/A",
        "commits_48h": 0,
        "dirty_count": 0,
        "dirty_files": [],
    }
    try:
        out = subprocess.check_output(
            [*args_base, "log", "-1", "--format=%cd\x1f%h\x1f%s", "--date=iso", *tail],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).strip()
        if not out:
            return result
        parts = out.split("\x1f", 2)
        c_date = parts[0].strip()
        c_sha = parts[1].strip() if len(parts) > 1 else ""
        c_msg = parts[2].strip() if len(parts) > 2 else ""
        if pathspec:
            c_branch = "master"
        else:
            c_branch = subprocess.check_output(
                [*args_base, "branch", "--show-current"],
                text=True,
                timeout=2,
                stderr=subprocess.DEVNULL,
            ).strip()
        cnt_out = subprocess.check_output(
            [*args_base, "rev-list", "--count", "--since=48 hours ago", "HEAD", *tail],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).strip()
        status_cmd = [*args_base, "status", "--porcelain"]
        if pathspec:
            status_cmd.extend(["--", pathspec])
        st_out = subprocess.check_output(
            status_cmd,
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
        dirty_lines = [ln.strip() for ln in st_out.splitlines() if ln.strip()]
        result.update(
            {
                "last_commit": c_date,
                "head_sha": c_sha,
                "commit_msg": c_msg,
                "branch": c_branch or "HEAD",
                "commits_48h": int(cnt_out) if cnt_out.isdigit() else 0,
                "dirty_count": len(dirty_lines),
                "dirty_files": dirty_lines[:5],
            }
        )
    except Exception:
        pass
    return result


def _query_git_last_commit(repo_path: str, pathspec: Optional[str] = None) -> Tuple[str, str, str]:
    """Returns (last_commit_iso[:16], commit_subject, branch) scoped cleanly to repo_path/pathspec."""
    details = _query_git_repo_details(repo_path, pathspec=pathspec)
    return details["last_commit"], details["commit_msg"], details["branch"]


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
            has_standalone_git = os.path.isfile(os.path.join(dot_git, "HEAD")) or os.path.isfile(dot_git)

            last_commit_date = ""
            commit_msg = ""
            branch = "N/A"
            head_sha = ""
            commits_48h = 0
            dirty_count = 0
            dirty_files: List[str] = []
            is_active_48h = False
            repo_kind = "untracked"

            if has_standalone_git:
                repo_kind = "standalone"
                details = _query_git_repo_details(p)
                c_date = details["last_commit"]
                if c_date:
                    branch = details["branch"]
                    commit_msg = details["commit_msg"]
                    head_sha = details["head_sha"]
                    commits_48h = details["commits_48h"]
                    dirty_count = details["dirty_count"]
                    dirty_files = details["dirty_files"]
                    last_commit_date = c_date[:16]
                    is_active_48h = _is_within_48h(c_date, now) or commits_48h > 0
            elif workspace_root:
                details = _query_git_repo_details(workspace_root, f"projects/{name}")
                c_date = details["last_commit"]
                if c_date:
                    repo_kind = "monorepo"
                    branch = f"{details['branch']} (monorepo)"
                    commit_msg = details["commit_msg"]
                    head_sha = details["head_sha"]
                    commits_48h = details["commits_48h"]
                    dirty_count = details["dirty_count"]
                    dirty_files = details["dirty_files"]
                    last_commit_date = c_date[:16]
                    is_active_48h = _is_within_48h(c_date, now) or commits_48h > 0

            roadmap = "None"
            for r_name in ("ROADMAP.md", "FUTURE_ROADMAP.md", "HANDOFF_NOVA_FEATURE_ROADMAP.md", "HANDOFF.md"):
                if os.path.exists(os.path.join(p, r_name)):
                    roadmap = r_name
                    break

            item = {
                "name": name,
                "branch": branch,
                "head_sha": head_sha,
                "last_commit": last_commit_date,
                "commit_msg": commit_msg,
                "commits_48h": commits_48h,
                "dirty_count": dirty_count,
                "dirty_files": dirty_files,
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
    by_name = {p["name"].lower(): p for p in projects}
    core_active_repos = [by_name[name.lower()] for name in CORE_ACTIVE_REPOS if name.lower() in by_name]

    return {
        "total_projects": len(projects),
        "projects": projects,
        "core_active_repos": core_active_repos,
        "recently_active": recently_active,
        "workspace_root_commits_48h": workspace_root_commits_48h,
        "workspace_dirty_count": workspace_dirty_count,
        "inbox_queues": inbox_queues,
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


def query_stripe_telemetry() -> Dict[str, Any]:
    """Queries live Stripe API for balance, 24h charges, and subscriptions."""
    api_key = os.getenv("STRIPE_SECRET_KEY") or os.getenv("STRIPE_API_KEY")
    if not api_key:
        return {
            "status": "unconfigured",
            "available_usd": 0.0,
            "pending_usd": 0.0,
            "recent_charges": 0,
            "active_subscriptions": 0,
        }

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
    except Exception as exc:
        return {
            "status": f"error: {exc}",
            "available_usd": 0.0,
            "pending_usd": 0.0,
            "recent_charges": 0,
            "active_subscriptions": 0,
        }


def _is_pid_alive(pid: Any) -> bool:
    """Checks whether an integer PID is currently running in the OS process table."""
    if not isinstance(pid, int) or pid <= 0 or psutil is None:
        return False
    try:
        return bool(psutil.pid_exists(pid))
    except Exception:
        return False


def query_daemon_health(state_file: str = r"A:\system\state\orbit_daemon_state.json") -> Dict[str, Any]:
    """Checks PID and live OS process status of Orbit Master Supervisor and Sentinel daemon."""
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
                1
                for s in services.values()
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
            from scripts.orbit_readiness_audit import run_readiness_audit
        except ImportError:
            from orbit_readiness_audit import run_readiness_audit  # type: ignore[import-not-found]
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
        "revenue_focus": audit.get(
            "revenue_focus",
            "Option C (Dual-Track Minimal: Verified Bounties + Inbound Fixpack/Audit)",
        ),
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


def query_inbox_pipeline(leads_file: Optional[str] = None) -> Dict[str, Any]:
    """Inspects leads_state.json for negotiation status and escalations."""
    target_file = leads_file or str(_REPO_ROOT / "data" / "leads_state.json")
    if not os.path.exists(target_file):
        return {"total_threads": 0, "escalations": 0, "inquiries": 0}

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            leads = json.load(f)
        total = len(leads)
        escalations = sum(
            1
            for v in leads.values()
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


def query_campaign_outreach(
    repo_root: Optional[Path] = None,
    dispatched_file: Optional[Path] = None,
    out_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Inspects dispatched_campaigns.json (sorted newest-first) and outbound freeze status."""
    root = Path(repo_root) if repo_root else _REPO_ROOT
    d_file = Path(dispatched_file) if dispatched_file else (root / "data" / "dispatched_campaigns.json")
    o_root = Path(out_root) if out_root else (root / "outbound_campaigns")
    dispatched_count = 0
    recent = []
    if d_file.is_file():
        try:
            data = json.loads(d_file.read_text(encoding="utf-8"))
            dispatched_count = len(data)
            sorted_entries = sorted(
                data.items(),
                key=lambda kv: str((kv[1] or {}).get("dispatched_at", "")),
                reverse=True,
            )
            for domain, info in sorted_entries[:5]:
                info_dict = info if isinstance(info, dict) else {}
                recent.append(
                    f"{info_dict.get('agency_name', domain)} ({domain}) - {info_dict.get('dispatched_at', '')}"
                )
        except Exception:
            pass

    staged_count = 0
    if o_root.is_dir():
        try:
            staged_count = len([d for d in o_root.iterdir() if d.is_dir()])
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
            fallback_headers = {k: v for k, v in headers.items() if k != "Authorization"}
            req2 = urllib.request.Request(url, headers=fallback_headers)
            with urllib.request.urlopen(req2, timeout=timeout + 4.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        runs = data.get("workflow_runs", [])
        if not runs:
            return {
                "status": "empty",
                "head_sha": "",
                "all_green": False,
                "failing_workflows": [],
                "passing_workflows": [],
            }

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


def query_geo_panel_telemetry(log_file: Optional[str] = None) -> Dict[str, Any]:
    """Queries the latest 12-query GEO visibility & citation panel summary and delta from data/geo_panels.jsonl."""
    try:
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
            "delta": {
                "mention_rate_delta_pct": 0.0,
                "citation_rate_delta_pct": 0.0,
                "authority_score_delta": 0.0,
            },
            "summary_markdown": f"- **GEO Panel Status:** Unavailable ({ex})",
        }


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
    elif re.search(
        r"\b(outage|flight|canceled|ground stop|grid|network|cyber|breach|hack|dns|cloud)\b",
        top_world,
        re.IGNORECASE,
    ):
        world_takeaway = (
            f"{top_world} underscores infrastructure blast radius, vendor resilience, and client continuity risk."
        )
    elif re.search(
        r"\b(fed|rate|market|tariff|economy|budget|funding|recession|stock)\b",
        top_world,
        re.IGNORECASE,
    ):
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
    """Queries Ollama /api/ps to reuse models already loaded in VRAM."""
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
            ai_out, world_out = _parse_ollama_takeaways(
                str(body.get("response", "") if isinstance(body, dict) else "")
            )
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


def query_intel_and_world_news(
    *,
    hn_fetcher: Optional[Callable[[], List[Dict[str, Any]]]] = None,
    rss_fetcher: Optional[Callable[[], List[str]]] = None,
) -> Dict[str, Any]:
    """Pulls top AI innovations, engineering/security frontpage items, world macro news, and 1-line takeaways."""
    hn_fn = hn_fetcher or _fetch_hn_algolia_hits
    rss_fn = rss_fetcher or _fetch_google_news_rss
    hn_hits: List[Dict[str, Any]] = []
    rss_headlines: List[str] = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        hn_future = pool.submit(hn_fn)
        rss_future = pool.submit(rss_fn)
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


def probe_workspace_critic_evidence(
    ci_candidates: List[Dict[str, str]],
    mb_blob: str,
    workspace_root: Optional[Path] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Phase 1 local disk/git probe for Critic verification (git HEAD/ahead counts + workspace go.mod files)."""
    ws_root = _find_workspace_root(workspace_root)
    repo_git_states: Dict[str, Dict[str, Any]] = {}

    for ci in ci_candidates:
        repo_full = str(ci.get("repo") or "")
        short_repo = repo_full.split("/")[-1].strip().lower()
        fail_sha = str(ci.get("sha") or "")
        if not short_repo:
            continue
        local_dir = ws_root / "projects" / short_repo
        local_head = ""
        commits_ahead = 0
        if (local_dir / ".git").exists():
            try:
                local_head = subprocess.check_output(
                    ["git", "-C", str(local_dir), "rev-parse", "--short", "HEAD"],
                    text=True,
                    timeout=2,
                    stderr=subprocess.DEVNULL,
                ).strip()
                ahead_out = subprocess.check_output(
                    ["git", "-C", str(local_dir), "rev-list", "--count", f"{fail_sha}..HEAD"],
                    text=True,
                    timeout=2,
                    stderr=subprocess.DEVNULL,
                ).strip()
                if ahead_out.isdigit():
                    commits_ahead = int(ahead_out)
            except Exception:
                pass
        repo_git_states[f"{short_repo}:{fail_sha.lower()}"] = {
            "local_dir": str(local_dir),
            "local_head": local_head,
            "commits_ahead": commits_ahead,
        }

    go_mod_files: Dict[str, str] = {}
    if re.search(r"CVE-2026-34742|go\s+mcp\s+sdk", mb_blob or "", re.IGNORECASE):
        go_mod_paths: List[Path] = []
        sys_gomod = ws_root / "system" / "scripts" / "go.mod"
        if sys_gomod.is_file():
            go_mod_paths.append(sys_gomod)
        proj_root = ws_root / "projects"
        if proj_root.is_dir():
            for child in sorted(proj_root.iterdir()):
                if child.is_dir() and not child.name.startswith("."):
                    gm = child / "go.mod"
                    if gm.is_file():
                        go_mod_paths.append(gm)

        for gm in go_mod_paths:
            try:
                rel = str(gm.relative_to(ws_root)).replace("\\", "/")
            except ValueError:
                rel = str(gm)
            try:
                go_mod_files[rel] = gm.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                go_mod_files[rel] = ""

    return repo_git_states, go_mod_files


def live_collector_adapters(
    *,
    repo_root: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
) -> CollectorAdapters:
    """Builds the production CollectorAdapters bundle wired to live hardware, IMAP, GitHub, Stripe, and news."""
    root = Path(repo_root) if repo_root else _REPO_ROOT

    def _email_adapter(req: EmailCollectRequest) -> Dict[str, Any]:
        return query_live_email_telemetry(
            max_retries=req.max_retries,
            retry_interval_sec=req.retry_interval_sec,
            target_date=req.target_date,
        )

    def _github_ci_adapter(repo: str = "CmfH009/Orbit-Security", branch: str = "main") -> Dict[str, Any]:
        return query_live_github_ci_status(repo=repo, branch=branch)

    def _commits_adapter(proj_radar: Dict[str, Any], now_dt: datetime.datetime) -> int:
        return _count_commits_24h(proj_radar, repo_root=root, now_dt=now_dt)

    def _critic_probe(
        ci_candidates: List[Dict[str, str]], mb_blob: str
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        return probe_workspace_critic_evidence(
            ci_candidates=ci_candidates,
            mb_blob=mb_blob,
            workspace_root=workspace_root,
        )

    return CollectorAdapters(
        system_telemetry=query_system_telemetry,
        daemon_health=query_daemon_health,
        email_telemetry=_email_adapter,
        email_hygiene=query_email_hygiene,
        calendar_tasks=query_calendar_and_tasks,
        archive_ci_alerts=archive_superseded_ci_alerts_in_imap,
        github_ci=_github_ci_adapter,
        stripe_telemetry=query_stripe_telemetry,
        option_c_readiness=lambda: query_option_c_readiness(repo_root=root),
        inbox_pipeline=query_inbox_pipeline,
        campaign_outreach=lambda: query_campaign_outreach(repo_root=root),
        geo_panel=query_geo_panel_telemetry,
        projects_radar=query_projects_radar,
        intel_news=query_intel_and_world_news,
        commits_24h=_commits_adapter,
        workspace_critic_probe=_critic_probe,
    )
