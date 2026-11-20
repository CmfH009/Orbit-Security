"""Persistent Windows Terminal (wt.exe) TUI briefing viewer & launcher for Orbit Security."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    psutil = None

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIEFINGS_DIR = _REPO_ROOT / "daily_briefings"
_STATE_FILE = _BRIEFINGS_DIR / "briefing_state_latest.json"
_PID_FILE = _BRIEFINGS_DIR / ".briefing_tui_viewer.json"
_SPOKEN_SIDECAR_FILE = _BRIEFINGS_DIR / ".briefing_tui_spoken.txt"
_HOOK_SCRIPT = Path(r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py")
_DESKTOP_AUTO_DIR = Path(r"C:\AgyHut\system\tools")
_WT_SETTINGS_PATH = (
    Path(os.environ.get("LOCALAPPDATA", ""))
    / "Packages"
    / "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
    / "LocalState"
    / "settings.json"
)
_VIEWER_TITLE = "Orbit Morning Briefing"

_ORBIT_THEME = Theme(
    {
        "markdown.h1": "bold bright_cyan",
        "markdown.h2": "bold bright_magenta",
        "markdown.h3": "bold cyan",
        "markdown.h4": "bold bright_white",
        "markdown.link": "bright_blue underline",
        "markdown.link_url": "dim bright_blue",
        "markdown.code": "bright_yellow on grey15",
        "markdown.hr": "dim cyan",
        "markdown.block_quote": "italic bright_white",
    }
)


def _make_stdio_safe() -> None:
    """Ensures stdout/stderr are valid streams when invoked under pythonw.exe."""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")


def attach_to_interactive_desktop() -> bool:
    """Attaches current thread to the user's interactive WinSta0\\Default desktop."""
    if sys.platform != "win32":
        return False
    try:
        user32 = ctypes.windll.user32
        desktop_all = 0x01FF
        hdesk = user32.OpenDesktopW("Default", 0, False, desktop_all)
        if hdesk:
            return bool(user32.SetThreadDesktop(hdesk))
    except Exception:
        pass
    return False


def _enable_vt_mode() -> None:
    """Enables ANSI/VT100 escape sequences and OSC-8 hyperlink rendering on Windows."""
    if sys.platform != "win32":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        std_output_handle = -11
        enable_vt = 0x0004
        enable_processed = 0x0001
        handle = kernel32.GetStdHandle(std_output_handle)
        if handle and handle != -1:
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | enable_vt | enable_processed)
    except Exception:
        pass


def _resolve_venv_python() -> str:
    """Returns the console python.exe inside the orbit-security venv for wt.exe tabs."""
    py_bin = _REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if py_bin.is_file():
        return str(py_bin)
    if sys.executable.lower().endswith("pythonw.exe"):
        candidate = Path(sys.executable).with_name("python.exe")
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def find_wt_executable() -> Optional[str]:
    """Resolves the Windows Terminal (wt.exe) executable path."""
    for name in ("wt.exe", "wt"):
        found = shutil.which(name)
        if found and Path(found).is_file():
            return found
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        candidate = Path(local_app_data) / "Microsoft" / "WindowsApps" / "wt.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _is_current_process_elevated() -> bool:
    """Returns True if the current process is running with elevated admin privileges."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_windows_terminal_elevated() -> Optional[bool]:
    """Detects whether the active WindowsTerminal.exe process (or profile default) is elevated."""
    if sys.platform != "win32":
        return None
    if psutil is not None:
        try:
            import win32api
            import win32con
            import win32security

            for proc in psutil.process_iter(["pid", "name"]):
                if (proc.info.get("name") or "").lower() == "windowsterminal.exe":
                    hp = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, proc.pid)
                    try:
                        ht = win32security.OpenProcessToken(hp, win32con.TOKEN_QUERY)
                        try:
                            elev = win32security.GetTokenInformation(ht, win32security.TokenElevation)
                            return bool(elev)
                        finally:
                            win32api.CloseHandle(ht)
                    finally:
                        win32api.CloseHandle(hp)
        except Exception:
            pass

    if _WT_SETTINGS_PATH.is_file():
        try:
            data = json.loads(_WT_SETTINGS_PATH.read_text(encoding="utf-8"))
            defaults = (data.get("profiles") or {}).get("defaults") or {}
            if "elevate" in defaults:
                return bool(defaults["elevate"])
        except Exception:
            pass
    return None


def _find_latest_briefing_file(explicit_file: Optional[str] = None) -> Optional[Path]:
    """Resolves the target briefing markdown path, defaulting to the newest daily briefing."""
    if explicit_file:
        p = Path(explicit_file)
        if p.is_file():
            return p
    if not _BRIEFINGS_DIR.is_dir():
        return None
    candidates = sorted(_BRIEFINGS_DIR.glob("briefing_????-??-??.md"), reverse=True)
    return candidates[0] if candidates else None


def _load_latest_spoken_summary(briefings_dir: Path = _BRIEFINGS_DIR) -> str:
    """Loads the persisted spoken_summary from briefing_state_latest.json if available."""
    state_file = briefings_dir / "briefing_state_latest.json"
    if state_file.is_file():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and str(data.get("spoken_summary") or "").strip():
                return str(data["spoken_summary"]).strip()
        except Exception:
            pass
    return ""


def _synthesize_fallback_spoken_summary(markdown_text: str) -> str:
    """Extracts top priority highlights into a concise spoken fallback if no cached spoken summary exists."""
    lines = [ln.strip() for ln in (markdown_text or "").splitlines() if ln.strip()]
    actions = [ln for ln in lines if ln[:2] in ("1.", "2.", "3.")][:3]
    joined = " ".join(a.replace("`", "") for a in actions)
    if joined:
        return f"[chuckle] Morning Carson. Nova here with your morning briefing. Top priorities today: {joined}"
    return "[chuckle] Morning Carson. Your unified morning briefing is up on screen whenever you're ready."


def _resolve_voice_python() -> str:
    """Returns the Python interpreter equipped with kokoro_onnx for Nova TTS synthesis."""
    py314 = Path(r"C:\Python314\python.exe")
    if py314.is_file():
        return str(py314)
    return _resolve_venv_python()


def _terminate_proc_tree(proc: Optional[subprocess.Popen[Any]]) -> None:
    """Terminates only the specified child subprocess and its descendants."""
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            return
        if psutil is not None:
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.terminate()
                    except Exception:
                        pass
                parent.terminate()
                _, alive = psutil.wait_procs([parent], timeout=1.5)
                for rem in alive:
                    try:
                        rem.kill()
                    except Exception:
                        pass
                return
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=1.5)
        except Exception:
            proc.kill()
    except Exception:
        pass


def _synthesize_briefing_audio_file(
    spoken_text: str,
    proc_holder: Optional[List[Optional[subprocess.Popen[Any]]]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> Optional[str]:
    """Synthesizes spoken_text via Nova's Kokoro AudioEngineRouter and returns the audio file path."""
    text = (spoken_text or "").strip()
    if not text:
        return None
    exe = _resolve_voice_python()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    synth_code = (
        "import json, os, sys; "
        "sys.path.insert(0, r'A:\\system\\scripts'); "
        "sys.path.insert(0, r'C:\\Users\\purav\\.gemini\\config\\scripts'); "
        "from nova_voice.cli import clean_for_speech, detect_operational_state; "
        "from nova_voice.core.engine import AudioEngineRouter; "
        "raw = sys.stdin.read(); "
        "clean = clean_for_speech(raw); "
        "op_state = detect_operational_state(clean); "
        "router = AudioEngineRouter(); "
        "path = router.synthesize(clean, persona='nova', op_state=op_state); "
        "print(json.dumps({'path': path or ''}))"
    )
    proc = subprocess.Popen(
        [exe, "-c", synth_code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
    )
    if proc_holder is not None:
        proc_holder[0] = proc
    try:
        stdout_data, _ = proc.communicate(input=text, timeout=60.0)
        if cancel_check and cancel_check():
            return None
        for line in reversed((stdout_data or "").splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                data = json.loads(line)
                out_path = str(data.get("path") or "").strip()
                if out_path and os.path.isfile(out_path):
                    return out_path
    except Exception:
        _terminate_proc_tree(proc)
    finally:
        if proc_holder is not None and proc_holder[0] is proc:
            proc_holder[0] = None
    return None


def _speak_via_nova_hook(spoken_text: str) -> None:
    """Invokes nova_voice_hook.py --speak cleanly using Kokoro-capable Python."""
    text = (spoken_text or "").strip()
    if not text or not _HOOK_SCRIPT.is_file():
        return
    exe = _resolve_voice_python()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.run([exe, str(_HOOK_SCRIPT), "--speak", text], check=False, creationflags=flags)


class BriefingAudioController:
    """Briefing-scoped audio player supporting Kokoro synthesis, Pause/Resume, Stop, and Quit cleanup.

    All WinMM MCI calls for a playback session execute on the single owner thread using a
    unique MCI alias (`orbit_brief_<pid>_<gen>`), ensuring Pause/Resume/Stop only affect this
    briefing window and never interrupt other Nova voice notifications.
    """

    def __init__(
        self,
        on_state_change: Optional[Callable[[str], None]] = None,
        speak_fn: Optional[Callable[[str], None]] = None,
        synthesizer: Optional[Callable[..., Optional[str]]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._state = "idle"
        self._gen = 0
        self._cmd_event = threading.Event()
        self._pending_cmd: Optional[str] = None
        self._synth_proc: List[Optional[subprocess.Popen[Any]]] = [None]
        self._thread: Optional[threading.Thread] = None
        self._on_state_change = on_state_change
        self._speak_fn = speak_fn
        self._synthesizer = synthesizer or _synthesize_briefing_audio_file

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def _set_state(self, new_state: str) -> None:
        with self._lock:
            self._state = new_state
        if self._on_state_change:
            try:
                self._on_state_change(new_state)
            except Exception:
                pass

    def play(self, spoken_text: str) -> None:
        """Starts or restarts briefing audio playback from the beginning."""
        text = (spoken_text or "").strip()
        if not text:
            return
        with self._lock:
            self._gen += 1
            my_gen = self._gen
            self._pending_cmd = "stop"
            self._cmd_event.set()
            active_proc = self._synth_proc[0]
            prev_thread = self._thread
        if active_proc is not None:
            _terminate_proc_tree(active_proc)
        if prev_thread is not None and prev_thread.is_alive() and threading.current_thread() is not prev_thread:
            prev_thread.join(timeout=1.5)

        t = threading.Thread(
            target=self._run_session,
            args=(text, my_gen),
            daemon=True,
        )
        with self._lock:
            self._thread = t
        t.start()

    def toggle_pause(self) -> str:
        """Toggles between playing and paused states for this briefing's audio."""
        with self._lock:
            if self._state == "playing":
                self._pending_cmd = "pause"
                self._cmd_event.set()
                return "paused"
            if self._state == "paused":
                self._pending_cmd = "resume"
                self._cmd_event.set()
                return "playing"
            return self._state

    def stop(self, wait: bool = True) -> None:
        """Stops only this briefing's synthesis and MCI playback immediately."""
        with self._lock:
            self._gen += 1
            self._pending_cmd = "stop"
            self._cmd_event.set()
            active_proc = self._synth_proc[0]
            prev_thread = self._thread
        if active_proc is not None:
            _terminate_proc_tree(active_proc)
        if wait and prev_thread is not None and prev_thread.is_alive() and threading.current_thread() is not prev_thread:
            prev_thread.join(timeout=1.5)
        if self.state != "idle":
            self._set_state("idle")

    def _is_stale(self, my_gen: int) -> bool:
        with self._lock:
            return self._gen != my_gen

    def _run_session(self, text: str, my_gen: int) -> None:
        if self._speak_fn is not None:
            self._set_state("playing")
            try:
                if not self._is_stale(my_gen):
                    self._speak_fn(text)
            finally:
                if not self._is_stale(my_gen):
                    self._set_state("idle")
            return

        self._set_state("synthesizing")
        audio_path = self._synthesizer(
            text,
            proc_holder=self._synth_proc,
            cancel_check=lambda: self._is_stale(my_gen),
        )
        if self._is_stale(my_gen) or not audio_path or not os.path.isfile(audio_path):
            if not self._is_stale(my_gen):
                self._set_state("idle")
            return

        if sys.platform != "win32":
            if not self._is_stale(my_gen):
                self._set_state("idle")
            return

        self._play_mci_on_owner_thread(audio_path, my_gen)

    def _play_mci_on_owner_thread(self, audio_path: str, my_gen: int) -> None:
        winmm = ctypes.windll.winmm
        alias = f"orbit_brief_{os.getpid()}_{my_gen}"
        short_path = audio_path
        try:
            buf_len = 260
            s_buf = ctypes.create_unicode_buffer(buf_len)
            if ctypes.windll.kernel32.GetShortPathNameW(audio_path, s_buf, buf_len) > 0:
                short_path = s_buf.value
        except Exception:
            pass

        with self._lock:
            if self._gen != my_gen:
                return
            self._pending_cmd = None
            self._cmd_event.clear()

        opened = False
        try:
            winmm.mciSendStringW(f"close {alias}", None, 0, None)
            rc = winmm.mciSendStringW(f'open "{short_path}" type mpegvideo alias {alias}', None, 0, None)
            if rc != 0:
                rc = winmm.mciSendStringW(f'open "{short_path}" alias {alias}', None, 0, None)
                if rc != 0:
                    return
            opened = True
            winmm.mciSendStringW(f"setaudio {alias} volume to 1000", None, 0, None)
            if winmm.mciSendStringW(f"play {alias}", None, 0, None) != 0:
                return

            self._set_state("playing")
            mode_buf = ctypes.create_unicode_buffer(128)

            while not self._is_stale(my_gen):
                self._cmd_event.wait(timeout=0.05)
                cmd: Optional[str] = None
                with self._lock:
                    if self._pending_cmd is not None:
                        cmd = self._pending_cmd
                        self._pending_cmd = None
                    self._cmd_event.clear()

                if cmd == "stop" or self._is_stale(my_gen):
                    winmm.mciSendStringW(f"stop {alias}", None, 0, None)
                    break
                if cmd == "pause":
                    winmm.mciSendStringW(f"pause {alias}", None, 0, None)
                    self._set_state("paused")
                elif cmd == "resume":
                    winmm.mciSendStringW(f"resume {alias}", None, 0, None)
                    self._set_state("playing")

                rc_mode = winmm.mciSendStringW(f"status {alias} mode", mode_buf, 128, None)
                mode_val = mode_buf.value.lower()
                if rc_mode != 0 or mode_val not in ("playing", "paused", "seeking"):
                    break
        finally:
            if opened:
                try:
                    winmm.mciSendStringW(f"stop {alias}", None, 0, None)
                    winmm.mciSendStringW(f"close {alias}", None, 0, None)
                except Exception:
                    pass
            if not self._is_stale(my_gen):
                self._set_state("idle")


def normalize_briefing_markdown(markdown_text: str) -> str:
    """Normalizes spaced Markdown links and bare URLs so Rich renders clickable OSC-8 links."""
    text = markdown_text or ""
    # Fix "[Label] (https://...)" -> "[Label](https://...)"
    text = re.sub(r"\]\s+\((https?://[^\s)]+)\)", r"](\1)", text)

    # Convert bare URLs not already inside Markdown link syntax into clickable links
    def _wrap_bare_url(match: re.Match[str]) -> str:
        prefix = match.group(1) or ""
        url = match.group(2)
        trail = ""
        while url and url[-1] in ".,;:!?)":
            if url[-1] == ")" and url.count("(") >= url.count(")"):
                break
            trail = url[-1] + trail
            url = url[:-1]
        return f"{prefix}[{url}]({url}){trail}"

    text = re.sub(r"(^|\s)(https?://[^\s<>)\]]+)", _wrap_bare_url, text)
    return text


def parse_briefing_header(markdown_text: str) -> Tuple[Dict[str, str], str]:
    """Extracts executive header metadata lines and returns (meta, body_markdown)."""
    lines = (markdown_text or "").splitlines()
    meta: Dict[str, str] = {}
    body_start = 0

    for idx, line in enumerate(lines[:10]):
        stripped = line.strip()
        if stripped == "---":
            body_start = idx + 1
            break
        if stripped.startswith("# "):
            meta["title"] = stripped[2:].strip()
            body_start = idx + 1
            continue
        if "**Generated:**" in stripped:
            m_gen = re.search(r"\*\*Generated:\*\*\s*([^|*]+)", stripped)
            m_sch = re.search(r"\*\*Schedule:\*\*\s*(.+)$", stripped)
            if m_gen:
                meta["generated"] = m_gen.group(1).strip()
            if m_sch:
                meta["schedule"] = m_sch.group(1).strip()
            body_start = idx + 1
            continue
        if "**Supervisor Status:**" in stripped:
            meta["supervisor"] = stripped.replace("**Supervisor Status:**", "").strip()
            body_start = idx + 1
            continue
        if "**24h Delta" in stripped:
            meta["delta"] = re.sub(r"^\*\*24h Delta[^*]*\*\*\s*", "", stripped).strip()
            body_start = idx + 1
            continue
        if not stripped:
            body_start = idx + 1
            continue
        break

    body = "\n".join(lines[body_start:]).lstrip("\n")
    if not body:
        body = markdown_text or ""
    return meta, body


def build_header_panel(meta: Dict[str, str], briefing_path: Optional[Path] = None) -> Panel:
    """Builds the stylized Rich Executive HUD Panel shown at the top of the briefing tab."""
    title = meta.get("title") or "Orbit Security & Antigravity: Unified Daily Executive Briefing"
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(style="white")
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(style="white")

    gen_val = meta.get("generated") or "Live Snapshot"
    sched_val = meta.get("schedule") or "10:15 MST"
    sup_raw = meta.get("supervisor") or "UNKNOWN"
    sup_style = "bold bright_green" if "ACTIVE" in sup_raw.upper() else "bold yellow"

    grid.add_row("Generated", gen_val, "Schedule", sched_val)
    grid.add_row("Supervisor", Text(sup_raw, style=sup_style), "Terminal", Text("Elevated Windows Terminal", style="bold bright_magenta"))

    if meta.get("delta"):
        grid.add_row("24h Delta", Text(meta["delta"], style="bright_cyan"), "", "")

    if briefing_path is not None:
        uri = briefing_path.resolve().as_uri()
        link_txt = Text(str(briefing_path), style=f"bright_blue underline link {uri}")
        grid.add_row("Source", link_txt, "", "")

    return Panel(
        grid,
        title=f"[bold bright_cyan]⚡ {title}[/]",
        subtitle="[dim]Hotkeys: [bold white]R[/] Replay  │  [bold white]P/Space[/] Pause/Resume  │  [bold white]S[/] Stop Voice  │  [bold white]L[/] Refresh  │  [bold white]Q / Ctrl+W[/] Dismiss[/]",
        border_style="bright_magenta",
        padding=(1, 2),
    )


def create_rich_console(file_stream: Any = None) -> Console:
    """Creates a truecolor Rich console with OSC-8 hyperlinks enabled on Windows Terminal."""
    return Console(
        file=file_stream,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
        theme=_ORBIT_THEME,
    )


def render_briefing_to_console(
    console: Console,
    content: str,
    briefing_path: Optional[Path] = None,
) -> None:
    """Renders the Executive HUD and normalized Markdown briefing cleanly to a Rich console."""
    meta, body = parse_briefing_header(content)
    console.print(build_header_panel(meta, briefing_path=briefing_path))
    normalized_body = normalize_briefing_markdown(body)
    console.print(Markdown(normalized_body, hyperlinks=True, code_theme="monokai"))


def _build_action_bar_text(audio_state: str = "idle") -> Text:
    """Builds the bottom interactive hotkey legend text for the active audio state."""
    txt = Text()
    if audio_state == "synthesizing":
        txt.append(" 🎙️ Preparing Kokoro Nova voice... ", style="bold black on bright_yellow")
        txt.append("   │   ", style="dim")
        txt.append("[S] ", style="bold bright_red")
        txt.append("Stop", style="white")
        txt.append("   │   ", style="dim")
    elif audio_state == "playing":
        txt.append(" 🔊 Speaking Nova Briefing ", style="bold black on bright_green")
        txt.append("   │   ", style="dim")
        txt.append("[P / Space] ", style="bold bright_yellow")
        txt.append("Pause", style="white")
        txt.append("   │   ", style="dim")
        txt.append("[S] ", style="bold bright_red")
        txt.append("Stop", style="white")
        txt.append("   │   ", style="dim")
        txt.append("[R] ", style="bold bright_cyan")
        txt.append("Restart", style="white")
        txt.append("   │   ", style="dim")
    elif audio_state == "paused":
        txt.append(" ⏸️ Voice Paused ", style="bold black on bright_yellow")
        txt.append("   │   ", style="dim")
        txt.append("[P / Space] ", style="bold bright_green")
        txt.append("Resume", style="white")
        txt.append("   │   ", style="dim")
        txt.append("[S] ", style="bold bright_red")
        txt.append("Stop", style="white")
        txt.append("   │   ", style="dim")
        txt.append("[R] ", style="bold bright_cyan")
        txt.append("Restart", style="white")
        txt.append("   │   ", style="dim")
    else:
        txt.append(" [R] ", style="bold black on bright_cyan")
        txt.append(" Replay Voice Briefing", style="bold white")
        txt.append("   │   ", style="dim")
    txt.append("[L] ", style="bold bright_magenta")
    txt.append("Refresh View", style="white")
    txt.append("   │   ", style="dim")
    txt.append("[Q / Ctrl+W] ", style="bold bright_red")
    txt.append("Dismiss Tab", style="white")
    return txt


def _set_terminal_title(title: str = _VIEWER_TITLE) -> None:
    """Sets the Windows Terminal tab title via OSC 0 escape sequence."""
    try:
        sys.stdout.write(f"\x1b]0;{title}\x07")
        sys.stdout.flush()
    except Exception:
        pass


def _read_active_viewer_pids() -> List[int]:
    """Finds PIDs of any live briefing_tui.py --viewer processes (excluding self)."""
    current_pid = os.getpid()
    pids: List[int] = []

    if _PID_FILE.is_file():
        try:
            data = json.loads(_PID_FILE.read_text(encoding="utf-8"))
            pid = int(data.get("pid", 0))
            if pid > 0 and pid != current_pid:
                if psutil is None or psutil.pid_exists(pid):
                    pids.append(pid)
        except Exception:
            pass

    if psutil is not None:
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                pid = proc.info.get("pid") or 0
                if not pid or pid == current_pid or pid in pids:
                    continue
                cmd = " ".join(proc.info.get("cmdline") or []).lower()
                if "briefing_tui.py" in cmd and "--viewer" in cmd:
                    pids.append(pid)
        except Exception:
            pass

    return pids


def close_existing_briefing_viewers(timeout_sec: float = 2.0) -> int:
    """Terminates any prior briefing_tui --viewer process so zero duplicate WT tabs accumulate."""
    pids = _read_active_viewer_pids()
    closed = 0
    if not pids:
        return 0

    for pid in pids:
        try:
            if psutil is not None:
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_sec)
                except psutil.TimeoutExpired:
                    proc.kill()
            else:
                os.kill(pid, 15)
            closed += 1
        except Exception:
            pass

    try:
        if _PID_FILE.is_file():
            _PID_FILE.unlink()
    except Exception:
        pass

    return closed


def _write_viewer_pid_file(briefing_path: Optional[Path]) -> None:
    """Records the active viewer PID so subsequent launches replace rather than duplicate tabs."""
    try:
        _BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "file": str(briefing_path) if briefing_path else "",
            "started_at": time.time(),
        }
        _PID_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def _remove_viewer_pid_file() -> None:
    """Removes the active viewer PID file if it still belongs to this process."""
    try:
        if _PID_FILE.is_file():
            data = json.loads(_PID_FILE.read_text(encoding="utf-8"))
            if int(data.get("pid", 0)) == os.getpid():
                _PID_FILE.unlink()
    except Exception:
        pass


def _launch_wt_command_win32(cmd_str: str, as_user: bool) -> Optional[int]:
    """Spawns wt.exe on WinSta0\\Default with SW_SHOWNORMAL, using desktop_automation if available."""
    if str(_DESKTOP_AUTO_DIR) not in sys.path and _DESKTOP_AUTO_DIR.is_dir():
        sys.path.insert(0, str(_DESKTOP_AUTO_DIR))
    try:
        from desktop_automation import launch_on_interactive_desktop

        pid = launch_on_interactive_desktop(cmd_str, as_user=as_user)
        if pid:
            return pid
    except Exception:
        pass

    if sys.platform != "win32":
        return None

    from ctypes import wintypes

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    si.lpDesktop = r"WinSta0\Default"
    si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
    si.wShowWindow = 1  # SW_SHOWNORMAL
    pi = PROCESS_INFORMATION()

    cmd_buf = ctypes.create_unicode_buffer(cmd_str)
    ok = ctypes.windll.kernel32.CreateProcessW(
        None,
        cmd_buf,
        None,
        None,
        False,
        0,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if ok:
        ctypes.windll.kernel32.CloseHandle(pi.hProcess)
        ctypes.windll.kernel32.CloseHandle(pi.hThread)
        return int(pi.dwProcessId)
    return None


def build_wt_launch_args(
    briefing_file: Optional[Path] = None,
    auto_speak: bool = False,
    title: str = _VIEWER_TITLE,
) -> List[str]:
    """Builds the exact wt.exe argument vector to open a single non-duplicate WT tab."""
    wt_exe = find_wt_executable()
    if not wt_exe:
        raise FileNotFoundError("Windows Terminal (wt.exe) not found on this host.")

    py_exe = _resolve_venv_python()
    viewer_script = str(Path(__file__).resolve())

    args = [
        wt_exe,
        "-w",
        "0",
        "new-tab",
        "--title",
        title,
        "--suppressApplicationTitle",
        "-d",
        str(_REPO_ROOT),
        py_exe,
        viewer_script,
        "--viewer",
    ]
    if briefing_file is not None:
        args.extend(["--file", str(briefing_file)])
    if auto_speak:
        args.append("--speak")
    return args


def launch_briefing_in_wt(
    briefing_file: Optional[str | Path] = None,
    spoken_summary: Optional[str] = None,
    auto_speak: bool = False,
    title_suffix: str = "",
    spawner: Optional[Callable[[str, bool], Optional[int]]] = None,
) -> Optional[int]:
    """Opens the briefing viewer in the active elevated Windows Terminal (zero duplicate tabs)."""
    attach_to_interactive_desktop()
    resolved_file = _find_latest_briefing_file(str(briefing_file) if briefing_file else None)

    if spoken_summary and spoken_summary.strip():
        try:
            _BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
            _SPOKEN_SIDECAR_FILE.write_text(spoken_summary.strip(), encoding="utf-8")
        except Exception:
            pass
    elif _SPOKEN_SIDECAR_FILE.is_file():
        try:
            _SPOKEN_SIDECAR_FILE.unlink()
        except Exception:
            pass

    close_existing_briefing_viewers()

    tab_title = _VIEWER_TITLE if not title_suffix else f"{_VIEWER_TITLE} ({title_suffix})"
    args = build_wt_launch_args(briefing_file=resolved_file, auto_speak=auto_speak, title=tab_title)
    cmd_str = subprocess.list2cmdline(args)

    wt_elev = is_windows_terminal_elevated()
    caller_elev = _is_current_process_elevated()
    if wt_elev is True:
        as_user = False
    elif wt_elev is False and caller_elev:
        as_user = True
    else:
        as_user = not caller_elev

    spawn_fn = spawner or _launch_wt_command_win32
    pid = spawn_fn(cmd_str, as_user)
    if pid:
        return pid

    # Fallback: launch directly via subprocess without CREATE_NO_WINDOW if CreateProcessW failed
    proc = subprocess.Popen(args, cwd=str(_REPO_ROOT))
    return proc.pid


def _read_key_nonblocking() -> Optional[str]:
    """Reads a single keypress without blocking; consumes extended key prefixes safely."""
    if sys.platform != "win32":
        return None
    import msvcrt

    if not msvcrt.kbhit():
        return None
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        if msvcrt.kbhit():
            msvcrt.getwch()
        return ""
    return ch


def run_briefing_viewer(
    briefing_file: Optional[str | Path] = None,
    spoken_summary: Optional[str] = None,
    auto_speak: bool = False,
    title: str = _VIEWER_TITLE,
    key_reader: Optional[Callable[[], Optional[str]]] = None,
    speak_fn: Optional[Callable[[str], None]] = None,
    audio_controller: Optional[BriefingAudioController] = None,
    console: Optional[Console] = None,
    poll_interval: float = 0.08,
) -> int:
    """Runs the persistent in-terminal Rich briefing viewer until Q or Ctrl+W is pressed."""
    _make_stdio_safe()
    _enable_vt_mode()
    _set_terminal_title(title)

    resolved = _find_latest_briefing_file(str(briefing_file) if briefing_file else None)
    _write_viewer_pid_file(resolved)

    out_console = console or create_rich_console()
    reader = key_reader or _read_key_nonblocking

    def _load_content_and_summary() -> Tuple[Optional[Path], str, str]:
        target = _find_latest_briefing_file(str(briefing_file) if briefing_file else None)
        md_text = target.read_text(encoding="utf-8") if target and target.is_file() else "Briefing file not found."
        sidecar_summary = ""
        if _SPOKEN_SIDECAR_FILE.is_file():
            try:
                sidecar_summary = _SPOKEN_SIDECAR_FILE.read_text(encoding="utf-8").strip()
            except Exception:
                sidecar_summary = ""
        eff_summary = (
            (spoken_summary or "").strip()
            or sidecar_summary
            or _load_latest_spoken_summary()
            or _synthesize_fallback_spoken_summary(md_text)
        )
        return target, md_text, eff_summary

    state_lock = threading.Lock()

    def _refresh_status_bar(audio_state: str) -> None:
        with state_lock:
            try:
                sys.stdout.write("\r\x1b[2K")
                sys.stdout.flush()
                out_console.print(_build_action_bar_text(audio_state=audio_state), end="")
                sys.stdout.flush()
            except Exception:
                pass
            if audio_state == "idle":
                _set_terminal_title(title)

    audio_ctrl = audio_controller or BriefingAudioController(
        on_state_change=_refresh_status_bar,
        speak_fn=speak_fn,
    )

    def _render_screen() -> None:
        nonlocal resolved
        resolved, md_text, _ = _load_content_and_summary()
        out_console.clear()
        render_briefing_to_console(out_console, md_text, briefing_path=resolved)
        out_console.rule(style="dim cyan")
        with state_lock:
            out_console.print(_build_action_bar_text(audio_state=audio_ctrl.state), end="")
        sys.stdout.flush()

    def _trigger_speak() -> None:
        _, _, latest_summary = _load_content_and_summary()
        audio_ctrl.play(latest_summary)

    try:
        _render_screen()
        if auto_speak:
            _trigger_speak()

        while True:
            try:
                ch = reader()
            except KeyboardInterrupt:
                # Ignore Ctrl+C so accidental copy/interrupt never dismisses the morning briefing
                continue

            if ch is None:
                time.sleep(poll_interval)
                continue
            if ch == "":
                continue

            lowered = ch.lower()
            if lowered == "q" or ch == "\x17":  # 'Q' or Ctrl+W
                audio_ctrl.stop()
                sys.stdout.write("\n")
                sys.stdout.flush()
                return 0
            if lowered == "r":
                _trigger_speak()
            elif lowered == "p" or ch == " ":
                audio_ctrl.toggle_pause()
            elif lowered == "s":
                audio_ctrl.stop()
            elif lowered == "l":
                _render_screen()
            # All other keys (Enter, Escape, Ctrl+C, random keys) are strictly ignored.
    finally:
        audio_ctrl.stop()
        _remove_viewer_pid_file()


def show_briefing_tui(
    content: Optional[str] = None,
    spoken_summary: Optional[str] = None,
    auto_speak: bool = True,
    title_suffix: str = "",
    briefing_file: Optional[str | Path] = None,
) -> Optional[int]:
    """Public entrypoint: displays the briefing in an elevated Windows Terminal tab."""
    target = _find_latest_briefing_file(str(briefing_file) if briefing_file else None)
    if target is None and content:
        _BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
        target = _BRIEFINGS_DIR / "briefing_preview.md"
        target.write_text(content, encoding="utf-8")

    return launch_briefing_in_wt(
        briefing_file=target,
        spoken_summary=spoken_summary,
        auto_speak=auto_speak,
        title_suffix=title_suffix,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Display Orbit Security Morning Briefing in a persistent Windows Terminal tab."
    )
    parser.add_argument("--file", type=str, default=None, help="Path to briefing markdown file (defaults to newest)")
    parser.add_argument("--speak", action="store_true", help="Speak the morning debrief aloud on launch")
    parser.add_argument("--speak-text", type=str, default=None, help="Explicit spoken summary text")
    parser.add_argument(
        "--viewer",
        action="store_true",
        help="Run the interactive Rich TUI viewer directly inside the current Windows Terminal tab",
    )
    args = parser.parse_args()

    if args.viewer:
        return run_briefing_viewer(
            briefing_file=args.file,
            spoken_summary=args.speak_text,
            auto_speak=bool(args.speak),
        )

    launch_briefing_in_wt(
        briefing_file=args.file,
        spoken_summary=args.speak_text,
        auto_speak=bool(args.speak),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
