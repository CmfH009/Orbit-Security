"""Briefing delivery helpers (TUI launch, spoken debrief, and delivery marker tracking)."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional

from .pipeline import DEFAULT_BRIEFINGS_DIR


def delivery_marker_path(date_key: str, briefings_dir: Optional[Path] = None) -> Path:
    """Returns the per-day delivery marker path inside the briefings directory."""
    target_dir = Path(briefings_dir) if briefings_dir else DEFAULT_BRIEFINGS_DIR
    return target_dir / f".briefing_delivered_{date_key}"


def write_delivery_marker(date_key: str, briefings_dir: Optional[Path] = None) -> None:
    """Records that today's briefing has been delivered via TUI/voice."""
    try:
        marker = delivery_marker_path(date_key, briefings_dir)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(datetime.datetime.now().isoformat(), encoding="utf-8")
    except Exception:
        pass


def speak_via_nova_hook(spoken_summary: str) -> None:
    """Speaks the briefing summary aloud using Nova's local Kokoro voice hook."""
    hook_script = r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py"
    if os.path.exists(hook_script):
        py314 = r"C:\Python314\python.exe"
        voice_exe = py314 if os.path.exists(py314) else sys.executable
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run([voice_exe, hook_script, "--speak", spoken_summary], creationflags=flags)


def deliver_existing_briefing(
    speak: bool = True,
    tui: bool = True,
    pause: bool = False,
    dry_run: bool = False,
    date_key: Optional[str] = None,
    briefings_dir: Optional[Path] = None,
) -> bool:
    """Delivers an already-generated daily briefing via Windows Terminal TUI and/or voice."""
    target_dir = Path(briefings_dir) if briefings_dir else DEFAULT_BRIEFINGS_DIR
    dk = date_key or datetime.datetime.now().strftime("%Y-%m-%d")
    report_path = target_dir / f"briefing_{dk}.md"
    if not report_path.is_file():
        print(f"[!] Existing briefing not found for {dk}: {report_path}")
        return False

    report = report_path.read_text(encoding="utf-8")
    spoken_summary = "Orbit Security daily briefing is ready in your terminal tab."
    state_path = target_dir / "briefing_state_latest.json"
    if state_path.is_file():
        try:
            state_obj = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(state_obj, dict) and state_obj.get("spoken_summary"):
                spoken_summary = str(state_obj["spoken_summary"])
        except Exception:
            pass

    if tui:
        try:
            try:
                from scripts.briefing_tui import show_briefing_tui
            except ImportError:
                from briefing_tui import show_briefing_tui  # type: ignore[import-not-found]

            wt_pid = show_briefing_tui(
                content=report,
                spoken_summary=spoken_summary,
                auto_speak=bool(speak and not dry_run),
                title_suffix=f"briefing_{dk}",
                briefing_file=report_path,
            )
            if wt_pid:
                if not dry_run:
                    write_delivery_marker(dk, target_dir)
                return True
        except Exception as tui_err:
            print(f"[!] Windows Terminal TUI launch error: {tui_err}")

    if speak and not dry_run:
        speak_via_nova_hook(spoken_summary)

    if pause:
        try:
            try:
                from scripts.briefing_tui import run_briefing_viewer
            except ImportError:
                from briefing_tui import run_briefing_viewer  # type: ignore[import-not-found]

            run_briefing_viewer(
                briefing_file=report_path,
                spoken_summary=spoken_summary,
                auto_speak=False,
            )
        except Exception:
            pass

    if not dry_run and (speak or tui):
        write_delivery_marker(dk, target_dir)
    return True
