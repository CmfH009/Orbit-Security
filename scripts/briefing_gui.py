"""Windows Terminal briefing launcher compatibility shim (replaces legacy tkinter popup)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from briefing_tui import (
    _BRIEFINGS_DIR,
    _HOOK_SCRIPT,
    _find_latest_briefing_file,
    _load_latest_spoken_summary,
    _speak_via_nova_hook,
    _synthesize_fallback_spoken_summary,
    attach_to_interactive_desktop,
    launch_briefing_in_wt,
    show_briefing_tui,
)

__all__ = [
    "_BRIEFINGS_DIR",
    "_HOOK_SCRIPT",
    "_find_latest_briefing_file",
    "_load_latest_spoken_summary",
    "_speak_via_nova_hook",
    "_synthesize_fallback_spoken_summary",
    "attach_to_interactive_desktop",
    "show_briefing_gui",
    "main",
]


def show_briefing_gui(
    content: str = "",
    spoken_summary: Optional[str] = None,
    auto_speak: bool = True,
    title_suffix: str = "",
    briefing_file: Optional[str | Path] = None,
) -> Optional[int]:
    """Displays the daily briefing in an elevated Windows Terminal tab (never tkinter/conhost)."""
    return show_briefing_tui(
        content=content,
        spoken_summary=spoken_summary,
        auto_speak=auto_speak,
        title_suffix=title_suffix,
        briefing_file=briefing_file,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Display Orbit Security Morning Briefing in an elevated Windows Terminal tab."
    )
    parser.add_argument("--file", type=str, default=None, help="Path to briefing markdown file (defaults to newest)")
    parser.add_argument("--speak", action="store_true", help="Speak the morning debrief aloud on launch")
    parser.add_argument("--speak-text", type=str, default=None, help="Explicit spoken summary text")
    args = parser.parse_args()

    launch_briefing_in_wt(
        briefing_file=args.file,
        spoken_summary=args.speak_text,
        auto_speak=bool(args.speak),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
