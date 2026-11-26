"""Unit tests for the Windows Terminal (wt.exe) Orbit Morning Briefing TUI & launcher."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
for _p in (str(_REPO_ROOT), str(_SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import scripts.briefing_gui as briefing_gui  # noqa: E402
import scripts.briefing_tui as briefing_tui  # noqa: E402


SAMPLE_BRIEFING_MD = """# Orbit Security & Antigravity: Unified Daily Executive Briefing
**Generated:** 2026-11-19 21:47 | **Schedule:** 10:15 MST (Default +45m Buffer)
**Supervisor Status:** 🟢 ACTIVE (PID: 18684)
**24h Delta (Δ):** vs 2026-11-18: Disk -6.1 GB | Commits +10

---

## ⚡ 1. TOP 3 PRIORITY ACTIONS TODAY
1. Port Triage: inspect unexpected local listener(s).
2. Check [AI Forum](https://discuss.ai.google.dev/t/202301) and [Anthropic IPO] (https://www.reuters.com/business/finance/anthropics-historic-debut/).

| Service | Status | Port |
| --- | --- | --- |
| Sentinel | ACTIVE | 9090 |
| Sidekick | RUNNING | 9008 |
"""


def test_normalize_briefing_markdown_fixes_spaced_links_and_bare_urls():
    raw = (
        "See [AI Forum](https://discuss.ai.google.dev/t/1), "
        "[Anthropic] (https://www.reuters.com/test), "
        "and bare https://example.com/path."
    )
    normalized = briefing_tui.normalize_briefing_markdown(raw)
    assert "[AI Forum](https://discuss.ai.google.dev/t/1)" in normalized
    assert "[Anthropic](https://www.reuters.com/test)" in normalized
    assert "[https://example.com/path](https://example.com/path)." in normalized


def test_render_briefing_to_console_emits_osc8_links_and_no_raw_markdown(tmp_path):
    md_path = tmp_path / "briefing_2026-11-19.md"
    md_path.write_text(SAMPLE_BRIEFING_MD, encoding="utf-8")

    console = briefing_tui.create_rich_console()
    with console.capture() as cap:
        briefing_tui.render_briefing_to_console(console, SAMPLE_BRIEFING_MD, briefing_path=md_path)
    rendered = cap.get()

    # OSC-8 hyperlinks present for both normal and spaced Markdown links
    assert "\x1b]8;" in rendered
    assert "https://discuss.ai.google.dev/t/202301" in rendered
    assert "https://www.reuters.com/business/finance/anthropics-historic-debut/" in rendered
    # Rendered table and content without raw markdown link syntax
    assert "Sentinel" in rendered
    assert "9090" in rendered
    assert "](https://" not in rendered


def test_build_wt_launch_args_uses_wt_exe_and_never_conhost(monkeypatch, tmp_path):
    fake_wt = tmp_path / "wt.exe"
    fake_wt.write_text("", encoding="utf-8")
    fake_md = tmp_path / "briefing_2026-11-19.md"
    fake_md.write_text("# Test", encoding="utf-8")

    monkeypatch.setattr(briefing_tui, "find_wt_executable", lambda: str(fake_wt))
    args = briefing_tui.build_wt_launch_args(briefing_file=fake_md, auto_speak=True)

    joined = " ".join(args).lower()
    assert args[0] == str(fake_wt)
    assert args[1:5] == ["-w", "0", "new-tab", "--title"]
    assert briefing_tui._VIEWER_TITLE in args
    assert "--suppressApplicationTitle" in args
    assert "--viewer" in args
    assert "--speak" in args
    assert "conhost" not in joined
    assert "pythonw.exe" not in joined
    assert "tkinter" not in joined


def test_launch_briefing_in_wt_deduplicates_viewer_and_respects_elevation(monkeypatch, tmp_path):
    fake_wt = tmp_path / "wt.exe"
    fake_wt.write_text("", encoding="utf-8")
    fake_md = tmp_path / "briefing_2026-11-19.md"
    fake_md.write_text("# Test", encoding="utf-8")
    sidecar = tmp_path / ".briefing_tui_spoken.txt"

    monkeypatch.setattr(briefing_tui, "find_wt_executable", lambda: str(fake_wt))
    monkeypatch.setattr(briefing_tui, "_BRIEFINGS_DIR", tmp_path)
    monkeypatch.setattr(briefing_tui, "_SPOKEN_SIDECAR_FILE", sidecar)
    monkeypatch.setattr(briefing_tui, "attach_to_interactive_desktop", lambda: True)

    closed_calls = []
    monkeypatch.setattr(briefing_tui, "close_existing_briefing_viewers", lambda: closed_calls.append(1) or 1)
    monkeypatch.setattr(briefing_tui, "is_windows_terminal_elevated", lambda: True)
    monkeypatch.setattr(briefing_tui, "_is_current_process_elevated", lambda: True)

    spawned = []

    def fake_spawner(cmd_str: str, as_user: bool) -> int:
        spawned.append((cmd_str, as_user))
        return 4242

    pid = briefing_tui.launch_briefing_in_wt(
        briefing_file=fake_md,
        spoken_summary="Morning Carson; test semicolon safety",
        auto_speak=True,
        spawner=fake_spawner,
    )

    assert pid == 4242
    assert len(closed_calls) == 1
    assert len(spawned) == 1
    cmd_str, as_user = spawned[0]
    assert as_user is False  # Elevated WT -> must not downgrade to Explorer token
    assert "Morning Carson; test semicolon safety" not in cmd_str  # Stored in sidecar, never raw on wt CLI
    assert sidecar.read_text(encoding="utf-8") == "Morning Carson; test semicolon safety"


def test_run_briefing_viewer_ignores_random_keys_replays_on_r_and_exits_on_q(monkeypatch, tmp_path):
    md_path = tmp_path / "briefing_2026-11-19.md"
    md_path.write_text(SAMPLE_BRIEFING_MD, encoding="utf-8")
    pid_file = tmp_path / ".briefing_tui_viewer.json"
    sidecar = tmp_path / ".briefing_tui_spoken.txt"

    monkeypatch.setattr(briefing_tui, "_BRIEFINGS_DIR", tmp_path)
    monkeypatch.setattr(briefing_tui, "_PID_FILE", pid_file)
    monkeypatch.setattr(briefing_tui, "_SPOKEN_SIDECAR_FILE", sidecar)
    monkeypatch.setattr(briefing_tui, "_set_terminal_title", lambda title="": None)
    monkeypatch.setattr(briefing_tui, "_enable_vt_mode", lambda: None)

    # Simulate accidental Enter, Escape, Ctrl+C, random letters, Replay 'r', Refresh 'l', then Quit 'q'
    keys = iter(["\r", "\n", "\x1b", "\x03", "x", "a", "", "r", "l", "q"])
    spoken_calls = []

    def fake_reader():
        return next(keys, None)

    def fake_speak(text: str):
        spoken_calls.append(text)

    rc = briefing_tui.run_briefing_viewer(
        briefing_file=md_path,
        spoken_summary="Nova cached debrief replay.",
        auto_speak=False,
        key_reader=fake_reader,
        speak_fn=fake_speak,
        console=briefing_tui.create_rich_console(),
        poll_interval=0.0,
    )

    assert rc == 0
    assert spoken_calls == ["Nova cached debrief replay."]
    assert not pid_file.exists()


def test_run_briefing_viewer_pause_stop_and_scoped_stop_on_quit(monkeypatch, tmp_path):
    md_path = tmp_path / "briefing_2026-11-19.md"
    md_path.write_text("# Test", encoding="utf-8")
    pid_file = tmp_path / ".briefing_tui_viewer.json"

    monkeypatch.setattr(briefing_tui, "_BRIEFINGS_DIR", tmp_path)
    monkeypatch.setattr(briefing_tui, "_PID_FILE", pid_file)
    monkeypatch.setattr(briefing_tui, "_set_terminal_title", lambda title="": None)
    monkeypatch.setattr(briefing_tui, "_enable_vt_mode", lambda: None)

    events = []

    class FakeAudioController:
        state = "playing"

        def play(self, text: str) -> None:
            events.append(("play", text))

        def toggle_pause(self) -> str:
            events.append(("toggle_pause",))
            self.state = "paused" if self.state == "playing" else "playing"
            return self.state

        def stop(self) -> None:
            events.append(("stop",))
            self.state = "idle"

    keys = iter(["\r", "p", " ", "s", "r", "q"])
    rc = briefing_tui.run_briefing_viewer(
        briefing_file=md_path,
        spoken_summary="Scoped Nova audio.",
        auto_speak=True,
        key_reader=lambda: next(keys, None),
        audio_controller=FakeAudioController(),
        console=briefing_tui.create_rich_console(),
        poll_interval=0.0,
    )
    assert rc == 0
    assert events == [
        ("play", "Scoped Nova audio."),
        ("toggle_pause",),
        ("toggle_pause",),
        ("stop",),
        ("play", "Scoped Nova audio."),
        ("stop",),  # Explicit stop on 'q'
        ("stop",),  # Cleanup stop in finally
    ]


def test_resolve_voice_python_and_scoped_mci_alias(monkeypatch, tmp_path):
    if Path(r"C:\Python314\python.exe").is_file():
        assert briefing_tui._resolve_voice_python().lower().endswith(r"\python314\python.exe")

    wav_file = tmp_path / "sample.wav"
    wav_file.write_bytes(b"RIFF" + b"\x00" * 128)

    mci_commands = []

    class FakeWinmm:
        def __init__(self):
            self.mode = "playing"

        def mciSendStringW(self, cmd: str, buf, length: int, cb) -> int:
            mci_commands.append(cmd)
            if cmd.startswith("pause "):
                self.mode = "paused"
            elif cmd.startswith("resume "):
                self.mode = "playing"
            elif cmd.startswith("stop "):
                self.mode = "stopped"
            elif cmd.startswith("status ") and buf is not None:
                buf.value = self.mode
            return 0

    fake_ctypes = SimpleNamespace(
        windll=SimpleNamespace(
            winmm=FakeWinmm(),
            kernel32=SimpleNamespace(GetShortPathNameW=lambda a, b, c: 0),
        ),
        create_unicode_buffer=lambda size: SimpleNamespace(value=""),
    )

    monkeypatch.setattr(briefing_tui, "ctypes", fake_ctypes)
    ctrl = briefing_tui.BriefingAudioController(synthesizer=lambda text, **kw: str(wav_file))
    ctrl.play("Morning Carson.")

    import time
    deadline = time.time() + 2.0
    while ctrl.state != "playing" and time.time() < deadline:
        time.sleep(0.01)
    assert ctrl.state == "playing"

    ctrl.toggle_pause()
    deadline = time.time() + 2.0
    while ctrl.state != "paused" and time.time() < deadline:
        time.sleep(0.01)
    assert ctrl.state == "paused"

    ctrl.toggle_pause()
    deadline = time.time() + 2.0
    while ctrl.state != "playing" and time.time() < deadline:
        time.sleep(0.01)
    assert ctrl.state == "playing"

    ctrl.stop()
    deadline = time.time() + 2.0
    while ctrl.state != "idle" and time.time() < deadline:
        time.sleep(0.01)
    assert ctrl.state == "idle"

    assert any(c.startswith("pause orbit_brief_") for c in mci_commands)
    assert any(c.startswith("resume orbit_brief_") for c in mci_commands)
    assert any(c.startswith("stop orbit_brief_") for c in mci_commands)
    assert all("stop all" not in c and "close all" not in c for c in mci_commands)


def test_run_briefing_viewer_exits_on_ctrl_w(monkeypatch, tmp_path):
    md_path = tmp_path / "briefing_2026-11-19.md"
    md_path.write_text("# Test", encoding="utf-8")
    pid_file = tmp_path / ".briefing_tui_viewer.json"

    monkeypatch.setattr(briefing_tui, "_BRIEFINGS_DIR", tmp_path)
    monkeypatch.setattr(briefing_tui, "_PID_FILE", pid_file)
    monkeypatch.setattr(briefing_tui, "_set_terminal_title", lambda title="": None)
    monkeypatch.setattr(briefing_tui, "_enable_vt_mode", lambda: None)

    keys = iter(["\r", "\x17"])  # Enter ignored, Ctrl+W dismisses
    rc = briefing_tui.run_briefing_viewer(
        briefing_file=md_path,
        spoken_summary="Test summary",
        auto_speak=False,
        key_reader=lambda: next(keys, None),
        speak_fn=lambda text: None,
        console=briefing_tui.create_rich_console(),
        poll_interval=0.0,
    )
    assert rc == 0


def test_briefing_gui_has_no_tkinter_and_delegates_to_tui(monkeypatch):
    gui_src = (_SCRIPTS_DIR / "briefing_gui.py").read_text(encoding="utf-8")
    assert "import tkinter" not in gui_src
    assert "from tkinter" not in gui_src

    called = {}

    def fake_show_tui(**kwargs):
        called.update(kwargs)
        return 777

    monkeypatch.setattr(briefing_gui, "show_briefing_tui", fake_show_tui)
    res = briefing_gui.show_briefing_gui(
        content="# Demo",
        spoken_summary="Spoken demo",
        auto_speak=True,
        title_suffix="briefing_2026-11-19",
    )
    assert res == 777
    assert called["spoken_summary"] == "Spoken demo"
    assert called["auto_speak"] is True


def test_scheduled_task_configs_and_manifest_use_highest_runlevel_and_tui():
    sys_scripts = Path(r"A:\system\scripts") if Path(r"A:\system\scripts").exists() else Path(r"C:\AgyHut\system\scripts")
    ps1_path = sys_scripts / "install_orbit_tasks.ps1"
    manifest_path = sys_scripts / "orbit_tasks_manifest.json"
    daemon_path = sys_scripts / "orbit_daemon.py"
    if not (ps1_path.exists() and manifest_path.exists() and daemon_path.exists()):
        pytest.skip("Host system task configs not present in CI environment")

    ps1_text = ps1_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    daemon_text = daemon_path.read_text(encoding="utf-8")

    # install_orbit_tasks.ps1 checks
    daily_block = ps1_text.split('$tasks["OrbitSecurityDailyBriefing"]', 1)[1].split("}", 1)[0]
    assert 'RunLevel    = "Highest"' in daily_block
    assert "--email" in daily_block
    assert "--tui" not in daily_block
    assert "pythonw.exe" in daily_block

    # orbit_tasks_manifest.json checks
    daily_entry = next(t for t in manifest["tasks"] if t["task_name"] == "OrbitSecurityDailyBriefing")
    assert daily_entry["run_level"] == "Highest"
    assert daily_entry["logon_type"] == "Interactive"
    assert "--email" in daily_entry["arguments"]
    assert "--tui" not in daily_entry["arguments"]
    assert daily_entry["python_executable"].endswith("pythonw.exe")

    # orbit_daemon.py checks
    assert '"--tui"' in daemon_text
    assert "already_running" in daemon_text
