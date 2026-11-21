"""Thin CLI / TUI / Mutex / Dispatch runner over `orbit_security.briefing`.

Delegates two-phase telemetry collection, prompt-injection sanitization, CI/delta reconciliation,
critic verification, Markdown rendering, and spoken debrief synthesis to `BriefingEngine`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence
from dotenv import load_dotenv

# Ensure UTF-8 output on Windows terminals (and safe streams under pythonw.exe)
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
elif hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")
elif hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = str(_REPO_ROOT / "src")
if _SRC_DIR not in sys.path and (_REPO_ROOT / "src").is_dir():
    sys.path.insert(0, _SRC_DIR)

from orbit_security.briefing import (  # noqa: E402
    BriefingConfig,
    BriefingEngine,
    BriefingResult,
    CollectorAdapters,
    DEFAULT_BRIEFINGS_DIR,
    EmailCollectRequest,
    TelemetrySnapshot,
    archive_superseded_ci_alerts_in_imap,
    compute_and_save_daily_deltas,
    poll_gemini_master_briefing_with_backoff,
    probe_workspace_critic_evidence,
    query_calendar_and_tasks,
    query_campaign_outreach,
    query_daemon_health,
    query_email_hygiene,
    query_geo_panel_telemetry,
    query_inbox_pipeline,
    query_intel_and_world_news,
    query_live_email_telemetry,
    query_live_github_ci_status,
    query_option_c_readiness,
    query_post_briefing_email_delta,
    query_projects_radar,
    query_stripe_telemetry,
    query_system_telemetry,
    reconcile_ci_alerts_with_live_status,
    render_master_briefing_block as _render_master_briefing_block,
    run_local_critic_reconciliation,
    sanitize_email_data,
    sanitize_inbound_text as _sanitize_inbound_text,
    sanitize_intel_news,
    sanitize_master_briefing,
    triage_email_messages,
)
from orbit_security.briefing.pipeline import _build_agenda_items  # noqa: E402
from orbit_security.briefing.system_collectors import _count_commits_24h  # noqa: E402

load_dotenv()

# Sentinel references so the CLI adapter bridge distinguishes live defaults from test stubs
_DEFAULT_QUERY_LIVE_EMAIL = query_live_email_telemetry
_DEFAULT_QUERY_LIVE_GITHUB_CI = query_live_github_ci_status
_DEFAULT_COMPUTE_AND_SAVE_DELTAS = compute_and_save_daily_deltas


def dispatch_email_briefing(report_markdown: str, recipient: Optional[str] = None) -> bool:
    """Dispatches the daily operational briefing to operator email via EmailDispatcher."""
    try:
        from orbit_security.mailer import EmailDispatcher

        dispatcher = EmailDispatcher()
        if not dispatcher.is_configured():
            print("[!] Email dispatch skipped: SMTP not fully configured.")
            return False

        target_email = (
            recipient
            or os.getenv("DEFAULT_AGENCY_EMAIL")
            or os.getenv("SMTP_USER")
            or "carsonmail009@gmail.com"
        )
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
    except Exception as exc:
        print(f"[!] Email dispatch error: {exc}")
        return False


def generate_markdown(
    *,
    today: Optional[str] = None,
    schedule_mode: str = "default",
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
    critic_reconciled: Optional[Dict[str, Any]] = None,
) -> str:
    """Backward-compatible wrapper delegating Markdown synthesis to BriefingEngine.synthesize()."""
    today_str = today or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    snapshot = TelemetrySnapshot(
        generated_at=today_str,
        date_key=today_str[:10],
        schedule_mode=schedule_mode,
        stripe=dict(stripe or {}),
        daemon=dict(daemon or {}),
        inbox=dict(inbox or {}),
        campaigns=dict(campaigns or {}),
        option_c=dict(option_c or {}),
        email_data=dict(email_data or {}),
        email_hygiene=dict(email_hygiene or {}),
        live_ci=dict(live_ci or {}),
        geo_panel=dict(geo_panel or {}),
        system_telemetry=dict(sys_telem or {}),
        projects_radar=dict(proj_radar or {}),
        calendar_tasks=dict(cal_tasks or {}),
        intel_news=dict(intel_news or {}),
    )
    cfg = BriefingConfig(
        schedule_mode=schedule_mode,
        delta_override=deltas if deltas is not None else {},
        ci_reconciled_override=ci_reconciled,
        critic_override=critic_reconciled,
        agenda_override=agenda_items,
    )
    engine = BriefingEngine(adapters=CollectorAdapters.in_memory())
    return engine.synthesize(snapshot, cfg).markdown


def _build_cli_adapters() -> CollectorAdapters:
    """Builds CollectorAdapters bound to current module-level collectors (supports legacy test hooks)."""

    def _email_adapter(req: EmailCollectRequest) -> Dict[str, Any]:
        if query_live_email_telemetry is _DEFAULT_QUERY_LIVE_EMAIL:
            return query_live_email_telemetry(
                max_retries=req.max_retries,
                retry_interval_sec=req.retry_interval_sec,
                target_date=req.target_date,
            )
        return query_live_email_telemetry()

    def _github_ci_adapter(repo: str = "CmfH009/Orbit-Security", branch: str = "main") -> Dict[str, Any]:
        if query_live_github_ci_status is _DEFAULT_QUERY_LIVE_GITHUB_CI:
            return query_live_github_ci_status(repo=repo, branch=branch)
        return query_live_github_ci_status()

    return CollectorAdapters(
        system_telemetry=query_system_telemetry,
        daemon_health=query_daemon_health,
        email_telemetry=_email_adapter,
        email_hygiene=query_email_hygiene,
        calendar_tasks=query_calendar_and_tasks,
        archive_ci_alerts=archive_superseded_ci_alerts_in_imap,
        github_ci=_github_ci_adapter,
        stripe_telemetry=query_stripe_telemetry,
        option_c_readiness=query_option_c_readiness,
        inbox_pipeline=query_inbox_pipeline,
        campaign_outreach=query_campaign_outreach,
        geo_panel=query_geo_panel_telemetry,
        projects_radar=query_projects_radar,
        intel_news=query_intel_and_world_news,
        commits_24h=lambda radar, now_dt: _count_commits_24h(radar, now_dt=now_dt),
        workspace_critic_probe=lambda cands, blob: probe_workspace_critic_evidence(cands, blob),
    )


def generate_briefing(
    speak: bool = False,
    email: bool = False,
    recipient: Optional[str] = None,
    dry_run: bool = False,
    pause: bool = False,
    gui: bool = False,
    tui: bool = False,
    schedule_mode: str = "default",
    max_retries: Optional[int] = None,
    retry_interval_sec: float = 300.0,
    *,
    engine: Optional[BriefingEngine] = None,
) -> BriefingResult:
    """Runs Phase 1 collection + Phase 2 synthesis via BriefingEngine, then writes/dispatches artifacts."""
    now_dt = datetime.datetime.now()
    date_key = now_dt.strftime("%Y-%m-%d")
    active_engine = engine or BriefingEngine(adapters=_build_cli_adapters())

    collect_cfg = BriefingConfig(
        now=now_dt,
        schedule_mode=schedule_mode,
        dry_run=dry_run,
        max_retries=max_retries,
        retry_interval_sec=retry_interval_sec,
        state_dir=DEFAULT_BRIEFINGS_DIR,
        persist_state=True,
    )
    snapshot = active_engine.collect_snapshot(collect_cfg)

    delta_override: Optional[Dict[str, Any]] = None
    if compute_and_save_daily_deltas is not _DEFAULT_COMPUTE_AND_SAVE_DELTAS:
        delta_override = compute_and_save_daily_deltas(
            date_str=date_key,
            current_snapshot=snapshot.delta_metrics(),
        )

    synth_cfg = BriefingConfig(
        now=now_dt,
        schedule_mode=schedule_mode,
        dry_run=dry_run,
        state_dir=DEFAULT_BRIEFINGS_DIR,
        persist_state=delta_override is None,
        delta_override=delta_override,
    )
    result = active_engine.synthesize(snapshot, synth_cfg)
    report = result.markdown
    spoken_summary = result.spoken_summary
    master_brief = result.snapshot.master_briefing

    # Save Unified Report
    DEFAULT_BRIEFINGS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DEFAULT_BRIEFINGS_DIR / f"briefing_{date_key}.md"
    report_path.write_text(report, encoding="utf-8")

    print(report)
    print(f"\n[✔] Written to {report_path}")

    # Dispatch email & persist extracted briefing intel into HyperDB + CognitiveMatrix (skipped in --dry-run)
    if not dry_run:
        if isinstance(master_brief, dict) and master_brief.get("found"):
            try:
                from orbit_security.hypernote_briefing import ingest_briefing_to_stores

                ingest_briefing_to_stores(master_brief)
            except Exception:
                pass
    if email and not dry_run:
        dispatch_email_briefing(report, recipient=recipient)

    latest_state_path = DEFAULT_BRIEFINGS_DIR / "briefing_state_latest.json"
    if latest_state_path.is_file():
        try:
            state_obj = json.loads(latest_state_path.read_text(encoding="utf-8"))
            if isinstance(state_obj, dict):
                state_obj["spoken_summary"] = spoken_summary
                latest_state_path.write_text(json.dumps(state_obj, indent=2), encoding="utf-8")
        except Exception:
            pass

    if tui or gui:
        try:
            try:
                from scripts.briefing_tui import show_briefing_tui
            except ImportError:
                from briefing_tui import show_briefing_tui  # type: ignore[import-not-found]

            wt_pid = show_briefing_tui(
                content=report,
                spoken_summary=spoken_summary,
                auto_speak=bool(speak and not dry_run),
                title_suffix=f"briefing_{date_key}",
                briefing_file=report_path,
            )
            if wt_pid:
                return result
        except Exception as tui_err:
            print(f"[!] Windows Terminal TUI launch error: {tui_err}")

    if speak and not dry_run:
        hook_script = r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py"
        if os.path.exists(hook_script):
            py314 = r"C:\Python314\python.exe"
            voice_exe = py314 if os.path.exists(py314) else sys.executable
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run([voice_exe, hook_script, "--speak", spoken_summary], creationflags=flags)

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
            return result
        except Exception:
            pass

    return result


def _acquire_briefing_run_mutex() -> Optional[int]:
    """Acquires a Windows named mutex so scheduled triggers never double-dispatch daily_briefing.py."""
    if os.name != "nt":
        return 1
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, "Local\\OrbitDailyBriefingRunMutex")
        if not handle:
            return None
        if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return None
        return int(handle)
    except Exception:
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified Orbit Security & Mailbox Daily Briefing")
    parser.add_argument("--speak", action="store_true", help="Speak the unified debrief aloud in Nova's voice")
    parser.add_argument("--email", action="store_true", help="Dispatch briefing to operator email")
    parser.add_argument("--recipient", type=str, default=None, help="Custom recipient email address")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate briefing and state files without email, TTS, or IMAP mutation",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="Run the interactive terminal viewer until Q or Ctrl+W is pressed",
    )
    parser.add_argument("--tui", action="store_true", help="Display briefing in a persistent elevated Windows Terminal tab")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Alias for --tui (opens elevated Windows Terminal briefing tab)",
    )
    parser.add_argument(
        "--schedule-mode",
        choices=["default", "early"],
        default=os.environ.get("ORBIT_BRIEFING_SCHEDULE_MODE", "default"),
        help="Schedule alignment mode: default (10:15 MST) or early (09:00 MST)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=None,
        help="Max Gmail arrival retry count (default: 3 live, 0 dry-run)",
    )
    parser.add_argument(
        "--retry-interval",
        type=float,
        default=300.0,
        help="Seconds between Gmail arrival retries (default: 300s)",
    )
    args = parser.parse_args()

    mutex_handle = None
    if not args.dry_run:
        mutex_handle = _acquire_briefing_run_mutex()
        if mutex_handle is None:
            print("[!] Another daily_briefing.py instance is already running; skipping duplicate dispatch.")
            return

    try:
        generate_briefing(
            speak=args.speak,
            email=args.email,
            recipient=args.recipient,
            dry_run=args.dry_run,
            pause=args.pause,
            gui=args.gui,
            tui=args.tui,
            schedule_mode=args.schedule_mode,
            max_retries=args.max_retries,
            retry_interval_sec=args.retry_interval,
        )
    finally:
        if os.name == "nt" and isinstance(mutex_handle, int) and mutex_handle > 1:
            try:
                import ctypes

                ctypes.windll.kernel32.CloseHandle(mutex_handle)
            except Exception:
                pass


if __name__ == "__main__":
    main()
