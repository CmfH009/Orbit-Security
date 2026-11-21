"""Deep Briefing & Morning Cockpit package for Orbit Security.

External interface:
- `BriefingEngine` (Phase 1 `collect_snapshot` -> Phase 2 in-process `synthesize` / `run`)
- `TelemetrySnapshot`, `BriefingResult`, `BriefingConfig`, `EmailCollectRequest`, `CollectorAdapters`
- `live_collector_adapters`, `sanitize_snapshot`, `verify_critic_snapshot`, `render_markdown`, `render_spoken_summary`
"""

from __future__ import annotations

from ._sanitize import (
    sanitize_email_data,
    sanitize_inbound_text,
    sanitize_intel_news,
    sanitize_master_briefing,
)
from .email_cockpit import (
    DELTA_GMAIL_QUERIES,
    MASTER_BRIEFING_GMAIL_QUERY,
    archive_superseded_ci_alerts_in_imap,
    fetch_gemini_master_briefing_from_gmail,
    poll_gemini_master_briefing_with_backoff,
    query_calendar_and_tasks,
    query_email_hygiene,
    query_google_calendar,
    query_live_email_telemetry,
    query_post_briefing_email_delta,
    query_sent_reply_metadata,
    triage_email_messages,
)
from .models import (
    BriefingConfig,
    BriefingResult,
    CollectorAdapters,
    EmailCollectRequest,
    TelemetrySnapshot,
)
from .pipeline import (
    DEFAULT_BRIEFINGS_DIR,
    BriefingEngine,
    build_agenda_items,
    compute_and_save_daily_deltas,
    compute_daily_deltas_in_memory,
    extract_critic_ci_candidates,
    reconcile_ci_alerts_with_live_status,
    render_markdown,
    render_master_briefing_block,
    render_spoken_summary,
    run_local_critic_reconciliation,
    sanitize_snapshot,
    verify_critic_snapshot,
)
from .system_collectors import (
    AI_KEYWORD_RE,
    CORE_ACTIVE_REPOS,
    KNOWN_EXPECTED_PORTS,
    SECURITY_TECH_RE,
    classify_intel_feeds,
    live_collector_adapters,
    probe_workspace_critic_evidence,
    query_campaign_outreach,
    query_daemon_health,
    query_geo_panel_telemetry,
    query_inbox_pipeline,
    query_intel_and_world_news,
    query_live_github_ci_status,
    query_option_c_readiness,
    query_projects_radar,
    query_stripe_telemetry,
    query_system_telemetry,
)

__all__ = [
    # Deep two-phase interface
    "BriefingEngine",
    "BriefingConfig",
    "BriefingResult",
    "CollectorAdapters",
    "EmailCollectRequest",
    "TelemetrySnapshot",
    "live_collector_adapters",
    # Pure Phase 2 primitives
    "sanitize_snapshot",
    "sanitize_inbound_text",
    "sanitize_intel_news",
    "sanitize_master_briefing",
    "sanitize_email_data",
    "reconcile_ci_alerts_with_live_status",
    "verify_critic_snapshot",
    "run_local_critic_reconciliation",
    "extract_critic_ci_candidates",
    "compute_daily_deltas_in_memory",
    "compute_and_save_daily_deltas",
    "build_agenda_items",
    "render_master_briefing_block",
    "render_markdown",
    "render_spoken_summary",
    # Production collector functions & constants
    "DEFAULT_BRIEFINGS_DIR",
    "KNOWN_EXPECTED_PORTS",
    "CORE_ACTIVE_REPOS",
    "AI_KEYWORD_RE",
    "SECURITY_TECH_RE",
    "MASTER_BRIEFING_GMAIL_QUERY",
    "DELTA_GMAIL_QUERIES",
    "query_system_telemetry",
    "query_projects_radar",
    "query_calendar_and_tasks",
    "query_google_calendar",
    "query_intel_and_world_news",
    "classify_intel_feeds",
    "query_email_hygiene",
    "query_sent_reply_metadata",
    "fetch_gemini_master_briefing_from_gmail",
    "poll_gemini_master_briefing_with_backoff",
    "query_post_briefing_email_delta",
    "triage_email_messages",
    "query_live_email_telemetry",
    "archive_superseded_ci_alerts_in_imap",
    "query_stripe_telemetry",
    "query_daemon_health",
    "query_option_c_readiness",
    "query_inbox_pipeline",
    "query_campaign_outreach",
    "query_live_github_ci_status",
    "query_geo_panel_telemetry",
    "probe_workspace_critic_evidence",
]
