"""Thin CLI & compatibility facade over `orbit_security.briefing` for the Unified Morning Cockpit.

All telemetry, workspace radar, IMAP/email hygiene, calendar, and news collectors now live
inside the deepened `orbit_security.briefing` package.
"""

from __future__ import annotations

import imaplib
import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = str(_REPO_ROOT / "src")
if _SRC_DIR not in sys.path and (_REPO_ROOT / "src").is_dir():
    sys.path.insert(0, _SRC_DIR)

from orbit_security.briefing.email_cockpit import (  # noqa: E402
    DELTA_GMAIL_QUERIES,
    MASTER_BRIEFING_GMAIL_QUERY,
    _clean_single_line,
    _coerce_email_message,
    _decode_mime_header,
    _denver_date_of,
    _detect_agy_delimiter,
    _detect_master_section,
    _ensure_email_organizer_on_path,
    _extract_ical_dtstart_date,
    _extract_master_briefing_delta,
    _extract_raw_urls,
    _extract_sent_reply_metadata,
    _fetch_imap_messages as _pkg_fetch_imap_messages,
    _fetch_sent_mail_headers as _pkg_fetch_sent_mail_headers,
    _fold_section_entries,
    _friendly_link_label,
    _get_denver_tz,
    _is_invite_event_today,
    _is_safe_auto_hygiene_candidate,
    _load_imap_credentials as _pkg_load_imap_credentials,
    _msg_field,
    _normalize_thread_key,
    _parse_msg_datetime,
    _preserve_inline_markdown_links,
    _scan_gmail_calendar_invites,
    _split_top_level_topics,
    _strip_html_to_lines,
    _strip_tracking_urls,
    _truncate_preserving_links,
    _unfold_ical_lines,
    _unwrap_tracking_url,
    fetch_gemini_master_briefing_from_gmail,
    poll_gemini_master_briefing_with_backoff,
    query_email_hygiene,
    query_google_calendar as _pkg_query_google_calendar,
    query_post_briefing_email_delta,
    query_sent_reply_metadata,
)
from orbit_security.briefing.system_collectors import (  # noqa: E402
    AI_KEYWORD_RE,
    CORE_ACTIVE_REPOS,
    KNOWN_EXPECTED_PORTS,
    SECURITY_TECH_RE,
    _clamp_single_sentence,
    _derive_ollama_ps_url,
    _deterministic_news_takeaway,
    _fetch_google_news_rss as _pkg_fetch_google_news_rss,
    _fetch_hn_algolia_hits as _pkg_fetch_hn_algolia_hits,
    _get_cpu_name,
    _headline_text,
    _is_within_48h,
    _parse_ollama_takeaways,
    _query_git_last_commit,
    _query_git_repo_details,
    _query_hardware_thermals,
    _query_inbox_queues,
    _query_warm_ollama_models,
    _synthesize_news_takeaway,
    _triage_listening_ports,
    classify_intel_feeds,
    query_intel_and_world_news as _pkg_query_intel_and_world_news,
    query_projects_radar,
    query_system_telemetry,
)

# Re-exported module bindings preserved for callers/tests
_load_imap_credentials = _pkg_load_imap_credentials
_fetch_imap_messages = _pkg_fetch_imap_messages
_fetch_hn_algolia_hits = _pkg_fetch_hn_algolia_hits
_fetch_google_news_rss = _pkg_fetch_google_news_rss


def _fetch_sent_mail_headers(limit: int = 30, timeout: float = 4.0) -> List[Dict[str, Any]]:
    return _pkg_fetch_sent_mail_headers(
        limit=limit,
        timeout=timeout,
        credentials_loader=_load_imap_credentials,
        imap_cls=imaplib.IMAP4_SSL,
    )


def query_google_calendar(
    ical_url: Optional[str] = None,
    messages: Optional[Sequence[Any]] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    return _pkg_query_google_calendar(
        ical_url=ical_url,
        messages=messages,
        limit=limit,
        imap_fetcher=_fetch_imap_messages,
    )


def query_calendar_and_tasks(
    ical_url: Optional[str] = None,
    messages: Optional[Sequence[Any]] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    return query_google_calendar(ical_url=ical_url, messages=messages, limit=limit)


def query_intel_and_world_news() -> Dict[str, Any]:
    return _pkg_query_intel_and_world_news(
        hn_fetcher=_fetch_hn_algolia_hits,
        rss_fetcher=_fetch_google_news_rss,
    )


def main() -> None:
    """Quick CLI telemetry dump over the deepened cockpit collectors."""
    payload = {
        "system_telemetry": query_system_telemetry(),
        "projects_radar": query_projects_radar(),
        "calendar_tasks": query_calendar_and_tasks(),
        "intel_news": query_intel_and_world_news(),
    }
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    main()
