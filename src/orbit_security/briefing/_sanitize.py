"""Prompt-injection sanitization for untrusted external briefing telemetry."""

from __future__ import annotations

from typing import Any, Dict, Optional

try:
    from orbit_security.inbox_guardrail import PromptInjectionSanitizer
except ImportError:
    PromptInjectionSanitizer = None


def sanitize_inbound_text(value: Any, max_chars: int = 4000) -> str:
    """Screens untrusted inbound text through PromptInjectionSanitizer."""
    if value is None:
        return ""
    raw = str(value)
    if PromptInjectionSanitizer is not None:
        return PromptInjectionSanitizer.sanitize(raw, max_chars=max_chars)
    return raw[:max_chars].strip()


def sanitize_intel_news(intel_news: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitizes HN and Google News RSS feed payloads before Markdown/TTS exposure."""
    if not isinstance(intel_news, dict):
        return {}
    cleaned = dict(intel_news)
    for list_key in ("ai_innovations", "tech_and_security", "world_news"):
        items = cleaned.get(list_key)
        if isinstance(items, list):
            cleaned[list_key] = [
                sanitize_inbound_text(item, max_chars=1000)
                for item in items
                if item is not None
            ]
    for str_key in ("ai_takeaway", "world_takeaway"):
        if cleaned.get(str_key) is not None:
            cleaned[str_key] = sanitize_inbound_text(cleaned[str_key], max_chars=1000)
    return cleaned


def sanitize_master_briefing(master_briefing: Any) -> Any:
    """Sanitizes extracted IMAP Combined Daily Master Briefing fields without clipping preserved Markdown links."""
    if not isinstance(master_briefing, dict):
        return master_briefing
    cleaned = dict(master_briefing)
    if cleaned.get("subject") is not None:
        cleaned["subject"] = sanitize_inbound_text(cleaned["subject"], max_chars=800)
    if cleaned.get("body_text") is not None:
        cleaned["body_text"] = sanitize_inbound_text(cleaned["body_text"], max_chars=12000)
    if isinstance(cleaned.get("highlights"), list):
        cleaned["highlights"] = [
            sanitize_inbound_text(h, max_chars=1500) for h in cleaned["highlights"]
        ]
    if isinstance(cleaned.get("sections"), dict):
        sec_clean: Dict[str, Any] = {}
        for sec_k, sec_vals in cleaned["sections"].items():
            if isinstance(sec_vals, list):
                sec_clean[sec_k] = [
                    sanitize_inbound_text(v, max_chars=1500) for v in sec_vals
                ]
            else:
                sec_clean[sec_k] = sec_vals
        cleaned["sections"] = sec_clean
    return cleaned


def sanitize_email_data(email_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitizes IMAP-derived lists, post-briefing delta items, and nested master_briefing payloads."""
    if not isinstance(email_data, dict):
        return {}
    cleaned = dict(email_data)
    for list_key in (
        "unread_list",
        "urgent_list",
        "awaiting_external_reply",
        "historical_alerts_sample",
        "ci_alerts",
        "deal_threads",
    ):
        items = cleaned.get(list_key)
        if isinstance(items, list):
            cleaned[list_key] = [
                sanitize_inbound_text(item, max_chars=600) for item in items
            ]
    if isinstance(cleaned.get("email_hygiene"), dict):
        hyg = dict(cleaned["email_hygiene"])
        if "master_briefing" in hyg:
            hyg["master_briefing"] = sanitize_master_briefing(hyg["master_briefing"])
        cleaned["email_hygiene"] = hyg
    if isinstance(cleaned.get("master_briefing"), dict):
        cleaned["master_briefing"] = sanitize_master_briefing(cleaned["master_briefing"])
    if isinstance(cleaned.get("post_briefing_delta"), dict):
        pdelta = dict(cleaned["post_briefing_delta"])
        for bucket_k in (
            "ci_cd_all",
            "ci_cd_delta",
            "vdp_all",
            "vdp_delta",
            "work_delta",
            "work_recent",
        ):
            bucket_vals = pdelta.get(bucket_k)
            if isinstance(bucket_vals, list):
                sanitized_entries = []
                for entry in bucket_vals:
                    if isinstance(entry, dict):
                        e_copy = dict(entry)
                        if e_copy.get("subject") is not None:
                            e_copy["subject"] = sanitize_inbound_text(
                                e_copy["subject"], max_chars=600
                            )
                        if e_copy.get("sender") is not None:
                            e_copy["sender"] = sanitize_inbound_text(
                                e_copy["sender"], max_chars=300
                            )
                        sanitized_entries.append(e_copy)
                    else:
                        sanitized_entries.append(
                            sanitize_inbound_text(entry, max_chars=600)
                        )
                pdelta[bucket_k] = sanitized_entries
        cleaned["post_briefing_delta"] = pdelta
    return cleaned
