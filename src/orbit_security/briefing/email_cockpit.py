"""IMAP/Email, Gmail Master Briefing, Post-Briefing Delta, Triage, and Calendar Collectors."""

from __future__ import annotations

import base64
import datetime
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
import imaplib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

from ._sanitize import (
    sanitize_email_data,
    sanitize_inbound_text,
)

_EMAIL_ORG_FALLBACK_DIR = Path(r"A:\projects\email-organizer")
_MASTER_BRIEFING_PREFIX = "combined daily master briefing"

MASTER_BRIEFING_GMAIL_QUERY = (
    'label:Orbit/Briefings subject:"Combined Daily Master Briefing" newer_than:1d'
)
DELTA_GMAIL_QUERIES: Dict[str, str] = {
    "ci_cd": "label:Orbit/CI-CD newer_than:2d",
    "vdp": "label:Orbit/VDP newer_than:7d",
    "work": "label:Work newer_than:3d",
}

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

_TRACKING_QUERY_PARAMS = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "fbclid",
        "gclid",
        "mc_cid",
        "mc_eid",
        "sa",
        "ust",
        "usg",
        "ved",
    }
)

_AGY_DELIMITER_MAP: Dict[str, str] = {
    "OPS_CICD_SLA": "ops_cicd_sla",
    "AI_DEV_RADAR": "ai_dev_radar",
    "COMPETITIVE_SECURITY": "competitive_security",
    "YOUTUBE_NEWSLETTERS": "youtube_newsletters",
    "DEADLINES_CHECKLIST": "deadlines_checklist",
    "ZIVA_AND_BRITTANY": "ziva_and_brittany",
    "CRITIC_AUDIT": "critic_audit",
    "FULL_DOSSIER": "__HARD_STOP__",
    "PERSONAL_DOSSIER": "__HARD_STOP__",
    "DOSSIER": "__HARD_STOP__",
}

_STALE_ORBIT_ECHO_HEADER_RE = re.compile(
    r"^orbit\s+security\s+daily\s+operational\s+briefing\b",
    re.IGNORECASE,
)
_STALE_ORBIT_ECHO_CHILD_RE = re.compile(
    r"^(?:daemon\s*&\s*mesh|track\s*a\s*vault(?:\s+expanded)?|track\s*b\s*&\s*stripe|geo\s*panel|recent\s*repo\s*commits|host\s*telemetry)\s*:",
    re.IGNORECASE,
)
_COMPETITIVE_CVE_CUE_RE = re.compile(
    r"(?:CVE-\d{4}-\d+|\b(?:vulnerability|injection|rebinding|heap\s+overflow|ruby2shell|exploit|security\s+advisory|ransomware|breach|0-?day|zero-?day)\b)",
    re.IGNORECASE,
)
_PURE_MD_LINK_RE = re.compile(r"^\[[^\]]+\]\([^)]+\)$")
_GH_CI_SUBJECT_RE = re.compile(
    r"^\[(?P<repo>[^\]]+)\]\s*Run\s+(?P<state>failed|cancelled|timed out)\s*:\s*(?P<workflow>.+?)\s*-\s*(?P<branch>[^\s(]+)\s*\((?P<sha>[0-9a-fA-F]{6,40})\)",
    re.IGNORECASE,
)

_OUTBOUND_ACTION_CUE_RE = re.compile(
    r"\b(submitted|uploaded|replied|responded|sent|filed|appealed|resolved|completed|confirmed)\b",
    re.IGNORECASE,
)
_ISO_OR_DT_IN_TEXT_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_TOPIC_STOPWORDS = frozenset(
    {
        "re",
        "fw",
        "fwd",
        "the",
        "and",
        "for",
        "with",
        "from",
        "your",
        "our",
        "immediate",
        "request",
        "update",
        "alert",
        "notice",
        "statement",
        "account",
        "urgent",
        "action",
        "required",
        "email",
        "message",
        "today",
        "closure",
        "http",
        "https",
        "www",
        "com",
        "google",
        "url",
    }
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent


def _email_organizer_candidates() -> Tuple[Path, Path]:
    sibling_dir = _repo_root().parent / "email-organizer"
    return (sibling_dir, _EMAIL_ORG_FALLBACK_DIR)


def _ensure_email_organizer_on_path() -> bool:
    """Adds A:\\projects\\email-organizer (or sibling repo) to sys.path when available."""
    for candidate in _email_organizer_candidates():
        if candidate.is_dir():
            cand_str = str(candidate)
            if cand_str not in sys.path:
                sys.path.insert(0, cand_str)
            return True
    return False


def _load_imap_credentials() -> Tuple[str, str]:
    """Loads IMAP credentials from email-organizer/.env and environment variables (single source of truth)."""
    imap_user = os.environ.get("IMAP_USER", "carsonmail009@gmail.com")
    imap_pass = os.environ.get("IMAP_PASS", "")
    for candidate in _email_organizer_candidates():
        env_path = candidate / ".env"
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


def _clean_subject(subject: str) -> str:
    return (subject or "").replace("\r", "").replace("\n", " ").strip()


def _normalize_thread_key(subject: str) -> str:
    """Strips leading Re:/Fwd:/Fw: prefixes and lowercases for outbound reply matching."""
    cleaned = _clean_single_line(subject)
    while True:
        stripped = re.sub(r"^(re|fwd?|fw)\s*:\s*", "", cleaned, flags=re.IGNORECASE).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    return cleaned.lower()


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
    """Extracts readable lines and list items from HTML email bodies while preserving anchor links."""
    if not raw_html:
        return []
    text = re.sub(
        r'(?is)<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        lambda m: (
            f"[{_clean_single_line(re.sub(r'<[^>]+>', ' ', m.group(2))) or m.group(1)}]({m.group(1).strip()})"
            if m.group(1).strip().lower().startswith(("http://", "https://"))
            else _clean_single_line(re.sub(r"<[^>]+>", " ", m.group(2)))
        ),
        raw_html,
    )
    text = re.sub(r"(?i)<li[^>]*>", "\n- ", text)
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


def _unwrap_tracking_url(raw_url: str) -> str:
    """Unwraps Google/Substack/YouTube redirect wrappers and strips tracking query params."""
    url = (raw_url or "").replace("&amp;", "&").strip().strip("<>")
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.netloc.lower()
        if host.endswith("google.com") and parsed.path == "/url":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
            target = (qs.get("q") or qs.get("url") or [""])[0].strip()
            if target.startswith(("http://", "https://")):
                url = target
        elif host.endswith("youtube.com") and parsed.path == "/redirect":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
            target = (qs.get("q") or [""])[0].strip()
            if target.startswith(("http://", "https://")):
                url = target
        elif "substack.com" in host and "/redirect/" in parsed.path:
            segs = [s for s in parsed.path.split("/") if s]
            for seg in reversed(segs):
                if len(seg) >= 16:
                    try:
                        padded = seg + "=" * (-len(seg) % 4)
                        decoded = json.loads(
                            base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
                        )
                        if isinstance(decoded, dict) and str(decoded.get("e", "")).startswith(
                            ("http://", "https://")
                        ):
                            url = str(decoded["e"]).strip()
                            break
                    except Exception:
                        continue
    except Exception:
        pass

    try:
        parsed2 = urllib.parse.urlsplit(url)
        if parsed2.query:
            pairs = urllib.parse.parse_qsl(parsed2.query, keep_blank_values=True)
            filtered = [
                (k, v)
                for k, v in pairs
                if k.lower() not in _TRACKING_QUERY_PARAMS
                and not (k.lower() == "source" and v.lower() in ("gmail", "editors"))
            ]
            new_query = urllib.parse.urlencode(
                filtered,
                doseq=True,
                quote_via=lambda s, safe="", encoding=None, errors=None: urllib.parse.quote(
                    s, safe=f"{safe}@", encoding=encoding or "utf-8", errors=errors or "strict"
                ),
            )
            url = urllib.parse.urlunsplit(
                (parsed2.scheme, parsed2.netloc, parsed2.path, new_query, parsed2.fragment)
            )
    except Exception:
        pass
    return url


def _friendly_link_label(clean_url: str) -> str:
    """Derives a concise human-readable label for a bare URL."""
    try:
        parsed = urllib.parse.urlsplit(clean_url)
        host = parsed.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        if host == "mail.google.com":
            return "Gmail Thread"
        if host == "keep.google.com":
            return "Google Keep"
        if host == "drive.google.com":
            return "Google Drive"
        if host == "sites.google.com":
            return "Google Site"
        if host == "discuss.ai.google.dev":
            return "AI Forum"
        if host == "github.com":
            parts = [p for p in parsed.path.split("/") if p]
            return f"github.com/{parts[0]}/{parts[1]}" if len(parts) >= 2 else "GitHub"
        if host == "arxiv.org":
            parts = [p for p in parsed.path.split("/") if p]
            return f"arXiv:{parts[-1]}" if parts else "arXiv"
        if host == "huggingface.co":
            parts = [p for p in parsed.path.split("/") if p]
            return "/".join(parts[:2]) if len(parts) >= 2 else "HuggingFace"
        return host or "Link"
    except Exception:
        return "Link"


def _preserve_inline_markdown_links(text: str) -> str:
    """Unwraps tracking URLs and converts bare URLs / 'Label: URL' items into inline [Label](URL) Markdown links."""
    raw = _clean_single_line((text or "").replace("&amp;", "&"))
    if not raw:
        return ""

    label_url_match = re.match(
        r"^(?P<label>.+?)\s*:\s*<?(?P<url>https?://[^\s<>\]\"']+)>?\s*$", raw
    )
    if label_url_match:
        label = label_url_match.group("label").strip(" -*•")
        url = _unwrap_tracking_url(label_url_match.group("url").rstrip(".,;:!?"))
        if label and url and "](" not in label:
            return f"[{label}]({url})"

    placeholders: List[str] = []

    def _stash_md_link(match: re.Match[str]) -> str:
        lbl = _clean_single_line(match.group(1))
        url = _unwrap_tracking_url(match.group(2))
        token = f"__MDLINK_{len(placeholders)}__"
        placeholders.append(f"[{lbl}]({url})" if url else lbl)
        return token

    tokenized = re.sub(r"\[([^\]]+)\]\(\s*(https?://[^)\s]+)\s*\)", _stash_md_link, raw)

    def _format_bare_url(raw_u: str) -> str:
        full = raw_u
        trailing = ""
        while full and full[-1] in ".,;:!?":
            trailing = full[-1] + trailing
            full = full[:-1]
        clean_url = _unwrap_tracking_url(full)
        if not clean_url:
            return trailing
        lbl = _friendly_link_label(clean_url)
        return f"[{lbl}]({clean_url}){trailing}"

    tokenized = re.sub(r"<\s*(https?://[^>\s]+)\s*>", lambda m: _format_bare_url(m.group(1)), tokenized)
    tokenized = re.sub(r"https?://[^\s<>\"'\)\]]+", lambda m: _format_bare_url(m.group(0)), tokenized)

    for idx, md_link in enumerate(placeholders):
        tokenized = tokenized.replace(f"__MDLINK_{idx}__", md_link)

    return _clean_single_line(tokenized)


def _strip_tracking_urls(text: str) -> str:
    """Preserves inline Markdown links while unwrapping tracking URLs (compat wrapper)."""
    return _preserve_inline_markdown_links(text)


def _detect_agy_delimiter(line: str) -> Optional[str]:
    """Detects strict [AGY_SECTION:...] top-level delimiters."""
    m = re.match(r"^\s*\[AGY_SECTION\s*:\s*([A-Z0-9_]+)\s*\]\s*$", (line or "").strip(), re.IGNORECASE)
    if not m:
        return None
    key = m.group(1).strip().upper()
    return _AGY_DELIMITER_MAP.get(key)


def _detect_master_section(line: str) -> Optional[str]:
    """Identifies [AGY_SECTION:...] delimiters, numbered TOC sections, or Section 5 hard-stop headers."""
    delim = _detect_agy_delimiter(line)
    if delim:
        return delim

    clean = re.sub(r"^[#*\s\-•]+", "", line or "").strip().lower()
    clean = re.sub(r"[*_:]+$", "", clean).strip()
    if not clean:
        return None

    if (
        re.search(r"^(?:section\s*5\b|5\.\s+).*?(?:dossier|cumulative|personal\s+dossier)", clean)
        or re.match(r"^(?:full\s+cumulative\s+personal\s+dossier|5\.1\s+core\s+identity)\b", clean)
    ):
        return "__HARD_STOP__"

    if (
        re.search(r"^(?:section\s*1\b|1\.\s+).*?(?:personal|delta|account|ops|ci/?cd|sla)", clean)
        or clean.startswith("24h personal delta")
    ):
        return "ops_cicd_sla"
    if (
        re.search(
            r"^(?:section\s*2\b|2\.\s+).*?(?:ai\s+news|google\s+ai|antigravity|gemini|gemma|dev\s+stack|ecosystem|research|model|tool|radar)",
            clean,
        )
        or re.match(r"^(?:ai\s+news|ecosystem\s+news|ai/dev\s+radar)\b", clean)
    ):
        return "ai_dev_radar"
    if re.match(r"^(?:competitive\s*(?:&|and)?\s*(?:adversarial\s+)?security|security\s+radar)\b", clean):
        return "competitive_security"
    if (
        re.search(r"^(?:section\s*3\b|3\.\s+).*?(?:youtube|video|newsletter)", clean)
        or re.match(r"^(?:technical\s+)?youtube\s+digest\b", clean)
    ):
        return "youtube_newsletters"
    if (
        re.search(
            r"^(?:section\s*4\b|4\.\s+).*?(?:deprecat|30-?day|deadline|pricing|retire|sunset|alert|checklist)",
            clean,
        )
        or re.match(r"^(?:30-?day\s+deprecations|upcoming\s+(?:30-day\s+)?(?:api\s+pricing|deprecations))\b", clean)
    ):
        return "deadlines_checklist"
    if re.match(r"^(?:ziva\s*(?:&|and)\s*brittany|missoula\s+(?:home|corner))\b", clean):
        return "ziva_and_brittany"
    if re.match(r"^(?:critic\s+(?:audit|verification))\b", clean):
        return "critic_audit"
    return None


def _extract_raw_urls(raw_text: str) -> List[str]:
    """Extract and deduplicate HTTP(S) URLs from plain text or HTML bodies."""
    unescaped = (raw_text or "").replace("&amp;", "&")
    seen: set[str] = set()
    urls: List[str] = []
    for match in re.findall(r"https?://[^\s<>\"'\)\]]+", unescaped):
        cleaned = match.rstrip(".,;:!?")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls


def _truncate_preserving_links(text: str, max_len: int = 900) -> str:
    """Truncates overly long prose without cutting inside a [Label](URL) Markdown link."""
    if len(text) <= max_len:
        return text
    cut = max_len - 3
    for m in re.finditer(r"\[[^\]]+\]\([^)]+\)", text):
        if m.start() < cut < m.end():
            if m.end() <= max_len + 260:
                return text
            cut = m.start()
            break
    truncated = text[:cut].rstrip(" ,;:-")
    if " " in truncated and len(truncated) > 160 and not truncated.endswith(")"):
        truncated = truncated.rsplit(" ", 1)[0].rstrip(" ,;:")
    return (truncated + "...") if truncated else text[:max_len]


def _fold_section_entries(raw_entries: List[Tuple[int, str]]) -> List[str]:
    """Folds parent header labels ending in ':' into child links/prose so zero dangling bullets remain."""
    folded: List[str] = []
    idx = 0
    total = len(raw_entries)

    while idx < total:
        indent, text = raw_entries[idx]
        if not text:
            idx += 1
            continue

        if text.endswith(":"):
            header_label = text[:-1].strip()
            children: List[Tuple[int, str]] = []
            look = idx + 1
            while look < total and raw_entries[look][0] > indent:
                children.append(raw_entries[look])
                look += 1

            if not children:
                idx += 1
                continue

            if all(_PURE_MD_LINK_RE.match(ch_txt) for _, ch_txt in children):
                folded.append(f"{header_label}: " + " | ".join(ch_txt for _, ch_txt in children))
                idx = look
                continue

            sub_folded = _fold_section_entries(children)
            if sub_folded:
                merged_sub: List[str] = []
                for sub_txt in sub_folded:
                    if _PURE_MD_LINK_RE.match(sub_txt) and merged_sub and not merged_sub[-1].endswith(")"):
                        merged_sub[-1] = f"{merged_sub[-1]} ({sub_txt})"
                    else:
                        merged_sub.append(sub_txt)
                first = merged_sub[0]
                if header_label and not first.lower().startswith(header_label.lower()[:12]):
                    folded.append(f"**{header_label}:** {first}")
                else:
                    folded.append(first)
                folded.extend(merged_sub[1:])
            idx = look
            continue

        if _PURE_MD_LINK_RE.match(text) and text.startswith("[Thread](") and folded:
            folded[-1] = f"{folded[-1]} ({text})"
            idx += 1
            continue

        folded.append(text)
        idx += 1

    return folded


def _extract_master_briefing_delta(messages: Sequence[Any]) -> Dict[str, Any]:
    """Extracts the latest 'Combined Daily Master Briefing' using strict boundaries, hard-stop before Section 5, and inline links."""
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
        timestamp_utc = float(dt.timestamp())
    elif raw_date:
        date_str = _clean_single_line(str(raw_date))
        timestamp_utc = 0.0
    else:
        date_str = ""
        timestamp_utc = 0.0

    highlights: List[str] = []
    seen_lower: set[str] = set()
    sections: Dict[str, List[str]] = {
        "ops_cicd_sla": [],
        "ai_dev_radar": [],
        "competitive_security": [],
        "youtube_newsletters": [],
        "deadlines_checklist": [],
        "ziva_and_brittany": [],
        "critic_audit": [],
        "personal_delta": [],
        "ai_news": [],
        "youtube_digest": [],
        "deprecations": [],
    }
    section_seen: Dict[str, set[str]] = {k: set() for k in sections}

    def _clean_item(candidate_text: str) -> str:
        stripped = re.sub(r"^[-*•]+\s+", "", (candidate_text or "").strip())
        cleaned = _preserve_inline_markdown_links(stripped)
        if not cleaned or len(cleaned) < 4:
            return ""
        if cleaned.endswith(":") and "](" not in cleaned:
            return ""
        return _truncate_preserving_links(cleaned, max_len=900)

    def _add_to_section(sec_key: Optional[str], cleaned_text: str) -> None:
        if not sec_key or sec_key not in sections:
            return
        k = cleaned_text.lower()
        if k not in section_seen[sec_key]:
            section_seen[sec_key].add(k)
            sections[sec_key].append(cleaned_text)

    def _add_highlight(
        candidate_text: str,
        section_name: Optional[str] = None,
        already_cleaned: bool = False,
    ) -> None:
        cleaned = candidate_text if already_cleaned else _clean_item(candidate_text)
        if not cleaned:
            return
        key = cleaned.lower()
        if section_name:
            _add_to_section(section_name, cleaned)
            if section_name == "ops_cicd_sla":
                _add_to_section("personal_delta", cleaned)
            elif section_name == "ai_dev_radar":
                _add_to_section("ai_news", cleaned)
            elif section_name == "competitive_security":
                _add_to_section("ai_news", cleaned)
            elif section_name == "youtube_newsletters":
                _add_to_section("youtube_digest", cleaned)
            elif section_name == "deadlines_checklist":
                _add_to_section("deprecations", cleaned)
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

    extracted_urls = [
        _unwrap_tracking_url(u)
        for u in _extract_raw_urls("\n".join(p for p in (body_text, body_html, snippet) if p))
    ]
    extracted_urls = [u for u in dict.fromkeys(extracted_urls) if u]

    raw_lines: List[str] = []
    if body_text.strip():
        raw_lines = [ln.rstrip() for ln in body_text.splitlines() if ln.strip()]
    elif body_html.strip():
        raw_lines = _strip_html_to_lines(body_html)
    elif snippet.strip():
        raw_lines = [ln.rstrip() for ln in snippet.splitlines() if ln.strip()]

    skip_line_re = re.compile(
        r"^(?:combined daily master briefing|prepared for|generated:|self-healing status|here is your\b|[=\-_]{3,}|note:\s*your\s+['\"]consolidation of personal information)",
        re.IGNORECASE,
    )

    raw_section_entries: Dict[Optional[str], List[Tuple[int, str]]] = {}
    numbered_entries: Dict[Optional[str], List[Tuple[int, str]]] = {}
    current_section: Optional[str] = None
    in_toc = False
    last_toc_num = 0
    explicit_delimiters_used = False
    hard_stopped_at_dossier = False
    suppressed_stale_echo_lines = 0
    stale_echo_notes: List[str] = []
    skip_echo_indent: Optional[int] = None
    in_sub_24_security = False

    for raw_ln in raw_lines:
        indent = len(raw_ln) - len(raw_ln.lstrip(" \t"))
        ln = raw_ln.strip()
        if not ln:
            continue

        if re.match(r"^executive\s+table\s+of\s+contents\b", ln, re.IGNORECASE):
            in_toc = True
            last_toc_num = 0
            continue

        agy_delim = _detect_agy_delimiter(ln)
        if agy_delim:
            in_toc = False
            explicit_delimiters_used = True
            skip_echo_indent = None
            in_sub_24_security = False
            if agy_delim == "__HARD_STOP__":
                hard_stopped_at_dossier = True
                break
            current_section = agy_delim
            continue

        if in_toc:
            if re.match(r"^[=\-_]{3,}$", ln):
                in_toc = False
                continue
            toc_num_m = re.match(r"^(\d+)\.\s+", ln)
            if toc_num_m:
                num_val = int(toc_num_m.group(1))
                if num_val > last_toc_num:
                    last_toc_num = num_val
                    continue
            in_toc = False

        detected_section = _detect_master_section(ln)
        if detected_section:
            skip_echo_indent = None
            in_sub_24_security = False
            if detected_section == "__HARD_STOP__":
                hard_stopped_at_dossier = True
                break
            current_section = detected_section
            continue

        if skip_line_re.match(ln):
            continue

        if current_section == "ai_dev_radar" and not explicit_delimiters_used:
            if re.match(r"^2\.4\b", ln):
                in_sub_24_security = True
                continue
            elif re.match(r"^2\.\d+\b", ln):
                in_sub_24_security = False
                continue

        if current_section == "ops_cicd_sla":
            bare_probe = re.sub(r"^[-*•]+\s+", "", ln).strip()
            if skip_echo_indent is not None:
                if indent > skip_echo_indent or _STALE_ORBIT_ECHO_CHILD_RE.match(bare_probe):
                    suppressed_stale_echo_lines += 1
                    continue
                skip_echo_indent = None
            if _STALE_ORBIT_ECHO_HEADER_RE.match(bare_probe) or _STALE_ORBIT_ECHO_CHILD_RE.match(bare_probe):
                skip_echo_indent = indent
                suppressed_stale_echo_lines += 1
                stale_echo_notes.append(bare_probe[:120])
                continue

        is_bullet = ln.startswith(("- ", "* ", "• "))
        if is_bullet:
            payload = ln[2:].strip()
            target_sec = current_section
            if target_sec == "ai_dev_radar" and not explicit_delimiters_used:
                if (in_sub_24_security and _COMPETITIVE_CVE_CUE_RE.search(payload)) or _COMPETITIVE_CVE_CUE_RE.search(payload):
                    target_sec = "competitive_security"
            preserved = _preserve_inline_markdown_links(payload)
            if preserved:
                raw_section_entries.setdefault(target_sec, []).append((indent, preserved))
        elif re.match(r"^\d+\.\s+", ln):
            payload = re.sub(r"^\d+\.\s+", "", ln).strip()
            preserved = _preserve_inline_markdown_links(payload)
            if preserved:
                numbered_entries.setdefault(current_section, []).append((indent, preserved))
        elif current_section and len(ln) >= 12 and not ln.startswith(("http://", "https://")):
            preserved = _preserve_inline_markdown_links(ln)
            if preserved:
                raw_section_entries.setdefault(current_section, []).append((indent, preserved))

    for sec_name, entry_list in raw_section_entries.items():
        for item_text in _fold_section_entries(entry_list):
            if item_text.endswith(":") and "](" not in item_text:
                continue
            _add_highlight(_truncate_preserving_links(item_text, max_len=900), section_name=sec_name, already_cleaned=True)

    if not raw_section_entries or any(numbered_entries.values()):
        for sec_name, entry_list in numbered_entries.items():
            for item_text in _fold_section_entries(entry_list):
                if item_text.endswith(":") and "](" not in item_text:
                    continue
                _add_highlight(_truncate_preserving_links(item_text, max_len=900), section_name=sec_name, already_cleaned=True)

    if not highlights and snippet.strip():
        _add_highlight(snippet)

    for sec_k, sec_vals in list(sections.items()):
        sections[sec_k] = [v for v in sec_vals if not (v.endswith(":") and "](" not in v)]

    return {
        "found": True,
        "subject": subject,
        "date": date_str,
        "timestamp_utc": timestamp_utc,
        "highlights": highlights[:40],
        "sections": sections,
        "extracted_urls": extracted_urls,
        "body_text": body_text or "\n".join(raw_lines),
        "parser_meta": {
            "strict_delimiters": explicit_delimiters_used,
            "hard_stopped_at_dossier": hard_stopped_at_dossier,
            "suppressed_stale_echo_lines": suppressed_stale_echo_lines,
            "stale_echo_notes": stale_echo_notes[:5],
        },
    }


def _get_denver_tz() -> datetime.tzinfo:
    """Returns America/Denver tzinfo with fixed MST (-07:00) fallback."""
    try:
        return ZoneInfo("America/Denver")
    except Exception:
        return datetime.timezone(datetime.timedelta(hours=-7))


def _denver_date_of(dt: Optional[datetime.datetime]) -> Optional[datetime.date]:
    if dt is None:
        return None
    aware = dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    return aware.astimezone(_get_denver_tz()).date()


def _build_xgm_raw_query(gmail_query: str) -> str:
    """Formats a Gmail search string into an IMAP X-GM-RAW criterion."""
    escaped = (gmail_query or "").replace("\\", "\\\\").replace('"', '\\"')
    return f'X-GM-RAW "{escaped}"'


def fetch_gemini_master_briefing_from_gmail(
    target_date: Optional[datetime.date] = None,
    client: Optional[Any] = None,
    query: str = MASTER_BRIEFING_GMAIL_QUERY,
    imap_fetcher: Optional[Callable[..., Tuple[List[Any], str]]] = None,
) -> Tuple[Dict[str, Any], str]:
    """Queries Gmail deterministically for today's Combined Daily Master Briefing without mutating \\Seen."""
    expected_date = target_date or datetime.datetime.now(_get_denver_tz()).date()
    xgm_query = _build_xgm_raw_query(query)
    msgs: List[Any] = []
    status = "connected"
    fetcher = imap_fetcher or _fetch_imap_messages

    if client is not None:
        try:
            msgs = list(client.fetch_messages(folder="[Gmail]/All Mail", query=xgm_query, limit=5) or [])
            if not msgs:
                msgs = list(client.fetch_messages(folder="INBOX", query=xgm_query, limit=5) or [])
        except Exception as exc:
            return {"found": False, "subject": "", "date": "", "highlights": []}, f"error: {exc}"
    else:
        msgs, status = fetcher(folder="[Gmail]/All Mail", query=xgm_query, limit=5)
        if not msgs:
            in_msgs, in_status = fetcher(folder="INBOX", query=xgm_query, limit=5)
            if in_msgs:
                msgs = in_msgs
                status = in_status
            elif status.startswith("error:") and in_status == "connected":
                status = in_status

    if not msgs:
        return {"found": False, "subject": "", "date": "", "highlights": [], "matches_target_date": False}, status

    matching_msgs: List[Any] = []
    stale_msgs: List[Any] = []
    for m in msgs:
        subj = _clean_single_line(str(_msg_field(m, "subject", "") or ""))
        if not subj.lower().startswith(_MASTER_BRIEFING_PREFIX):
            continue
        msg_dt = _parse_msg_datetime(_msg_field(m, "date"))
        msg_denver_date = _denver_date_of(msg_dt)
        if msg_denver_date is None or msg_denver_date == expected_date:
            matching_msgs.append(m)
        else:
            stale_msgs.append(m)

    if matching_msgs:
        extracted = _extract_master_briefing_delta(matching_msgs)
        extracted["matches_target_date"] = True
        extracted["gmail_query"] = query
        return extracted, status

    stale_extracted = (
        _extract_master_briefing_delta(stale_msgs)
        if stale_msgs
        else {"found": False, "subject": "", "date": ""}
    )
    return {
        "found": False,
        "subject": "",
        "date": "",
        "highlights": [],
        "matches_target_date": False,
        "stale_candidate": {
            "subject": stale_extracted.get("subject", ""),
            "date": stale_extracted.get("date", ""),
        }
        if stale_extracted.get("found")
        else None,
    }, status


def poll_gemini_master_briefing_with_backoff(
    target_date: Optional[datetime.date] = None,
    max_retries: int = 3,
    retry_interval_sec: float = 300.0,
    sleep_fn: Callable[[float], None] = time.sleep,
    fetcher_fn: Optional[Callable[[], Tuple[Dict[str, Any], str]]] = None,
) -> Dict[str, Any]:
    """Polls Gmail for today's Master Briefing, retrying every 5 minutes up to 3 times before local-only fallback."""
    expected_date = target_date or datetime.datetime.now(_get_denver_tz()).date()
    retries = max(0, int(max_retries))
    last_status = "unconfigured"
    stale_candidate = None

    for attempt in range(retries + 1):
        if fetcher_fn is not None:
            briefing, last_status = fetcher_fn()
        else:
            briefing, last_status = fetch_gemini_master_briefing_from_gmail(target_date=expected_date)

        if briefing.get("stale_candidate"):
            stale_candidate = briefing["stale_candidate"]

        if briefing.get("found") and briefing.get("matches_target_date", True):
            return {
                **briefing,
                "ingestion_status": "received",
                "attempts": attempt + 1,
                "warning_banner": "",
                "gmail_status": last_status,
            }

        if last_status == "unconfigured":
            break

        if attempt < retries and retry_interval_sec > 0:
            sleep_fn(float(retry_interval_sec))

    return {
        "found": False,
        "subject": "",
        "date": "",
        "timestamp_utc": 0.0,
        "highlights": [],
        "sections": {
            "ops_cicd_sla": [],
            "ai_dev_radar": [],
            "competitive_security": [],
            "youtube_newsletters": [],
            "deadlines_checklist": [],
            "ziva_and_brittany": [],
            "critic_audit": [],
            "personal_delta": [],
            "ai_news": [],
            "youtube_digest": [],
            "deprecations": [],
        },
        "extracted_urls": [],
        "ingestion_status": "missing_after_backoff",
        "attempts": 1 if last_status == "unconfigured" else retries + 1,
        "warning_banner": "[WARN] Gemini Master Briefing not yet received",
        "gmail_status": last_status,
        "stale_candidate": stale_candidate,
    }


def query_post_briefing_email_delta(
    since_ts: Optional[float] = None,
    client: Optional[Any] = None,
    limit: int = 15,
    imap_fetcher: Optional[Callable[..., Tuple[List[Any], str]]] = None,
) -> Dict[str, Any]:
    """Scans Orbit/CI-CD, Orbit/VDP, and Work labels for high-priority messages after the Gemini briefing timestamp."""
    empty_result: Dict[str, Any] = {
        "status": "unconfigured",
        "since_ts": since_ts or 0.0,
        "ci_cd_all": [],
        "ci_cd_delta": [],
        "vdp_all": [],
        "vdp_delta": [],
        "work_delta": [],
        "work_recent": [],
        "total_delta_count": 0,
    }
    fetcher = imap_fetcher or _fetch_imap_messages

    def _fetch_label(raw_q: str) -> Tuple[List[Any], str]:
        xgm = _build_xgm_raw_query(raw_q)
        if client is not None:
            try:
                return list(client.fetch_messages(folder="[Gmail]/All Mail", query=xgm, limit=limit) or []), "connected"
            except Exception as exc:
                return [], f"error: {exc}"
        return fetcher(folder="[Gmail]/All Mail", query=xgm, limit=limit)

    ci_msgs, ci_status = _fetch_label(DELTA_GMAIL_QUERIES["ci_cd"])
    if ci_status == "unconfigured":
        return empty_result
    vdp_msgs, _ = _fetch_label(DELTA_GMAIL_QUERIES["vdp"])
    work_msgs, _ = _fetch_label(DELTA_GMAIL_QUERIES["work"])

    cutoff_ts = float(since_ts or 0.0)
    now_utc = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def _format_entry(msg: Any, bucket: str) -> Dict[str, Any]:
        subj = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
        sender = _clean_single_line(str(_msg_field(msg, "sender", "") or ""))
        dt = _parse_msg_datetime(_msg_field(msg, "date"))
        ts = float(dt.timestamp()) if dt else 0.0
        denver_str = dt.astimezone(_get_denver_tz()).strftime("%Y-%m-%d %H:%M %Z") if dt else ""
        age_hours = round(max(0.0, (now_utc - ts) / 3600.0), 1) if ts > 0 else 0.0
        entry: Dict[str, Any] = {
            "bucket": bucket,
            "subject": subj,
            "sender": sender,
            "date": denver_str,
            "timestamp_utc": ts,
            "age_hours": age_hours,
            "is_after_briefing": bool(ts > cutoff_ts) if cutoff_ts > 0.0 else True,
            "labels": sorted(str(l) for l in (_msg_field(msg, "labels", set()) or set())),
        }
        ci_m = _GH_CI_SUBJECT_RE.match(subj)
        if ci_m:
            entry["repo"] = ci_m.group("repo").strip()
            entry["workflow"] = ci_m.group("workflow").strip()
            entry["branch"] = ci_m.group("branch").strip()
            entry["sha"] = ci_m.group("sha").strip()
        return entry

    ci_all = [_format_entry(m, "ci_cd") for m in ci_msgs]
    ci_all.sort(key=lambda e: e["timestamp_utc"], reverse=True)
    ci_delta = [e for e in ci_all if e["is_after_briefing"]]

    vdp_all = []
    seen_vdp = set()
    for m in sorted(
        vdp_msgs,
        key=lambda x: (
            _parse_msg_datetime(_msg_field(x, "date"))
            or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        ).timestamp(),
        reverse=True,
    ):
        entry = _format_entry(m, "vdp")
        if "your profile was recently changed" in entry["subject"].lower():
            continue
        tkey = _normalize_thread_key(entry["subject"])
        if tkey in seen_vdp:
            continue
        seen_vdp.add(tkey)
        vdp_all.append(entry)
    vdp_delta = [e for e in vdp_all if e["is_after_briefing"]]

    seen_ci_vdp_keys = {_normalize_thread_key(e["subject"]) for e in (*ci_all, *vdp_all)}
    work_recent: List[Dict[str, Any]] = []
    for m in work_msgs:
        entry = _format_entry(m, "work")
        s_low = entry["subject"].lower()
        if s_low.startswith(_MASTER_BRIEFING_PREFIX) or "orbit security daily operational briefing" in s_low:
            continue
        if _normalize_thread_key(entry["subject"]) in seen_ci_vdp_keys:
            continue
        work_recent.append(entry)
    work_recent.sort(key=lambda e: e["timestamp_utc"], reverse=True)
    work_delta = [e for e in work_recent if e["is_after_briefing"]]

    return {
        "status": "connected",
        "since_ts": cutoff_ts,
        "ci_cd_all": ci_all,
        "ci_cd_delta": ci_delta,
        "vdp_all": vdp_all,
        "vdp_delta": vdp_delta,
        "work_delta": work_delta,
        "work_recent": work_recent[:8],
        "total_delta_count": len(ci_delta) + len(vdp_delta) + len(work_delta),
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

    if is_automated_sender and is_automated_alert_body:
        return True

    return False


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
    *,
    credentials_loader: Optional[Callable[[], Tuple[str, str]]] = None,
    imap_cls: Any = None,
) -> List[Dict[str, Any]]:
    """Fetches headers-only from [Gmail]/Sent Mail (readonly, no body download or \\Seen mutation)."""
    loader = credentials_loader or _load_imap_credentials
    imap_user, imap_pass = loader()
    if not imap_pass or limit <= 0:
        return []

    imap_factory = imap_cls or imaplib.IMAP4_SSL
    conn: Any = None
    try:
        conn = imap_factory("imap.gmail.com", 993, timeout=timeout)
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

    if classifier is None:
        promo_re = re.compile(
            r"\b(flash sale|%\s*off|limited time|promo|deals?@|discount|special offer)\b",
            re.IGNORECASE,
        )
        for idx, msg in enumerate(coerced):
            msg_id = str(_msg_field(msg, "id", f"msg-{idx}") or f"msg-{idx}")
            is_starred = bool(_msg_field(msg, "is_starred", False))
            is_read = bool(_msg_field(msg, "is_read", False))
            is_in_inbox = bool(_msg_field(msg, "is_in_inbox", True))
            subject = _clean_single_line(str(_msg_field(msg, "subject", "") or ""))
            sender = str(_msg_field(msg, "sender", "") or "")
            body_preview = str(_msg_field(msg, "body_text", "") or _msg_field(msg, "snippet", "") or "")[:500]
            combined = f"{subject} {sender} {body_preview}"
            dt = _parse_msg_datetime(_msg_field(msg, "date"))
            age_days = ((ref_ts - dt.timestamp()) / 86400.0) if dt is not None else 0.0

            has_unsub = bool(_msg_field(msg, "list_unsubscribe") or _msg_field(msg, "list_id"))
            if has_unsub:
                unsubscribed_count += 1

            if is_starred:
                continue

            if not _FINANCIAL_OR_LEGAL_GUARD_RE.search(combined) and age_days >= 7.0 and promo_re.search(combined):
                trashed_count += 1
                triage_flagged_ids.add(msg_id)
                continue

            if is_read and is_in_inbox and age_days >= 30.0:
                archived_count += 1
                triage_flagged_ids.add(msg_id)

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


def _msg_epoch_ts(msg: Any) -> float:
    """Converts EmailMessage.date into a UTC epoch float safely."""
    dt = getattr(msg, "date", None)
    if dt is None:
        return 0.0
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    except Exception:
        return 0.0


def _is_self_briefing_or_ci(subject: str, sender: str = "") -> Tuple[bool, bool]:
    """Returns (is_self_briefing, is_ci_alert)."""
    subj_low = _clean_subject(subject).lower()
    comb_low = f"{subj_low} {sender.lower()}"
    is_self = (
        "orbit security daily operational briefing" in subj_low
        or "google ai daily briefing" in subj_low
    )
    is_ci = any(k in comb_low for k in ("orbit-security", "cmfh009", "run failed"))
    return is_self, is_ci


def _parse_any_ts(val: Any) -> float:
    """Parses datetime/epoch/ISO/YYYY-MM-DD HH:MM values into UTC epoch seconds."""
    if val is None or val == "":
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, datetime.datetime):
        dt = val if val.tzinfo else val.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    text = str(val).strip()
    if not text:
        return 0.0
    try:
        dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return float(dt.timestamp())
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(text[:19], fmt).replace(tzinfo=datetime.timezone.utc)
            return float(dt.timestamp())
        except ValueError:
            continue
    return 0.0


def _detect_outbound_reply_reason(
    *,
    subject: str,
    sender: str,
    msg_ts: float,
    outbound_by_thread: Dict[str, float],
    norm_sent_ts: Dict[str, float],
    norm_sent_subjects: set[str],
    master_briefing: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Returns a status reason if an urgent inbound thread already has a newer outbound reply/confirmation."""
    t_key = _normalize_thread_key(subject)
    if t_key in outbound_by_thread and outbound_by_thread[t_key] > msg_ts:
        return "outbound reply in thread"
    if t_key in norm_sent_ts:
        if msg_ts == 0.0 or norm_sent_ts[t_key] > msg_ts:
            return "outbound reply in Sent"
    elif t_key in norm_sent_subjects:
        return "outbound reply in Sent"

    if not isinstance(master_briefing, dict) or not master_briefing.get("found", True):
        return None
    highlights = [str(h).strip() for h in (master_briefing.get("highlights") or []) if str(h).strip()]
    if not highlights:
        return None

    mb_ts = _parse_any_ts(master_briefing.get("date"))
    if msg_ts > 0.0 and mb_ts > 0.0 and mb_ts < msg_ts:
        return None

    sender_low = str(sender or "").lower()
    domain_root = ""
    if "@" in sender_low:
        dom = sender_low.rsplit("@", 1)[-1].strip("<> ")
        domain_root = dom.split(".")[0] if dom else ""

    topic_tokens = {
        tok
        for tok in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", t_key)
        if len(tok) >= 4 and tok not in _TOPIC_STOPWORDS
    }

    for hl in highlights:
        if not _OUTBOUND_ACTION_CUE_RE.search(hl):
            continue
        embedded_dt_match = _ISO_OR_DT_IN_TEXT_RE.search(hl)
        if embedded_dt_match and msg_ts > 0.0:
            hl_ts = _parse_any_ts(embedded_dt_match.group(1))
            if hl_ts > 0.0 and hl_ts <= msg_ts:
                continue

        hl_low = hl.lower()
        hl_words = {
            w
            for w in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", hl_low)
            if len(w) >= 4 and w not in _TOPIC_STOPWORDS
        }
        brand_match = bool(
            domain_root
            and len(domain_root) >= 4
            and (
                domain_root in hl_words
                or any(domain_root.startswith(w) or w.startswith(domain_root) for w in hl_words)
            )
        )
        topic_overlap = topic_tokens & hl_words
        if brand_match or len(topic_overlap) >= 2:
            return "confirmed in Master Briefing"

    return None


def triage_email_messages(
    messages: List[Any],
    digest: Any,
    now_ts: Optional[float] = None,
    *,
    owner_email: str = "carsonmail009@gmail.com",
    sent_replied_subjects: Optional[Sequence[str]] = None,
    sent_replied_timestamps: Optional[Dict[str, Any]] = None,
    master_briefing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Filters, deduplicates, and sorts email digest signals into actionable today vs awaiting/historical buckets."""
    ref_ts = float(now_ts if now_ts is not None else datetime.datetime.now(datetime.timezone.utc).timestamp())
    msg_by_id = {getattr(m, "id", None): m for m in messages}
    owner_low = (owner_email or "carsonmail009@gmail.com").strip().lower()

    outbound_by_thread: Dict[str, float] = {}
    for m in messages:
        m_sender = str(getattr(m, "sender", "") or "").lower()
        m_labels = {str(lbl).lower() for lbl in (getattr(m, "labels", None) or ())}
        m_subj = _clean_subject(getattr(m, "subject", ""))
        is_self_briefing, _ = _is_self_briefing_or_ci(m_subj, m_sender)
        if is_self_briefing or m_subj.lower().startswith(_MASTER_BRIEFING_PREFIX):
            continue
        is_outbound = (owner_low and owner_low in m_sender) or ("sent" in m_labels)
        if not is_outbound:
            continue
        m_key = _normalize_thread_key(m_subj)
        m_ts = _msg_epoch_ts(m)
        if m_key and m_ts > outbound_by_thread.get(m_key, -1.0):
            outbound_by_thread[m_key] = m_ts

    norm_sent_ts: Dict[str, float] = {}
    for raw_subj, raw_ts in (sent_replied_timestamps or {}).items():
        n_key = _normalize_thread_key(str(raw_subj))
        parsed = _parse_any_ts(raw_ts)
        if n_key and parsed > norm_sent_ts.get(n_key, -1.0):
            norm_sent_ts[n_key] = parsed

    norm_sent_subjects = {
        _normalize_thread_key(str(s))
        for s in (sent_replied_subjects or ())
        if _normalize_thread_key(str(s))
    }

    ci_alerts = [
        sanitize_inbound_text(_clean_subject(w.subject), max_chars=500)
        for w in getattr(digest, "work_items", [])
        if any(k in f"{w.subject} {w.sender}".lower() for k in ("orbit-security", "cmfh009", "run failed", "secrets", "ci"))
    ]
    deal_threads = [
        sanitize_inbound_text(_clean_subject(d.subject), max_chars=500)
        for d in getattr(digest, "work_items", [])
        if any(k in f"{d.subject} {d.sender}".lower() for k in ("stripe", "lead", "pricing", "inquiry", "deal", "client", "revenue"))
    ]

    raw_urgent = list(getattr(digest, "urgent_items", []))
    raw_urgent.sort(key=lambda u: _msg_epoch_ts(msg_by_id.get(u.message_id)), reverse=True)

    seen_threads: set[str] = set()
    urgent_today: List[str] = []
    awaiting_external_reply: List[str] = []
    historical_urgent: List[str] = []

    for item in raw_urgent:
        subj = sanitize_inbound_text(_clean_subject(item.subject), max_chars=500)
        item_sender = sanitize_inbound_text(item.sender, max_chars=300)
        is_self, is_ci = _is_self_briefing_or_ci(subj, item_sender)
        if is_self or is_ci:
            continue
        if owner_low and owner_low in item_sender.lower():
            continue
        t_key = _normalize_thread_key(subj)
        if t_key in seen_threads:
            continue
        seen_threads.add(t_key)

        msg = msg_by_id.get(item.message_id)
        is_unread = not bool(getattr(msg, "is_read", True)) if msg is not None else False
        ts = _msg_epoch_ts(msg)
        is_recent_24h = ts > 0.0 and (ref_ts - ts) <= 86400.0
        formatted = f"{subj} — {item_sender} ({item.date_str})"

        if is_unread or is_recent_24h:
            reply_reason = None
            if owner_low not in item_sender.lower():
                reply_reason = _detect_outbound_reply_reason(
                    subject=subj,
                    sender=item_sender,
                    msg_ts=ts,
                    outbound_by_thread=outbound_by_thread,
                    norm_sent_ts=norm_sent_ts,
                    norm_sent_subjects=norm_sent_subjects,
                    master_briefing=master_briefing,
                )
            if reply_reason:
                awaiting_external_reply.append(f"{formatted} [{reply_reason}]")
            else:
                urgent_today.append(formatted)
        else:
            historical_urgent.append(formatted)

    unread_msgs = [m for m in messages if not getattr(m, "is_read", True)]
    unread_msgs.sort(key=_msg_epoch_ts, reverse=True)
    unread_non_ci: List[str] = []
    for m in unread_msgs:
        subj = sanitize_inbound_text(_clean_subject(getattr(m, "subject", "")), max_chars=500)
        sender = sanitize_inbound_text(str(getattr(m, "sender", "")), max_chars=300)
        is_self, is_ci = _is_self_briefing_or_ci(subj, sender)
        if is_self or is_ci:
            continue
        unread_non_ci.append(f"{subj} ({sender})")

    total_fin = sum((getattr(digest, "financial_totals", {}) or {}).values())

    return {
        "status": "connected",
        "scanned": getattr(digest, "total_scanned", len(messages)),
        "unread": getattr(digest, "unread_count", len(unread_msgs)),
        "unread_non_ci_count": len(unread_non_ci),
        "unread_list": unread_non_ci[:5],
        "urgent": len(urgent_today),
        "urgent_list": urgent_today[:5],
        "awaiting_external_reply_count": len(awaiting_external_reply),
        "awaiting_external_reply": awaiting_external_reply[:5],
        "historical_alerts_count": len(historical_urgent),
        "historical_alerts_sample": historical_urgent[:3],
        "ci_alerts": ci_alerts,
        "deal_threads": deal_threads,
        "total_financial_amount": total_fin,
        "financial_currency": "USD",
        "hygiene": getattr(digest, "hygiene_stats", {}),
    }


def query_live_email_telemetry(
    max_retries: int = 0,
    retry_interval_sec: float = 300.0,
    target_date: Optional[datetime.date] = None,
) -> Dict[str, Any]:
    """Connects to email-organizer, polls Gemini Master Briefing with backoff, runs delta scan, and extracts telemetry."""
    try:
        _ensure_email_organizer_on_path()
        from email_organizer.client import IMAPEmailClient
        from email_organizer.classifier import EmailClassifier
        from email_organizer.digest import MorningDigestGenerator
        from email_organizer.ledger import SenderLedger
        from email_organizer.models import OrganizerConfig

        imap_user, imap_pass = _load_imap_credentials()
        if not imap_pass:
            return {
                "status": "unconfigured",
                "scanned": 0,
                "unread": 0,
                "unread_non_ci_count": 0,
                "unread_list": [],
                "ci_alerts": [],
                "deal_threads": [],
                "urgent": 0,
                "urgent_list": [],
                "historical_alerts_count": 0,
                "post_briefing_delta": {},
            }

        polled_master: Optional[Dict[str, Any]] = None
        try:
            polled_master = poll_gemini_master_briefing_with_backoff(
                target_date=target_date,
                max_retries=max_retries,
                retry_interval_sec=retry_interval_sec,
            )
        except Exception:
            polled_master = None

        client = IMAPEmailClient(
            host="imap.gmail.com",
            port=993,
            user=imap_user,
            password=imap_pass,
        )
        client.connect()
        try:
            messages = client.fetch_messages(folder="INBOX", limit=50)
        finally:
            client.disconnect()

        db_path = None
        for cand in _email_organizer_candidates():
            p = cand / "email_organizer.db"
            if p.is_file():
                db_path = str(p)
                break
        ledger = SenderLedger(db_path) if db_path else None
        config = OrganizerConfig()
        classifier = EmailClassifier(config=config, ledger=ledger)
        generator = MorningDigestGenerator(classifier=classifier, ledger=ledger)

        digest = generator.generate(messages=messages)
        hygiene_res: Dict[str, Any] = {}
        try:
            hygiene_res = query_email_hygiene(messages=messages) or {}
        except Exception:
            hygiene_res = {}

        if isinstance(polled_master, dict):
            hygiene_res["master_briefing"] = polled_master

        effective_master = hygiene_res.get("master_briefing")
        since_ts = (
            effective_master.get("timestamp_utc")
            if isinstance(effective_master, dict) and effective_master.get("found")
            else None
        )
        post_delta: Dict[str, Any] = {}
        try:
            post_delta = query_post_briefing_email_delta(since_ts=since_ts)
        except Exception:
            post_delta = {}

        result = triage_email_messages(
            messages=messages,
            digest=digest,
            owner_email=imap_user,
            sent_replied_subjects=hygiene_res.get("sent_replied_subjects"),
            sent_replied_timestamps=hygiene_res.get("sent_replied_timestamps"),
            master_briefing=effective_master,
        )
        result["email_hygiene"] = hygiene_res
        result["post_briefing_delta"] = post_delta
        return sanitize_email_data(result)
    except Exception as exc:
        return {
            "status": f"error: {exc}",
            "scanned": 0,
            "unread": 0,
            "unread_non_ci_count": 0,
            "unread_list": [],
            "ci_alerts": [],
            "deal_threads": [],
            "urgent": 0,
            "urgent_list": [],
            "historical_alerts_count": 0,
            "post_briefing_delta": {},
        }


def archive_superseded_ci_alerts_in_imap(live_ci: Dict[str, Any]) -> int:
    """Marks superseded GitHub Actions failure emails as read, labels Orbit/CI-CD, and archives from INBOX when HEAD is all_green."""
    if not live_ci.get("all_green"):
        return 0

    try:
        imap_user, imap_pass = _load_imap_credentials()
        if not imap_pass:
            return 0

        conn = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        conn.login(imap_user, imap_pass)
        conn.select("INBOX")
        status, data = conn.search(None, 'SUBJECT "Run failed"')
        if status != "OK" or not data or not data[0]:
            conn.logout()
            return 0

        msg_ids = data[0].split()
        archived_count = 0
        try:
            conn.create('"Orbit/CI-CD"')
        except Exception:
            pass

        for mid in msg_ids:
            try:
                conn.store(mid, "+X-GM-LABELS", '("Orbit/CI-CD")')
            except Exception:
                pass
            conn.store(mid, "+FLAGS", r"(\Seen \Deleted)")
            archived_count += 1

        if archived_count > 0:
            conn.expunge()
        conn.close()
        conn.logout()
        return archived_count
    except Exception:
        return 0


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
    *,
    imap_fetcher: Optional[Callable[..., Tuple[List[Any], str]]] = None,
    url_opener: Optional[Callable[..., Any]] = None,
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
    opener = url_opener or urllib.request.urlopen
    fetcher = imap_fetcher or _fetch_imap_messages

    if has_http_url:
        try:
            req = urllib.request.Request(str(resolved_url), headers={"User-Agent": "OrbitBriefing/1.0"})
            with opener(req, timeout=5) as resp:
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

    should_run_fallback = (has_http_url and vevent_count == 0) or (messages is not None and vevent_count == 0)
    if should_run_fallback:
        invite_msgs: List[Any] = []
        fallback_scan_ok = False
        if messages is not None:
            invite_msgs = list(messages)
            fallback_scan_ok = True
        else:
            fetched_msgs, fetch_status = fetcher(
                folder="INBOX",
                query='OR SUBJECT "Invitation" TEXT ".ics"',
                limit=limit,
            )
            if fetch_status == "connected":
                invite_msgs = fetched_msgs
                fallback_scan_ok = True
            elif fetch_status.startswith("error:"):
                fetched_msgs, fetch_status2 = fetcher(folder="INBOX", query=None, limit=min(limit, 15))
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
    *,
    imap_fetcher: Optional[Callable[..., Tuple[List[Any], str]]] = None,
    url_opener: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Extracts today's and this week's events, birthdays, and tasks from Google Workspace."""
    return query_google_calendar(
        ical_url=ical_url,
        messages=messages,
        limit=limit,
        imap_fetcher=imap_fetcher,
        url_opener=url_opener,
    )
