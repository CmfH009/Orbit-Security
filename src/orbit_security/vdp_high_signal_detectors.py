"""orbit_security.vdp_high_signal_detectors: High-signal non-destructive VDP detectors.

Provides strict, self-proving checks designed to earn Triaged/Resolved Signal on
HackerOne VDPs while rejecting HTML/SPA fallback pages, benign macOS metadata,
static public web assets, and public client-side tokens.
"""

from __future__ import annotations

import html as html_lib
import ipaddress
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import urllib.parse

EXTENDED_SENSITIVE_PATHS: Tuple[str, ...] = (
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/server-status",
    "/actuator/mappings",
    "/actuator/beans",
)

_HTML_LOOKALIKE_RE = re.compile(r"^\s*(?:<!doctype|<html|<head|<body|<script)", re.IGNORECASE)
_HTML_TAG_RE = re.compile(
    r"<(?:!doctype|/?(?:html|head|body|script|style|div|span|p|a|h[1-6]|title|meta|link|ul|li|table|tr|td|th|form|input))(?:\s|>|/)",
    re.IGNORECASE,
)

_URL_CREDENTIALS_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^:/@\s]+):([^@\s]+)@", re.IGNORECASE)
_IP_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_:])"
    r"(?:\[(?P<v6b>[0-9A-Fa-f:]+(?:%\w+)?)\]"
    r"|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})"
    r"|(?P<v6>[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*))"
    r"(?![A-Za-z0-9_.])"
)

_SVN_VERSION_RE = re.compile(r"^(?:8|9|10|11|12)\n")
_SVN_DIR_RE = re.compile(r"(?:^|\n)dir(?:\n|$)")
_SVN_REPO_URL_RE = re.compile(r"(?:svn(?:\+ssh)?|https?|file)://[^\s]+", re.IGNORECASE)

_DS_STORE_SENSITIVE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\.env", re.IGNORECASE),
    re.compile(r"\.bak", re.IGNORECASE),
    re.compile(r"\.sql", re.IGNORECASE),
    re.compile(r"config", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"admin", re.IGNORECASE),
    re.compile(r"backup", re.IGNORECASE),
    re.compile(r"(?<![a-z])key", re.IGNORECASE),
    re.compile(r"dump", re.IGNORECASE),
)

_STATIC_PUBLIC_ASSET_EXTS: Tuple[str, ...] = (
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".map",
)

_STATIC_PUBLIC_FILENAMES: Tuple[str, ...] = (
    "robots.txt",
    "favicon.ico",
    "sitemap.xml",
)

_SENSITIVE_BUCKET_KEY_RE = re.compile(
    r"(?:\.(?:sql|bak|tar|gz|zip|pem|key|env|log)(?:$|\?)"
    r"|(?:^|[/._-])(?:backup|backups|dump|dumps|secret|secrets|private|internal"
    r"|credential|credentials|password|passwords|token|tokens|invoice|invoices"
    r"|billing|customer|customers|employee|employees|user|users|export|exports"
    r"|audit|config|logs?)(?:$|[/._-]))",
    re.IGNORECASE,
)

# Cloud URL extraction patterns (host suffix anchored to reject lookalike domains like .s3.amazonaws.com.evil.com)
_S3_VHOST_RE = re.compile(
    r"https?://(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-](?P<region>[a-z0-9-]+))?\.amazonaws\.com(?=[/?#]|$|[\s\"'<>`\\),;])(?:[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)
_S3_PATH_RE = re.compile(
    r"https?://s3(?:[.-](?P<region>[a-z0-9-]+))?\.amazonaws\.com/(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?=[/?#]|$|[\s\"'<>`\\),;])(?:[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)
_GCS_PATH_RE = re.compile(
    r"https?://storage\.googleapis\.com/(?P<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?=[/?#]|$|[\s\"'<>`\\),;])(?P<rest>[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)
_GCS_VHOST_RE = re.compile(
    r"https?://(?P<bucket>[a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com(?=[/?#]|$|[\s\"'<>`\\),;])(?:[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)
_AZURE_BLOB_RE = re.compile(
    r"https?://(?P<account>[a-z0-9]{3,24})\.blob\.core\.windows\.net/(?P<container>[a-z0-9$][a-z0-9-]{2,62})(?=[/?#]|$|[\s\"'<>`\\),;])(?:[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)
_FIREBASE_RTDB_RE = re.compile(
    r"https?://(?P<project>[a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.firebaseio\.com(?=[/?#]|$|[\s\"'<>`\\),;])(?:[/?#][^\s\"'<>`\\)]*)?",
    re.IGNORECASE,
)

_TRAILING_URL_PUNCT = ".,;:!?\"'\\`)>]}"

# High-confidence secret patterns (strictly excludes public keys, sitekeys, AIza, and UUIDs)
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])")
_AWS_SECRET_ASSIGN_RE = re.compile(
    r"(?:aws_secret(?:_access_key|_key)?|secretAccessKey|secret_access_key)['\"`]?\s*[:=]\s*['\"`]?[^\s'\",;}{)\]]{4,}",
    re.IGNORECASE,
)
_STRIPE_LIVE_SECRET_RE = re.compile(r"(?<![A-Za-z0-9_])sk_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9_])")
_GITHUB_PAT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![A-Za-z0-9_])"
)
_SENDGRID_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"
)
_SLACK_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9-])xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]{20,}(?![A-Za-z0-9-])"
)
_SLACK_WEBHOOK_RE = re.compile(
    r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"
)

_SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*\ssrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>`]+))""",
    re.IGNORECASE,
)


def _redact_url_credentials(text: str) -> str:
    """Redact user:pass@ credentials embedded in remote repository or service URLs."""
    return _URL_CREDENTIALS_RE.sub(r"\1<REDACTED>:<REDACTED>@", text)


def _redact_ip_addresses(text: str) -> str:
    """Redact validated IPv4 and IPv6 addresses while leaving version numbers and timestamps intact."""

    def _replace(match: re.Match[str]) -> str:
        bracketed = match.group("v6b")
        candidate = bracketed or match.group("v4") or match.group("v6") or ""
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return match.group(0)
        return "[<REDACTED_IP>]" if bracketed else "<REDACTED_IP>"

    return _IP_CANDIDATE_RE.sub(_replace, text)


def _redact_secret_middle(secret: str, *, prefix_len: int = 8, suffix_len: int = 4) -> str:
    """Mask the middle portion of a credential string so raw secrets are never stored."""
    if len(secret) <= prefix_len + suffix_len + 2:
        return "<REDACTED>"
    return f"{secret[:prefix_len]}<REDACTED>{secret[-suffix_len:]}"


def _build_git_config_snippet(redacted_body: str, max_len: int = 500) -> str:
    """Extract a bounded snippet preserving both [core] and [remote] / url lines."""
    lines = [line.rstrip() for line in redacted_body.splitlines() if line.strip()]
    joined = "\n".join(lines)
    if len(joined) <= max_len:
        return joined

    selected: List[str] = []
    for line in lines:
        low = line.strip().lower()
        if low.startswith(("[core]", "repositoryformatversion", "[remote ", "url =", "url=")):
            selected.append(line)
    compact = "\n".join(selected) if selected else joined
    return compact[:max_len]


def _check_git_config(path: str, body: str) -> Optional[Dict[str, Any]]:
    if _HTML_TAG_RE.search(body[:500]):
        return None
    body_low = body.lower()
    if "[core]" not in body_low:
        return None
    if "repositoryformatversion" not in body_low and "[remote " not in body_low:
        return None
    redacted = _redact_url_credentials(body)
    return {
        "path": path,
        "finding_type": "exposed_git",
        "severity": "medium",
        "snippet": _build_git_config_snippet(redacted),
    }


def _check_svn_entries(path: str, body: str) -> Optional[Dict[str, Any]]:
    if _HTML_TAG_RE.search(body):
        return None
    norm = body.replace("\r\n", "\n").lstrip("\r\n")
    if not _SVN_VERSION_RE.match(norm):
        return None
    if not (_SVN_DIR_RE.search(norm) or _SVN_REPO_URL_RE.search(norm)):
        return None
    redacted = _redact_url_credentials(norm)
    lines = [line.strip() for line in redacted.splitlines() if line.strip()][:8]
    return {
        "path": path,
        "finding_type": "exposed_svn",
        "severity": "medium",
        "snippet": " | ".join(lines)[:300],
    }


def _check_ds_store(path: str, body: str) -> Optional[Dict[str, Any]]:
    if _HTML_TAG_RE.search(body[:500]):
        return None
    if "Bud1" not in body[:32]:
        return None
    searchable_low = body.replace("\x00", "").lower()
    matched = [m.group(0) for pat in _DS_STORE_SENSITIVE_PATTERNS if (m := pat.search(searchable_low)) is not None]
    if not matched:
        return None
    return {
        "path": path,
        "finding_type": "exposed_ds_store",
        "severity": "medium",
        "snippet": f"DS_Store (Bud1) exposed sensitive filename tokens={matched[:6]}",
    }


def _strip_status_html_to_lines(body: str) -> List[str]:
    """Convert Apache mod_status HTML into clean structured text lines."""
    text = re.sub(r"</(?:tr|dt|dd|h[1-6]|p|div|li|br\s*/?)>", "\n", body, flags=re.IGNORECASE)
    text = re.sub(r"</(?:td|th)>", " | ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    lines: List[str] = []
    for raw in text.splitlines():
        cleaned = re.sub(r"\s+", " ", raw).strip(" |")
        if cleaned:
            lines.append(cleaned)
    return lines


def _check_server_status(path: str, body: str) -> Optional[Dict[str, Any]]:
    body_low = body.lower()
    if "apache server status for" not in body_low:
        return None
    if "total accesses:" not in body_low and "scoreboard:" not in body_low:
        return None
    if not (
        re.search(r"\bclient\b", body_low)
        and re.search(r"\bvhost\b", body_low)
        and re.search(r"\brequest\b", body_low)
    ):
        return None

    lines = _strip_status_html_to_lines(body)
    chosen: List[str] = []
    table_started = False
    table_rows_captured = 0
    for line in lines:
        low = line.lower()
        if "apache server status for" in low or "total accesses:" in low or "scoreboard:" in low:
            chosen.append(line)
        elif not table_started and "client" in low and "vhost" in low and "request" in low:
            table_started = True
            chosen.append(line)
        elif table_started and table_rows_captured < 3:
            chosen.append(line)
            table_rows_captured += 1

    snippet_raw = " ; ".join(chosen) if chosen else " ".join(lines[:6])
    snippet_redacted = _redact_ip_addresses(snippet_raw)
    return {
        "path": path,
        "finding_type": "exposed_server_status",
        "severity": "medium",
        "snippet": snippet_redacted[:600],
    }


def _check_actuator_endpoint(path: str, norm_path: str, body: str) -> Optional[Dict[str, Any]]:
    if _HTML_TAG_RE.search(body[:300]):
        return None
    trimmed = body.strip()
    if not trimmed.startswith("{"):
        return None
    try:
        parsed = json.loads(trimmed)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    contexts = parsed.get("contexts")
    if not isinstance(contexts, dict) or not contexts:
        return None

    expected_key = "mappings" if norm_path.endswith("/mappings") else "beans"
    has_definitions = any(
        isinstance(ctx, dict)
        and isinstance(ctx.get(expected_key), (dict, list))
        and len(ctx[expected_key]) >= 1
        for ctx in contexts.values()
    )
    if not has_definitions:
        return None

    return {
        "path": path,
        "finding_type": "exposed_actuator",
        "severity": "medium",
        "snippet": f"Spring Actuator {norm_path} contexts={list(contexts.keys())[:4]} (len={len(trimmed)})",
    }


def check_extended_sensitive_exposures(path: str, status: int, body: str) -> Optional[Dict[str, Any]]:
    """Detect high-signal exposed VCS, DS_Store, Apache status, and Spring Actuator endpoints."""
    if status != 200 or not isinstance(body, str) or not body.strip():
        return None

    norm_path = (path or "").split("?", 1)[0].strip()
    norm_low = norm_path.lower()

    if norm_low != "/server-status" and _HTML_LOOKALIKE_RE.match(body):
        return None

    if norm_low == "/.git/config":
        return _check_git_config(path, body)
    if norm_low == "/.svn/entries":
        return _check_svn_entries(path, body)
    if norm_low == "/.ds_store":
        return _check_ds_store(path, body)
    if norm_low == "/server-status":
        return _check_server_status(path, body)
    if norm_low in ("/actuator/mappings", "/actuator/beans"):
        return _check_actuator_endpoint(path, norm_low, body)
    return None


def _clean_source_url(raw_url: str) -> str:
    return raw_url.strip().rstrip(_TRAILING_URL_PUNCT)


def extract_cloud_urls_from_text(text: str) -> List[Dict[str, str]]:
    """Extract unique referenced S3, GCS, Azure Blob, and Firebase RTDB URLs from text."""
    if not isinstance(text, str) or not text.strip():
        return []

    normalized = text.replace("\\/", "/")
    candidates: List[Tuple[int, Dict[str, str]]] = []

    for match in _S3_VHOST_RE.finditer(normalized):
        bucket = match.group("bucket").lower()
        region = (match.group("region") or "").lower()
        if bucket == "s3" or region == "website" or ".s3-website" in match.group(0).lower():
            continue
        probe_host = f"{bucket}.s3.{region}.amazonaws.com" if region else f"{bucket}.s3.amazonaws.com"
        candidates.append(
            (
                match.start(),
                {
                    "provider": "AWS S3",
                    "bucket_or_project": bucket,
                    "probe_url": f"https://{probe_host}/",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    for match in _S3_PATH_RE.finditer(normalized):
        bucket = match.group("bucket").lower()
        region = (match.group("region") or "").lower()
        probe_host = f"s3.{region}.amazonaws.com" if region else "s3.amazonaws.com"
        candidates.append(
            (
                match.start(),
                {
                    "provider": "AWS S3",
                    "bucket_or_project": bucket,
                    "probe_url": f"https://{probe_host}/{bucket}/",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    for match in _GCS_PATH_RE.finditer(normalized):
        bucket = match.group("bucket").lower()
        rest = (match.group("rest") or "").lower()
        if bucket in {"storage", "upload", "download", "batch"} and (
            rest.startswith("/v1") or rest.startswith("/storage/v1")
        ):
            continue
        candidates.append(
            (
                match.start(),
                {
                    "provider": "Google Cloud Storage",
                    "bucket_or_project": bucket,
                    "probe_url": f"https://storage.googleapis.com/{bucket}/",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    for match in _GCS_VHOST_RE.finditer(normalized):
        bucket = match.group("bucket").lower()
        candidates.append(
            (
                match.start(),
                {
                    "provider": "Google Cloud Storage",
                    "bucket_or_project": bucket,
                    "probe_url": f"https://storage.googleapis.com/{bucket}/",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    for match in _AZURE_BLOB_RE.finditer(normalized):
        account = match.group("account").lower()
        container = match.group("container").lower()
        candidates.append(
            (
                match.start(),
                {
                    "provider": "Azure Blob Storage",
                    "bucket_or_project": f"{account}/{container}",
                    "probe_url": f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    for match in _FIREBASE_RTDB_RE.finditer(normalized):
        project = match.group("project").lower()
        candidates.append(
            (
                match.start(),
                {
                    "provider": "Firebase Realtime DB",
                    "bucket_or_project": project,
                    "probe_url": f"https://{project}.firebaseio.com/.json?shallow=true",
                    "source_url": _clean_source_url(match.group(0)),
                },
            )
        )

    candidates.sort(key=lambda item: item[0])
    seen: Set[Tuple[str, str]] = set()
    unique: List[Dict[str, str]] = []
    for _, entry in candidates:
        dedup_key = (entry["provider"], entry["bucket_or_project"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        unique.append(entry)
    return unique


def _filter_non_static_bucket_keys(keys: Iterable[str]) -> List[str]:
    """Return keys that are either non-static objects or contain sensitive path tokens."""
    interesting: List[str] = []
    for raw_key in keys:
        key = str(raw_key).strip()
        if not key:
            continue
        key_low = key.lower()
        if _SENSITIVE_BUCKET_KEY_RE.search(key_low):
            interesting.append(key)
            continue
        if key_low.endswith("/"):
            continue
        if key_low.endswith(_STATIC_PUBLIC_ASSET_EXTS) or key_low.endswith(_STATIC_PUBLIC_FILENAMES):
            continue
        interesting.append(key)
    return interesting


def evaluate_cloud_reference_response(
    ref: Dict[str, str],
    status: int,
    body: str,
) -> Optional[Dict[str, Any]]:
    """Evaluate a probed cloud storage or Firebase reference response for high-signal findings."""
    if not isinstance(ref, dict) or status <= 0 or not isinstance(body, str) or not body.strip():
        return None
    if _HTML_LOOKALIKE_RE.match(body) or "<html" in body[:300].lower():
        return None

    provider = str(ref.get("provider") or "")
    provider_low = provider.lower()
    probe_url = str(ref.get("probe_url") or ref.get("source_url") or "")
    probe_low = probe_url.lower()
    bucket_or_project = str(ref.get("bucket_or_project") or "")
    body_low = body.lower()

    is_firebase = (
        "firebase" in provider_low
        or "firebaseio.com" in probe_low
        or "firebasedatabase.app" in probe_low
        or "/.json" in probe_low
    )

    if is_firebase:
        if status != 200:
            return None
        trimmed = body.strip()
        if trimmed == "null" or not trimmed.startswith("{"):
            return None
        try:
            parsed = json.loads(trimmed)
        except (ValueError, TypeError):
            return None
        if not isinstance(parsed, dict) or not parsed:
            return None
        lower_keys = {str(k).lower() for k in parsed.keys()}
        if "error" in lower_keys and lower_keys <= {"error", "status", "message", "code", "detail"}:
            return None
        top_keys = [str(k) for k in list(parsed.keys())[:8]]
        return {
            "provider": provider or "Firebase Realtime DB",
            "bucket_or_project": bucket_or_project,
            "probe_url": probe_url,
            "source_url": str(ref.get("source_url") or ""),
            "finding_type": "exposed_firebase_db",
            "severity": "high",
            "snippet": f"Firebase RTDB {probe_url} exposed top-level keys={top_keys}",
        }

    # Dangling S3 / GCS / Azure unallocated storage check
    if status in (400, 404) and ("<error" in body_low or "<?xml" in body_low or "<code>" in body_low):
        dangling_markers = (
            "nosuchbucket",
            "the specified bucket does not exist",
            "the specified account does not exist",
        )
        matched_marker = next((m for m in dangling_markers if m in body_low), None)
        if matched_marker is not None:
            return {
                "provider": provider or "Cloud Storage",
                "bucket_or_project": bucket_or_project,
                "probe_url": probe_url,
                "source_url": str(ref.get("source_url") or ""),
                "finding_type": "dangling_referenced_bucket",
                "severity": "high",
                "snippet": f"Unallocated referenced bucket ({bucket_or_project}) returned '{matched_marker}' at {probe_url}",
            }

    # Public bucket directory listing check (S3/GCS <ListBucketResult> or Azure <EnumerationResults>)
    if status == 200:
        keys: List[str] = []
        if "<listbucketresult" in body_low:
            keys = re.findall(r"<Key>([^<]+)</Key>", body, re.IGNORECASE)
        elif "<enumerationresults" in body_low:
            keys = re.findall(r"<Blob>.*?<Name>([^<]+)</Name>", body, re.IGNORECASE | re.DOTALL)

        interesting_keys = _filter_non_static_bucket_keys(keys)
        if interesting_keys:
            sample = interesting_keys[:5]
            return {
                "provider": provider or "Cloud Storage",
                "bucket_or_project": bucket_or_project,
                "probe_url": probe_url,
                "source_url": str(ref.get("source_url") or ""),
                "finding_type": "open_bucket",
                "severity": "medium",
                "sample_keys": sample,
                "snippet": f"Open bucket listing ({bucket_or_project}) exposed non-static keys={sample}",
            }

    return None


def evaluate_cors_response(
    url: str,
    tested_origin: str,
    status: int,
    headers: Dict[str, str],
    body: str,
) -> Optional[Dict[str, Any]]:
    """Detect credentialed arbitrary-origin CORS reflection backed by non-empty JSON state."""
    clean_origin = (tested_origin or "").strip()
    if status != 200 or not clean_origin or clean_origin == "*":
        return None
    if not isinstance(headers, dict) or not isinstance(body, str) or not body.strip():
        return None

    lower_headers = {str(k).strip().lower(): str(v).strip() for k, v in headers.items() if k is not None}
    acao = lower_headers.get("access-control-allow-origin", "")
    acac = lower_headers.get("access-control-allow-credentials", "").lower()
    content_type = lower_headers.get("content-type", "").lower()

    if not acao or acao == "*" or acao != clean_origin or acac != "true":
        return None

    if _HTML_LOOKALIKE_RE.match(body) or ("text/html" in content_type and "json" not in content_type):
        return None

    trimmed = body.strip()
    if not trimmed.startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(trimmed)
    except (ValueError, TypeError):
        return None

    if isinstance(parsed, dict):
        if not parsed:
            return None
        json_summary = f"JSON object keys={list(parsed.keys())[:6]}"
    elif isinstance(parsed, list):
        if not parsed:
            return None
        json_summary = f"JSON array len={len(parsed)}"
    else:
        return None

    return {
        "url": url,
        "finding_type": "cors_credentialed_reflection",
        "severity": "medium",
        "tested_origin": clean_origin,
        "snippet": (
            f"Access-Control-Allow-Origin: {acao}; "
            f"Access-Control-Allow-Credentials: true; {json_summary}"
        ),
    }


def scan_text_for_high_confidence_secrets(
    source_url: str,
    status: int,
    body: str,
) -> Optional[Dict[str, Any]]:
    """Scan HTTP 200 text/JS responses for high-confidence server credentials (redacting secrets)."""
    if status != 200 or not isinstance(body, str) or not body.strip():
        return None

    # 1. PEM Private Key
    pem_match = _PEM_PRIVATE_KEY_RE.search(body)
    if pem_match:
        return {
            "source_url": source_url,
            "finding_type": "exposed_js_secret",
            "severity": "high",
            "secret_type": "pem_private_key",
            "snippet": f"PEM Private Key exposed in {source_url}: {pem_match.group(0)} <REDACTED>",
        }

    # 2. AWS Access Key ID paired within 300 chars with a secret assignment
    for aws_match in _AWS_ACCESS_KEY_RE.finditer(body):
        window_start = max(0, aws_match.start() - 300)
        window_end = min(len(body), aws_match.end() + 300)
        if _AWS_SECRET_ASSIGN_RE.search(body[window_start:window_end]):
            redacted = _redact_secret_middle(aws_match.group(0), prefix_len=6, suffix_len=4)
            return {
                "source_url": source_url,
                "finding_type": "exposed_js_secret",
                "severity": "high",
                "secret_type": "aws_access_key",
                "snippet": (
                    f"AWS Access Key ID + secret assignment exposed in {source_url}: "
                    f"{redacted} (secret=<REDACTED>)"
                ),
            }

    # 3. Direct high-confidence token formats
    token_specs: Tuple[Tuple[str, str, re.Pattern[str], int, int], ...] = (
        ("stripe_live_secret", "Stripe Live Secret Key", _STRIPE_LIVE_SECRET_RE, 10, 4),
        ("github_pat", "GitHub Personal Access Token", _GITHUB_PAT_RE, 8, 4),
        ("sendgrid_api_key", "SendGrid API Key", _SENDGRID_KEY_RE, 7, 4),
        ("slack_token", "Slack Token", _SLACK_TOKEN_RE, 9, 4),
        ("slack_webhook", "Slack Webhook URL", _SLACK_WEBHOOK_RE, 38, 4),
    )
    for secret_type, label, pattern, prefix_len, suffix_len in token_specs:
        match = pattern.search(body)
        if match:
            redacted = _redact_secret_middle(match.group(0), prefix_len=prefix_len, suffix_len=suffix_len)
            return {
                "source_url": source_url,
                "finding_type": "exposed_js_secret",
                "severity": "high",
                "secret_type": secret_type,
                "snippet": f"{label} exposed in {source_url}: {redacted}",
            }

    return None


def _origin_tuple(parsed: urllib.parse.ParseResult) -> Optional[Tuple[str, str, int]]:
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, effective_port)


def extract_same_origin_script_urls(base_url: str, html_body: str, limit: int = 2) -> List[str]:
    """Extract up to `limit` deduplicated same-origin <script src=...> URLs from HTML."""
    if not base_url or not html_body or limit <= 0:
        return []

    base_origin = _origin_tuple(urllib.parse.urlparse(base_url))
    if base_origin is None:
        return []

    results: List[str] = []
    seen: Set[str] = set()
    for match in _SCRIPT_SRC_RE.finditer(html_body):
        raw_src = (match.group(1) or match.group(2) or match.group(3) or "").strip()
        if not raw_src or raw_src.lower().startswith(("javascript:", "data:", "blob:")):
            continue
        resolved, _ = urllib.parse.urldefrag(urllib.parse.urljoin(base_url, raw_src))
        parsed_resolved = urllib.parse.urlparse(resolved)
        if _origin_tuple(parsed_resolved) != base_origin:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        results.append(resolved)
        if len(results) >= limit:
            break
    return results
