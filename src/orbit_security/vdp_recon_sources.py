"""orbit_security.vdp_recon_sources: Multi-source passive recon, safe CT cache, and scope helpers.

Provides:
1. Empty-cache prevention and purging for `data/vdp_ct_cache.json`:
   - `load_non_empty_ct_cache`
   - `save_non_empty_ct_cache`
   - `purge_empty_ct_cache_entries`
2. Multi-source passive subdomain discovery (`discover_multi_source_subdomains`) across
   CertSpotter CT, AnubisDB, AlienVault OTX, Wayback CDX, HackerTarget, RapidDNS,
   fallback/explicit crt.sh, and optional `subfinder` CLI.
3. Explicit structured scope host extraction (`extract_explicit_scope_hosts`) supporting
   `URL`, `DOMAIN`, and `WILDCARD` scopes with out-of-scope and SSRF safety filtering.
4. Program target-signal eligibility pre-filtering (`is_program_signal_eligible`).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
import urllib.parse
import urllib.request

from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.vdp_recon_sources")

_CACHE_LOCK = threading.Lock()

DEFAULT_USER_AGENT = "OrbitSecurity-VDP/1.0"
_MAX_RESPONSE_BYTES = 524288
_ALLOWED_SCOPE_ASSET_TYPES = frozenset({"URL", "DOMAIN", "WILDCARD"})
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

__all__ = [
    "load_non_empty_ct_cache",
    "save_non_empty_ct_cache",
    "purge_empty_ct_cache_entries",
    "discover_multi_source_subdomains",
    "extract_explicit_scope_hosts",
    "is_program_signal_eligible",
]


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Atomically serialize JSON payload to `path` using a same-directory temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(json.dumps(payload, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def _normalize_cache_root(root: str) -> str:
    clean = (root or "").strip().lower()
    if clean.startswith("*."):
        clean = clean[2:]
    return clean.rstrip(".")


def load_non_empty_ct_cache(
    cache_path: Path,
    root: str,
    ttl_seconds: float = 86400.0,
) -> Optional[List[str]]:
    """Load cached subdomains for `root`, treating empty, expired, or invalid entries as cache misses."""
    path = Path(cache_path)
    if not path.exists():
        return None
    clean_root = _normalize_cache_root(root)
    if not clean_root:
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    entry = data.get(clean_root)
    if entry is None and root.strip().lower() != clean_root:
        entry = data.get(root.strip().lower())
    if not isinstance(entry, dict):
        return None

    if "timestamp" not in entry or entry["timestamp"] is None:
        return None
    ts_raw = entry["timestamp"]
    if isinstance(ts_raw, bool):
        return None
    try:
        timestamp = float(ts_raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(timestamp) or math.isinf(timestamp):
        return None
    if (time.time() - timestamp) >= ttl_seconds:
        return None

    subs = entry.get("subdomains")
    if not isinstance(subs, list):
        return None
    cleaned = [s.strip() for s in subs if isinstance(s, str) and s.strip()]
    if not cleaned:
        return None
    return cleaned


def save_non_empty_ct_cache(
    cache_path: Path,
    root: str,
    subdomains: List[str],
) -> bool:
    """Atomically persist subdomains to `cache_path` only when `subdomains` is non-empty."""
    clean_root = _normalize_cache_root(root)
    if not clean_root:
        return False

    cleaned = list(dict.fromkeys(s.strip() for s in subdomains if isinstance(s, str) and s.strip()))
    if not cleaned:
        return False

    path = Path(cache_path)
    with _CACHE_LOCK:
        existing: Dict[str, Any] = {}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except Exception:
                existing = {}

        existing[clean_root] = {
            "timestamp": time.time(),
            "subdomains": cleaned,
        }
        try:
            _atomic_write_json(path, existing)
            return True
        except Exception as exc:
            logger.debug("Failed to write CT cache %s for %s: %s", path, clean_root, exc)
            return False


def purge_empty_ct_cache_entries(cache_path: Path) -> List[str]:
    """Remove all keys with empty or invalid `subdomains` lists and return sorted purged keys."""
    path = Path(cache_path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    purged: List[str] = []
    retained: Dict[str, Any] = {}
    for key, value in data.items():
        subs = value.get("subdomains") if isinstance(value, dict) else None
        has_valid_subs = isinstance(subs, list) and any(
            isinstance(item, str) and item.strip() for item in subs
        )
        if has_valid_subs:
            retained[key] = value
        else:
            purged.append(str(key))

    if purged:
        _atomic_write_json(path, retained)
    return sorted(purged)


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253 or "." not in host:
        return False
    if _IPV4_RE.match(host):
        return False
    labels = host.split(".")
    if any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit():
        return False
    return True


def _normalize_subdomain_candidate(raw: Any, clean_root: str) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    val = raw.strip().lower()
    if not val:
        return None
    if val.startswith("*."):
        val = val[2:]
    val = val.rstrip(".")
    if not val or "*" in val:
        return None
    if not val.endswith(f".{clean_root}"):
        return None
    if not _is_valid_hostname(val):
        return None
    return val


def _extract_hostname_from_url(raw_url: str) -> Optional[str]:
    text = raw_url.strip()
    if not text or text.lower() == "original":
        return None
    if "://" not in text:
        text = f"http://{text}"
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return None
    return parsed.hostname


def _http_get_text(
    url: str,
    *,
    timeout: int,
    opener: Callable[..., Any],
) -> Optional[str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json, text/plain, text/html, */*",
        },
    )
    resp_obj = opener(req, timeout=timeout)
    if hasattr(resp_obj, "__enter__"):
        with resp_obj as resp:
            return _read_response_text(resp)
    return _read_response_text(resp_obj)


def _read_response_text(resp: Any) -> Optional[str]:
    status = getattr(resp, "status", None)
    if status is None and hasattr(resp, "getcode") and callable(resp.getcode):
        status = resp.getcode()
    if status is not None and int(status) != 200:
        return None
    try:
        raw = resp.read(_MAX_RESPONSE_BYTES)
    except TypeError:
        raw = resp.read()
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)


def _collect_candidates(
    candidates: Iterable[Any],
    clean_root: str,
    found: Set[str],
) -> None:
    for candidate in candidates:
        normalized = _normalize_subdomain_candidate(candidate, clean_root)
        if normalized:
            found.add(normalized)


def _query_certspotter(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = (
        f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(clean_root)}"
        "&include_subdomains=true&expand=dns_names"
    )
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    entries = json.loads(text)
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                _collect_candidates(item.get("dns_names") or [], clean_root, found)
    return found


def _query_anubisdb(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = f"https://anubisdb.com/anubis/subdomains/{urllib.parse.quote(clean_root)}"
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    entries = json.loads(text)
    if isinstance(entries, list):
        _collect_candidates(entries, clean_root, found)
    return found


def _query_otx(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(clean_root)}/passive_dns"
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    payload = json.loads(text)
    if isinstance(payload, dict):
        records = payload.get("passive_dns") or []
        if isinstance(records, list):
            _collect_candidates(
                (rec.get("hostname") for rec in records if isinstance(rec, dict)),
                clean_root,
                found,
            )
    return found


def _query_wayback_cdx(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(clean_root)}/*"
        "&output=json&fl=original&collapse=urlkey&limit=400"
    )
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    rows = json.loads(text)
    if isinstance(rows, list):
        hosts: List[Optional[str]] = []
        for row in rows:
            if isinstance(row, (list, tuple)) and row:
                raw_url = str(row[0])
            elif isinstance(row, str):
                raw_url = row
            else:
                continue
            hosts.append(_extract_hostname_from_url(raw_url))
        _collect_candidates(hosts, clean_root, found)
    return found


def _query_hackertarget(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(clean_root)}"
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    head = text.strip().lower()[:120]
    if head.startswith("error ") or "api count exceeded" in text.lower() or "no records found" in head:
        return found
    hosts = [line.split(",", 1)[0].strip() for line in text.splitlines() if line.strip()]
    _collect_candidates(hosts, clean_root, found)
    return found


def _query_rapiddns(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(clean_root)}?full=1"
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    pattern = re.compile(rf"(?<![a-z0-9._-])[a-z0-9._-]+\.{re.escape(clean_root)}", re.IGNORECASE)
    _collect_candidates(pattern.findall(text), clean_root, found)
    return found


def _query_crtsh(clean_root: str, timeout: int, opener: Callable[..., Any]) -> Set[str]:
    found: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(clean_root)}&output=json"
    text = _http_get_text(url, timeout=timeout, opener=opener)
    if not text:
        return found
    entries = json.loads(text)
    if isinstance(entries, list):
        candidates: List[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cn = entry.get("common_name")
            if isinstance(cn, str) and cn.strip():
                candidates.append(cn)
            nv = entry.get("name_value")
            if isinstance(nv, str) and nv.strip():
                candidates.extend(nv.splitlines())
        _collect_candidates(candidates, clean_root, found)
    return found


def _query_subfinder(clean_root: str, timeout: int) -> Set[str]:
    found: Set[str] = set()
    subfinder_bin = shutil.which("subfinder")
    if not subfinder_bin:
        return found
    cli_timeout = max(1, int(timeout))
    proc_timeout = max(5, cli_timeout + 5)
    cmd = [subfinder_bin, "-d", clean_root, "-silent", "-timeout", str(cli_timeout)]
    stdout_text = ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=proc_timeout,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            stdout_text = proc.stdout
    except subprocess.TimeoutExpired as exc:
        if isinstance(exc.stdout, bytes):
            stdout_text = exc.stdout.decode("utf-8", errors="ignore")
        elif isinstance(exc.stdout, str):
            stdout_text = exc.stdout
    if stdout_text:
        _collect_candidates(stdout_text.splitlines(), clean_root, found)
    return found


def discover_multi_source_subdomains(
    root: str,
    *,
    use_crtsh: bool = False,
    use_subfinder: bool = False,
    timeout: int = 10,
    urlopen_fn: Optional[Callable[..., Any]] = None,
) -> Set[str]:
    """Query multiple passive CT/archive/DNS sources and return normalized subdomains of `root`."""
    clean_root = _normalize_cache_root(root)
    if not _is_valid_hostname(clean_root):
        return set()

    opener = urlopen_fn or urllib.request.urlopen
    found: Set[str] = set()

    primary_sources: Tuple[Tuple[str, Callable[[str, int, Callable[..., Any]], Set[str]]], ...] = (
        ("certspotter", _query_certspotter),
        ("anubisdb", _query_anubisdb),
        ("otx", _query_otx),
        ("wayback", _query_wayback_cdx),
        ("hackertarget", _query_hackertarget),
        ("rapiddns", _query_rapiddns),
    )

    with ThreadPoolExecutor(max_workers=6) as pool:
        future_map = {
            pool.submit(query_fn, clean_root, timeout, opener): source_name
            for source_name, query_fn in primary_sources
        }
        for future, source_name in future_map.items():
            try:
                found.update(future.result())
            except Exception as exc:
                logger.debug("Subdomain source %s failed for %s: %s", source_name, clean_root, exc)

    if use_crtsh or len(found) < 5:
        try:
            found.update(_query_crtsh(clean_root, timeout, opener))
        except Exception as exc:
            logger.debug("Subdomain source crtsh failed for %s: %s", clean_root, exc)

    if use_subfinder and len(found) < 5:
        try:
            found.update(_query_subfinder(clean_root, timeout))
        except Exception as exc:
            logger.debug("Subdomain source subfinder failed for %s: %s", clean_root, exc)

    return found


def _normalize_scope_identifier(identifier: str) -> str:
    val = (identifier or "").strip().lower()
    if not val:
        return ""
    if "://" in val:
        try:
            val = urllib.parse.urlsplit(val).hostname or ""
        except ValueError:
            return ""
    else:
        val = val.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in val:
            val = val.rsplit("@", 1)[-1]
        if ":" in val:
            val = val.split(":", 1)[0]
    return val.rstrip(".")


def _host_matches_scope_pattern(host: str, asset_type: str, identifier: str) -> bool:
    clean_host = host.strip().lower().rstrip(".")
    pattern = _normalize_scope_identifier(identifier)
    if not pattern or not clean_host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return clean_host == suffix or clean_host.endswith(f".{suffix}")
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", r"[a-z0-9.-]+") + "$"
        return bool(re.match(regex, clean_host))
    if asset_type.upper() == "WILDCARD":
        return clean_host == pattern or clean_host.endswith(f".{pattern}")
    return clean_host == pattern


def extract_explicit_scope_hosts(
    structured_scopes: List[Dict[str, Any]],
    out_of_scope_matcher: Optional[Callable[[str], bool]] = None,
) -> List[str]:
    """Extract deduplicated, SSRF-safe, in-scope hostnames from HackerOne structured scopes."""
    if not isinstance(structured_scopes, list):
        return []

    out_of_scope_rules: List[Tuple[str, str]] = []
    for scope in structured_scopes:
        if not isinstance(scope, dict):
            continue
        attrs = scope.get("attributes") if isinstance(scope.get("attributes"), dict) else scope
        if attrs.get("eligible_for_submission") is False:
            atype = str(attrs.get("asset_type") or "").strip().upper()
            ident = str(attrs.get("asset_identifier") or "").strip()
            if ident:
                out_of_scope_rules.append((atype, ident))

    hosts: List[str] = []
    seen: Set[str] = set()

    for scope in structured_scopes:
        if not isinstance(scope, dict):
            continue
        attrs = scope.get("attributes") if isinstance(scope.get("attributes"), dict) else scope
        if attrs.get("eligible_for_submission") is not True:
            continue
        atype = str(attrs.get("asset_type") or "").strip().upper()
        if atype not in _ALLOWED_SCOPE_ASSET_TYPES:
            continue

        raw_ident = str(attrs.get("asset_identifier") or "")
        candidate = _normalize_scope_identifier(raw_ident)
        if candidate.startswith("*."):
            candidate = candidate[2:]
        candidate = candidate.rstrip(".")

        if not candidate or "*" in candidate:
            continue
        if not _is_valid_hostname(candidate):
            continue
        if not is_safe_host(candidate):
            continue
        if any(_host_matches_scope_pattern(candidate, oos_type, oos_ident) for oos_type, oos_ident in out_of_scope_rules):
            continue
        if out_of_scope_matcher is not None and out_of_scope_matcher(candidate):
            continue
        if candidate in seen:
            continue

        seen.add(candidate)
        hosts.append(candidate)

    return hosts


def is_program_signal_eligible(
    target_signal: Optional[float],
    researcher_signal: Optional[float],
) -> Tuple[bool, str]:
    """Return `(False, reason)` when `researcher_signal` is strictly below `target_signal`."""
    if researcher_signal is None:
        return True, "researcher_signal unknown; allowing pre-screen"
    if target_signal is None:
        return True, "program has no target_signal requirement"
    try:
        r_sig = float(researcher_signal)
        t_sig = float(target_signal)
    except (TypeError, ValueError):
        return True, "non-numeric signal values; allowing pre-screen"
    if math.isnan(r_sig) or math.isnan(t_sig):
        return True, "non-finite signal value; allowing pre-screen"
    if r_sig < t_sig:
        return (
            False,
            f"researcher_signal ({r_sig:g}) < target_signal ({t_sig:g})",
        )
    return (
        True,
        f"researcher_signal ({r_sig:g}) >= target_signal ({t_sig:g})",
    )
