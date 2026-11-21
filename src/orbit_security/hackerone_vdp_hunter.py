"""orbit_security.hackerone_vdp_hunter: Deep HackerOne VDP Recon, Screening & Dispatch Module.

Strictly targets open HackerOne Vulnerability Disclosure Programs (`offers_bounties: false`,
`submission_state: "open"`, `i_must_verify_identity_to_submit: false`). Never submits to
paid BBPs (`offers_bounties: true`) or KYC-gated programs while physical ID KYC is pending.

Architecture (Deep Module + Ports & Adapters):
- External interface: `HackerOneVdpHunter` (`discover_targets`, `screen_target`,
  `evaluate_quality_gate`, `render_dossier`, `dispatch_finding`, `run_hunt`) plus
  `VdpHuntConfig`, `TargetDiscoveryResult`, `VdpProgram`, `VdpFinding`, `QualityGateResult`.
- Transport seams: `HttpTransport`, `DnsTransport`, `HackerOneTransport`, and
  `SubdomainDiscoveryTransport` with production adapters (`UrllibHttpTransport`,
  `CloudflareDohTransport`, `UrllibHackerOneTransport`, `MultiSourceSubdomainTransport`)
  that can be swapped cleanly for in-memory fakes in tests.
- Internal implementation modules tucked behind this module:
  `orbit_security.vdp_high_signal_detectors` and `orbit_security.vdp_recon_sources`.
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Set, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

from orbit_security.bounty_triage_copilot import GemmaTriageCopilot
from orbit_security.cert_transparency import CertificateTransparencyMonitor
from orbit_security.cloud_sentinels import CloudBucketTakeoverSentinel
from orbit_security.cname_takeover import PassiveTakeoverDetector
from orbit_security.egress_guard import (
    EgressDecision,
    EgressViolationError,
    _is_bogon_or_internal_ip,
    enforce_egress_or_raise,
    evaluate_egress_target,
)
from orbit_security.report_verifier import (
    EmpiricalEvidenceArtifact,
    ReportCriticVerifier,
    compute_evidence_digest,
)
from orbit_security.scanner import is_safe_host, is_safe_ip
from orbit_security.vdp_high_signal_detectors import (
    EXTENDED_SENSITIVE_PATHS,
    HTML_LOOKALIKE_RE,
    SENSITIVE_BUCKET_KEY_RE,
    STATIC_PUBLIC_ASSET_EXTS,
    STATIC_PUBLIC_FILENAMES,
    check_extended_sensitive_exposures,
    compress_vdp_payload_anchors,
    evaluate_cloud_reference_response,
    evaluate_cors_response,
    extract_cloud_urls_from_text,
    extract_same_origin_script_urls,
    is_bucket_listing_non_public,
    scan_text_for_high_confidence_secrets,
)
from orbit_security.vdp_recon_sources import (
    discover_multi_source_subdomains,
    extract_explicit_scope_hosts,
    host_matches_scope_pattern,
    is_program_signal_eligible,
    load_non_empty_ct_cache,
    normalize_scope_host,
    purge_empty_ct_cache_entries,
    save_non_empty_ct_cache,
)

try:
    from nova_brain.memory.memorilla import LoopPreventionSentinel
except ImportError:
    from orbit_security.memorilla import LoopPreventionSentinel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"
HACKERONE_API_BASE = "https://api.hackerone.com"
HACKERONE_WEB_BASE = "https://hackerone.com"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

DEFAULT_PROGRAMS_PATH = PROJECT_ROOT / "data" / "bounty_programs.json"
DEFAULT_CANDIDATES_PATH = PROJECT_ROOT / "data" / "bounty_candidates.json"
DEFAULT_VDP_CT_CACHE_PATH = PROJECT_ROOT / "data" / "vdp_ct_cache.json"
DEFAULT_VDP_READY_DIR = PROJECT_ROOT / "artifacts" / "vdp_ready"
DEFAULT_MANIFEST_PATH = DEFAULT_VDP_READY_DIR / "vdp_verification_manifest.json"
DEFAULT_RESEARCHER_HANDLE = "arsoncarson"
DEFAULT_PROBE_USER_AGENT = f"OrbitSecurity-VDP/1.0 (HackerOne:@{DEFAULT_RESEARCHER_HANDLE})"

PRIORITY_SUBDOMAIN_TOKENS: Tuple[str, ...] = (
    "try",
    "shop",
    "promo",
    "go",
    "lp",
    "landing",
    "campaign",
    "events",
    "pages",
    "info",
    "demo",
    "test",
    "staging",
    "stage",
    "dev",
    "sandbox",
    "uat",
    "qa",
    "beta",
    "cdn",
    "assets",
    "static",
    "media",
    "storage",
    "bucket",
    "docs",
    "help",
    "support",
    "blog",
    "status",
    "git",
    "portal",
    "app",
    "api",
    "old",
    "legacy",
)

WEAKNESS_PREFERENCES: Dict[str, Tuple[str, ...]] = {
    "dangling_cname": ("cwe-350", "cwe-940", "cwe-284", "cwe-200", "cwe-16"),
    "open_bucket": ("cwe-200", "cwe-284", "cwe-732", "cwe-276", "cwe-16"),
    "dangling_referenced_bucket": ("cwe-284", "cwe-350", "cwe-940", "cwe-200", "cwe-16"),
    "exposed_firebase_db": ("cwe-284", "cwe-200", "cwe-732", "cwe-862", "cwe-16"),
    "cors_credentialed_reflection": ("cwe-942", "cwe-346", "cwe-284", "cwe-200", "cwe-16"),
    "exposed_js_secret": ("cwe-798", "cwe-540", "cwe-200", "cwe-538", "cwe-284"),
    "exposed_git": ("cwe-538", "cwe-200", "cwe-540", "cwe-284", "cwe-16"),
    "exposed_svn": ("cwe-538", "cwe-200", "cwe-540", "cwe-284", "cwe-16"),
    "exposed_ds_store": ("cwe-538", "cwe-200", "cwe-284", "cwe-16"),
    "exposed_server_status": ("cwe-200", "cwe-215", "cwe-284", "cwe-16"),
    "exposed_env": ("cwe-538", "cwe-200", "cwe-540", "cwe-798", "cwe-284", "cwe-16"),
    "exposed_actuator": ("cwe-200", "cwe-215", "cwe-284", "cwe-16"),
    "exposed_aws_credentials": ("cwe-798", "cwe-538", "cwe-200", "cwe-540", "cwe-284"),
    "exposed_backup_config": ("cwe-530", "cwe-538", "cwe-200", "cwe-798", "cwe-284"),
}

SENSITIVE_EXPOSURE_PATHS: Tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            "/.git/HEAD",
            "/.git/config",
            "/.svn/entries",
            "/.DS_Store",
            "/.env",
            "/server-status",
            "/actuator/env",
            "/actuator/configprops",
            "/actuator/mappings",
            "/.aws/credentials",
            "/wp-config.php~",
            "/wp-config.php.bak",
            "/config.php.bak",
            *EXTENDED_SENSITIVE_PATHS,
        )
    )
)

_PASSIVE_SAAS_CNAME_PROVIDERS = {
    "unbounce",
    "webflow",
    "instapage",
    "zendesk",
    "hubspot",
    "squarespace",
    "tilda",
    "cargo",
}

_MARKETING_HOST_PREFIXES: Tuple[str, ...] = (
    "try.",
    "promo.",
    "lp.",
    "events.",
    "go.",
    "blog.",
    "shop.",
    "pages.",
)

_TENANT_ENDPOINT_SUFFIXES: Tuple[str, ...] = (
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".herokuapp.com",
    ".github.io",
    ".netlify.app",
    ".vercel.app",
    ".fly.dev",
    ".pantheonsite.io",
    ".webflow.io",
    ".zendesk.com",
)

_PARKED_DOMAIN_MARKERS: Tuple[str, ...] = (
    "domain is for sale",
    "buy this domain",
    "sedoparking",
    "hugedomains",
    "afternic",
    "dan.com",
    "domain has expired",
    "this domain is parked",
)

_CRITIC_PERSONAS: Tuple[Tuple[str, str], ...] = (
    (
        "Scope & Policy Compliance Auditor",
        "Verify strict VDP status, KYC-free eligibility, exact structured scope, and absence of policy exclusions.",
    ),
    (
        "HackerOne Triager False-Positive Skeptic",
        "Act as a strict HackerOne triager hunting for Informative, N/A, parked domain, SPA fallback, or non-claimable CDN false positives.",
    ),
    (
        "Reproducibility & Evidence Integrity Critic",
        "Verify DNS CNAME/A grounding, persistent HTTP signature across re-probes, realistic severity, and non-destructive testing proof.",
    ),
)

_ENV_LINE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=[^\r\n]+$", re.MULTILINE)
_SENSITIVE_ENV_KEY_RE = re.compile(
    r"^(?:APP_KEY|DB_PASSWORD|DB_PASS|DATABASE_URL|AWS_SECRET|AWS_ACCESS|SECRET_KEY|JWT_SECRET|STRIPE_|PRIVATE_KEY|API_KEY|AUTH_TOKEN)=",
    re.MULTILINE,
)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_POLICY_HEADER_RE = re.compile(r"\b(X-[A-Za-z0-9-]{3,40})\b")


# ---------------------------------------------------------------------------
# Domain Models & Configuration
# ---------------------------------------------------------------------------


@dataclass
class VdpProgram:
    handle: str
    name: str
    offers_bounties: bool
    submission_state: str
    i_must_verify_identity_to_submit: bool
    policy: str = ""
    structured_scopes: List[Dict[str, Any]] = field(default_factory=list)
    weaknesses: List[Dict[str, Any]] = field(default_factory=list)
    compliance_headers: Dict[str, str] = field(default_factory=dict)
    target_signal: Optional[float] = None


@dataclass
class VdpFinding:
    program_handle: str
    program_name: str
    host: str
    finding_type: str
    title: str
    severity: str
    weakness_id: Optional[str]
    structured_scope_id: str
    cname_target: Optional[str]
    a_records: List[str]
    http_status: int
    http_url: str
    evidence_snippet: str
    remediation: str
    captured_utc: str
    provider: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QualityGateResult:
    passed: bool
    verdict: str
    reverification_passes: int
    reverification_runs: int
    deterministic_checks: Dict[str, bool]
    critic_runs: List[Dict[str, Any]]
    critic_passes: int
    critic_total: int
    critic_rejections: int
    evidence_artifact_id: str
    blocking_reasons: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class TargetDiscoveryResult:
    """In-scope, deduplicated screening targets derived for a single VDP program."""

    program_handle: str
    wildcards_scanned: List[str]
    explicit_hosts_scanned: List[str]
    hosts_to_screen: List[str]
    total_explicit_candidates: int


@dataclass(frozen=True)
class VdpHuntConfig:
    """Configuration envelope for a HackerOne VDP hunt run."""

    max_programs: int = 25
    program_offset: int = 0
    max_wildcards_per_program: int = 5
    max_subdomains: int = 25
    workers: int = 12
    include_covered: bool = False
    submit_vdp: bool = False
    use_crtsh: bool = False
    use_subfinder: bool = False
    env_path: Path = DEFAULT_ENV_PATH
    cache_path: Path = DEFAULT_VDP_CT_CACHE_PATH
    vdp_ready_dir: Path = DEFAULT_VDP_READY_DIR
    manifest_path: Path = DEFAULT_MANIFEST_PATH
    base_url: str = HACKERONE_API_BASE
    check_graphql_kyc: bool = True
    reverify_runs: int = 2
    critic_runs: int = 3
    use_ollama_critic: bool = False
    critic_model: str = "orbit-critic:latest"
    ollama_timeout: float = 45.0
    reject_passive_saas_cname: bool = True
    purge_empty_cache: bool = False
    ignore_signal_gate: bool = False
    program_handles: Optional[Union[str, Iterable[str]]] = None
    reverify_sleep_seconds: float = 0.5


# ---------------------------------------------------------------------------
# Transport Adapter Ports (Seams) & Production Adapters
# ---------------------------------------------------------------------------


class HttpTransport(Protocol):
    """Port for bounded, non-destructive HTTP sampling against target assets."""

    def fetch(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: int = 8192,
        timeout: int = 5,
    ) -> Tuple[int, Dict[str, str], str]: ...


class DnsTransport(Protocol):
    """Port for passive DNS resolution (CNAME / A / TXT)."""

    def resolve(
        self,
        host: str,
        record_type: str = "CNAME",
        timeout: int = 5,
    ) -> Dict[str, Any]: ...


class HackerOneTransport(Protocol):
    """Port for HackerOne REST API v1 and public GraphQL program gate queries."""

    def fetch_paginated(
        self,
        path_or_url: str,
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        max_items: int = 200,
        timeout: int = 15,
    ) -> List[Dict[str, Any]]: ...

    def fetch_program_detail(
        self,
        handle: str,
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        timeout: int = 15,
    ) -> Dict[str, Any]: ...

    def fetch_program_kyc_status(
        self,
        handle: str,
        *,
        timeout: int = 12,
    ) -> Optional[bool]: ...

    def fetch_program_graphql_gates(
        self,
        handle: str,
        *,
        timeout: int = 10,
    ) -> Dict[str, Any]: ...

    def post_report(
        self,
        payload: Dict[str, Any],
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        timeout: int = 20,
    ) -> Tuple[int, Dict[str, Any], str]: ...


class SubdomainDiscoveryTransport(Protocol):
    """Port for passive subdomain discovery across CT/archive/DNS sources."""

    def discover(
        self,
        root: str,
        *,
        use_crtsh: bool = False,
        use_subfinder: bool = False,
        timeout: int = 10,
    ) -> Set[str]: ...


class _SafeVdpRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Guards redirect execution by validating target hostnames against is_safe_host
    and eliminating circular 302 redirect loops with LoopPreventionSentinel."""

    def __init__(self, history_window: int = 8, repetition_threshold: int = 3):
        super().__init__()
        self.sentinel = LoopPreventionSentinel(
            history_window=history_window,
            repetition_threshold=repetition_threshold,
        )

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_parsed = urllib.parse.urlparse(newurl)
        new_host = (new_parsed.hostname or "").strip().lower()
        if not new_host or not is_safe_host(new_host):
            return None
        if self.sentinel.record_action(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _parse_env_file(env_path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not env_path.exists():
        return values
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def load_hackerone_credentials(env_path: Optional[Path] = None) -> Tuple[str, str]:
    """Load HackerOne API username and token from os.environ or a dotenv file."""
    username = os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = os.environ.get("HACKERONE_API_TOKEN", "").strip()

    if not username or not token:
        target_env = env_path or DEFAULT_ENV_PATH
        file_env = _parse_env_file(target_env)
        username = username or file_env.get("HACKERONE_API_USERNAME", "").strip()
        token = token or file_env.get("HACKERONE_API_TOKEN", "").strip()

    if not username or not token:
        raise RuntimeError(
            "Missing HACKERONE_API_USERNAME or HACKERONE_API_TOKEN in environment or .env."
        )
    return username, token


def build_auth_header(username: str, api_token: str) -> str:
    token = base64.b64encode(f"{username}:{api_token}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_get_json(url: str, headers: Dict[str, str], timeout: int = 15) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # roe-exempt: HackerOne API control plane
        return json.loads(resp.read().decode("utf-8"))


def fetch_paginated_h1(
    path_or_url: str,
    auth_header: str,
    *,
    base_url: str = HACKERONE_API_BASE,
    max_items: int = 200,
    timeout: int = 15,
) -> List[Dict[str, Any]]:
    """Fetch paginated HackerOne JSON:API resources up to max_items."""
    root = base_url.rstrip("/")
    next_url: Optional[str] = (
        path_or_url if path_or_url.startswith("http") else f"{root}{path_or_url}"
    )
    headers = {
        "Authorization": auth_header,
        "Accept": "application/json",
        "User-Agent": DEFAULT_PROBE_USER_AGENT,
    }
    collected: List[Dict[str, Any]] = []
    while next_url and len(collected) < max_items:
        payload = _http_get_json(next_url, headers=headers, timeout=timeout)
        page_items = payload.get("data") or []
        if not isinstance(page_items, list) or not page_items:
            break
        collected.extend(page_items)
        links = payload.get("links") or {}
        next_url = links.get("next")
    return collected[:max_items]


def fetch_program_kyc_status_graphql(handle: str, timeout: int = 12) -> Optional[bool]:
    """Best-effort check of HackerOne GraphQL i_must_verify_identity_to_submit flag."""
    try:
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))  # roe-exempt: HackerOne GraphQL control plane
        page_url = f"{HACKERONE_WEB_BASE}/{handle}"
        page_req = urllib.request.Request(page_url, headers={"User-Agent": BROWSER_USER_AGENT})
        with opener.open(page_req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        m = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
        if not m:
            return None
        csrf = m.group(1)
        query = (
            "query($h:String!){team(handle:$h)"
            "{handle offers_bounties submission_state i_must_verify_identity_to_submit}}"
        )
        gql_req = urllib.request.Request(
            f"{HACKERONE_WEB_BASE}/graphql",
            data=json.dumps({"query": query, "variables": {"h": handle}}).encode("utf-8"),
            headers={
                "User-Agent": BROWSER_USER_AGENT,
                "Content-Type": "application/json",
                "X-Csrf-Token": csrf,
                "Origin": HACKERONE_WEB_BASE,
                "Referer": page_url,
            },
        )
        with opener.open(gql_req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        team = (payload.get("data") or {}).get("team") or {}
        val = team.get("i_must_verify_identity_to_submit")
        return bool(val) if val is not None else None
    except Exception:
        return None


def fetch_program_graphql_gates(handle: str, timeout: int = 10) -> Dict[str, Any]:
    """Fetch public GraphQL submission gate metadata (target_signal, trial_report_limit) without failing."""
    query = (
        "query($h:String!){team(handle:$h)"
        "{handle state submission_state i_must_verify_identity_to_submit "
        "signal_requirements_setting{target_signal} "
        "trial_report_limit_setting{limit}}}"
    )
    try:
        req = urllib.request.Request(
            f"{HACKERONE_WEB_BASE}/graphql",
            data=json.dumps({"query": query, "variables": {"h": handle}}).encode("utf-8"),
            headers={
                "User-Agent": BROWSER_USER_AGENT,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # roe-exempt: HackerOne GraphQL control plane
            payload = json.loads(resp.read().decode("utf-8"))
        team = (payload.get("data") or {}).get("team") or {}
        sig_raw = (team.get("signal_requirements_setting") or {}).get("target_signal")
        trial_raw = (team.get("trial_report_limit_setting") or {}).get("limit")
        return {
            "target_signal": float(sig_raw) if sig_raw is not None else None,
            "trial_report_limit": int(trial_raw) if trial_raw is not None else None,
            "kyc_required": team.get("i_must_verify_identity_to_submit"),
        }
    except Exception:
        return {}


def resolve_dns_doh(host: str, record_type: str = "CNAME", timeout: int = 5) -> Dict[str, Any]:
    """Query Cloudflare DNS-over-HTTPS for passive CNAME/A/TXT verification."""
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type={record_type}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/dns-json", "User-Agent": DEFAULT_PROBE_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # roe-exempt: passive Cloudflare DoH lookup
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {"Status": -1, "Answer": []}


def fetch_http_sample(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = 8192,
    timeout: int = 5,
) -> Tuple[int, Dict[str, str], str]:
    """Perform a single bounded non-destructive HTTP GET and return (status, headers, body)."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host or not is_safe_host(host):
        return 0, {}, ""

    req_headers = {"User-Agent": DEFAULT_PROBE_USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    opener = urllib.request.build_opener(_SafeVdpRedirectHandler())  # roe-exempt: guarded by is_safe_host + _SafeVdpRedirectHandler
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode("utf-8", errors="ignore")
            return int(getattr(resp, "status", 200)), dict(resp.headers.items()), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(max_bytes).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return int(exc.code), dict(exc.headers.items()) if exc.headers else {}, body
    except Exception:
        return 0, {}, ""


class UrllibHttpTransport:
    """Production HTTP transport adapter enforcing SSRF safe-host & redirect-loop guards."""

    def fetch(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: int = 8192,
        timeout: int = 5,
    ) -> Tuple[int, Dict[str, str], str]:
        return fetch_http_sample(url, headers=headers, max_bytes=max_bytes, timeout=timeout)


class CloudflareDohTransport:
    """Production passive DNS transport adapter backed by Cloudflare DoH."""

    def resolve(
        self,
        host: str,
        record_type: str = "CNAME",
        timeout: int = 5,
    ) -> Dict[str, Any]:
        return resolve_dns_doh(host, record_type, timeout=timeout)


class UrllibHackerOneTransport:
    """Production HackerOne REST v1 + GraphQL transport adapter."""

    def fetch_paginated(
        self,
        path_or_url: str,
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        max_items: int = 200,
        timeout: int = 15,
    ) -> List[Dict[str, Any]]:
        return fetch_paginated_h1(
            path_or_url,
            auth_header,
            base_url=base_url,
            max_items=max_items,
            timeout=timeout,
        )

    def fetch_program_detail(
        self,
        handle: str,
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        return _http_get_json(
            f"{base_url.rstrip('/')}/v1/hackers/programs/{handle}",
            headers={
                "Authorization": auth_header,
                "Accept": "application/json",
                "User-Agent": DEFAULT_PROBE_USER_AGENT,
            },
            timeout=timeout,
        )

    def fetch_program_kyc_status(
        self,
        handle: str,
        *,
        timeout: int = 12,
    ) -> Optional[bool]:
        return fetch_program_kyc_status_graphql(handle, timeout=timeout)

    def fetch_program_graphql_gates(
        self,
        handle: str,
        *,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        return fetch_program_graphql_gates(handle, timeout=timeout)

    def post_report(
        self,
        payload: Dict[str, Any],
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        timeout: int = 20,
    ) -> Tuple[int, Dict[str, Any], str]:
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/v1/hackers/reports",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": auth_header,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": DEFAULT_PROBE_USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # roe-exempt: HackerOne API report submission
                raw = resp.read().decode("utf-8")
                return int(getattr(resp, "status", 201)), json.loads(raw), ""
        except urllib.error.HTTPError as exc:
            raw_err = exc.read().decode("utf-8", errors="ignore")
            return int(exc.code), {}, raw_err


class MultiSourceSubdomainTransport:
    """Production passive subdomain discovery transport adapter."""

    def __init__(self, *, ct_monitor: Optional[CertificateTransparencyMonitor] = None) -> None:
        self._ct_monitor = ct_monitor

    def discover(
        self,
        root: str,
        *,
        use_crtsh: bool = False,
        use_subfinder: bool = False,
        timeout: int = 10,
    ) -> Set[str]:
        clean_root = root.strip().lower().lstrip("*.").rstrip(".")
        names: Set[str] = set()
        monitor = self._ct_monitor or CertificateTransparencyMonitor()
        if monitor.is_cache_valid(clean_root):
            for rec in monitor.load_from_cache(clean_root) or []:
                if rec.get("common_name"):
                    names.add(str(rec["common_name"]))
                for line in str(rec.get("name_value") or "").splitlines():
                    if line.strip():
                        names.add(line.strip())

        names.update(
            discover_multi_source_subdomains(
                clean_root,
                use_crtsh=use_crtsh,
                use_subfinder=use_subfinder,
                timeout=timeout,
                urlopen_fn=urllib.request.urlopen,
            )
        )
        return names


# ---------------------------------------------------------------------------
# Pure In-Process Domain Logic (Program Filtering, Scope, Detectors, Dossiers)
# ---------------------------------------------------------------------------


def filter_kyc_free_vdp_programs(raw_programs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only open, non-bounty (VDP) programs that do not require identity verification."""
    kept: List[Dict[str, Any]] = []
    for item in raw_programs:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or {}
        if attrs.get("offers_bounties") is not False:
            continue
        if str(attrs.get("submission_state") or "").lower() != "open":
            continue
        if attrs.get("i_must_verify_identity_to_submit") is True:
            continue
        state = str(attrs.get("state") or "").lower()
        if state in {"disabled", "soft_closed", "archived"}:
            continue
        if attrs.get("handle"):
            kept.append(item)
    return kept


def parse_compliance_headers(policy: str, researcher: str = DEFAULT_RESEARCHER_HANDLE) -> Dict[str, str]:
    """Extract custom VDP tracking headers if referenced in a program's policy text."""
    if not policy:
        return {}
    headers: Dict[str, str] = {}
    for match in _POLICY_HEADER_RE.finditer(policy):
        hdr = match.group(1)
        lowered = hdr.lower()
        if any(tok in lowered for tok in ("vdp", "hackerone", "bounty", "research", "security")):
            if lowered not in {"x-forwarded-for", "x-frame-options", "x-content-type-options"}:
                headers[hdr] = f"HackerOne-{researcher}"
    return headers


def match_structured_scope(
    host: str,
    structured_scopes: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Return matching eligible structured_scope, enforcing out-of-scope exclusions first."""
    clean_host = host.strip().lower().rstrip(".")
    for scope in structured_scopes:
        attrs = scope.get("attributes") or {}
        if attrs.get("eligible_for_submission") is False:
            if host_matches_scope_pattern(
                clean_host,
                str(attrs.get("asset_type") or ""),
                str(attrs.get("asset_identifier") or ""),
            ):
                return None

    exact_match: Optional[Dict[str, Any]] = None
    wildcard_match: Optional[Dict[str, Any]] = None
    for scope in structured_scopes:
        attrs = scope.get("attributes") or {}
        if attrs.get("eligible_for_submission") is not True:
            continue
        atype = str(attrs.get("asset_type") or "").upper()
        ident = str(attrs.get("asset_identifier") or "")
        if atype not in {"WILDCARD", "URL", "DOMAIN"}:
            continue
        if host_matches_scope_pattern(clean_host, atype, ident):
            if "*" not in ident and atype != "WILDCARD":
                exact_match = scope
                break
            if wildcard_match is None:
                wildcard_match = scope
    return exact_match or wildcard_match


def extract_wildcard_roots(program: VdpProgram) -> List[str]:
    """Return unique root domains from eligible WILDCARD scopes."""
    roots: List[str] = []
    seen: Set[str] = set()
    for scope in program.structured_scopes:
        attrs = scope.get("attributes") or {}
        if attrs.get("eligible_for_submission") is not True:
            continue
        atype = str(attrs.get("asset_type") or "").upper()
        ident = normalize_scope_host(str(attrs.get("asset_identifier") or ""))
        if not ident:
            continue
        if atype == "WILDCARD" or ident.startswith("*."):
            root = ident.lstrip("*.")
            if re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", root) and root not in seen:
                seen.add(root)
                roots.append(root)
    return roots


def load_covered_domains(
    programs_path: Path = DEFAULT_PROGRAMS_PATH,
    candidates_path: Path = DEFAULT_CANDIDATES_PATH,
) -> Set[str]:
    """Collect root domains already covered in bounty_programs.json / bounty_candidates.json."""
    covered: Set[str] = set()
    for path in (programs_path, candidates_path):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        entries = data if isinstance(data, list) else (data.get("programs") or data.get("candidates") or [])
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for item in entry.get("in_scope") or []:
                norm = normalize_scope_host(str(item)).lstrip("*.")
                if norm:
                    covered.add(norm)
            for key in ("domain", "root_domain", "asset_identifier"):
                if entry.get(key):
                    norm = normalize_scope_host(str(entry[key])).lstrip("*.")
                    if norm:
                        covered.add(norm)
    return covered


def select_weakness_id(finding_type: str, weaknesses: List[Dict[str, Any]]) -> Optional[str]:
    """Select the best matching HackerOne weakness_id for a finding type."""
    if not weaknesses:
        return None
    by_cwe: Dict[str, str] = {}
    for w in weaknesses:
        attrs = w.get("attributes") or {}
        ext = str(attrs.get("external_id") or "").strip().lower()
        if ext and w.get("id") is not None:
            by_cwe[ext] = str(w["id"])

    for pref in WEAKNESS_PREFERENCES.get(finding_type, ("cwe-200", "cwe-16")):
        if pref in by_cwe:
            return by_cwe[pref]

    keywords = {
        "dangling_cname": ("takeover", "dns", "misconfiguration", "information"),
        "open_bucket": ("information", "disclosure", "access control", "permission"),
        "dangling_referenced_bucket": (
            "takeover",
            "access control",
            "bucket",
            "storage",
            "information",
            "disclosure",
        ),
        "exposed_firebase_db": (
            "access control",
            "authorization",
            "information",
            "disclosure",
            "permission",
        ),
        "cors_credentialed_reflection": (
            "cors",
            "cross-origin",
            "origin",
            "access control",
            "information",
        ),
        "exposed_js_secret": (
            "credential",
            "hard-coded",
            "hardcoded",
            "secret",
            "information",
            "sensitive",
            "source",
        ),
        "exposed_git": ("information", "sensitive", "source", "configuration", "file"),
        "exposed_svn": ("information", "sensitive", "source", "configuration", "file"),
        "exposed_ds_store": ("information", "sensitive", "file", "directory", "disclosure"),
        "exposed_server_status": ("information", "debug", "disclosure", "configuration"),
        "exposed_env": ("information", "credentials", "sensitive", "configuration"),
        "exposed_actuator": ("information", "debug", "configuration", "disclosure"),
        "exposed_aws_credentials": ("credential", "hard-coded", "sensitive", "information"),
        "exposed_backup_config": ("backup", "information", "sensitive", "configuration"),
    }.get(finding_type, ("information",))
    for w in weaknesses:
        name = str((w.get("attributes") or {}).get("name") or "").lower()
        if any(kw in name for kw in keywords) and w.get("id") is not None:
            return str(w["id"])
    return str(weaknesses[0]["id"]) if weaknesses[0].get("id") is not None else None


def resolve_dns_cname_chain_guarded(
    host: str,
    doh_lookup_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    max_hops: int = 10,
) -> Tuple[List[str], bool]:
    """Resolve recursive CNAME chain with LoopPreventionSentinel eliminating cyclical hops."""
    lookup = doh_lookup_fn or resolve_dns_doh
    sentinel = LoopPreventionSentinel(history_window=8, repetition_threshold=2)
    current = host.strip().lower()
    chain: List[str] = [current]
    loop_detected = False

    for _ in range(max_hops):
        ans = lookup(current, record_type="CNAME")
        records = ans.get("Answer", [])
        cname_target = None
        for r in records:
            if isinstance(r, dict) and r.get("data"):
                cname_target = str(r["data"]).rstrip(".").strip().lower()
                break
        if not cname_target:
            break

        if sentinel.record_action(cname_target):
            loop_detected = True
            chain.append(cname_target)
            break

        chain.append(cname_target)
        current = cname_target

    return chain, loop_detected


def check_open_bucket_listing(url: str, status: int, body: str) -> Optional[Dict[str, Any]]:
    """Detect non-empty public S3/GCS XML <ListBucketResult> directory listings."""
    if status != 200 or not body or HTML_LOOKALIKE_RE.match(body):
        return None
    if "<listbucketresult" not in body.lower() and "<listallmybucketsresult" not in body.lower():
        return None
    keys = re.findall(r"<Key>([^<]+)</Key>", body)
    if not keys:
        return None
    name_match = re.search(r"<Name>([^<]+)</Name>", body)
    return {
        "url": url,
        "bucket_name": name_match.group(1) if name_match else "unknown",
        "sample_keys": keys[:5],
        "key_count_in_sample": len(keys),
    }


def check_exposed_config_or_git(path: str, status: int, body: str) -> Optional[Dict[str, Any]]:
    """Detect verified exposed /.git/*, /.svn/entries, /.DS_Store, /server-status, /.env, Spring Actuator, AWS credentials, or backup configs."""
    ext_hit = check_extended_sensitive_exposures(path, status, body)
    if ext_hit is not None:
        return ext_hit
    if status != 200 or not body or HTML_LOOKALIKE_RE.match(body):
        return None
    trimmed = body.strip()
    if path == "/.git/HEAD":
        if trimmed.startswith("ref: refs/") or _GIT_SHA_RE.match(trimmed):
            return {"path": path, "finding_type": "exposed_git", "snippet": trimmed[:200]}
        return None
    if path == "/.env":
        env_lines = _ENV_LINE_RE.findall(body)
        sensitive_lines = _SENSITIVE_ENV_KEY_RE.findall(body)
        if len(env_lines) >= 2 and sensitive_lines:
            redacted = "\n".join(
                f"{line.split('=', 1)[0]}=<REDACTED_LEN_{len(line.split('=', 1)[1])}>"
                for line in env_lines[:6]
            )
            return {"path": path, "finding_type": "exposed_env", "snippet": redacted}
    if path in ("/actuator/env", "/actuator/configprops"):
        if trimmed.startswith("{"):
            try:
                parsed = json.loads(trimmed)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and any(
                k in parsed for k in ("propertySources", "activeProfiles", "systemEnvironment", "contexts", "beans")
            ):
                keys = list(parsed.keys())[:6]
                return {
                    "path": path,
                    "finding_type": "exposed_actuator",
                    "snippet": f"Spring Actuator JSON keys={keys} (len={len(trimmed)})",
                }
    if path == "/.aws/credentials":
        if re.search(r"^\s*\[[^\]]+\]", body, re.MULTILINE) and re.search(
            r"\baws_(?:access_key_id|secret_access_key|session_token)\b", body, re.IGNORECASE
        ):
            sections = re.findall(r"^\s*(\[[^\]]+\])", body, re.MULTILINE)[:3]
            return {
                "path": path,
                "finding_type": "exposed_aws_credentials",
                "snippet": f"AWS credentials INI profiles={sections} (secrets redacted)",
            }
    if path in ("/wp-config.php~", "/wp-config.php.bak", "/config.php.bak"):
        if re.search(
            r"define\s*\(\s*['\"](?:DB_PASSWORD|DB_HOST|DB_NAME|AUTH_KEY|SECRET_KEY)['\"]",
            body,
            re.IGNORECASE,
        ):
            matched_defs = re.findall(
                r"define\s*\(\s*['\"]([A-Z0-9_]+)['\"]", body, re.IGNORECASE
            )[:6]
            return {
                "path": path,
                "finding_type": "exposed_backup_config",
                "snippet": f"Backup PHP config defines={matched_defs} (credentials redacted)",
            }
    return None


def _prioritize_subdomains(subdomains: Iterable[str], root: str, limit: int) -> List[str]:
    clean: List[str] = []
    seen: Set[str] = set()
    for raw in subdomains:
        s = raw.strip().lower().lstrip("*.").rstrip(".")
        if not s or s == root or not s.endswith(f".{root}") or s in seen:
            continue
        seen.add(s)
        clean.append(s)

    def _rank(sub: str) -> Tuple[int, str]:
        label = sub[: -(len(root) + 1)]
        for idx, token in enumerate(PRIORITY_SUBDOMAIN_TOKENS):
            if token in label:
                return (idx, sub)
        return (len(PRIORITY_SUBDOMAIN_TOKENS) + len(label), sub)

    clean.sort(key=_rank)
    return clean[:limit]


def check_takeover_claimability(
    provider: Optional[str],
    cname_target: Optional[str],
    host_body: str,
    host: Optional[str] = None,
    *,
    dns_transport: Optional[DnsTransport] = None,
    http_transport: Optional[HttpTransport] = None,
) -> Tuple[bool, str]:
    """Verify a CNAME takeover candidate is genuinely claimable and not an active/WAF endpoint."""
    body_low = (host_body or "").lower()
    cname_low = (cname_target or "").strip().lower().rstrip(".")
    prov_low = (provider or "").lower()

    if "cloudfront" in prov_low or cname_low.endswith(".cloudfront.net"):
        if "request blocked" in body_low or "can't connect to the server for this app or website" in body_low:
            return (
                False,
                "CloudFront distribution is active (WAF/origin Request blocked, not an unattached distribution).",
            )
        if "bad request" not in body_low:
            return False, "CloudFront response lacks unattached distribution 'Bad request' signature."

    if "vercel" in prov_low or cname_low.endswith(("vercel-dns.com", ".vercel.app")):
        clean_host = (host or "").strip().lower().rstrip(".")
        labels = [lbl for lbl in clean_host.split(".") if lbl]
        if len(labels) >= 2:
            parent_domain = ".".join(labels[-2:])
            vercel_txt = (
                dns_transport.resolve(f"_vercel.{parent_domain}", "TXT", timeout=5)
                if dns_transport is not None
                else resolve_dns_doh(f"_vercel.{parent_domain}", "TXT", timeout=5)
            )
            has_txt_lock = any(
                ans.get("type") == 16 and ans.get("data")
                for ans in ((vercel_txt or {}).get("Answer") or [])
            )
            if has_txt_lock:
                return (
                    False,
                    f"Vercel domain ownership is locked by active _vercel.{parent_domain} TXT verification record.",
                )

    if "fastly" in prov_low or cname_low.endswith(".fastly.net"):
        clean_fastly_host = (host or "").strip().lower().rstrip(".")
        if clean_fastly_host and "unknown domain:" in body_low:
            if f"unknown domain: {clean_fastly_host}" not in body_low:
                return (
                    False,
                    f"Fastly unknown domain error does not match probed host '{host}' (cross-host redirect).",
                )

    if "firebase" in prov_low or cname_low.endswith((".web.app", ".firebaseapp.com")):
        return (
            False,
            "Firebase Hosting custom domains require DNS TXT ownership verification and cannot be claimed by third parties.",
        )

    if cname_low and any(cname_low.endswith(sfx) for sfx in _TENANT_ENDPOINT_SUFFIXES):
        fetch_fn = http_transport.fetch if http_transport is not None else fetch_http_sample
        t_status, _, t_body = fetch_fn(f"https://{cname_low}/", timeout=5)
        if t_status == 0:
            t_status, _, t_body = fetch_fn(f"http://{cname_low}/", timeout=5)
        t_low = (t_body or "").lower()
        unclaimed_markers = (
            "404 web site not found",
            "no such app",
            "there isn't a github pages site here",
            "404 error unknown site",
            "not found on this server",
            "help center closed",
        )
        if t_status in (200, 301, 302, 401, 403) and not any(m in t_low for m in unclaimed_markers):
            return (
                False,
                f"CNAME target '{cname_low}' is an active occupied tenant (HTTP {t_status}); cannot be claimed.",
            )

    return True, "Takeover candidate passed claimability checks."


def is_duplicate_finding(
    host: str,
    existing_reports: List[Dict[str, Any]],
    vdp_ready_files: Iterable[Path],
) -> bool:
    """Return True if host already exists in HackerOne reports or staged VDP dossiers."""
    clean_host = host.strip().lower()
    for rep in existing_reports:
        title = str((rep.get("attributes") or {}).get("title") or "").lower()
        if clean_host in title:
            return True
    slug = clean_host.replace(".", "_")
    for p in vdp_ready_files:
        if slug in p.name.lower() or clean_host in p.name.lower():
            return True
    return False


def render_vdp_dossier(program: VdpProgram, finding: VdpFinding) -> Tuple[str, str]:
    """Render standardized Markdown dossier and return (markdown, sha256_hex)."""
    hdr_lines = "\n".join(f"- **{k}:** `{v}`" for k, v in program.compliance_headers.items())
    if not hdr_lines:
        hdr_lines = f"- **User-Agent:** `{DEFAULT_PROBE_USER_AGENT}`"
    curl_hdr = " ".join(f'-H "{k}: {v}"' for k, v in program.compliance_headers.items())
    is_nxdomain = finding.http_status == 0 and "nxdomain" in (finding.evidence_snippet or "").lower()
    repro_cmd = (
        f"dig +short CNAME {finding.host}\ndig A {finding.cname_target or finding.host}"
        if is_nxdomain
        else f"dig +short CNAME {finding.host}\ncurl -i {curl_hdr} {finding.http_url}"
    )
    obs_status_line = (
        f"- **DNS Status:** `NXDOMAIN (Status: 3)` on `{finding.cname_target or finding.host}`"
        if is_nxdomain
        else f"- **HTTP Status:** `{finding.http_status}`"
    )
    md = (
        f"# VDP Submission Dossier: {finding.title}\n\n"
        f"- **Target Program:** {program.name} (`https://hackerone.com/{program.handle}`)\n"
        f"- **Disclosure Channel:** HackerOne VDP API\n"
        f"- **Researcher:** Carson Haynes (`@{DEFAULT_RESEARCHER_HANDLE}`) | Orbit Security\n"
        f"- **Affected Asset:** `{finding.host}` (Structured Scope ID: `{finding.structured_scope_id}`)\n"
        f"- **CNAME Target:** `{finding.cname_target or 'None'}`\n"
        f"- **Resolved A Records:** `{', '.join(finding.a_records) or 'None'}`\n"
        f"- **Severity:** `{finding.severity}`\n"
        f"- **Weakness ID:** `{finding.weakness_id or 'Unmapped'}`\n"
        f"- **Captured UTC:** `{finding.captured_utc}`\n"
        f"{hdr_lines}\n\n"
        f"## Summary\n\n"
        f"Non-destructive reconnaissance against in-scope asset `{finding.host}` identified `{finding.finding_type}` "
        f"({finding.evidence_snippet}). Only passive DNS queries and single bounded HTTP GET requests were performed; "
        f"no service claiming, modification, or bulk data retrieval occurred.\n\n"
        f"## Steps to Reproduce\n\n"
        f"```bash\n"
        f"{repro_cmd}\n"
        f"```\n\n"
        f"## Observed Evidence\n\n"
        f"{obs_status_line}\n"
        f"- **Matched Signature / Output:**\n"
        f"```text\n{finding.evidence_snippet}\n```\n\n"
        f"## Suggested Remediation\n\n"
        f"{finding.remediation}\n"
    )
    digest = hashlib.sha256(md.encode("utf-8")).hexdigest()
    return md, digest


def build_h1_report_payload(program: VdpProgram, finding: VdpFinding) -> Dict[str, Any]:
    """Construct HackerOne POST /v1/hackers/reports payload."""
    dossier_md, _ = render_vdp_dossier(program, finding)
    is_nxdomain = finding.http_status == 0 and "nxdomain" in (finding.evidence_snippet or "").lower()
    verification_note = (
        f"DNS CNAME to {finding.cname_target} returning NXDOMAIN (Status 3)"
        if is_nxdomain
        else f"{finding.http_url} (HTTP {finding.http_status})"
    )
    attrs: Dict[str, Any] = {
        "team_handle": program.handle,
        "title": finding.title,
        "vulnerability_information": dossier_md,
        "impact": (
            f"Unauthenticated external exposure ({finding.finding_type}) on in-scope asset {finding.host}, "
            f"verified non-destructively via {verification_note}."
        ),
        "severity_rating": finding.severity,
        "structured_scope_id": int(finding.structured_scope_id),
    }
    if finding.weakness_id and str(finding.weakness_id).isdigit():
        attrs["weakness_id"] = int(finding.weakness_id)
    return {"data": {"type": "report", "attributes": attrs}}


def _check_policy_exclusions(program: VdpProgram, finding: VdpFinding) -> Tuple[bool, str]:
    """Detect explicit out-of-scope or excluded-vulnerability language in program policy."""
    policy_low = (program.policy or "").lower()
    if not policy_low:
        return True, "No restrictive policy text found."

    host_low = finding.host.lower()
    for line in policy_low.splitlines():
        if host_low in line and any(
            tok in line for tok in ("out of scope", "out-of-scope", "ineligible", "excluded", "do not test")
        ):
            return False, f"Host '{finding.host}' explicitly mentioned near exclusion clause in policy."

    if finding.finding_type == "dangling_cname":
        if re.search(
            r"(?:subdomain\s+takeover|dangling\s+(?:dns|cname)).{0,80}(?:out\s+of\s+scope|not\s+eligible|ineligible|excluded)",
            policy_low,
            re.DOTALL,
        ):
            return False, "Policy marks subdomain takeover / dangling DNS out of scope or ineligible."
        if re.search(
            r"(?:(?:full\s+)?working\s+(?:proof[- ]of[- ]concept|poc)\b|(?:proof[- ]of[- ]concept|\bpoc\b).{0,80}(?:required|demonstrat)|without\s+(?:a\s+)?(?:full\s+)?(?:working\s+)?(?:proof[- ]of[- ]concept|poc)\b|passive\s+dns.{0,60}(?:not\s+accepted|insufficient|alone))",
            policy_low,
            re.DOTALL,
        ):
            return (
                False,
                "Policy requires active working takeover PoC; passive DNS/HTTP verification alone is insufficient.",
            )

    return True, "No policy exclusion match detected."


def _parse_critic_llm_json(raw: str) -> Optional[Dict[str, Any]]:
    text = (raw or "").strip()
    if not text:
        return None
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def infer_researcher_signal_floor(existing_reports: List[Dict[str, Any]]) -> Optional[float]:
    """Infer conservative 0.0 researcher Signal floor when reports include Informative/N/A with 0 resolved/triaged."""
    states = [
        str((r.get("attributes") or {}).get("state") or "").lower()
        for r in existing_reports
    ]
    if any(s in {"triaged", "resolved", "bounty"} for s in states):
        return None
    if any(s in {"informative", "not-applicable", "spam"} for s in states):
        return 0.0
    return None


def _record_manifest_entry(manifest_path: Path, entry: Dict[str, Any]) -> None:
    try:
        data: Dict[str, Any] = {}
        if manifest_path.exists():
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        dispatches = data.setdefault("vdp_hunter_dispatches", {})
        dispatches[entry["host"]] = {
            **entry,
            "recorded_utc": datetime.now(timezone.utc).isoformat(),
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Deep Module: HackerOneVdpHunter
# ---------------------------------------------------------------------------


class HackerOneVdpHunter:
    """Deep VDP reconnaissance, screening, quality-gating, and dossier dispatch module.

    All network and external I/O crosses injected transport adapters (`http`, `dns`,
    `h1`, `discovery`, `credentials_loader`), making the full pipeline deterministic
    and testable through this small high-level interface.
    """

    def __init__(
        self,
        *,
        http: Optional[HttpTransport] = None,
        dns: Optional[DnsTransport] = None,
        h1: Optional[HackerOneTransport] = None,
        discovery: Optional[SubdomainDiscoveryTransport] = None,
        credentials_loader: Optional[Callable[[Optional[Path]], Tuple[str, str]]] = None,
        takeover_detector: Optional[PassiveTakeoverDetector] = None,
        ct_monitor: Optional[CertificateTransparencyMonitor] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        log_stream: Optional[Any] = None,
    ) -> None:
        self._http: HttpTransport = http or UrllibHttpTransport()
        self._dns: DnsTransport = dns or CloudflareDohTransport()
        self._h1: HackerOneTransport = h1 or UrllibHackerOneTransport()
        self._ct_monitor = ct_monitor
        self._discovery: SubdomainDiscoveryTransport = discovery or MultiSourceSubdomainTransport(
            ct_monitor=ct_monitor
        )
        self._credentials_loader = credentials_loader or load_hackerone_credentials
        self._takeover_detector = takeover_detector or PassiveTakeoverDetector()
        self._sleep_fn = sleep_fn or time.sleep
        self._log_stream = log_stream

    def _log(self, message: str) -> None:
        stream = self._log_stream if self._log_stream is not None else sys.stderr
        print(message, file=stream, flush=True)

    # -- Program Hydration & Target Discovery -------------------------------

    def hydrate_program(
        self,
        raw_program: Dict[str, Any],
        auth_header: str,
        *,
        base_url: str = HACKERONE_API_BASE,
        check_graphql_kyc: bool = True,
        timeout: int = 15,
    ) -> Optional[VdpProgram]:
        """Load full policy, structured_scopes, weaknesses, and signal gates for a VDP."""
        attrs = raw_program.get("attributes") or {}
        handle = str(attrs.get("handle") or "").strip()
        if not handle:
            return None

        detail = self._h1.fetch_program_detail(
            handle, auth_header, base_url=base_url, timeout=timeout
        )
        d_attrs = detail.get("attributes") or attrs
        if d_attrs.get("offers_bounties") is not False:
            return None
        if str(d_attrs.get("submission_state") or "").lower() != "open":
            return None

        kyc_required = bool(d_attrs.get("i_must_verify_identity_to_submit") is True)
        if not kyc_required and check_graphql_kyc:
            gql_kyc = self._h1.fetch_program_kyc_status(handle, timeout=min(timeout, 10))
            if gql_kyc is True:
                kyc_required = True

        if kyc_required:
            return None

        scopes = self._h1.fetch_paginated(
            f"/v1/hackers/programs/{handle}/structured_scopes?page[size]=100",
            auth_header,
            base_url=base_url,
            max_items=200,
            timeout=timeout,
        )
        weaknesses = self._h1.fetch_paginated(
            f"/v1/hackers/programs/{handle}/weaknesses?page[size]=100",
            auth_header,
            base_url=base_url,
            max_items=200,
            timeout=timeout,
        )
        policy = str(d_attrs.get("policy") or "")
        target_signal: Optional[float] = None
        if check_graphql_kyc:
            gates = self._h1.fetch_program_graphql_gates(handle, timeout=min(timeout, 10))
            target_signal = gates.get("target_signal")
        return VdpProgram(
            handle=handle,
            name=str(d_attrs.get("name") or handle),
            offers_bounties=False,
            submission_state=str(d_attrs.get("submission_state") or "open"),
            i_must_verify_identity_to_submit=False,
            policy=policy,
            structured_scopes=scopes,
            weaknesses=weaknesses,
            compliance_headers=parse_compliance_headers(policy),
            target_signal=target_signal,
        )

    def discover_subdomains(
        self,
        root: str,
        *,
        cache_path: Path = DEFAULT_VDP_CT_CACHE_PATH,
        use_crtsh: bool = False,
        use_subfinder: bool = False,
        timeout: int = 10,
    ) -> Set[str]:
        """Discover subdomains passively via non-empty cache and injected discovery adapter."""
        clean_root = root.strip().lower().lstrip("*.").rstrip(".")
        cached = load_non_empty_ct_cache(cache_path, clean_root)
        if cached is not None:
            return set(cached)

        raw_names = self._discovery.discover(
            clean_root,
            use_crtsh=use_crtsh,
            use_subfinder=use_subfinder,
            timeout=timeout,
        )
        normalized = sorted(
            {
                s.strip().lower().lstrip("*.").rstrip(".")
                for s in raw_names
                if s and s.strip().lower().lstrip("*.").rstrip(".").endswith(f".{clean_root}")
            }
        )
        save_non_empty_ct_cache(cache_path, clean_root, normalized)
        return set(normalized)

    def discover_targets(
        self,
        program: VdpProgram,
        *,
        existing_reports: List[Dict[str, Any]],
        vdp_ready_dir: Path = DEFAULT_VDP_READY_DIR,
        covered_domains: Optional[Set[str]] = None,
        include_covered: bool = False,
        max_wildcards_per_program: int = 5,
        max_subdomains: int = 25,
        cache_path: Path = DEFAULT_VDP_CT_CACHE_PATH,
        use_crtsh: bool = False,
        use_subfinder: bool = False,
    ) -> TargetDiscoveryResult:
        """Resolve in-scope, deduplicated wildcard & explicit target hosts for a VDP program."""
        active_covered = covered_domains if covered_domains is not None else set()
        existing_files = list(vdp_ready_dir.glob("*.md")) if vdp_ready_dir.exists() else []

        roots = extract_wildcard_roots(program)
        if not include_covered:
            roots = [r for r in roots if r not in active_covered]

        explicit_non_wildcard = {
            normalize_scope_host(str((s.get("attributes") or {}).get("asset_identifier") or ""))
            for s in program.structured_scopes
            if (s.get("attributes") or {}).get("eligible_for_submission") is True
            and str((s.get("attributes") or {}).get("asset_type") or "").upper() in {"URL", "DOMAIN"}
        }
        explicit_hosts = extract_explicit_scope_hosts(program.structured_scopes)
        if not include_covered:
            explicit_hosts = [
                h
                for h in explicit_hosts
                if h in explicit_non_wildcard or h not in active_covered
            ]

        if not roots and not explicit_hosts:
            return TargetDiscoveryResult(
                program_handle=program.handle,
                wildcards_scanned=[],
                explicit_hosts_scanned=[],
                hosts_to_screen=[],
                total_explicit_candidates=0,
            )

        hosts_to_screen: List[str] = []
        seen_hosts: Set[str] = set()
        explicit_hosts_scanned: List[str] = []
        wildcards_scanned: List[str] = []

        explicit_cap = max(0, max_subdomains * 2)
        explicit_added = 0
        for host in explicit_hosts:
            if explicit_added >= explicit_cap:
                break
            if host in seen_hosts:
                continue
            if is_duplicate_finding(host, existing_reports, existing_files):
                continue
            if match_structured_scope(host, program.structured_scopes) is None:
                continue
            seen_hosts.add(host)
            hosts_to_screen.append(host)
            explicit_hosts_scanned.append(f"{program.handle}:{host}")
            explicit_added += 1

        for root in roots[:max_wildcards_per_program]:
            wildcards_scanned.append(f"{program.handle}:*.{root}")
            discovered = self.discover_subdomains(
                root,
                cache_path=cache_path,
                use_crtsh=use_crtsh,
                use_subfinder=use_subfinder,
            )
            candidates = _prioritize_subdomains(discovered, root, max_subdomains)
            for host in candidates:
                if host in seen_hosts:
                    continue
                if is_duplicate_finding(host, existing_reports, existing_files):
                    continue
                if match_structured_scope(host, program.structured_scopes) is None:
                    continue
                seen_hosts.add(host)
                hosts_to_screen.append(host)

        return TargetDiscoveryResult(
            program_handle=program.handle,
            wildcards_scanned=wildcards_scanned,
            explicit_hosts_scanned=explicit_hosts_scanned,
            hosts_to_screen=hosts_to_screen,
            total_explicit_candidates=len(explicit_hosts),
        )

    # -- Host Screening -----------------------------------------------------

    def screen_target(
        self,
        program: VdpProgram,
        host: str,
        *,
        detector: Optional[PassiveTakeoverDetector] = None,
    ) -> Optional[VdpFinding]:
        """Screen a single in-scope host non-destructively across all high-signal detectors."""
        scope = match_structured_scope(host, program.structured_scopes)
        if not scope:
            return None

        scope_id = str(scope["id"])
        takeover_detector = detector or self._takeover_detector
        now_utc = datetime.now(timezone.utc).isoformat()

        cname_chain, cname_loop = resolve_dns_cname_chain_guarded(
            host, doh_lookup_fn=self._dns.resolve
        )
        cname_target = cname_chain[-1] if len(cname_chain) > 1 and not cname_loop else None
        a_resp = self._dns.resolve(host, "A")
        a_records = [
            str(ans.get("data") or "")
            for ans in (a_resp.get("Answer") or [])
            if ans.get("type") == 1 and ans.get("data")
        ]

        cname_is_nxdomain = False
        if cname_target and not cname_loop:
            target_a = self._dns.resolve(cname_target, "A")
            cname_is_nxdomain = target_a.get("Status") == 3

        http_status, _, body = self._http.fetch(
            f"https://{host}/", headers=program.compliance_headers, max_bytes=32768
        )
        probe_url = f"https://{host}/"
        if http_status == 0:
            probe_url = f"http://{host}/"
            http_status, _, body = self._http.fetch(
                probe_url, headers=program.compliance_headers, max_bytes=32768
            )

        # 1. Dangling CNAME screening
        if cname_target:
            takeover = takeover_detector.evaluate_cname(
                domain=host,
                cname_target=cname_target,
                body_snippet=body,
                is_nxdomain=cname_is_nxdomain,
            )
            if takeover:
                claimable, _ = check_takeover_claimability(
                    takeover.provider,
                    cname_target,
                    body,
                    host=host,
                    dns_transport=self._dns,
                    http_transport=self._http,
                )
                if not claimable:
                    takeover = None
            if takeover:
                return VdpFinding(
                    program_handle=program.handle,
                    program_name=program.name,
                    host=host,
                    finding_type="dangling_cname",
                    title=f"Dangling DNS CNAME to Unattached {takeover.provider} Endpoint on {host}",
                    severity="medium",
                    weakness_id=select_weakness_id("dangling_cname", program.weaknesses),
                    structured_scope_id=scope_id,
                    cname_target=cname_target,
                    a_records=a_records,
                    http_status=http_status,
                    http_url=probe_url,
                    evidence_snippet=takeover.fingerprint_matched,
                    remediation=takeover.remediation,
                    captured_utc=now_utc,
                    provider=takeover.provider,
                )

        # 2. Open bucket XML listing on root
        bucket = check_open_bucket_listing(probe_url, http_status, body)
        if bucket:
            return VdpFinding(
                program_handle=program.handle,
                program_name=program.name,
                host=host,
                finding_type="open_bucket",
                title=f"Open Public Cloud Storage Bucket ({bucket['bucket_name']}) Directory Listing on {host}",
                severity="medium",
                weakness_id=select_weakness_id("open_bucket", program.weaknesses),
                structured_scope_id=scope_id,
                cname_target=cname_target,
                a_records=a_records,
                http_status=http_status,
                http_url=probe_url,
                evidence_snippet=f"<ListBucketResult><Name>{bucket['bucket_name']}</Name> sample_keys={bucket['sample_keys']}",
                remediation="Disable public bucket listing (ListBucket) for allUsers/anonymous principals.",
                captured_utc=now_utc,
                provider=CloudBucketTakeoverSentinel.identify_provider_from_cname(cname_target or "")
                or "Cloud Storage",
                extra=bucket,
            )

        # 3. Exposed sensitive files
        if http_status > 0:
            base_root = probe_url.rstrip("/")
            spa_catchall_detected = False
            skip_remaining_actuators = False
            for sensitive_path in SENSITIVE_EXPOSURE_PATHS:
                if spa_catchall_detected and sensitive_path != "/server-status":
                    continue
                if skip_remaining_actuators and sensitive_path.startswith("/actuator/"):
                    continue
                path_max_bytes = (
                    16384
                    if sensitive_path in {"/server-status", "/actuator/mappings", "/actuator/beans"}
                    else 8192
                )
                s_code, _, s_body = self._http.fetch(
                    f"{base_root}{sensitive_path}",
                    headers=program.compliance_headers,
                    max_bytes=path_max_bytes,
                )
                if s_code == 0:
                    break
                if sensitive_path == "/.git/HEAD" and s_code == 200 and HTML_LOOKALIKE_RE.match(s_body or ""):
                    spa_catchall_detected = True
                if sensitive_path == "/actuator/env" and (
                    s_code != 200 or HTML_LOOKALIKE_RE.match(s_body or "")
                ):
                    skip_remaining_actuators = True
                leak = check_exposed_config_or_git(sensitive_path, s_code, s_body)
                if leak:
                    ftype = leak["finding_type"]
                    sev = str(
                        leak.get("severity")
                        or (
                            "high"
                            if ftype in {"exposed_env", "exposed_aws_credentials", "exposed_backup_config"}
                            else "medium"
                        )
                    )
                    if ftype == "exposed_server_status":
                        leak_title = f"Exposed {sensitive_path} Apache Server Status Disclosure on {host}"
                    elif ftype == "exposed_actuator":
                        leak_title = f"Exposed {sensitive_path} Spring Actuator Endpoint on {host}"
                    else:
                        leak_title = f"Exposed {sensitive_path} Sensitive Configuration File on {host}"
                    return VdpFinding(
                        program_handle=program.handle,
                        program_name=program.name,
                        host=host,
                        finding_type=ftype,
                        title=leak_title,
                        severity=sev,
                        weakness_id=select_weakness_id(ftype, program.weaknesses),
                        structured_scope_id=scope_id,
                        cname_target=cname_target,
                        a_records=a_records,
                        http_status=s_code,
                        http_url=f"{base_root}{sensitive_path}",
                        evidence_snippet=leak["snippet"],
                        remediation=f"Block public web access to {sensitive_path} and rotate any exposed secrets.",
                        captured_utc=now_utc,
                    )

            # 4. Hardcoded high-confidence secrets in root body or 1 referenced same-origin JS bundle
            js_bundle_url: Optional[str] = None
            js_bundle_status = 0
            js_bundle_body = ""
            body_low = (body or "").lower()
            is_html_root = (
                http_status == 200
                and bool(body)
                and ("<script" in body_low or "<html" in body_low or "<!doctype" in body_low)
            )
            payload_anchors: List[Any] = []
            if is_html_root:
                script_urls = extract_same_origin_script_urls(probe_url, body, limit=1)
                if script_urls:
                    js_bundle_url = script_urls[0]
                    js_bundle_status, _, js_bundle_body = self._http.fetch(
                        js_bundle_url,
                        headers=program.compliance_headers,
                        max_bytes=65536,
                    )
                    if js_bundle_body and len(js_bundle_body.encode("utf-8")) >= 50000:
                        payload_anchors.extend(
                            compress_vdp_payload_anchors(
                                js_bundle_body,
                                content_type="application/javascript",
                                url=js_bundle_url,
                            )
                        )

            if body and len(body.encode("utf-8")) >= 50000:
                payload_anchors.extend(
                    compress_vdp_payload_anchors(body, content_type="text/html", url=probe_url)
                )

            secret_hit = scan_text_for_high_confidence_secrets(probe_url, http_status, body)
            secret_status = http_status
            if secret_hit is None and js_bundle_url and js_bundle_status == 200 and js_bundle_body:
                secret_hit = scan_text_for_high_confidence_secrets(
                    js_bundle_url, js_bundle_status, js_bundle_body
                )
                secret_status = js_bundle_status

            if secret_hit:
                return VdpFinding(
                    program_handle=program.handle,
                    program_name=program.name,
                    host=host,
                    finding_type="exposed_js_secret",
                    title=f"Exposed Hardcoded {secret_hit.get('secret_type', 'Secret')} on {host}",
                    severity=str(secret_hit.get("severity") or "high"),
                    weakness_id=select_weakness_id("exposed_js_secret", program.weaknesses),
                    structured_scope_id=scope_id,
                    cname_target=cname_target,
                    a_records=a_records,
                    http_status=secret_status,
                    http_url=secret_hit["source_url"],
                    evidence_snippet=secret_hit["snippet"],
                    remediation="Revoke and rotate the exposed credential immediately and move secret handling server-side.",
                    captured_utc=now_utc,
                    extra={
                        "secret_type": secret_hit.get("secret_type"),
                        "source_url": secret_hit["source_url"],
                    },
                )

            # 5. Referenced cloud storage buckets / Firebase RTDB URLs
            cloud_refs_with_origin: List[Tuple[Dict[str, str], str]] = [
                (ref, probe_url) for ref in extract_cloud_urls_from_text(body)
            ]
            seen_cloud_keys = {
                (ref["provider"], ref["bucket_or_project"]) for ref, _ in cloud_refs_with_origin
            }
            if js_bundle_body and js_bundle_url:
                for ref in extract_cloud_urls_from_text(js_bundle_body):
                    c_key = (ref["provider"], ref["bucket_or_project"])
                    if c_key not in seen_cloud_keys:
                        seen_cloud_keys.add(c_key)
                        cloud_refs_with_origin.append((ref, js_bundle_url))

            for ref, ref_origin in cloud_refs_with_origin[:2]:
                c_url = ref["probe_url"]
                c_status, _, c_body = self._http.fetch(c_url, max_bytes=16384, timeout=5)
                cloud_hit = evaluate_cloud_reference_response(ref, c_status, c_body)
                if not cloud_hit:
                    continue
                ftype = cloud_hit["finding_type"]
                if ftype == "open_bucket":
                    non_pub, _ = is_bucket_listing_non_public(cloud_hit.get("sample_keys") or [])
                    if not non_pub:
                        continue
                if ftype == "dangling_referenced_bucket":
                    c_title = (
                        f"Dangling Referenced {cloud_hit['provider']} Bucket "
                        f"({cloud_hit['bucket_or_project']}) on {host}"
                    )
                    c_remediation = (
                        f"Remove the stale cloud storage reference to {c_url} or re-claim the "
                        f"unallocated {cloud_hit['provider']} bucket."
                    )
                elif ftype == "exposed_firebase_db":
                    c_title = (
                        f"Unauthenticated Exposed Firebase Realtime Database "
                        f"({cloud_hit['bucket_or_project']}) Referenced on {host}"
                    )
                    c_remediation = (
                        "Restrict Firebase Realtime Database security rules to disallow unauthenticated "
                        "public read access (require auth != null)."
                    )
                else:
                    c_title = (
                        f"Open Public Cloud Storage Bucket ({cloud_hit['bucket_or_project']}) "
                        f"Referenced on {host}"
                    )
                    c_remediation = (
                        "Disable public bucket listing (ListBucket) for anonymous/allUsers principals."
                    )
                c_snippet = cloud_hit["snippet"]
                if ref_origin != probe_url:
                    c_snippet = f"{c_snippet} (referenced on {ref_origin})"
                return VdpFinding(
                    program_handle=program.handle,
                    program_name=program.name,
                    host=host,
                    finding_type=ftype,
                    title=c_title,
                    severity=str(cloud_hit.get("severity") or "medium"),
                    weakness_id=select_weakness_id(ftype, program.weaknesses),
                    structured_scope_id=scope_id,
                    cname_target=cname_target,
                    a_records=a_records,
                    http_status=c_status,
                    http_url=c_url,
                    evidence_snippet=c_snippet,
                    remediation=c_remediation,
                    captured_utc=now_utc,
                    provider=cloud_hit.get("provider") or ref.get("provider"),
                    extra={
                        "referenced_from": ref_origin,
                        "cloud_probe_url": c_url,
                        "source_url": cloud_hit.get("source_url") or ref.get("source_url"),
                        "bucket_or_project": cloud_hit.get("bucket_or_project"),
                        "sample_keys": cloud_hit.get("sample_keys") or [],
                    },
                )

            # 6. High-signal credentialed CORS reflection on JSON, api* hosts, or CORS-anchored payloads
            trimmed_root = (body or "").lstrip()
            looks_like_json = trimmed_root.startswith(("{", "["))
            has_cors_anchor = any(
                (getattr(a, "concept", "").startswith("CORS_") or "cors" in getattr(a, "tags", []))
                for a in payload_anchors
            )
            if http_status == 200 and (looks_like_json or "api" in host.lower() or has_cors_anchor):
                cors_origin = "https://untrusted-adversary.example"
                cors_req_headers = {**program.compliance_headers, "Origin": cors_origin}
                cors_status, cors_resp_headers, cors_body = self._http.fetch(
                    probe_url,
                    headers=cors_req_headers,
                    max_bytes=16384,
                    timeout=5,
                )
                cors_hit = evaluate_cors_response(
                    probe_url, cors_origin, cors_status, cors_resp_headers, cors_body
                )
                if cors_hit:
                    return VdpFinding(
                        program_handle=program.handle,
                        program_name=program.name,
                        host=host,
                        finding_type="cors_credentialed_reflection",
                        title=f"Credentialed Arbitrary-Origin CORS Reflection on {host}",
                        severity=str(cors_hit.get("severity") or "medium"),
                        weakness_id=select_weakness_id("cors_credentialed_reflection", program.weaknesses),
                        structured_scope_id=scope_id,
                        cname_target=cname_target,
                        a_records=a_records,
                        http_status=cors_status,
                        http_url=probe_url,
                        evidence_snippet=cors_hit["snippet"],
                        remediation=(
                            "Enforce a strict allowlist of trusted origins for Access-Control-Allow-Origin "
                            "and never reflect untrusted Origin headers with Access-Control-Allow-Credentials: true."
                        ),
                        captured_utc=now_utc,
                        extra={"tested_origin": cors_origin},
                    )

        return None

    # -- Quality Gate & Live Re-Verification --------------------------------

    def _reverify_live(self, finding: VdpFinding, program: VdpProgram) -> Tuple[bool, str]:
        """Perform an independent live DNS + HTTP re-probe via injected adapters."""
        is_nxdomain_cname = (
            finding.finding_type == "dangling_cname"
            and "nxdomain" in (finding.evidence_snippet or "").lower()
        )
        if finding.finding_type == "dangling_cname" and finding.cname_target:
            cname_resp = self._dns.resolve(finding.host, "CNAME", timeout=5)
            cnames = [
                str(ans.get("data") or "").rstrip(".").lower()
                for ans in (cname_resp.get("Answer") or [])
                if ans.get("type") == 5 and ans.get("data")
            ]
            if finding.cname_target.lower().rstrip(".") not in cnames:
                return False, f"Re-probe DNS CNAME mismatch: expected {finding.cname_target}, got {cnames}."

        if is_nxdomain_cname:
            target_a = self._dns.resolve(finding.cname_target or "", "A", timeout=5)
            if target_a.get("Status") != 3:
                return (
                    False,
                    f"Re-probe CNAME target {finding.cname_target} is no longer NXDOMAIN (Status={target_a.get('Status')}).",
                )
            host_a = self._dns.resolve(finding.host, "A", timeout=5)
            if host_a.get("Status") != 3:
                return (
                    False,
                    f"Re-probe host {finding.host} A lookup is no longer NXDOMAIN (Status={host_a.get('Status')}).",
                )
            claimable, claim_reason = check_takeover_claimability(
                finding.provider,
                finding.cname_target,
                "",
                host=finding.host,
                dns_transport=self._dns,
                http_transport=self._http,
            )
            if not claimable:
                return False, f"Re-probe claimability check failed: {claim_reason}"
            return True, f"Live DNS re-probe confirmed CNAME -> {finding.cname_target} (NXDOMAIN)."

        parsed_url = urllib.parse.urlparse(finding.http_url or "")
        is_target_host = (parsed_url.hostname or "").lower() == finding.host.lower()
        req_headers = dict(program.compliance_headers) if is_target_host else {}
        tested_origin = str((finding.extra or {}).get("tested_origin") or "https://untrusted-adversary.example")
        if finding.finding_type == "cors_credentialed_reflection":
            req_headers["Origin"] = tested_origin

        reprobe_max_bytes = 65536 if finding.finding_type == "exposed_js_secret" else 16384
        status, resp_headers, body = self._http.fetch(
            finding.http_url,
            headers=req_headers,
            max_bytes=reprobe_max_bytes,
            timeout=5,
        )
        if status == 0:
            return False, f"Re-probe HTTP request failed to connect to {finding.http_url}."
        if status != finding.http_status:
            return False, f"Re-probe HTTP status drifted: expected {finding.http_status}, got {status}."

        if finding.finding_type == "open_bucket":
            body_low = body.lower()
            if (
                "<listbucketresult" not in body_low
                and "<listallmybucketsresult" not in body_low
                and "<enumerationresults" not in body_low
            ):
                return False, "Re-probe no longer returns XML <ListBucketResult> or <EnumerationResults>."
        elif finding.finding_type in {"dangling_referenced_bucket", "exposed_firebase_db"}:
            extra = finding.extra or {}
            ref = {
                "provider": finding.provider or "",
                "bucket_or_project": str(extra.get("bucket_or_project") or ""),
                "probe_url": finding.http_url,
                "source_url": str(extra.get("source_url") or ""),
            }
            cloud_hit = evaluate_cloud_reference_response(ref, status, body)
            if cloud_hit is None or cloud_hit.get("finding_type") != finding.finding_type:
                return False, f"Re-probe no longer confirms {finding.finding_type} at {finding.http_url}."
        elif finding.finding_type in {
            "exposed_git",
            "exposed_svn",
            "exposed_ds_store",
            "exposed_server_status",
            "exposed_env",
            "exposed_actuator",
            "exposed_aws_credentials",
            "exposed_backup_config",
        }:
            parsed_path = parsed_url.path or "/"
            if check_exposed_config_or_git(parsed_path, status, body) is None:
                return False, f"Re-probe no longer matches exposed signature at {parsed_path}."
        elif finding.finding_type == "cors_credentialed_reflection":
            if evaluate_cors_response(finding.http_url, tested_origin, status, resp_headers, body) is None:
                return False, "Re-probe no longer reflects credentialed CORS Origin on non-empty JSON."
        elif finding.finding_type == "exposed_js_secret":
            if scan_text_for_high_confidence_secrets(finding.http_url, status, body) is None:
                return False, f"Re-probe no longer detects high-confidence secret in {finding.http_url}."
        elif finding.finding_type == "dangling_cname":
            if finding.evidence_snippet.lower() not in body.lower():
                return False, f"Re-probe body missing takeover fingerprint '{finding.evidence_snippet}'."
            claimable, claim_reason = check_takeover_claimability(
                finding.provider,
                finding.cname_target,
                body,
                host=finding.host,
                dns_transport=self._dns,
                http_transport=self._http,
            )
            if not claimable:
                return False, f"Re-probe claimability check failed: {claim_reason}"

        return True, f"Live re-probe confirmed HTTP {status} and matching signature."

    def evaluate_quality_gate(
        self,
        program: VdpProgram,
        finding: VdpFinding,
        *,
        reverify_runs: int = 2,
        critic_runs: int = 3,
        critic_quorum: Optional[int] = None,
        skip_live_reverify: bool = False,
        use_ollama_critic: bool = False,
        critic_model: str = "orbit-critic:latest",
        ollama_timeout: float = 45.0,
        ollama_fn: Optional[Callable[[str, int, str], str]] = None,
        reject_passive_saas_cname: bool = False,
        reverify_sleep_seconds: float = 0.5,
        reverify_fn: Optional[Callable[[VdpFinding, VdpProgram], Tuple[bool, str]]] = None,
    ) -> QualityGateResult:
        """Run multi-pass re-verification, deterministic grounding, and adversarial critic quorum."""
        blocking_reasons: List[str] = []
        required_quorum = critic_quorum if critic_quorum is not None else critic_runs
        reprobe_fn = reverify_fn or self._reverify_live

        # Stage A: Live persistence re-verification runs
        reverify_passes = 0
        if skip_live_reverify:
            reverify_passes = reverify_runs
        else:
            for idx in range(max(1, reverify_runs)):
                ok, reason = reprobe_fn(finding, program)
                if ok:
                    reverify_passes += 1
                else:
                    blocking_reasons.append(f"REVERIFY_RUN_{idx + 1}_FAILED: {reason}")
                if idx + 1 < reverify_runs and reverify_sleep_seconds > 0:
                    self._sleep_fn(reverify_sleep_seconds)

        # Stage B: Deterministic Policy, Scope & Hallucination Critic
        scope_match = match_structured_scope(finding.host, program.structured_scopes)
        scope_ok = scope_match is not None and str(scope_match.get("id")) == str(finding.structured_scope_id)
        valid_weakness_ids = {str(w.get("id")) for w in program.weaknesses if w.get("id") is not None}
        weakness_ok = (not valid_weakness_ids) or (str(finding.weakness_id) in valid_weakness_ids)
        policy_ok, policy_msg = _check_policy_exclusions(program, finding)

        snippet_low = (finding.evidence_snippet or "").lower()
        not_parked = not any(marker in snippet_low for marker in _PARKED_DOMAIN_MARKERS)
        non_html_evidence_types = {
            "open_bucket",
            "dangling_referenced_bucket",
            "exposed_firebase_db",
            "cors_credentialed_reflection",
            "exposed_js_secret",
            "exposed_git",
            "exposed_svn",
            "exposed_ds_store",
            "exposed_env",
            "exposed_actuator",
            "exposed_aws_credentials",
            "exposed_backup_config",
        }
        evidence_non_trivial = (
            len((finding.evidence_snippet or "").strip()) >= 8
            and not HTML_LOOKALIKE_RE.match(finding.evidence_snippet or "")
            if finding.finding_type in non_html_evidence_types
            else len((finding.evidence_snippet or "").strip()) >= 8
        )

        material_ok = True
        material_reason = "Material security impact verified."
        if finding.finding_type == "open_bucket":
            sample_keys = (finding.extra or {}).get("sample_keys") or []
            material_ok, material_reason = is_bucket_listing_non_public(sample_keys)
        elif reject_passive_saas_cname and finding.finding_type == "dangling_cname":
            prov_low = (finding.provider or "").lower()
            host_low = finding.host.lower()
            if any(p in prov_low for p in _PASSIVE_SAAS_CNAME_PROVIDERS) or host_low.startswith(
                _MARKETING_HOST_PREFIXES
            ):
                material_ok = False
                material_reason = (
                    "Passive SaaS/marketing dangling CNAME without working claimed PoC carries high Informative risk."
                )

        dossier_md, _ = self.render_dossier(program, finding)
        artifact_id = compute_evidence_digest(
            target=finding.http_url,
            status_code=finding.http_status,
            flaw_type=finding.finding_type,
            evidence_snippet=finding.evidence_snippet,
            provider=finding.provider or program.name,
        )
        parsed_http_path = urllib.parse.urlparse(finding.http_url or "").path
        endpoint_path = parsed_http_path if parsed_http_path not in {"", "/"} else None
        artifact = EmpiricalEvidenceArtifact(
            artifact_id=artifact_id,
            target=finding.http_url,
            status_code=finding.http_status,
            flaw_type=finding.finding_type,
            evidence_snippet=finding.evidence_snippet,
            provider=finding.provider or program.name,
            endpoint_path=endpoint_path,
        )
        core_flaw_label = {
            "dangling_cname": "cname takeover",
            "open_bucket": "cloud_storage listbucket",
            "dangling_referenced_bucket": "cloud_storage dangling bucket",
            "exposed_firebase_db": "firebase database exposure",
            "cors_credentialed_reflection": "cors credentialed reflection",
            "exposed_js_secret": "js secret exposure",
            "exposed_git": "git exposure",
            "exposed_svn": "svn exposure",
            "exposed_ds_store": "ds_store exposure",
            "exposed_server_status": "server_status exposure",
            "exposed_env": "env configuration exposure",
            "exposed_actuator": "spring actuator exposure",
            "exposed_aws_credentials": "aws credential exposure",
            "exposed_backup_config": "backup configuration exposure",
        }.get(finding.finding_type, finding.finding_type)
        verifier_res = ReportCriticVerifier.verify_briefing_pitch(
            dossier_md,
            target_domain=finding.host,
            core_finding=core_flaw_label,
            artifacts=[artifact],
            require_artifact_grounding=True,
        )

        deterministic_checks = {
            "is_vdp_non_bounty": program.offers_bounties is False,
            "is_kyc_free": program.i_must_verify_identity_to_submit is False,
            "is_submission_open": program.submission_state.lower() == "open",
            "scope_eligible": scope_ok,
            "weakness_valid": weakness_ok,
            "policy_not_excluded": policy_ok,
            "not_parked_domain": not_parked,
            "evidence_worthy": evidence_non_trivial,
            "material_security_impact": material_ok,
            "report_critic_grounded": verifier_res.passed,
            "reverification_persistent": reverify_passes == max(1, reverify_runs),
        }

        for chk_name, passed_flag in deterministic_checks.items():
            if not passed_flag:
                if chk_name == "policy_not_excluded":
                    detail = policy_msg
                elif chk_name == "material_security_impact":
                    detail = material_reason
                elif chk_name == "report_critic_grounded":
                    detail = "; ".join(verifier_res.reasons)
                else:
                    detail = chk_name
                blocking_reasons.append(f"CHECK_FAILED[{chk_name}]: {detail}")

        # Stage C: Multi-Run Adversarial Critic Quorum
        critic_run_results: List[Dict[str, Any]] = []
        critic_passes = 0
        critic_rejections = 0

        for idx in range(max(1, critic_runs)):
            persona_name, persona_focus = _CRITIC_PERSONAS[idx % len(_CRITIC_PERSONAS)]
            run_reasons: List[str] = []
            run_verdict = "PASS"
            run_confidence = 0.92
            engine = "deterministic_rubric"

            if idx % 3 == 0:
                if not (
                    deterministic_checks["is_vdp_non_bounty"]
                    and deterministic_checks["is_kyc_free"]
                    and deterministic_checks["scope_eligible"]
                    and deterministic_checks["policy_not_excluded"]
                ):
                    run_verdict = "REJECT"
                    run_reasons.append("Scope, VDP/KYC gate, or policy exclusion check failed.")
            elif idx % 3 == 1:
                if not (
                    deterministic_checks["not_parked_domain"]
                    and deterministic_checks["evidence_worthy"]
                    and deterministic_checks["material_security_impact"]
                    and deterministic_checks["reverification_persistent"]
                ):
                    run_verdict = "REJECT"
                    run_reasons.append(
                        material_reason
                        if not deterministic_checks["material_security_impact"]
                        else "High false-positive / Informative risk: weak evidence, parked page, or non-persistent probe."
                    )
            else:
                if not (deterministic_checks["report_critic_grounded"] and deterministic_checks["weakness_valid"]):
                    run_verdict = "REJECT"
                    run_reasons.append("Evidence grounding or weakness mapping failed verification.")

            if run_verdict == "PASS" and (use_ollama_critic or ollama_fn is not None):
                prompt = (
                    f"You are '{persona_name}'. Focus: {persona_focus}\n"
                    f"Evaluate this HackerOne VDP submission candidate for false positives or Informative/N/A risk. "
                    f"Reject passive marketing/SaaS CNAMEs lacking PoC or intended static CDN open buckets.\n"
                    f"Program: {program.handle} (offers_bounties={program.offers_bounties})\n"
                    f"Asset: {finding.host} (scope_id={finding.structured_scope_id})\n"
                    f"Type: {finding.finding_type} | URL: {finding.http_url} | CNAME: {finding.cname_target} | HTTP: {finding.http_status}\n"
                    f"Evidence: {finding.evidence_snippet[:400]}\n"
                    'Reply ONLY with JSON: {"verdict": "PASS" or "REJECT", "confidence": 0.0-1.0, "reason": "..."}'
                )
                raw_llm = (
                    ollama_fn(prompt, idx + 1, persona_name)
                    if ollama_fn is not None
                    else GemmaTriageCopilot.query_local_gemma(
                        prompt, model_name=critic_model, timeout=ollama_timeout
                    )
                )
                parsed = _parse_critic_llm_json(raw_llm or "")
                if parsed is not None:
                    engine = f"ollama:{critic_model}" if ollama_fn is None else "custom_critic"
                    llm_verdict = str(parsed.get("verdict") or "REJECT").upper()
                    run_confidence = float(parsed.get("confidence") or 0.8)
                    llm_reason = str(parsed.get("reason") or "").strip()
                    if llm_verdict != "PASS":
                        run_verdict = "REJECT"
                        run_reasons.append(llm_reason or "Rejected by adversarial critic model.")
                    elif llm_reason:
                        run_reasons.append(llm_reason)
                else:
                    engine = "deterministic_fallback_on_llm_timeout"
                    run_reasons.append("LLM critic unavailable/timed out; deterministic rubric passed.")

            if run_verdict == "PASS":
                critic_passes += 1
            else:
                critic_rejections += 1
                blocking_reasons.extend(f"CRITIC_RUN_{idx + 1}[{persona_name}]: {r}" for r in run_reasons)

            critic_run_results.append(
                {
                    "run_index": idx + 1,
                    "persona": persona_name,
                    "engine": engine,
                    "verdict": run_verdict,
                    "confidence": round(run_confidence, 2),
                    "reasons": run_reasons or ["All checks passed."],
                }
            )

        all_det_ok = all(deterministic_checks.values())
        passed = all_det_ok and critic_rejections == 0 and critic_passes >= required_quorum
        return QualityGateResult(
            passed=passed,
            verdict="APPROVED" if passed else "REJECTED",
            reverification_passes=reverify_passes,
            reverification_runs=max(1, reverify_runs),
            deterministic_checks=deterministic_checks,
            critic_runs=critic_run_results,
            critic_passes=critic_passes,
            critic_total=len(critic_run_results),
            critic_rejections=critic_rejections,
            evidence_artifact_id=artifact_id,
            blocking_reasons=blocking_reasons,
        )

    # -- Dossier Rendering & Dispatch ---------------------------------------

    def render_dossier(self, program: VdpProgram, finding: VdpFinding) -> Tuple[str, str]:
        """Render standardized Markdown dossier and return (markdown, sha256_hex)."""
        return render_vdp_dossier(program, finding)

    def dispatch_finding(
        self,
        program: VdpProgram,
        finding: VdpFinding,
        username: str,
        api_token: str,
        *,
        dry_run: bool = True,
        existing_reports: Optional[List[Dict[str, Any]]] = None,
        vdp_ready_dir: Path = DEFAULT_VDP_READY_DIR,
        manifest_path: Path = DEFAULT_MANIFEST_PATH,
        base_url: str = HACKERONE_API_BASE,
        timeout: int = 20,
        quality_gate: Optional[QualityGateResult] = None,
        reverify_runs: int = 2,
        critic_runs: int = 3,
        skip_live_reverify: bool = False,
        use_ollama_critic: bool = False,
        critic_model: str = "orbit-critic:latest",
        researcher_signal: Optional[float] = None,
        reject_passive_saas_cname: bool = False,
        reverify_sleep_seconds: float = 0.5,
    ) -> Dict[str, Any]:
        """Enforce KYC/VDP/signal/duplicate/quality gates, POST via HackerOne transport, and stage dossier."""
        if program.offers_bounties:
            return {"status": "BLOCKED_BBP_NOT_VDP", "host": finding.host, "program": program.handle}
        if program.i_must_verify_identity_to_submit:
            return {"status": "BLOCKED_KYC_REQUIRED", "host": finding.host, "program": program.handle}
        if program.submission_state.lower() != "open":
            return {"status": "BLOCKED_SUBMISSION_CLOSED", "host": finding.host, "program": program.handle}

        auth_header = build_auth_header(username, api_token)
        reports = (
            existing_reports
            if existing_reports is not None
            else self._h1.fetch_paginated(
                "/v1/hackers/me/reports?page[size]=100",
                auth_header,
                base_url=base_url,
                max_items=200,
                timeout=timeout,
            )
        )
        effective_signal = (
            researcher_signal if researcher_signal is not None else infer_researcher_signal_floor(reports)
        )
        if (
            effective_signal is not None
            and program.target_signal is not None
            and effective_signal < program.target_signal
        ):
            return {
                "status": "BLOCKED_SIGNAL_REQUIREMENT",
                "host": finding.host,
                "program": program.handle,
                "required_signal": program.target_signal,
                "researcher_signal": effective_signal,
            }
        existing_files = list(vdp_ready_dir.glob("*.md")) if vdp_ready_dir.exists() else []
        if is_duplicate_finding(finding.host, reports, existing_files):
            return {"status": "DUPLICATE_ABORTED", "host": finding.host, "program": program.handle}

        gate = quality_gate or self.evaluate_quality_gate(
            program,
            finding,
            reverify_runs=reverify_runs,
            critic_runs=critic_runs,
            skip_live_reverify=skip_live_reverify,
            use_ollama_critic=use_ollama_critic,
            critic_model=critic_model,
            reject_passive_saas_cname=reject_passive_saas_cname,
            reverify_sleep_seconds=reverify_sleep_seconds,
        )
        if not gate.passed:
            return {
                "status": "BLOCKED_QUALITY_GATE",
                "host": finding.host,
                "program": program.handle,
                "quality_gate": asdict(gate),
            }

        payload = build_h1_report_payload(program, finding)
        if dry_run:
            return {
                "status": "DRY_RUN_READY",
                "host": finding.host,
                "program": program.handle,
                "quality_gate": asdict(gate),
                "payload": payload,
            }

        dossier_md, digest = self.render_dossier(program, finding)
        host_slug = finding.host.replace(".", "_")
        dossier_path = vdp_ready_dir / f"{program.handle}_vdp_{host_slug}.md"

        http_status, resp_payload, raw_err = self._h1.post_report(
            payload, auth_header, base_url=base_url, timeout=timeout
        )
        if 200 <= http_status < 300:
            vdp_ready_dir.mkdir(parents=True, exist_ok=True)
            dossier_path.write_text(dossier_md, encoding="utf-8")
            created = resp_payload.get("data") or {}
            report_id = str(created.get("id") or "")
            attrs = created.get("attributes") or {}
            result = {
                "status": "SUBMITTED",
                "http_status": http_status,
                "report_id": report_id,
                "report_url": f"https://hackerone.com/reports/{report_id}" if report_id else None,
                "state": attrs.get("state"),
                "host": finding.host,
                "program": program.handle,
                "dossier_path": str(dossier_path),
                "report_sha256": digest,
                "quality_gate": asdict(gate),
            }
            _record_manifest_entry(manifest_path, result)
            return result

        if http_status in (400, 403):
            blocked_dir = vdp_ready_dir.parent / "vdp_blocked"
            blocked_dir.mkdir(parents=True, exist_ok=True)
            blocked_path = blocked_dir / f"{program.handle}_vdp_{host_slug}.md"
            blocked_path.write_text(dossier_md, encoding="utf-8")
        else:
            blocked_path = None

        if http_status == 400 and "id_verification" in raw_err.lower():
            return {
                "status": "BLOCKED_KYC_ID_VERIFICATION",
                "http_status": http_status,
                "host": finding.host,
                "program": program.handle,
                "blocked_dossier_path": str(blocked_path) if blocked_path else None,
                "error_detail": raw_err,
            }
        if http_status == 403:
            return {
                "status": "BLOCKED_PROGRAM_FORBIDDEN",
                "http_status": http_status,
                "host": finding.host,
                "program": program.handle,
                "target_signal": program.target_signal,
                "blocked_dossier_path": str(blocked_path) if blocked_path else None,
                "error_detail": raw_err,
            }
        return {
            "status": "HTTP_ERROR",
            "http_status": http_status,
            "host": finding.host,
            "program": program.handle,
            "error_detail": raw_err,
        }

    # -- End-to-End Orchestration -------------------------------------------

    def run_hunt(
        self,
        config: Optional[VdpHuntConfig] = None,
        *,
        covered_domains: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Execute full Zero-KYC VDP discovery, screening, quality gate, and optional dispatch."""
        cfg = config or VdpHuntConfig()
        purged_roots = purge_empty_ct_cache_entries(cfg.cache_path) if cfg.purge_empty_cache else []
        if cfg.max_programs <= 0:
            return {
                "total_programs_fetched": 0,
                "open_vdp_candidates": 0,
                "programs_skipped_signal_gate": 0,
                "programs_with_uncovered_wildcards_scanned": 0,
                "wildcards_scanned": [],
                "explicit_hosts_scanned": [],
                "subdomains_screened": 0,
                "findings_count": 0,
                "findings": [],
                "submissions": [],
                "purged_empty_cache_count": len(purged_roots),
                "purged_empty_cache_roots": purged_roots,
            }

        username, token = self._credentials_loader(cfg.env_path)
        auth_header = build_auth_header(username, token)

        existing_reports = self._h1.fetch_paginated(
            "/v1/hackers/me/reports?page[size]=100",
            auth_header,
            base_url=cfg.base_url,
            max_items=200,
        )
        effective_signal = infer_researcher_signal_floor(existing_reports)
        raw_programs = self._h1.fetch_paginated(
            "/v1/hackers/programs?page[size]=100",
            auth_header,
            base_url=cfg.base_url,
            max_items=1000,
        )
        vdp_candidates = filter_kyc_free_vdp_programs(raw_programs)

        handle_filter: Set[str] = set()
        if cfg.program_handles:
            if isinstance(cfg.program_handles, str):
                handle_filter = {h.strip().lower() for h in cfg.program_handles.split(",") if h.strip()}
            else:
                handle_filter = {str(h).strip().lower() for h in cfg.program_handles if str(h).strip()}
        if handle_filter:
            vdp_candidates = [
                p
                for p in vdp_candidates
                if str((p.get("attributes") or {}).get("handle") or "").strip().lower() in handle_filter
            ]

        active_covered = covered_domains if covered_domains is not None else load_covered_domains()

        programs_checked = 0
        programs_skipped_signal_gate = 0
        wildcards_scanned: List[str] = []
        explicit_hosts_scanned: List[str] = []
        subdomains_screened = 0
        findings: List[Dict[str, Any]] = []
        submissions: List[Dict[str, Any]] = []

        for raw_prog in vdp_candidates[cfg.program_offset :]:
            if programs_checked >= cfg.max_programs:
                break
            prog = self.hydrate_program(
                raw_prog,
                auth_header,
                base_url=cfg.base_url,
                check_graphql_kyc=cfg.check_graphql_kyc,
            )
            if not prog:
                continue

            if not cfg.ignore_signal_gate:
                sig_ok, sig_reason = is_program_signal_eligible(prog.target_signal, effective_signal)
                if not sig_ok:
                    programs_skipped_signal_gate += 1
                    self._log(f"[VDP-HUNT] Skipping {prog.handle} (signal gate: {sig_reason})")
                    continue

            target_plan = self.discover_targets(
                prog,
                existing_reports=existing_reports,
                vdp_ready_dir=cfg.vdp_ready_dir,
                covered_domains=active_covered,
                include_covered=cfg.include_covered,
                max_wildcards_per_program=cfg.max_wildcards_per_program,
                max_subdomains=cfg.max_subdomains,
                cache_path=cfg.cache_path,
                use_crtsh=cfg.use_crtsh,
                use_subfinder=cfg.use_subfinder,
            )
            if not target_plan.wildcards_scanned and target_plan.total_explicit_candidates == 0:
                continue

            programs_checked += 1
            wildcards_scanned.extend(target_plan.wildcards_scanned)
            explicit_hosts_scanned.extend(target_plan.explicit_hosts_scanned)
            prog_hosts = target_plan.hosts_to_screen

            self._log(
                f"[VDP-HUNT] ({programs_checked}/{cfg.max_programs}) {prog.handle}: "
                f"{len(target_plan.wildcards_scanned)} wildcards, "
                f"{target_plan.total_explicit_candidates} explicit, {len(prog_hosts)} hosts"
            )
            subdomains_screened += len(prog_hosts)
            if prog_hosts:
                pool = ThreadPoolExecutor(max_workers=max(1, cfg.workers))
                batch_timeout = max(90, min(240, len(prog_hosts) * 3))
                try:
                    future_map = {
                        pool.submit(self.screen_target, prog, host): host
                        for host in prog_hosts
                    }
                    try:
                        for fut in as_completed(future_map, timeout=batch_timeout):
                            try:
                                finding = fut.result(timeout=15)
                            except Exception:
                                finding = None
                            if finding:
                                self._log(
                                    f"[VDP-HUNT] FOUND [{prog.handle}] {finding.host} -> "
                                    f"{finding.finding_type} ({finding.http_url})"
                                )
                                findings.append(asdict(finding))
                                res = self.dispatch_finding(
                                    prog,
                                    finding,
                                    username,
                                    token,
                                    dry_run=not cfg.submit_vdp,
                                    existing_reports=existing_reports,
                                    vdp_ready_dir=cfg.vdp_ready_dir,
                                    manifest_path=cfg.manifest_path,
                                    base_url=cfg.base_url,
                                    reverify_runs=cfg.reverify_runs,
                                    critic_runs=cfg.critic_runs,
                                    use_ollama_critic=cfg.use_ollama_critic,
                                    critic_model=cfg.critic_model,
                                    researcher_signal=effective_signal,
                                    reject_passive_saas_cname=cfg.reject_passive_saas_cname,
                                    reverify_sleep_seconds=cfg.reverify_sleep_seconds,
                                )
                                self._log(
                                    f"[VDP-HUNT] DISPATCH [{prog.handle}] {finding.host} -> {res.get('status')}"
                                )
                                submissions.append(res)
                    except TimeoutError:
                        self._log(f"[VDP-HUNT] {prog.handle}: batch timeout reached; moving on.")
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)

        return {
            "total_programs_fetched": len(raw_programs),
            "open_vdp_candidates": len(vdp_candidates),
            "programs_skipped_signal_gate": programs_skipped_signal_gate,
            "programs_with_uncovered_wildcards_scanned": programs_checked,
            "wildcards_scanned": wildcards_scanned,
            "explicit_hosts_scanned": explicit_hosts_scanned,
            "subdomains_screened": subdomains_screened,
            "findings_count": len(findings),
            "findings": findings,
            "submissions": submissions,
            "purged_empty_cache_count": len(purged_roots),
            "purged_empty_cache_roots": purged_roots,
        }


# ---------------------------------------------------------------------------
# Functional Convenience Entrypoints (Delegating to HackerOneVdpHunter)
# ---------------------------------------------------------------------------


def hydrate_vdp_program(
    raw_program: Dict[str, Any],
    auth_header: str,
    *,
    base_url: str = HACKERONE_API_BASE,
    check_graphql_kyc: bool = True,
    timeout: int = 15,
    h1_transport: Optional[HackerOneTransport] = None,
) -> Optional[VdpProgram]:
    """Load full policy, structured_scopes, and weaknesses for a qualifying VDP program."""
    return HackerOneVdpHunter(h1=h1_transport).hydrate_program(
        raw_program,
        auth_header,
        base_url=base_url,
        check_graphql_kyc=check_graphql_kyc,
        timeout=timeout,
    )


def screen_host_non_destructively(
    program: VdpProgram,
    host: str,
    *,
    detector: Optional[PassiveTakeoverDetector] = None,
    http_transport: Optional[HttpTransport] = None,
    dns_transport: Optional[DnsTransport] = None,
) -> Optional[VdpFinding]:
    """Screen a single in-scope host for dangling CNAMEs, open buckets, or sensitive leaks."""
    return HackerOneVdpHunter(
        http=http_transport,
        dns=dns_transport,
        takeover_detector=detector,
    ).screen_target(program, host)


def _reverify_finding_live(
    finding: VdpFinding,
    program: VdpProgram,
    *,
    http_transport: Optional[HttpTransport] = None,
    dns_transport: Optional[DnsTransport] = None,
) -> Tuple[bool, str]:
    """Perform an independent live DNS + HTTP re-probe to verify persistence."""
    return HackerOneVdpHunter(http=http_transport, dns=dns_transport)._reverify_live(finding, program)


def evaluate_submission_quality_gate(
    program: VdpProgram,
    finding: VdpFinding,
    *,
    reverify_runs: int = 2,
    critic_runs: int = 3,
    critic_quorum: Optional[int] = None,
    skip_live_reverify: bool = False,
    use_ollama_critic: bool = False,
    critic_model: str = "orbit-critic:latest",
    ollama_timeout: float = 45.0,
    ollama_fn: Optional[Any] = None,
    reject_passive_saas_cname: bool = False,
    http_transport: Optional[HttpTransport] = None,
    dns_transport: Optional[DnsTransport] = None,
) -> QualityGateResult:
    """Run multi-pass re-verification, deterministic grounding, and adversarial critic quorum."""
    hunter = HackerOneVdpHunter(http=http_transport, dns=dns_transport)
    reverify_fn = (
        hunter._reverify_live
        if (http_transport is not None or dns_transport is not None)
        else _reverify_finding_live
    )
    return hunter.evaluate_quality_gate(
        program,
        finding,
        reverify_runs=reverify_runs,
        critic_runs=critic_runs,
        critic_quorum=critic_quorum,
        skip_live_reverify=skip_live_reverify,
        use_ollama_critic=use_ollama_critic,
        critic_model=critic_model,
        ollama_timeout=ollama_timeout,
        ollama_fn=ollama_fn,
        reject_passive_saas_cname=reject_passive_saas_cname,
        reverify_fn=reverify_fn,
    )


def submit_vdp_finding(
    program: VdpProgram,
    finding: VdpFinding,
    username: str,
    api_token: str,
    *,
    dry_run: bool = True,
    existing_reports: Optional[List[Dict[str, Any]]] = None,
    vdp_ready_dir: Path = DEFAULT_VDP_READY_DIR,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    base_url: str = HACKERONE_API_BASE,
    timeout: int = 20,
    quality_gate: Optional[QualityGateResult] = None,
    reverify_runs: int = 2,
    critic_runs: int = 3,
    skip_live_reverify: bool = False,
    use_ollama_critic: bool = False,
    critic_model: str = "orbit-critic:latest",
    researcher_signal: Optional[float] = None,
    reject_passive_saas_cname: bool = False,
    h1_transport: Optional[HackerOneTransport] = None,
    http_transport: Optional[HttpTransport] = None,
    dns_transport: Optional[DnsTransport] = None,
) -> Dict[str, Any]:
    """Enforce KYC/VDP/signal/duplicate/multi-run critic gates, POST, and stage dossier."""
    return HackerOneVdpHunter(
        http=http_transport,
        dns=dns_transport,
        h1=h1_transport,
    ).dispatch_finding(
        program,
        finding,
        username,
        api_token,
        dry_run=dry_run,
        existing_reports=existing_reports,
        vdp_ready_dir=vdp_ready_dir,
        manifest_path=manifest_path,
        base_url=base_url,
        timeout=timeout,
        quality_gate=quality_gate,
        reverify_runs=reverify_runs,
        critic_runs=critic_runs,
        skip_live_reverify=skip_live_reverify,
        use_ollama_critic=use_ollama_critic,
        critic_model=critic_model,
        researcher_signal=researcher_signal,
        reject_passive_saas_cname=reject_passive_saas_cname,
    )


def discover_passive_subdomains(
    root: str,
    *,
    ct_monitor: Optional[CertificateTransparencyMonitor] = None,
    cache_path: Path = DEFAULT_VDP_CT_CACHE_PATH,
    use_crtsh: bool = False,
    use_subfinder: bool = False,
    timeout: int = 10,
    discovery_transport: Optional[SubdomainDiscoveryTransport] = None,
) -> Set[str]:
    """Discover subdomains passively via non-empty cache and multi-source passive recon."""
    return HackerOneVdpHunter(
        ct_monitor=ct_monitor,
        discovery=discovery_transport,
    ).discover_subdomains(
        root,
        cache_path=cache_path,
        use_crtsh=use_crtsh,
        use_subfinder=use_subfinder,
        timeout=timeout,
    )


def run_vdp_hunt(
    *,
    max_programs: int = 25,
    program_offset: int = 0,
    max_wildcards_per_program: int = 5,
    max_subdomains: int = 25,
    workers: int = 12,
    include_covered: bool = False,
    submit_vdp: bool = False,
    use_crtsh: bool = False,
    use_subfinder: bool = False,
    env_path: Path = DEFAULT_ENV_PATH,
    cache_path: Path = DEFAULT_VDP_CT_CACHE_PATH,
    vdp_ready_dir: Path = DEFAULT_VDP_READY_DIR,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    covered_domains: Optional[Set[str]] = None,
    check_graphql_kyc: bool = True,
    reverify_runs: int = 2,
    critic_runs: int = 3,
    use_ollama_critic: bool = False,
    critic_model: str = "orbit-critic:latest",
    reject_passive_saas_cname: bool = True,
    purge_empty_cache: bool = False,
    ignore_signal_gate: bool = False,
    program_handles: Optional[Union[str, Iterable[str]]] = None,
    hunter: Optional[HackerOneVdpHunter] = None,
) -> Dict[str, Any]:
    """Execute full Zero-KYC VDP discovery, screening, quality gate, and optional submission."""
    active_hunter = hunter or HackerOneVdpHunter()
    cfg = VdpHuntConfig(
        max_programs=max_programs,
        program_offset=program_offset,
        max_wildcards_per_program=max_wildcards_per_program,
        max_subdomains=max_subdomains,
        workers=workers,
        include_covered=include_covered,
        submit_vdp=submit_vdp,
        use_crtsh=use_crtsh,
        use_subfinder=use_subfinder,
        env_path=env_path,
        cache_path=cache_path,
        vdp_ready_dir=vdp_ready_dir,
        manifest_path=manifest_path,
        check_graphql_kyc=check_graphql_kyc,
        reverify_runs=reverify_runs,
        critic_runs=critic_runs,
        use_ollama_critic=use_ollama_critic,
        critic_model=critic_model,
        reject_passive_saas_cname=reject_passive_saas_cname,
        purge_empty_cache=purge_empty_cache,
        ignore_signal_gate=ignore_signal_gate,
        program_handles=program_handles,
    )
    return active_hunter.run_hunt(cfg, covered_domains=covered_domains)


__all__ = [
    # Primary deep module interface
    "HackerOneVdpHunter",
    "VdpHuntConfig",
    "TargetDiscoveryResult",
    "VdpProgram",
    "VdpFinding",
    "QualityGateResult",
    # Transport adapter ports & production adapters
    "HttpTransport",
    "DnsTransport",
    "HackerOneTransport",
    "SubdomainDiscoveryTransport",
    "UrllibHttpTransport",
    "CloudflareDohTransport",
    "UrllibHackerOneTransport",
    "MultiSourceSubdomainTransport",
    # Configuration & constants
    "BROWSER_USER_AGENT",
    "DEFAULT_CANDIDATES_PATH",
    "DEFAULT_ENV_PATH",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_PROBE_USER_AGENT",
    "DEFAULT_PROGRAMS_PATH",
    "DEFAULT_RESEARCHER_HANDLE",
    "DEFAULT_VDP_CT_CACHE_PATH",
    "DEFAULT_VDP_READY_DIR",
    "EXTENDED_SENSITIVE_PATHS",
    "HACKERONE_API_BASE",
    "HACKERONE_WEB_BASE",
    "HTML_LOOKALIKE_RE",
    "PRIORITY_SUBDOMAIN_TOKENS",
    "SENSITIVE_BUCKET_KEY_RE",
    "SENSITIVE_EXPOSURE_PATHS",
    "STATIC_PUBLIC_ASSET_EXTS",
    "STATIC_PUBLIC_FILENAMES",
    "WEAKNESS_PREFERENCES",
    # Egress & safety primitives
    "EgressDecision",
    "EgressViolationError",
    "_SafeVdpRedirectHandler",
    "_is_bogon_or_internal_ip",
    "enforce_egress_or_raise",
    "evaluate_egress_target",
    "is_safe_host",
    "is_safe_ip",
    # Functional convenience entrypoints & tucked internal helpers
    "_reverify_finding_live",
    "build_auth_header",
    "build_h1_report_payload",
    "check_exposed_config_or_git",
    "check_extended_sensitive_exposures",
    "check_open_bucket_listing",
    "check_takeover_claimability",
    "discover_multi_source_subdomains",
    "discover_passive_subdomains",
    "evaluate_cors_response",
    "evaluate_submission_quality_gate",
    "extract_cloud_urls_from_text",
    "extract_explicit_scope_hosts",
    "extract_wildcard_roots",
    "fetch_http_sample",
    "fetch_paginated_h1",
    "fetch_program_graphql_gates",
    "fetch_program_kyc_status_graphql",
    "filter_kyc_free_vdp_programs",
    "hydrate_vdp_program",
    "infer_researcher_signal_floor",
    "is_bucket_listing_non_public",
    "is_duplicate_finding",
    "is_program_signal_eligible",
    "load_covered_domains",
    "load_hackerone_credentials",
    "match_structured_scope",
    "parse_compliance_headers",
    "purge_empty_ct_cache_entries",
    "render_vdp_dossier",
    "resolve_dns_cname_chain_guarded",
    "resolve_dns_doh",
    "run_vdp_hunt",
    "save_non_empty_ct_cache",
    "scan_text_for_high_confidence_secrets",
    "screen_host_non_destructively",
    "select_weakness_id",
    "submit_vdp_finding",
]
