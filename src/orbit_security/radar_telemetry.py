#!/usr/bin/env python3
"""orbit_security.radar_telemetry: Real-Time Radar Query Telemetry & Observer.
=============================================================================
Provides real-time visibility, OSINT enrichment, retainer proposal staging, and
webhook alerting whenever a domain is entered into the ORBIT // PERIMETER RADAR TERMINAL
(https://cmfh009.github.io/Orbit-Security/).

Key Features:
- Structured JSONL persistence (data/radar_queries.jsonl) with atomic append.
- Decoupled SQLite WAL Blackboard event bus dispatch (RADAR_DOMAIN_ENTERED)
  for real-time streaming to the Orbit Aerospace Cockpit HUD / SSE stream (<500ms).
- Rich Discord & Slack webhook alerting with parsed device User-Agent, hygiene
  score/grade, OSINT tech stack, registrar, and staged deliverable paths.
- Background OSINT & Lead Enrichment via `RadarLeadEnricher` (`public_apis_osint.py`).
- Automated Retainer Proposal & PDF Audit staging in `outbound_campaigns/<domain_slug>/`.
- Standalone zero-dependency HTTP server with full CORS & PNA preflight support.
- CLI streaming monitor (--tail), aggregate statistics (--stats), and backfill (--backfill).
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime
import hashlib
import hmac
import http.server
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from orbit_security.radar_lead_enricher import DEFAULT_ENRICHED_LEADS_FILE, RadarLeadEnricher
from orbit_security.radar_proposal_stager import DEFAULT_CAMPAIGNS_DIR, RadarRetainerProposalStager

logger = logging.getLogger("orbit_security.radar_telemetry")

DATA_DIR = REPO_ROOT / "data"


def get_effective_data_dir() -> Path:
    """Returns the writable data directory for radar telemetry logs.

    Detects read-only filesystems (such as Google Cloud Run containers with
    readOnlyRootFilesystem=true) and automatically falls back to /tmp/orbit_data.
    """
    env_dir = os.environ.get("ORBIT_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Test default DATA_DIR writability
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        test_file = DATA_DIR / f".write_test_{os.getpid()}.tmp"
        test_file.write_text("test", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return DATA_DIR
    except (OSError, PermissionError):
        fallback = Path("/tmp/orbit_data") if os.name != "nt" else Path(tempfile.gettempdir()) / "orbit_data"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


DEFAULT_QUERIES_FILE = get_effective_data_dir() / "radar_queries.jsonl"

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
RESTRICTED_DOMAINS = {
    "localhost",
    "localdomain",
    "internal",
    "lan",
    "home.arpa",
}


_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

ACTION_SIGNING_SALT = os.environ.get("ORBIT_ACTION_SALT", "orbit-action-secret-v1")


def generate_action_token(domain: str, action: str = "stage_retainer") -> str:
    """Generates a keyed HMAC-SHA256 signature for 1-click webhook action triggers."""
    salt = os.environ.get("ORBIT_ACTION_SALT", ACTION_SIGNING_SALT)
    msg = f"{action}:{domain.lower().strip()}"
    return hmac.new(salt.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def verify_action_token(domain: str, action: str, token: str) -> bool:
    """Validates an action token in constant time."""
    if not token or not domain:
        return False
    expected = generate_action_token(domain, action)
    return hmac.compare_digest(expected, token)


def anonymize_client_ip(ip_raw: Optional[str]) -> Optional[str]:
    """GDPR/CCPA-compliant IP anonymizer: masks public IPv4 to /24 and IPv6 to /48 + SHA-256 token.

    Loopback and RFC1918 LAN addresses are preserved for local diagnostics and unit testing.
    Raw public visitor IP addresses are never persisted to disk logs.
    """
    if not ip_raw:
        return None
    clean = str(ip_raw).split(",")[0].strip()
    if not clean:
        return None
    try:
        ip_obj = ipaddress.ip_address(clean)
        if ip_obj.is_loopback or (
            isinstance(ip_obj, ipaddress.IPv4Address)
            and any(ip_obj in net for net in _RFC1918_NETWORKS)
        ):
            return str(ip_obj)
        salt = os.environ.get("ORBIT_IP_SALT", "orbit-privacy-shield-v1")
        token = hashlib.sha256(f"{salt}:{clean}".encode("utf-8")).hexdigest()[:8]
        if isinstance(ip_obj, ipaddress.IPv4Address):
            net = ipaddress.IPv4Network(f"{clean}/24", strict=False)
            return f"{net.network_address}/24#{token}"
        net6 = ipaddress.IPv6Network(f"{clean}/48", strict=False)
        return f"{net6.network_address}/48#{token}"
    except ValueError:
        return "anon#invalid"


def parse_user_agent_summary(
    user_agent: Optional[str], screen_resolution: Optional[str] = None
) -> Dict[str, str]:
    """Parses raw browser User-Agent string into human-readable device, OS, and browser telemetry."""
    ua = (user_agent or "").strip()
    screen = (screen_resolution or "").strip() or "N/A"
    if not ua:
        return {
            "device_type": "Unknown",
            "os": "Unknown OS",
            "browser": "Unknown Browser",
            "screen": screen,
            "summary": f"Unknown Device ({screen})" if screen != "N/A" else "Unknown Device",
            "raw": "N/A",
        }

    ua_lower = ua.lower()

    # 1. OS Detection
    os_name = "Unknown OS"
    android_m = re.search(r"android\s+([0-9.]+)", ua, re.IGNORECASE)
    ios_m = re.search(r"(?:iphone os|cpu os)\s+([0-9_]+)", ua, re.IGNORECASE)
    if android_m:
        os_name = f"Android {android_m.group(1)}"
    elif ios_m:
        os_name = f"iOS {ios_m.group(1).replace('_', '.')}"
    elif "iphone" in ua_lower:
        os_name = "iOS (iPhone)"
    elif "ipad" in ua_lower:
        os_name = "iPadOS"
    elif "windows nt 10.0" in ua_lower:
        os_name = "Windows 10/11"
    elif "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os x" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"

    # 2. Device Type Detection
    if any(tok in ua_lower for tok in ("mobile", "iphone", "android")) and "ipad" not in ua_lower:
        device_type = "Mobile"
    elif any(tok in ua_lower for tok in ("ipad", "tablet")):
        device_type = "Tablet"
    elif any(tok in ua_lower for tok in ("bot", "HeadlessChrome".lower(), "curl", "python")):
        device_type = "Bot/CLI"
    else:
        device_type = "Desktop"

    # 3. Browser Detection
    browser = "Browser"
    edg_m = re.search(r"edg(?:e|a|ios)?/([0-9.]+)", ua, re.IGNORECASE)
    chrome_m = re.search(r"(?:chrome|crios)/([0-9.]+)", ua, re.IGNORECASE)
    fx_m = re.search(r"(?:firefox|fxios)/([0-9.]+)", ua, re.IGNORECASE)
    safari_m = re.search(r"version/([0-9.]+).*safari", ua, re.IGNORECASE)

    if edg_m:
        browser = f"Edge {edg_m.group(1).split('.')[0]}"
    elif chrome_m:
        ver = chrome_m.group(1).split(".")[0]
        browser = f"Chrome Mobile {ver}" if device_type == "Mobile" else f"Chrome {ver}"
    elif fx_m:
        browser = f"Firefox {fx_m.group(1).split('.')[0]}"
    elif safari_m or ("safari" in ua_lower and "chrome" not in ua_lower):
        ver = safari_m.group(1).split(".")[0] if safari_m else ""
        browser = f"Mobile Safari {ver}".strip() if device_type in ("Mobile", "Tablet") else f"Safari {ver}".strip()

    res_suffix = f" ({screen})" if screen and screen != "N/A" else ""
    summary = f"{os_name} {device_type} • {browser}{res_suffix}"

    return {
        "device_type": device_type,
        "os": os_name,
        "browser": browser,
        "screen": screen,
        "summary": summary,
        "raw": ua[:180],
    }


def format_discord_radar_embed(
    record: Dict[str, Any],
    enrichment: Optional[Dict[str, Any]] = None,
    proposal: Optional[Dict[str, Any]] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds a rich Discord Embed payload for an inbound Radar Terminal domain scan."""
    domain = record.get("domain", "unknown")
    enrich = enrichment or {}
    prop = proposal or {}

    score = record.get("score")
    if score is None:
        score = enrich.get("computed_score")

    grade = record.get("grade") or enrich.get("computed_grade") or "PENDING"
    risk_label = record.get("risk_label") or (
        "LOW RISK" if (score is not None and score >= 88)
        else ("MODERATE RISK" if (score is not None and score >= 70) else "ACTION RECOMMENDED")
    )
    trigger_source = record.get("trigger_source") or "radar_submit"
    dmarc_status = (record.get("dmarc_status") or enrich.get("dmarc_status") or "pending").upper()
    spf_status = (record.get("spf_status") or enrich.get("spf_status") or "pending").upper()
    cname_status = (record.get("cname_status") or "PASS").upper()

    ua_info = parse_user_agent_summary(
        record.get("user_agent"),
        record.get("screen_resolution"),
    )

    if score is not None and score >= 88:
        color = 0x10B981  # Emerald
    elif score is not None and score >= 70:
        color = 0xF59E0B  # Amber
    else:
        color = 0xEF4444  # Crimson

    score_display = f"**{score}/100** (Grade: `{grade}`)" if score is not None else f"Pending (Grade: `{grade}`)"

    fields: List[Dict[str, Any]] = [
        {
            "name": "🎯 Target Domain",
            "value": f"`{domain}`",
            "inline": True,
        },
        {
            "name": "🛡️ Hygiene Score & Grade",
            "value": score_display,
            "inline": True,
        },
        {
            "name": "⚡ Trigger & Posture",
            "value": f"`{trigger_source}` • `{risk_label}`",
            "inline": True,
        },
        {
            "name": "📱 Visitor Device & User Agent",
            "value": f"**{ua_info['summary']}**\n`{ua_info['raw']}`",
            "inline": False,
        },
        {
            "name": "📡 DNS Authentication Posture",
            "value": f"DMARC: `{dmarc_status}` | SPF: `{spf_status}` | CNAME: `{cname_status}`",
            "inline": False,
        },
    ]

    if enrich:
        def _as_int(value: Any, default: int = 0) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        history = enrich.get("enrichment_history") or []
        probe_count = _as_int(enrich.get("probe_count"), len(history) or 1)
        score_delta = _as_int(enrich.get("score_delta"), 0)
        previous_score = enrich.get("previous_score")
        previous_score = score if previous_score is None else previous_score
        current_score = score if score is not None else enrich.get("computed_score", "?")

        if enrich.get("is_buying_signal"):
            reason = (
                f"Posture regressed `{abs(score_delta)} pts` since the last probe"
                if score_delta <= -10
                else "Sustained repeat research intent"
            )
            fields.insert(
                0,
                {
                    "name": "🔥 BUYING SIGNAL DETECTED",
                    "value": (
                        f"**Repeat Probe #{probe_count}** • Delta: `{score_delta:+d} pts` "
                        f"({previous_score} → {current_score})\n{reason}"
                    ),
                    "inline": False,
                },
            )
        elif probe_count >= 2:
            fields.append(
                {
                    "name": "📈 Re-Scan Score Delta",
                    "value": (
                        f"Probe #{probe_count} • Delta: `{score_delta:+d} pts` "
                        f"({previous_score} → {current_score})"
                    ),
                    "inline": False,
                }
            )

        company = enrich.get("company_profile", {}).get("company_name") or domain
        registrar = enrich.get("registrar") or "Unknown"
        stack = ", ".join(enrich.get("tech_stack") or ["Standard Web"])
        mx_prov = enrich.get("mx_provider") or "Standard MX"
        osint = enrich.get("public_apis_osint") or {}
        osint_count = osint.get("security_osint_count", 0)
        total_apis = osint.get("total_catalog_apis", 0)

        fields.append(
            {
                "name": "🔍 OSINT & Tech Stack Profile (public-apis)",
                "value": (
                    f"**Company:** {company} | **Registrar:** `{registrar}`\n"
                    f"**Tech Stack:** `{stack}` | **MX:** `{mx_prov}`\n"
                    f"**OSINT Catalog:** `{osint_count}` security endpoints correlated (`{total_apis}` indexed APIs)"
                ),
                "inline": False,
            }
        )

    if prop:
        slug = prop.get("domain_slug") or domain.replace(".", "_")
        pdf_name = Path(prop.get("pdf_path") or f"{slug}_security_audit.pdf").name
        fields.append(
            {
                "name": "📄 Staged Retainer Deliverables",
                "value": (
                    f"Folder: `outbound_campaigns/{slug}/`\n"
                    f"• PDF Audit: `{pdf_name}`\n"
                    f"• DNS Fix: `dns_remediation_plan.md` | Proposal: `retainer_proposal.md`"
                ),
                "inline": False,
            }
        )

    ts = record.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

    target_base = base_url or os.environ.get(
        "ORBIT_LIVE_CLOUD_ENDPOINT",
        "https://orbit-security-api-911438991206.us-central1.run.app",
    )
    action_token = generate_action_token(domain, "stage_retainer")
    stage_action_url = f"{target_base}/api/orbit/radar/action?action=stage_retainer&domain={domain}&token={action_token}"
    radar_url = f"https://cmfh009.github.io/Orbit-Security/?target={domain}"
    fleet_url = f"https://cmfh009.github.io/Orbit-Security/fleet.html?domain={domain}"

    embed = {
        "title": f"🎯 Orbit Radar Probe Detected: {domain} (Grade {grade})",
        "description": (
            f"⚡ **[1-Click Stage Retainer Proposal]({stage_action_url})** • "
            f"🛡️ **[Open Terminal Radar]({radar_url})** • "
            f"🌐 **[Fleet Command]({fleet_url})**"
        ),
        "color": color,
        "fields": fields,
        "footer": {
            "text": "Project ORBIT // Perimeter Radar Terminal Live Telemetry",
        },
        "timestamp": ts,
    }

    components = [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 5,  # Link button
                    "label": "⚡ Generate Retainer",
                    "url": stage_action_url,
                },
                {
                    "type": 2,
                    "style": 5,
                    "label": "🛡️ Open Terminal Radar",
                    "url": radar_url,
                },
                {
                    "type": 2,
                    "style": 5,
                    "label": "🌐 Fleet Command",
                    "url": fleet_url,
                },
            ],
        }
    ]

    return {
        "username": "ORBIT Radar Sentinel",
        "avatar_url": "https://cmfh009.github.io/Orbit-Security/assets/logo.png",
        "embeds": [embed],
        "components": components,
    }


@dataclass
class RadarQueryRecord:
    id: str
    domain: str
    raw_input: str
    timestamp: str
    timestamp_epoch: float
    trigger_source: str
    score: Optional[int] = None
    grade: Optional[str] = None
    risk_label: Optional[str] = None
    dmarc_status: Optional[str] = None
    spf_status: Optional[str] = None
    cname_status: Optional[str] = None
    is_nxdomain: bool = False
    is_lookup_failed: bool = False
    session_id: Optional[str] = None
    source_url: Optional[str] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
    screen_resolution: Optional[str] = None
    client_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RadarTelemetryService:
    """Thread-safe telemetry recorder, OSINT enricher, and proposal stager for perimeter radar probes."""

    def __init__(
        self,
        queries_file: Optional[Path] = None,
        leads_file: Optional[Path] = None,
        campaigns_dir: Optional[Path] = None,
        dedup_window_seconds: float = 3.0,
    ):
        effective_data = get_effective_data_dir()
        self.queries_file = Path(queries_file) if queries_file else (effective_data / "radar_queries.jsonl")
        self.queries_file.parent.mkdir(parents=True, exist_ok=True)
        self.dedup_window_seconds = dedup_window_seconds
        self._lock = threading.Lock()
        self._recent_probes_cache: Dict[str, float] = {}
        leads_path = leads_file or (effective_data / "radar_enriched_leads.json" if effective_data != DATA_DIR else DEFAULT_ENRICHED_LEADS_FILE)
        campaigns_path = campaigns_dir or (effective_data / "campaigns" if effective_data != DATA_DIR else DEFAULT_CAMPAIGNS_DIR)
        self.enricher = RadarLeadEnricher(leads_file=leads_path)
        self.proposal_stager = RadarRetainerProposalStager(campaigns_dir=campaigns_path)

    @staticmethod
    def normalize_domain(domain_raw: str) -> str:
        """Sanitizes raw input string to lowercase fully qualified domain name."""
        if not domain_raw or not isinstance(domain_raw, str):
            return ""
        clean = domain_raw.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        clean = re.sub(r"/.*$", "", clean)
        clean = re.sub(r"\?.*$", "", clean)
        clean = re.sub(r":\d+$", "", clean)
        clean = clean.rstrip(".")
        return clean

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        if not DOMAIN_REGEX.match(domain):
            return False
        parts = domain.split(".")
        if any(p in RESTRICTED_DOMAINS for p in parts):
            return False
        if domain.endswith((".local", ".internal", ".localhost", ".localdomain", ".test", ".example", ".invalid", ".home.arpa", ".lan", ".arpa")):
            return False
        return True

    def _is_duplicate(
        self,
        domain: str,
        session_id: str,
        now_epoch: float,
        trigger_source: str = "radar_submit",
    ) -> bool:
        cache_key = f"{domain}:{session_id or 'none'}:{trigger_source}"
        last_time = self._recent_probes_cache.get(cache_key, 0.0)
        # Purge stale keys
        if len(self._recent_probes_cache) > 200:
            self._recent_probes_cache = {
                k: v for k, v in self._recent_probes_cache.items()
                if (now_epoch - v) < self.dedup_window_seconds * 2
            }
        if (now_epoch - last_time) < self.dedup_window_seconds:
            return True
        self._recent_probes_cache[cache_key] = now_epoch
        return False

    def record_query(
        self,
        event_data: Dict[str, Any],
        client_ip: str = "",
        enrich_async: bool = True,
        network_probe: bool = True,
        background_enrich: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Validates, records, enriches, stages retainer deliverables, and dispatches webhook alerts."""
        raw_input = str(event_data.get("domain") or event_data.get("target") or event_data.get("raw_input") or "").strip()
        domain = self.normalize_domain(raw_input)

        if not self.is_valid_domain(domain):
            return {
                "ok": False,
                "error": f"Invalid or restricted domain target: '{raw_input}'",
                "domain": domain,
            }

        now = datetime.datetime.now(datetime.timezone.utc)
        now_epoch = now.timestamp()
        session_id = str(event_data.get("session_id") or "")[:64]
        trigger_source = str(event_data.get("trigger_source") or "radar_submit")[:32]

        # Extract audit result details if provided
        audit = event_data.get("audit_result") or {}
        score = audit.get("score") if audit.get("score") is not None else event_data.get("score")
        if score is not None:
            try:
                score = max(0, min(100, int(score)))
            except (ValueError, TypeError):
                score = None

        grade = audit.get("grade") or event_data.get("grade")
        if grade:
            grade = str(grade)[:4].upper()

        risk_label = audit.get("risk_label") or event_data.get("risk_label")
        dmarc_status = audit.get("dmarc_status") or event_data.get("dmarc_status")
        spf_status = audit.get("spf_status") or event_data.get("spf_status")
        cname_status = audit.get("cname_status") or event_data.get("cname_status")
        is_nxdomain = bool(audit.get("is_nxdomain") or event_data.get("is_nxdomain"))
        is_lookup_failed = bool(audit.get("is_lookup_failed") or event_data.get("is_lookup_failed"))

        # Deterministic unique query ID
        safe_ip = anonymize_client_ip(client_ip)
        hash_seed = f"{domain}:{now_epoch}:{session_id}:{safe_ip}:{trigger_source}"
        query_id = f"rad_{int(now_epoch)}_{hashlib.sha256(hash_seed.encode('utf-8')).hexdigest()[:8]}"

        record = RadarQueryRecord(
            id=query_id,
            domain=domain,
            raw_input=raw_input,
            timestamp=now.isoformat(),
            timestamp_epoch=now_epoch,
            trigger_source=trigger_source,
            score=score,
            grade=grade,
            risk_label=str(risk_label)[:32] if risk_label else None,
            dmarc_status=str(dmarc_status)[:16] if dmarc_status else None,
            spf_status=str(spf_status)[:16] if spf_status else None,
            cname_status=str(cname_status)[:16] if cname_status else None,
            is_nxdomain=is_nxdomain,
            is_lookup_failed=is_lookup_failed,
            session_id=session_id or None,
            source_url=str(event_data.get("source_url") or "")[:256] or None,
            referrer=str(event_data.get("referrer") or "")[:256] or None,
            user_agent=str(event_data.get("user_agent") or "")[:256] or None,
            screen_resolution=str(event_data.get("screen_resolution") or "")[:32] or None,
            client_ip=str(safe_ip)[:64] if safe_ip else None,
        )

        record_dict = record.to_dict()

        # Check deduplication window per (domain, session_id, trigger_source)
        with self._lock:
            is_dup = self._is_duplicate(domain, session_id, now_epoch, trigger_source=trigger_source)
            if not is_dup:
                try:
                    with open(self.queries_file, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(record_dict) + "\n")
                except Exception as ex:
                    logger.warning(f"Failed to append radar query to {self.queries_file}: {ex}")

        # Broadcast to local Blackboard event bus
        self._publish_to_blackboard(record_dict)

        # Trigger OSINT enrichment, retainer proposal staging, and rich webhook alerting
        if background_enrich is False:
            pass
        elif enrich_async and background_enrich is not False:
            threading.Thread(
                target=self._enrich_stage_and_alert,
                args=(record_dict, network_probe),
                daemon=True,
            ).start()
        else:
            self._enrich_stage_and_alert(record_dict, network_probe=network_probe)

        return {
            "ok": True,
            "id": query_id,
            "domain": domain,
            "score": record_dict.get("score"),
            "grade": record_dict.get("grade"),
            "recorded_at": now.isoformat(),
            "trigger_source": trigger_source,
        }

    def _enrich_stage_and_alert(self, record_dict: Dict[str, Any], network_probe: bool = True) -> Dict[str, Any]:
        """Executes OSINT enrichment, stages retainer deliverables, and dispatches Discord/Slack webhooks."""
        domain = record_dict.get("domain", "")
        enrichment: Optional[Dict[str, Any]] = None
        proposal: Optional[Dict[str, Any]] = None

        try:
            enrichment = self.enricher.enrich_domain(domain, network_probe=network_probe)
            if record_dict.get("score") is None and enrichment.get("computed_score") is not None:
                record_dict["score"] = enrichment["computed_score"]
            if not record_dict.get("grade") and enrichment.get("computed_grade"):
                record_dict["grade"] = enrichment["computed_grade"]
            if not record_dict.get("dmarc_status") and enrichment.get("dmarc_status"):
                record_dict["dmarc_status"] = enrichment["dmarc_status"]
            if not record_dict.get("spf_status") and enrichment.get("spf_status"):
                record_dict["spf_status"] = enrichment["spf_status"]
        except Exception as ex:
            logger.warning(f"Radar OSINT enrichment failed for {domain}: {ex}")

        try:
            proposal = self.proposal_stager.stage_campaign(
                domain=domain,
                query_record=record_dict,
                enrichment=enrichment,
            )
        except Exception as ex:
            logger.warning(f"Radar retainer proposal staging failed for {domain}: {ex}")

        self._dispatch_webhooks(record_dict, enrichment=enrichment, proposal=proposal, sync=True)
        return {
            "enrichment": enrichment,
            "proposal": proposal,
        }

    def _publish_to_blackboard(self, record_dict: Dict[str, Any]) -> None:
        """Publishes RADAR_DOMAIN_ENTERED event to Blackboard event bus for Cockpit SSE HUD."""
        try:
            sec_src = str(REPO_ROOT / "src")
            if sec_src not in sys.path:
                sys.path.insert(0, sec_src)
            from orbit_security.blackboard import (
                EVENT_RADAR_DOMAIN_ENTERED,
                TOPIC_TELEMETRY,
                publish_event,
            )
            publish_event(
                event_type=EVENT_RADAR_DOMAIN_ENTERED,
                payload=record_dict,
                source="radar_terminal",
                topic=TOPIC_TELEMETRY,
            )
        except Exception as ex:
            logger.debug(f"Blackboard event publication notice: {ex}")

    def _dispatch_webhooks(
        self,
        record: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None,
        proposal: Optional[Dict[str, Any]] = None,
        sync: bool = False,
    ) -> None:
        """Dispatches a rich embed alert to configured Discord / Slack webhooks."""
        discord_url = (
            os.environ.get("ORBIT_RADAR_WEBHOOK_URL")
            or os.environ.get("ORBIT_DISCORD_WEBHOOK_URL")
            or os.environ.get("DISCORD_WEBHOOK_URL")
        )
        slack_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not discord_url and not slack_url:
            return

        def _worker():
            try:
                domain = record.get("domain", "")
                score = record.get("score")
                grade = record.get("grade") or "N/A"
                source = record.get("trigger_source") or "terminal"
                ts = record.get("timestamp", "")[:19]
                ua_info = parse_user_agent_summary(
                    record.get("user_agent"),
                    record.get("screen_resolution"),
                )

                if discord_url:
                    payload = format_discord_radar_embed(
                        record,
                        enrichment=enrichment,
                        proposal=proposal,
                    )
                    req = urllib.request.Request(
                        discord_url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "OrbitRadarTelemetry/2.0"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as _:
                        pass

                if slack_url:
                    score_text = f"{score}/100" if score is not None else "Pending"
                    title = f"🎯 Orbit Radar Probe Detected: {domain} (Grade {grade})"
                    summary = (
                        f"*Target Domain:* `{domain}`\n"
                        f"*Perimeter Hygiene:* {score_text} (Grade: `{grade}`)\n"
                        f"*Visitor Device:* {ua_info['summary']}\n"
                        f"*Trigger Source:* `{source}`\n"
                        f"*Timestamp:* {ts} UTC"
                    )
                    payload = {"text": f"{title}\n{summary}"}
                    req = urllib.request.Request(
                        slack_url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "OrbitRadarTelemetry/2.0"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as _:
                        pass
            except Exception as ex:
                logger.warning(f"Webhook dispatch failed: {ex}")

        if sync:
            _worker()
        else:
            threading.Thread(target=_worker, daemon=True).start()

    def _merge_enriched_lead_into_query(
        self,
        record: Dict[str, Any],
        all_leads: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Back-propagates computed hygiene score, grade, and DNS/DKIM/CAA telemetry from enriched leads."""
        dom = record.get("domain") or ""
        lead = all_leads.get(dom)
        if not lead:
            return record
        merged = dict(record)
        if merged.get("score") is None and lead.get("computed_score") is not None:
            merged["score"] = lead["computed_score"]
        if not merged.get("grade") and lead.get("computed_grade"):
            merged["grade"] = lead["computed_grade"]
        if not merged.get("dmarc_status") and lead.get("dmarc_status"):
            merged["dmarc_status"] = lead["dmarc_status"]
        if not merged.get("spf_status") and lead.get("spf_status"):
            merged["spf_status"] = lead["spf_status"]
        if lead.get("dkim_status"):
            merged["dkim_status"] = lead["dkim_status"]
        if lead.get("dkim_selectors_found") is not None:
            merged["dkim_selectors_found"] = lead["dkim_selectors_found"]
        if lead.get("caa_status"):
            merged["caa_status"] = lead["caa_status"]
        if lead.get("ct_subdomains") is not None:
            merged["ct_subdomains"] = lead["ct_subdomains"]
        return merged

    def get_recent_queries(
        self, limit: int = 50, domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Reads recent queries from JSONL in reverse chronological order with enriched score back-propagation."""
        if not self.queries_file.exists():
            return []
        all_leads = self.enricher.get_all_enriched_leads()
        queries: List[Dict[str, Any]] = []
        target = self.normalize_domain(domain) if domain else None
        try:
            with open(self.queries_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if target and target not in record.get("domain", ""):
                            continue
                        queries.append(self._merge_enriched_lead_into_query(record, all_leads))
                    except json.JSONDecodeError:
                        continue
        except Exception as ex:
            logger.warning(f"Failed to read queries from {self.queries_file}: {ex}")
            return []

        queries.reverse()
        return queries[:limit]

    def get_query_stats(self) -> Dict[str, Any]:
        """Calculates aggregate metrics across recorded perimeter radar probes with enriched grade back-propagation."""
        if not self.queries_file.exists():
            return {
                "total_probes": 0,
                "unique_domains": 0,
                "top_domains": [],
                "grade_breakdown": {},
                "latest_probe": None,
            }

        all_leads = self.enricher.get_all_enriched_leads()
        domain_counts: Dict[str, int] = {}
        grade_counts: Dict[str, int] = {}
        total = 0
        latest: Optional[Dict[str, Any]] = None

        try:
            with open(self.queries_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_record = json.loads(line)
                        record = self._merge_enriched_lead_into_query(raw_record, all_leads)
                        total += 1
                        d = record.get("domain", "unknown")
                        domain_counts[d] = domain_counts.get(d, 0) + 1
                        g = record.get("grade") or "PENDING"
                        grade_counts[g] = grade_counts.get(g, 0) + 1
                        latest = record
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        sorted_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        top_domains = [{"domain": d, "probes": count} for d, count in sorted_domains]

        return {
            "total_probes": total,
            "unique_domains": len(domain_counts),
            "top_domains": top_domains,
            "grade_breakdown": grade_counts,
            "latest_probe": latest,
        }

    def clear_queries(self) -> None:
        """Truncates the query log file (primarily for testing suites)."""
        with self._lock:
            self._recent_probes_cache.clear()
            if self.queries_file.exists():
                try:
                    self.queries_file.write_text("", encoding="utf-8")
                except Exception:
                    pass

    def backfill_existing_queries(self, network_probe: bool = True) -> List[Dict[str, Any]]:
        """Enriches and stages retainer proposals for all unique domains in radar_queries.jsonl."""
        queries = self.get_recent_queries(limit=500)
        seen_domains = set()
        results: List[Dict[str, Any]] = []
        for q in queries:
            dom = q.get("domain")
            if not dom or dom in seen_domains:
                continue
            seen_domains.add(dom)
            res = self._enrich_stage_and_alert(dict(q), network_probe=network_probe)
            results.append(
                {
                    "domain": dom,
                    "score": res["proposal"]["score"] if res.get("proposal") else q.get("score"),
                    "grade": res["proposal"]["grade"] if res.get("proposal") else q.get("grade"),
                    "company_name": res["enrichment"]["company_profile"]["company_name"] if res.get("enrichment") else dom,
                    "tech_stack": res["enrichment"]["tech_stack"] if res.get("enrichment") else [],
                    "registrar": res["enrichment"]["registrar"] if res.get("enrichment") else "Unknown",
                    "campaign_dir": res["proposal"]["campaign_dir"] if res.get("proposal") else "",
                    "pdf_path": res["proposal"]["pdf_path"] if res.get("proposal") else "",
                }
            )
        return results

    def get_enriched_leads_summary(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns enriched lead profiles merged with latest telemetry query metadata and deliverable status."""
        all_leads = self.enricher.get_all_enriched_leads()
        recent_queries = self.get_recent_queries(limit=500)

        latest_query_by_domain: Dict[str, Dict[str, Any]] = {}
        probe_counts: Dict[str, int] = {}
        for q in recent_queries:
            dom = q.get("domain")
            if not dom:
                continue
            probe_counts[dom] = probe_counts.get(dom, 0) + 1
            if dom not in latest_query_by_domain or (
                q.get("score") is not None and latest_query_by_domain[dom].get("score") is None
            ):
                latest_query_by_domain[dom] = q

        all_domains = list(dict.fromkeys(list(latest_query_by_domain.keys()) + list(all_leads.keys())))
        items: List[Dict[str, Any]] = []

        for dom in all_domains[:limit]:
            lead = all_leads.get(dom) or {}
            q = latest_query_by_domain.get(dom) or {}
            slug = self.proposal_stager.domain_to_slug(dom)
            camp_dir = self.proposal_stager.campaigns_dir / slug

            score = q.get("score") if q.get("score") is not None else lead.get("computed_score")
            grade = q.get("grade") or lead.get("computed_grade") or "--"
            ua_info = parse_user_agent_summary(q.get("user_agent"), q.get("screen_resolution"))

            pdf_file = camp_dir / f"{slug}_security_audit.pdf"
            md_audit_file = camp_dir / f"{slug}_security_audit.md"
            dns_file = camp_dir / "dns_remediation_plan.md"
            proposal_file = camp_dir / "retainer_proposal.md"
            pitch_file = camp_dir / "pitch_email.txt"

            items.append({
                "domain": dom,
                "domain_slug": slug,
                "company_name": (lead.get("company_profile") or {}).get("company_name") or dom,
                "title": (lead.get("company_profile") or {}).get("title") or dom,
                "description": (lead.get("company_profile") or {}).get("description") or "",
                "score": score,
                "grade": grade,
                "dmarc_status": q.get("dmarc_status") or lead.get("dmarc_status") or "unknown",
                "spf_status": q.get("spf_status") or lead.get("spf_status") or "unknown",
                "dkim_status": lead.get("dkim_status") or "unknown",
                "dkim_selectors_found": lead.get("dkim_selectors_found") or [],
                "caa_status": lead.get("caa_status") or "unknown",
                "caa_records": lead.get("caa_records") or [],
                "ct_subdomains": lead.get("ct_subdomains") or [],
                "ct_subdomain_count": lead.get("ct_subdomain_count", len(lead.get("ct_subdomains") or [])),
                "registrar": lead.get("registrar") or "Unknown",
                "dns_provider": lead.get("dns_provider") or "Standard DNS",
                "mx_provider": lead.get("mx_provider") or "Corporate Mail",
                "tech_stack": lead.get("tech_stack") or [],
                "leadership": lead.get("leadership") or {},
                "probe_count": probe_counts.get(dom, 1),
                "last_probed_at": q.get("timestamp") or lead.get("enriched_at") or "",
                "trigger_source": q.get("trigger_source") or "radar_submit",
                "device_summary": ua_info.get("summary", "Unknown Device"),
                "device_type": ua_info.get("device_type", "Unknown"),
                "deliverables": {
                    "staged": camp_dir.exists(),
                    "campaign_dir": f"outbound_campaigns/{slug}",
                    "has_pdf": pdf_file.exists(),
                    "has_audit_md": md_audit_file.exists(),
                    "has_dns_plan": dns_file.exists(),
                    "has_retainer_proposal": proposal_file.exists(),
                    "has_pitch_email": pitch_file.exists(),
                },
            })

        return items

    def get_deliverable_content(self, domain: str, file_type: str = "retainer_proposal") -> Dict[str, Any]:
        """Safely reads a staged deliverable file for a given domain."""
        clean_dom = self.normalize_domain(domain)
        if not clean_dom or not self.is_valid_domain(clean_dom):
            return {"ok": False, "error": f"Invalid domain: {domain}"}

        slug = self.proposal_stager.domain_to_slug(clean_dom)
        camp_dir = (self.proposal_stager.campaigns_dir / slug).resolve()
        base_dir = self.proposal_stager.campaigns_dir.resolve()
        if not str(camp_dir).startswith(str(base_dir)):
            return {"ok": False, "error": "Access denied"}

        file_map = {
            "retainer_proposal": "retainer_proposal.md",
            "retainer_proposal.md": "retainer_proposal.md",
            "dns_remediation": "dns_remediation_plan.md",
            "dns_remediation_plan.md": "dns_remediation_plan.md",
            "pitch_email": "pitch_email.txt",
            "pitch_email.txt": "pitch_email.txt",
            "security_audit": f"{slug}_security_audit.md",
            "audit_md": f"{slug}_security_audit.md",
            f"{slug}_security_audit.md": f"{slug}_security_audit.md",
            "pdf": f"{slug}_security_audit.pdf",
            f"{slug}_security_audit.pdf": f"{slug}_security_audit.pdf",
        }
        target_name = file_map.get(file_type.strip().lower())
        if not target_name:
            return {"ok": False, "error": f"Unsupported deliverable type: {file_type}"}

        target_path = (camp_dir / target_name).resolve()
        if not str(target_path).startswith(str(camp_dir)) or not target_path.exists():
            return {"ok": False, "error": f"Deliverable not found: {target_name}"}

        if target_name.endswith(".pdf"):
            return {
                "ok": True,
                "domain": clean_dom,
                "filename": target_name,
                "is_binary": True,
                "path": str(target_path),
                "size_bytes": target_path.stat().st_size,
            }

        content = target_path.read_text(encoding="utf-8", errors="replace")
        return {
            "ok": True,
            "domain": clean_dom,
            "filename": target_name,
            "is_binary": False,
            "content": content,
            "size_bytes": len(content.encode("utf-8")),
        }


# =============================================================================
# Self-Healing Public Telemetry Tunnel Watchdog
# =============================================================================

DEFAULT_TUNNEL_STATE_FILE = get_effective_data_dir() / "radar_tunnel_state.json"


class RadarTunnelWatchdog:
    """Supervises and tracks public HTTPS tunnel URL rotations (e.g., localhost.run / lhr.life)."""

    TUNNEL_URL_REGEX = re.compile(
        r"https://[a-zA-Z0-9.-]+\.(?:lhr\.life|localhost\.run|trycloudflare\.com|ngrok-free\.app|ngrok\.io)",
        re.IGNORECASE,
    )

    def __init__(self, state_file: Optional[Path] = None, repo_root: Optional[Path] = None):
        self.state_file = Path(state_file) if state_file else (get_effective_data_dir() / "radar_tunnel_state.json")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.repo_root = Path(repo_root) if repo_root else REPO_ROOT

    @classmethod
    def extract_tunnel_url(cls, text: str) -> Optional[str]:
        """Extracts the latest public HTTPS tunnel base URL from SSH/tunnel stdout logs."""
        if not text:
            return None
        matches = cls.TUNNEL_URL_REGEX.findall(text)
        if not matches:
            return None
        return matches[-1].rstrip("/")

    def get_state(self) -> Dict[str, Any]:
        """Reads the current persisted tunnel state."""
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {
            "tunnel_base_url": None,
            "telemetry_endpoint": None,
            "rotation_count": 0,
            "updated_at": None,
            "status": "uninitialized",
        }

    def record_tunnel_rotation(
        self,
        tunnel_base_url: str,
        sync_assets: bool = True,
    ) -> Dict[str, Any]:
        """Persists a newly detected public HTTPS tunnel URL and optionally syncs landing/docs assets."""
        clean_base = (tunnel_base_url or "").strip().rstrip("/")
        if not clean_base.startswith("https://"):
            raise ValueError(f"Invalid HTTPS tunnel URL: {tunnel_base_url}")

        current = self.get_state()
        rotations = int(current.get("rotation_count") or 0)
        if current.get("tunnel_base_url") != clean_base:
            rotations += 1

        endpoint = f"{clean_base}/api/orbit/radar/telemetry"
        state = {
            "tunnel_base_url": clean_base,
            "telemetry_endpoint": endpoint,
            "rotation_count": rotations,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "active",
        }
        tmp = self.state_file.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception:
            if tmp.exists():
                tmp.unlink()

        if sync_assets:
            self.sync_tunnel_endpoint_in_assets(endpoint, state=state)
        return state

    def sync_tunnel_endpoint_in_assets(
        self, new_endpoint: str, state: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Updates the public HTTPS tunnel fallback endpoint in landing/assets/orbit_radar.js, docs/, and radar_tunnel_state.json."""
        updated = False
        pattern = re.compile(
            r"addEp\('https://[a-zA-Z0-9.-]+\.(?:lhr\.life|localhost\.run|trycloudflare\.com)/api/orbit/radar/telemetry'\);"
        )
        replacement = f"addEp('{new_endpoint}');"
        for rel_path in ("landing/assets/orbit_radar.js", "docs/assets/orbit_radar.js"):
            target = self.repo_root / rel_path
            if target.exists():
                try:
                    raw = target.read_text(encoding="utf-8")
                    new_raw, count = pattern.subn(replacement, raw)
                    if count > 0 and new_raw != raw:
                        target.write_text(new_raw, encoding="utf-8")
                        updated = True
                except Exception as ex:
                    logger.warning("Failed to sync tunnel endpoint in %s: %s", target, ex)

        public_state = {
            "telemetry_endpoint": new_endpoint,
            "updated_at": (state or {}).get("updated_at")
            or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "active",
        }
        public_json = json.dumps(public_state, indent=2)
        for state_rel in (
            "landing/assets/radar_tunnel_state.json",
            "docs/assets/radar_tunnel_state.json",
        ):
            state_target = self.repo_root / state_rel
            try:
                state_target.parent.mkdir(parents=True, exist_ok=True)
                state_target.write_text(public_json, encoding="utf-8")
                updated = True
            except Exception as ex:
                logger.warning("Failed to write public tunnel state %s: %s", state_target, ex)
        return updated


# =============================================================================
# Standalone HTTP Ingestion Handler & Server
# =============================================================================

class RadarTelemetryHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Zero-dependency HTTP handler for incoming telemetry beacons from the browser."""

    service = RadarTelemetryService()
    tunnel_watchdog = RadarTunnelWatchdog()
    MAX_POST_BODY_BYTES = 16384
    MAX_REQUESTS_PER_MINUTE = 30
    _rate_lock = threading.Lock()
    _rate_buckets: Dict[str, List[float]] = {}

    @classmethod
    def _build_server_config(cls) -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": "orbit-radar-telemetry",
            "version": "2.4.0",
            "env": "cloudrun" if os.environ.get("K_SERVICE") else "standalone",
            "zero_tunnel": True,
            "data_dir": str(get_effective_data_dir()),
        }

    def _extract_client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For", "").strip()
        if xff:
            return xff.split(",")[0].strip()
        xrip = self.headers.get("X-Real-IP", "").strip()
        if xrip:
            return xrip
        return self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"

    def _is_authorized_reader(self) -> bool:
        """Restricts sensitive GET inspection endpoints (/leads, /deliverable, /telemetry) to loopback or Bearer auth."""
        auth_header = self.headers.get("Authorization", "").strip()
        expected_token = os.environ.get("ORBIT_TELEMETRY_TOKEN", "").strip()
        if expected_token and auth_header.startswith("Bearer "):
            provided = auth_header[7:].strip()
            if hmac.compare_digest(provided, expected_token):
                return True

        # Reject unauthenticated read attempts arriving over public reverse tunnels
        if self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP"):
            return False
        host_hdr = (self.headers.get("Host") or "").lower().split(":")[0]
        if host_hdr.endswith((".lhr.life", ".localhost.run", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com")):
            return False

        raw_ip = self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"
        return raw_ip in ("127.0.0.1", "::1", "localhost")

    @classmethod
    def _check_rate_limit(cls, client_ip: str) -> bool:
        now = time.time()
        key = anonymize_client_ip(client_ip) or client_ip
        with cls._rate_lock:
            timestamps = [t for t in cls._rate_buckets.get(key, []) if (now - t) < 60.0]
            if len(timestamps) >= cls.MAX_REQUESTS_PER_MINUTE:
                cls._rate_buckets[key] = timestamps
                return False
            timestamps.append(now)
            cls._rate_buckets[key] = timestamps
            if len(cls._rate_buckets) > 500:
                cls._rate_buckets = {
                    k: [t for t in v if (now - t) < 60.0]
                    for k, v in cls._rate_buckets.items()
                    if any((now - t) < 60.0 for t in v)
                }
            return True

    def send_cors_headers(self, status: int = 200, content_type: str = "application/json"):
        origin = self.headers.get("Origin", "*")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", origin or "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Orbit-Session, X-Requested-With",
        )
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send_json_error(self, status: int, message: str):
        body = json.dumps({"ok": False, "error": message}).encode("utf-8")
        self.send_cors_headers(status, "application/json")
        if status == 429:
            self.send_header("Retry-After", "60")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_OPTIONS(self):
        self.send_cors_headers(200, "text/plain")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/health", "/health"):
            body = b'{"status": "ok", "service": "orbit-radar-telemetry"}'
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path in ("/api/orbit/radar/config", "/api/radar/config"):
            config = self._build_server_config()
            body = json.dumps(config).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path in ("/api/orbit/radar/action", "/api/radar/action"):
            params = urllib.parse.parse_qs(parsed.query)
            action = params.get("action", [""])[0]
            domain = params.get("domain", [""])[0]
            token = params.get("token", [""])[0]

            if not verify_action_token(domain, action, token):
                self._send_json_error(403, "Invalid or expired action token")
                return

            if action == "stage_retainer":
                # Enrich first: the stager needs the freshly computed score/DMARC snapshot,
                # not the stale profile from a previous probe.
                enricher = getattr(self.service, "enricher", None) or RadarLeadEnricher()
                enrichment = enricher.enrich_domain(domain=domain)
                stager = getattr(self.service, "proposal_stager", None) or RadarRetainerProposalStager()
                result = stager.stage_campaign(domain=domain, enrichment=enrichment)
                response = {
                    "status": "ok",
                    "action": "stage_retainer",
                    "domain": domain,
                    "deliverables": result,
                    "message": f"Retainer campaign successfully staged for {domain}",
                }
                body = json.dumps(response, indent=2).encode("utf-8")
                self.send_cors_headers(200, "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self._send_json_error(400, f"Unsupported action: {action}")
            return

        if parsed.path in (
            "/api/orbit/radar/telemetry",
            "/api/radar/telemetry",
            "/api/orbit/radar/leads",
            "/api/radar/leads",
            "/api/orbit/radar/deliverable",
            "/api/radar/deliverable",
            "/api/orbit/radar/tunnel",
            "/api/radar/tunnel",
        ):
            if not self._is_authorized_reader():
                self._send_json_error(403, "Forbidden: loopback or Bearer token required for telemetry inspection")
                return

        if parsed.path in ("/api/orbit/radar/tunnel", "/api/radar/tunnel"):
            state = self.tunnel_watchdog.get_state()
            body = json.dumps({"ok": True, "tunnel": state}).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ("/api/orbit/radar/telemetry", "/api/radar/telemetry"):
            q_params = urllib.parse.parse_qs(parsed.query)
            limit = max(1, min(200, int(q_params.get("limit", [50])[0])))
            domain = q_params.get("domain", [None])[0]
            queries = self.service.get_recent_queries(limit=limit, domain=domain)
            stats = self.service.get_query_stats()
            body = json.dumps({"ok": True, "count": len(queries), "stats": stats, "queries": queries}).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ("/api/orbit/radar/leads", "/api/radar/leads"):
            q_params = urllib.parse.parse_qs(parsed.query)
            limit = max(1, min(200, int(q_params.get("limit", [50])[0])))
            leads = self.service.get_enriched_leads_summary(limit=limit)
            stats = self.service.get_query_stats()
            body = json.dumps({"ok": True, "count": len(leads), "stats": stats, "leads": leads}).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ("/api/orbit/radar/deliverable", "/api/radar/deliverable"):
            q_params = urllib.parse.parse_qs(parsed.query)
            domain = q_params.get("domain", [""])[0]
            file_type = q_params.get("file", ["retainer_proposal"])[0]
            res = self.service.get_deliverable_content(domain=domain, file_type=file_type)
            if res.get("ok") and res.get("is_binary") and q_params.get("raw", ["0"])[0] == "1":
                pdf_bytes = Path(res["path"]).read_bytes()
                self.send_cors_headers(200, "application/pdf")
                self.send_header("Content-Disposition", f'inline; filename="{res["filename"]}"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
            else:
                status = 200 if res.get("ok") else 404
                body = json.dumps(res).encode("utf-8")
                self.send_cors_headers(status, "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            self.send_cors_headers(404, "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/orbit/radar/telemetry", "/api/radar/telemetry"):
            client_ip = self._extract_client_ip()
            if not self._check_rate_limit(client_ip):
                self._send_json_error(429, "Rate limit exceeded (max 30 telemetry events per minute)")
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._send_json_error(400, "Invalid Content-Length header")
                return

            if content_length < 0 or content_length > self.MAX_POST_BODY_BYTES:
                try:
                    self.rfile.read(min(content_length, 65536))
                except Exception:
                    pass
                self._send_json_error(413, f"Payload exceeds {self.MAX_POST_BODY_BYTES} byte limit")
                return

            try:
                raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
                data = json.loads(raw_body)
                if not isinstance(data, dict):
                    raise ValueError("Payload must be a JSON object")
            except Exception as ex:
                self._send_json_error(400, f"Invalid JSON payload: {ex}")
                return

            res = self.service.record_query(data, client_ip=client_ip)
            status_code = 200 if res.get("ok") else 400
            body = json.dumps(res).encode("utf-8")
            self.send_cors_headers(status_code, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_cors_headers(404, "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format_str, *args):
        pass  # Silent logging to prevent console pollution


RadarTelemetryHandler = RadarTelemetryHTTPHandler


def run_server(port: Optional[int] = None, host: str = "0.0.0.0") -> None:
    if port is None:
        port = int(os.environ.get("PORT", 9095))
    server_address = (host, port)
    httpd = http.server.ThreadingHTTPServer(server_address, RadarTelemetryHTTPHandler)
    print(f"[ORBIT-TELEMETRY] Listening on http://{host}:{port}/api/orbit/radar/telemetry")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print("\n[ORBIT-TELEMETRY] Server terminated.")


# =============================================================================
# CLI Tail & Stats Functions
# =============================================================================

def run_tail(poll_interval: float = 1.0, limit: int = 10) -> None:
    """Streams live incoming perimeter queries to stdout in retro cyber format."""
    service = RadarTelemetryService()
    print("=" * 78)
    print("ORBIT // PERIMETER RADAR TERMINAL - LIVE INBOUND PROBE STREAM")
    print(f"Log source: {service.queries_file}")
    print("Press Ctrl+C to stop.")
    print("=" * 78)

    seen_ids = set()
    initial_queries = service.get_recent_queries(limit=limit)
    for q in reversed(initial_queries):
        seen_ids.add(q.get("id"))
        _print_query_line(q)

    while True:
        try:
            time.sleep(poll_interval)
            latest = service.get_recent_queries(limit=20)
            for q in reversed(latest):
                qid = q.get("id")
                if qid and qid not in seen_ids:
                    seen_ids.add(qid)
                    _print_query_line(q)
        except KeyboardInterrupt:
            print("\n[Tail terminated]")
            break


def _print_query_line(q: Dict[str, Any]) -> None:
    domain = q.get("domain", "unknown")
    score = q.get("score")
    grade = q.get("grade") or "--"
    src = q.get("trigger_source", "submit")
    ts = q.get("timestamp", "")[:19].replace("T", " ")
    score_str = f"{score:>3}/100" if score is not None else "  ---  "
    ua_info = parse_user_agent_summary(q.get("user_agent"), q.get("screen_resolution"))
    print(f"[{ts}] [{grade:^3}] ({score_str}) PROBE: {domain:<26} | {ua_info['summary']} [via: {src}]")


def run_stats() -> None:
    """Prints a structured summary of domain inquiries to stdout."""
    service = RadarTelemetryService()
    stats = service.get_query_stats()
    print("=" * 60)
    print("ORBIT // PERIMETER RADAR TERMINAL INQUIRY METRICS")
    print("=" * 60)
    print(f"Total Radar Probes Logged : {stats['total_probes']}")
    print(f"Unique Domains Audited     : {stats['unique_domains']}")
    print("-" * 60)
    print("Top Probed Domains:")
    for item in stats.get("top_domains", []):
        print(f"  • {item['domain']:<35} : {item['probes']} probe(s)")
    print("-" * 60)
    print("Security Hygiene Breakdown:")
    for grade, count in sorted(stats.get("grade_breakdown", {}).items()):
        print(f"  • Grade {grade:<8} : {count}")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="radar_telemetry",
        description="ORBIT Radar Terminal Inbound Query Telemetry Service & Observer",
    )
    parser.add_argument("--tail", action="store_true", help="Live tail inbound queries")
    parser.add_argument("--stats", action="store_true", help="Display inquiry statistics")
    parser.add_argument("--serve", action="store_true", help="Run standalone ingestion HTTP server")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", 9095)),
        help="Port for server (default: 9095 or $PORT)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--probe", help="Emit manual test probe for specified domain")
    parser.add_argument("--enrich", help="Run OSINT enrichment and retainer staging for a domain")
    parser.add_argument("--backfill", action="store_true", help="Enrich and stage proposals for all logged queries")
    parser.add_argument("--tunnel-status", action="store_true", help="Show active public HTTPS tunnel telemetry state")
    parser.add_argument("--sync-tunnel", help="Record and sync a public HTTPS tunnel base URL or log file")

    args = parser.parse_args()

    if args.tunnel_status:
        watchdog = RadarTunnelWatchdog()
        print(json.dumps(watchdog.get_state(), indent=2))
        return 0

    if args.sync_tunnel:
        watchdog = RadarTunnelWatchdog()
        raw_arg = args.sync_tunnel.strip()
        if raw_arg.startswith("https://"):
            url = watchdog.extract_tunnel_url(raw_arg) or raw_arg
        else:
            log_path = Path(raw_arg)
            url = watchdog.extract_tunnel_url(log_path.read_text(encoding="utf-8", errors="ignore")) if log_path.exists() else None
        if not url:
            print(json.dumps({"ok": False, "error": f"No tunnel URL found in {raw_arg}"}))
            return 1
        state = watchdog.record_tunnel_rotation(url, sync_assets=True)
        print(json.dumps({"ok": True, "tunnel": state}, indent=2))
        return 0

    if args.probe:
        service = RadarTelemetryService()
        res = service.record_query({"domain": args.probe, "trigger_source": "cli_test"}, enrich_async=False)
        print(json.dumps(res, indent=2))
        return 0

    if args.enrich:
        service = RadarTelemetryService()
        out = service._enrich_stage_and_alert(
            {"domain": service.normalize_domain(args.enrich), "trigger_source": "cli_enrich"},
            network_probe=True,
        )
        print(json.dumps(out.get("proposal") or {}, indent=2))
        return 0

    if args.backfill:
        service = RadarTelemetryService()
        results = service.backfill_existing_queries(network_probe=True)
        print(json.dumps({"backfilled_count": len(results), "results": results}, indent=2))
        return 0

    if args.serve:
        run_server(port=args.port, host=args.host)
        return 0

    if args.tail:
        run_tail()
        return 0

    if args.stats:
        run_stats()
        return 0

    # Default action: show stats
    run_stats()
    return 0


if __name__ == "__main__":
    sys.exit(main())
