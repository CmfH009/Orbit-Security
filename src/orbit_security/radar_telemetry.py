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
import http.server
import json
import logging
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

from orbit_security.radar_lead_enricher import DEFAULT_ENRICHED_LEADS_FILE, RadarLeadEnricher
from orbit_security.radar_proposal_stager import DEFAULT_CAMPAIGNS_DIR, RadarRetainerProposalStager

logger = logging.getLogger("orbit_security.radar_telemetry")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
DEFAULT_QUERIES_FILE = DATA_DIR / "radar_queries.jsonl"

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

    return {
        "username": "ORBIT Radar Sentinel",
        "avatar_url": "https://cmfh009.github.io/Orbit-Security/assets/logo.png",
        "embeds": [
            {
                "title": f"🎯 Orbit Radar Probe Detected: {domain} (Grade {grade})",
                "description": (
                    f"Live perimeter scan captured on **ORBIT // PERIMETER RADAR TERMINAL** "
                    f"for `{domain}` via `{ua_info['device_type']}` ({ua_info['browser']})."
                ),
                "color": color,
                "fields": fields,
                "footer": {
                    "text": "Project ORBIT // Perimeter Radar Terminal Live Telemetry",
                },
                "timestamp": ts,
            }
        ],
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
        self.queries_file = Path(queries_file) if queries_file else DEFAULT_QUERIES_FILE
        self.queries_file.parent.mkdir(parents=True, exist_ok=True)
        self.dedup_window_seconds = dedup_window_seconds
        self._lock = threading.Lock()
        self._recent_probes_cache: Dict[str, float] = {}
        self.enricher = RadarLeadEnricher(leads_file=leads_file or DEFAULT_ENRICHED_LEADS_FILE)
        self.proposal_stager = RadarRetainerProposalStager(campaigns_dir=campaigns_dir or DEFAULT_CAMPAIGNS_DIR)

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
        hash_seed = f"{domain}:{now_epoch}:{session_id}:{client_ip}:{trigger_source}"
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
            client_ip=str(client_ip)[:64] if client_ip else None,
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
        if enrich_async:
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

    def get_recent_queries(
        self, limit: int = 50, domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Reads recent queries from JSONL in reverse chronological order."""
        if not self.queries_file.exists():
            return []
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
                        queries.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception as ex:
            logger.warning(f"Failed to read queries from {self.queries_file}: {ex}")
            return []

        queries.reverse()
        return queries[:limit]

    def get_query_stats(self) -> Dict[str, Any]:
        """Calculates aggregate metrics across recorded perimeter radar probes."""
        if not self.queries_file.exists():
            return {
                "total_probes": 0,
                "unique_domains": 0,
                "top_domains": [],
                "grade_breakdown": {},
                "latest_probe": None,
            }

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
                        record = json.loads(line)
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


# =============================================================================
# Standalone HTTP Ingestion Handler & Server
# =============================================================================

class RadarTelemetryHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Zero-dependency HTTP handler for incoming telemetry beacons from the browser."""

    service = RadarTelemetryService()

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

    def do_OPTIONS(self):
        self.send_cors_headers(200, "text/plain")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/orbit/radar/telemetry", "/api/radar/telemetry"):
            q_params = urllib.parse.parse_qs(parsed.query)
            limit = int(q_params.get("limit", [50])[0])
            domain = q_params.get("domain", [None])[0]
            queries = self.service.get_recent_queries(limit=limit, domain=domain)
            stats = self.service.get_query_stats()
            body = json.dumps({"ok": True, "count": len(queries), "stats": stats, "queries": queries}).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ("/api/health", "/health"):
            body = b'{"status": "ok", "service": "orbit-radar-telemetry"}'
            self.send_cors_headers(200, "application/json")
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
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
                data = json.loads(raw_body)
            except Exception as ex:
                err_body = json.dumps({"ok": False, "error": f"Invalid JSON payload: {ex}"}).encode("utf-8")
                self.send_cors_headers(400, "application/json")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
                return

            client_ip = self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"
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


def run_server(port: int = 9095, host: str = "0.0.0.0") -> None:
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
    parser.add_argument("--port", type=int, default=9095, help="Port for server (default: 9095)")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--probe", help="Emit manual test probe for specified domain")
    parser.add_argument("--enrich", help="Run OSINT enrichment and retainer staging for a domain")
    parser.add_argument("--backfill", action="store_true", help="Enrich and stage proposals for all logged queries")

    args = parser.parse_args()

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
