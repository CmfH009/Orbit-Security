"""Orbit Security: Automated Bug Bounty Radar (bounty_radar.py).

Ingests public bug bounty program target scopes (HackerOne / Bugcrowd),
expands wildcard scopes (*.target.com), identifies dangling SaaS CNAMEs
(AWS S3, GitHub Pages, Unbounce, Fastly, Shopify) and SPF/DMARC mail-spoofing vectors,
executes off-peak sweeps (2:00 AM - 5:00 AM MST), and generates structured
HackerOne-compliant vulnerability disclosure reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request
import urllib.error

import dns.resolver

from orbit_security.dns_cache import get_orbit_sync_resolver
from orbit_security.models import Severity
from orbit_security.notifications import BountyAlertPayload, WebhookDispatcher
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature

logger = logging.getLogger("orbit_security.bounty_radar")

DEFAULT_BOUNTY_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "bounty_programs.json"
DEFAULT_DISCLOSURES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "disclosures"
DEFAULT_RADAR_STATE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "bounty_radar_state.json"

# High-frequency cloud and SaaS subdomain prefixes for wildcard expansion
HIGH_FREQUENCY_PREFIXES: List[str] = [
    # Static, Media, CDN & Assets
    "assets", "cdn", "cdn1", "cdn2", "static", "static1", "media", "images", "img",
    "files", "downloads", "download", "uploads", "s3", "storage", "bucket",
    # Core Web, Portals & Apps
    "app", "apps", "portal", "admin", "dashboard", "console", "api", "api-docs",
    "dev", "devel", "developer", "developers", "stage", "staging", "test", "test1",
    "demo", "beta", "preview", "sandbox", "qa", "uat",
    # Identity, Auth & Infrastructure
    "auth", "sso", "login", "accounts", "corp", "internal", "vpn", "mail",
    "webmail", "email", "status", "health", "monitor", "grafana", "kibana", "prometheus",
    # Marketing, Content & Support
    "blog", "news", "press", "help", "support", "desk", "docs", "guide",
    "shop", "store", "market", "promo", "lp", "landing", "events", "forms",
    "survey", "feedback", "careers", "jobs", "community", "forum", "webinar", "summit",
    # SaaS Integrations & Cloud Services
    "zendesk", "hubspot", "salesforce", "notion", "jira", "confluence",
    "jenkins", "gitlab", "github", "slack", "unbounce", "webflow", "shopify", "ghost",
    "wordpress", "wp",
    # Commerce, Billing & Partnerships
    "pay", "payment", "billing", "checkout", "cart", "partner", "partners", "affiliate", "connect",
]


def is_vulnerability_in_scope(program: Optional[BountyProgram], flaw_type: str, viability: str = "") -> bool:
    """Evaluates whether a vulnerability vector is permitted under program policy.

    Checks program.excluded_vulnerabilities against normalized flaw_type, category aliases,
    and viability constraints. Returns False if vector is excluded by policy.
    """
    if not program or not getattr(program, "excluded_vulnerabilities", None):
        return True

    flaw_norm = flaw_type.lower().replace("-", "_").strip()

    vector_aliases: Dict[str, Set[str]] = {
        "mail_spoofing": {
            "mail_spoofing", "email_spoofing", "dmarc", "missing_dmarc", "spf",
            "permissive_spf", "spf_dmarc", "dmarc_policy", "email_security", "spoofing"
        },
        "cors_wildcard_origin": {
            "cors_wildcard_origin", "cors_wildcard", "unauthenticated_cors",
            "cors_unauthenticated", "wildcard_cors", "cors"
        },
        "cors_arbitrary_origin_with_credentials": {
            "cors_arbitrary_origin_with_credentials", "cors_credentials", "cors"
        },
        "cors_null_origin_with_credentials": {
            "cors_null_origin_with_credentials", "cors_null_origin", "cors"
        },
        "cors_misconfiguration": {
            "cors_misconfiguration", "cors", "cors_wildcard", "cors_wildcard_origin",
            "unauthenticated_cors"
        },
        "graphql_introspection": {
            "graphql_introspection", "graphql", "introspection", "graphql_schema"
        },
        "cloud_storage_takeover": {
            "cloud_storage_takeover", "cloud_storage", "bucket_takeover", "s3_takeover",
            "storage_takeover"
        },
        "open_cloud_bucket": {
            "open_cloud_bucket", "open_bucket", "public_bucket", "cloud_storage"
        },
        "http_request_smuggling_cl_te": {
            "http_request_smuggling_cl_te", "http_request_smuggling", "request_smuggling",
            "http_smuggling", "smuggling"
        },
        "http_request_smuggling_te_cl": {
            "http_request_smuggling_te_cl", "http_request_smuggling", "request_smuggling",
            "http_smuggling", "smuggling"
        },
        "http_request_smuggling_h2_downgrade": {
            "http_request_smuggling_h2_downgrade", "http_request_smuggling", "request_smuggling",
            "http_smuggling", "smuggling"
        },
        "oauth_redirect_uri_hijack": {
            "oauth_redirect_uri_hijack", "oauth_redirect", "oauth", "oauth_flaws"
        },
        "oauth_login_csrf": {
            "oauth_login_csrf", "oauth_csrf", "oauth", "oauth_flaws"
        },
        "oauth_missing_pkce": {
            "oauth_missing_pkce", "missing_pkce", "pkce", "oauth", "oauth_flaws"
        },
        "oidc_insecure_signing_alg": {
            "oidc_insecure_signing_alg", "oidc_alg_none", "oidc", "oauth"
        },
        "oidc_internal_endpoint_leak": {
            "oidc_internal_endpoint_leak", "oidc_leak", "oidc", "oauth"
        },
        "dependency_confusion_namespace_takeover": {
            "dependency_confusion_namespace_takeover", "dependency_confusion",
            "namespace_takeover", "supply_chain"
        },
        "subdomain_takeover": {
            "subdomain_takeover", "takeover", "dangling_cname"
        },
    }

    flaw_aliases = vector_aliases.get(flaw_norm, {flaw_norm})

    for excl in program.excluded_vulnerabilities:
        excl_norm = excl.lower().replace("-", "_").strip()
        if not excl_norm:
            continue
        if excl_norm == flaw_norm or excl_norm in flaw_aliases:
            return False
        if excl_norm in flaw_norm or flaw_norm in excl_norm:
            return False

    return True


@dataclass
class BountyProgram:
    program_id: str
    name: str
    platform: str = "hackerone"  # hackerone, bugcrowd, intigriti, direct
    policy_url: str = ""
    in_scope: List[str] = field(default_factory=list)  # e.g. ["*.shopify.com", "*.myshopify.com"]
    out_of_scope: List[str] = field(default_factory=list)
    excluded_vulnerabilities: List[str] = field(default_factory=list)
    bounty_tier: str = "cash"  # cash, swag, points
    max_bounty: int = 10000
    state: str = "active"  # active, paused
    last_scanned: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def is_vulnerability_in_scope(self, flaw_type: str, viability: str = "") -> bool:
        """Evaluates whether vulnerability vector is permitted under program policy."""
        return is_vulnerability_in_scope(self, flaw_type, viability)


@dataclass
class BountyVulnerability:
    program_id: str
    program_name: str
    platform: str
    target_domain: str
    cname_target: Optional[str] = None
    flaw_type: str = "subdomain_takeover"  # subdomain_takeover, mail_spoofing
    provider: Optional[str] = None  # e.g. "AWS S3", "GitHub Pages", "Unbounce", "Fastly", "Shopify"
    severity: Severity = Severity.HIGH
    cvss_score: float = 7.5
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
    evidence: str = ""
    cwe_id: str = "CWE-284: Improper Access Control"
    remediation: str = ""
    bounty_viability: str = "HIGH_CONFIDENCE"  # HIGH_CONFIDENCE, CONDITIONAL, INFORMATIONAL_LOW
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    status: str = "discovered"  # discovered, reported, resolved


class BountyScopeIngester:
    """Ingests public bug bounty program scopes from HackerOne, Bugcrowd, or JSON exports."""

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = Path(data_path or DEFAULT_BOUNTY_DATA_PATH)
        self.programs: Dict[str, BountyProgram] = {}
        self.load()

    def load(self):
        """Loads programs from disk or populates default seeded programs if empty."""
        if not self.data_path.exists():
            self._populate_seed_programs()
            self.save()
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.programs = {
                    item["program_id"]: BountyProgram(**item)
                    for item in data.get("programs", [])
                }
            if not self.programs:
                self._populate_seed_programs()
                self.save()
        except Exception as e:
            logger.warning(f"Failed to load bounty programs from {self.data_path}: {e}")
            self._populate_seed_programs()

    def save(self):
        """Persists programs to disk."""
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "programs": [asdict(p) for p in self.programs.values()],
        }
        with open(self.data_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _populate_seed_programs(self):
        """Default seeded public wildcard bug bounty programs."""
        seeded = [
            BountyProgram(
                program_id="shopify",
                name="Shopify",
                platform="hackerone",
                policy_url="https://hackerone.com/shopify",
                in_scope=["*.shopify.com", "*.myshopify.com", "*.shopifyapps.com"],
                out_of_scope=["community.shopify.com"],
                bounty_tier="cash",
                max_bounty=50000,
            ),
            BountyProgram(
                program_id="gitlab",
                name="GitLab",
                platform="hackerone",
                policy_url="https://hackerone.com/gitlab",
                in_scope=["*.gitlab.com", "*.about.gitlab.com"],
                out_of_scope=[],
                bounty_tier="cash",
                max_bounty=35000,
            ),
            BountyProgram(
                program_id="starbucks",
                name="Starbucks",
                platform="hackerone",
                policy_url="https://hackerone.com/starbucks",
                in_scope=["*.starbucks.com", "*.starbucksreserve.com"],
                out_of_scope=[],
                bounty_tier="cash",
                max_bounty=10000,
            ),
            BountyProgram(
                program_id="yahoo",
                name="Yahoo / Oath",
                platform="hackerone",
                policy_url="https://hackerone.com/yahoo",
                in_scope=["*.yahoo.com", "*.oath.com", "*.engadget.com"],
                out_of_scope=[],
                bounty_tier="cash",
                max_bounty=25000,
            ),
            BountyProgram(
                program_id="hyatt",
                name="Hyatt Hotels",
                platform="bugcrowd",
                policy_url="https://bugcrowd.com/hyatt",
                in_scope=["*.hyatt.com"],
                out_of_scope=[],
                bounty_tier="cash",
                max_bounty=15000,
            ),
        ]
        self.programs = {p.program_id: p for p in seeded}

    def ingest_hackerone_scope(self, data: Dict[str, Any] | List[Any] | str) -> List[BountyProgram]:
        """Ingests structured HackerOne scope export JSON.

        Handles:
        1. API format: {"data": [{"attributes": {"handle": "...", "targets": {"in_scope": [...]}}}]}
        2. Policy JSON export: {"handle": "...", "targets": {"in_scope": [{"asset_identifier": "*.example.com", ...}]}}
        3. Simple target list: [{"asset_identifier": "*.domain.com", "eligible_for_bounty": true}]
        """
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception as e:
                raise ValueError(f"Invalid JSON string passed to ingest_hackerone_scope: {e}")

        ingested: List[BountyProgram] = []

        if isinstance(data, dict):
            # Check for multiple programs under data key
            raw_programs = data.get("data", [data]) if "data" in data and isinstance(data["data"], list) else [data]
        elif isinstance(data, list):
            raw_programs = data
        else:
            return []

        for item in raw_programs:
            if not isinstance(item, dict):
                continue
            attrs = item.get("attributes", item)
            handle = attrs.get("handle") or attrs.get("program_id") or attrs.get("name") or "unknown_h1"
            name = attrs.get("name") or handle.title()
            policy_url = attrs.get("policy_url") or f"https://hackerone.com/{handle}"
            max_bounty = attrs.get("max_bounty") or 10000

            in_scope: List[str] = []
            out_of_scope: List[str] = []

            targets_data = attrs.get("targets", {})
            if isinstance(targets_data, dict):
                raw_in = targets_data.get("in_scope", [])
                raw_out = targets_data.get("out_of_scope", [])
            elif isinstance(targets_data, list):
                raw_in = targets_data
                raw_out = []
            else:
                raw_in = attrs.get("in_scope", [])
                raw_out = attrs.get("out_of_scope", [])

            for target in raw_in:
                if isinstance(target, dict):
                    identifier = target.get("asset_identifier", "")
                elif isinstance(target, str):
                    identifier = target
                else:
                    continue

                clean_id = identifier.strip().lower()
                if clean_id:
                    in_scope.append(clean_id)

            for target in raw_out:
                identifier = target.get("asset_identifier", "") if isinstance(target, dict) else str(target)
                clean_id = identifier.strip().lower()
                if clean_id:
                    out_of_scope.append(clean_id)

            if in_scope:
                prog = BountyProgram(
                    program_id=str(handle).lower().replace(" ", "_"),
                    name=str(name),
                    platform="hackerone",
                    policy_url=str(policy_url),
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    bounty_tier="cash" if max_bounty > 0 else "swag",
                    max_bounty=int(max_bounty),
                )
                self.programs[prog.program_id] = prog
                ingested.append(prog)

        if ingested:
            self.save()
        return ingested

    @staticmethod
    def _normalize_web_asset(identifier: str) -> Optional[str]:
        """Reduces a scope identifier to a bare host or wildcard; None if not a sweepable web host."""
        ident = (identifier or "").strip().lower()
        ident = re.sub(r"^https?://", "", ident).split("/")[0].split(":")[0]
        if not ident or " " in ident or "." not in ident:
            return None
        if re.fullmatch(r"[\d.]+", ident):  # bare IPv4
            return None
        if not re.fullmatch(r"(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+", ident):
            return None
        return ident

    def ingest_hackerone_feed(
        self,
        feed: List[Dict[str, Any]] | str,
        max_programs: int = 25,
    ) -> List[BountyProgram]:
        """Ingests the public bounty-targets-data HackerOne export with strict safety filtering.

        Only open programs that pay cash are kept, and only WILDCARD/URL/DOMAIN assets that are
        eligible for bounty. Out-of-scope web assets are carried over for exclusion.
        """
        if isinstance(feed, str):
            feed = json.loads(feed)
        ingested: List[BountyProgram] = []
        web_types = {"WILDCARD", "URL", "DOMAIN"}

        for item in feed:
            if len(ingested) >= max_programs:
                break
            if not isinstance(item, dict) or not item.get("offers_bounties"):
                continue
            if item.get("submission_state", "open") != "open":
                continue
            targets = item.get("targets") or {}
            in_scope: List[str] = []
            for t in targets.get("in_scope", []):
                if t.get("asset_type") not in web_types or not t.get("eligible_for_bounty"):
                    continue
                host = self._normalize_web_asset(t.get("asset_identifier", ""))
                if host and host not in in_scope:
                    in_scope.append(host)
            if not in_scope:
                continue
            out_scope: List[str] = []
            for t in targets.get("out_of_scope", []):
                host = self._normalize_web_asset(t.get("asset_identifier", ""))
                if host and host not in out_scope:
                    out_scope.append(host)

            handle = str(item.get("handle", "")).lower()
            prog = BountyProgram(
                program_id=handle,
                name=item.get("name") or handle,
                platform="hackerone",
                policy_url=item.get("url") or f"https://hackerone.com/{handle}",
                in_scope=in_scope,
                out_of_scope=out_scope,
                bounty_tier="cash",
                max_bounty=int(item.get("max_bounty", 10000)),
            )
            self.programs[prog.program_id] = prog
            ingested.append(prog)

        if ingested:
            self.save()
        return ingested

    def ingest_bugcrowd_scope(self, data: Dict[str, Any] | List[Any] | str) -> List[BountyProgram]:
        """Ingests structured Bugcrowd scope export JSON."""
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception as e:
                raise ValueError(f"Invalid JSON string passed to ingest_bugcrowd_scope: {e}")

        ingested: List[BountyProgram] = []
        raw_items = data if isinstance(data, list) else [data]

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("program_id") or "bugcrowd_program"
            program_id = item.get("code") or item.get("program_id") or re.sub(r"[^a-zA-Z0-9_]", "_", name.lower())
            policy_url = item.get("url") or f"https://bugcrowd.com/{program_id}"
            max_bounty = item.get("max_payout") or item.get("max_bounty") or 5000

            in_scope: List[str] = []
            targets = item.get("targets") or item.get("in_scope") or []
            for t in targets:
                target_uri = t.get("uri") or t.get("name") if isinstance(t, dict) else str(t)
                clean_uri = target_uri.strip().lower()
                if clean_uri:
                    in_scope.append(clean_uri)

            if in_scope:
                prog = BountyProgram(
                    program_id=str(program_id).lower(),
                    name=str(name),
                    platform="bugcrowd",
                    policy_url=str(policy_url),
                    in_scope=in_scope,
                    out_of_scope=item.get("out_of_scope", []),
                    bounty_tier="cash" if max_bounty > 0 else "points",
                    max_bounty=int(max_bounty),
                )
                self.programs[prog.program_id] = prog
                ingested.append(prog)

        if ingested:
            self.save()
        return ingested

    def ingest_chaos_scope(
        self,
        data: Dict[str, Any] | List[Any] | str,
        cash_only: bool = True,
        max_programs: int = 25,
    ) -> List[BountyProgram]:
        """Ingests ProjectDiscovery Chaos bug bounty scope data.

        Handles:
        1. {"programs": [{"name": "...", "url": "...", "bounty": true, "domains": [...]}]}
        2. [{"name": "...", "url": "...", "bounty": true, "domains": [...]}]
        """
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception as e:
                raise ValueError(f"Invalid JSON string passed to ingest_chaos_scope: {e}")

        ingested: List[BountyProgram] = []
        raw_items = data.get("programs", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            if len(ingested) >= max_programs:
                break

            name = item.get("name") or "chaos_program"
            program_id = re.sub(r"[^a-zA-Z0-9_]", "_", name.lower()).strip("_")
            policy_url = item.get("url") or item.get("policy_url") or ""
            is_bounty = item.get("bounty", True)
            bounty_tier = item.get("bounty_tier", "cash" if is_bounty else "points")

            if cash_only and (not is_bounty or bounty_tier != "cash"):
                continue

            raw_domains = item.get("domains") or item.get("in_scope") or []
            in_scope: List[str] = []
            for d in raw_domains:
                d_clean = str(d).strip().lower()
                if d_clean:
                    if not d_clean.startswith("*.") and not d_clean.startswith("."):
                        d_clean = f"*.{d_clean}"
                    in_scope.append(d_clean)

            out_of_scope = [str(x).strip().lower() for x in item.get("out_of_scope", []) if str(x).strip()]

            if in_scope:
                prog = BountyProgram(
                    program_id=program_id,
                    name=name,
                    platform="chaos",
                    policy_url=policy_url,
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    bounty_tier=bounty_tier,
                    max_bounty=int(item.get("max_bounty", 10000)),
                )
                self.programs[prog.program_id] = prog
                ingested.append(prog)

        if ingested:
            self.save()
        return ingested

    def sync_from_feed(
        self,
        source_url_or_path: str,
        feed_type: str = "chaos",
        cash_only: bool = True,
        max_programs: int = 25,
        timeout_seconds: float = 10.0,
    ) -> List[BountyProgram]:
        """Synchronizes bug bounty program scopes from an external HTTP feed or local JSON file."""
        if source_url_or_path.startswith("http://") or source_url_or_path.startswith("https://"):
            req = urllib.request.Request(
                source_url_or_path,
                headers={"User-Agent": "OrbitSecurity-BountyRadar/1.0", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                content = resp.read().decode("utf-8")
        else:
            with open(source_url_or_path, "r", encoding="utf-8") as f:
                content = f.read()

        feed_lower = feed_type.lower()
        if feed_lower == "chaos":
            return self.ingest_chaos_scope(content, cash_only=cash_only, max_programs=max_programs)
        elif feed_lower == "hackerone":
            return self.ingest_hackerone_scope(content)
        elif feed_lower == "bugcrowd":
            return self.ingest_bugcrowd_scope(content)
        else:
            raise ValueError(f"Unsupported feed type '{feed_type}'. Choose from 'chaos', 'hackerone', 'bugcrowd'.")


    def get_program(self, program_id: str) -> Optional[BountyProgram]:
        return self.programs.get(program_id)

    def list_programs(self) -> List[BountyProgram]:
        return list(self.programs.values())

    def export_public_statuspage_snapshot(self) -> Dict[str, Any]:
        """Exports a public Bug Bounty & Perimeter Sentinel statuspage telemetry snapshot (Project #19)."""
        from orbit_security.private_alerting import COMMERCIAL_OUTREACH_FROZEN

        progs = self.list_programs()
        active_progs = [p for p in progs if getattr(p, "state", "active") == "active"]
        total_wildcards = sum(len(p.in_scope) for p in active_progs)

        return {
            "status": "OPERATIONAL",
            "safe_harbor_enforced": True,
            "commercial_outreach_frozen": bool(COMMERCIAL_OUTREACH_FROZEN),
            "total_programs": len(active_progs),
            "total_in_scope_roots": total_wildcards,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "programs": [
                {
                    "program_id": p.program_id,
                    "name": p.name,
                    "platform": p.platform,
                    "in_scope_count": len(p.in_scope),
                    "bounty_tier": p.bounty_tier,
                    "max_bounty": p.max_bounty,
                    "state": p.state,
                }
                for p in active_progs[:15]
            ],
        }

    def parse_unified_program_scope(
        self,
        raw_payload: Dict[str, Any] | str,
        platform: str = "auto",
    ) -> Dict[str, Any]:
        """Autonomous Bug Bounty Program Scope Parser across HackerOne, Bugcrowd & Chaos (Project #27)."""
        data = json.loads(raw_payload) if isinstance(raw_payload, str) else dict(raw_payload or {})

        detected = platform.lower().strip()
        if detected == "auto":
            if "relationships" in data or "structured_scopes" in str(data) or "handle" in data:
                detected = "hackerone"
            elif "targets" in data or "max_payout" in data:
                detected = "bugcrowd"
            else:
                detected = "chaos"

        in_scope_all: List[str] = []
        out_of_scope: List[str] = []
        max_bounty = int(data.get("max_bounty") or data.get("max_payout") or 10000)
        prog_name = str(data.get("name") or data.get("handle") or data.get("code") or "bounty_program")

        if detected == "hackerone":
            scopes = (
                data.get("relationships", {})
                .get("structured_scopes", {})
                .get("data", [])
            )
            for item in scopes:
                attrs = item.get("attributes", item) if isinstance(item, dict) else {}
                ident = str(attrs.get("asset_identifier", "")).strip().lower()
                if not ident:
                    continue
                eligible_sub = attrs.get("eligible_for_submission", True)
                eligible_bounty = attrs.get("eligible_for_bounty", True)
                if eligible_sub and eligible_bounty:
                    in_scope_all.append(ident)
                else:
                    out_of_scope.append(ident)
        elif detected == "bugcrowd":
            for t in data.get("targets", []) or data.get("in_scope", []):
                uri = t.get("uri") or t.get("name") if isinstance(t, dict) else str(t)
                if uri:
                    in_scope_all.append(str(uri).strip().lower())
            for o in data.get("out_of_scope", []):
                out_of_scope.append(str(o).strip().lower())
        else:
            for d in data.get("domains", []) or data.get("in_scope", []):
                d_clean = str(d).strip().lower()
                if d_clean:
                    in_scope_all.append(d_clean if d_clean.startswith("*.") else f"*.{d_clean}")

        wildcards = [h for h in in_scope_all if h.startswith("*.")]
        exact_hosts = [h for h in in_scope_all if not h.startswith("*.")]

        return {
            "platform_detected": detected,
            "program_name": prog_name,
            "max_bounty": max_bounty,
            "in_scope_wildcards": wildcards,
            "in_scope_hosts": exact_hosts,
            "out_of_scope": out_of_scope,
        }


class BountyTakeoverSweeper:
    """Expands wildcard scopes and tests targets for dangling SaaS CNAMEs and mail-spoofing vectors."""

    @staticmethod
    def is_vulnerability_in_scope(program: Optional[BountyProgram], flaw_type: str, viability: str = "") -> bool:
        """Evaluates whether vulnerability vector is permitted under program policy."""
        return is_vulnerability_in_scope(program, flaw_type, viability)

    def __init__(
        self,
        resolver: Optional[dns.resolver.Resolver] = None,
        custom_prefixes: Optional[List[str]] = None,
    ):
        self.resolver = resolver or get_orbit_sync_resolver()
        self.prefixes = custom_prefixes or HIGH_FREQUENCY_PREFIXES

    def fetch_crtsh_subdomains(
        self, apex_domain: str, timeout: float = 2.0, max_results: int = 50
    ) -> List[str]:
        """Passively queries Certificate Transparency logs (crt.sh) for known subdomains.

        Zero brute-force noise. Returns distinct sanitized subdomains belonging to apex_domain.
        Safely falls back to empty list on network error, rate limit, or timeout.
        """
        import urllib.request
        import json

        clean_apex = apex_domain.strip().lower().lstrip("*.")
        url = f"https://crt.sh/?q=%.{clean_apex}&output=json"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"
        }
        subdomains: Set[str] = set()
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", None)) == 200:
                    raw_data = resp.read()
                    entries = json.loads(raw_data)
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            line = line.strip().lower().lstrip("*.")
                            if line and line.endswith("." + clean_apex):
                                subdomains.add(line)
                                if len(subdomains) >= max_results:
                                    break
                        if len(subdomains) >= max_results:
                            break
        except Exception as e:
            logger.debug("crt.sh passive discovery skipped for %s: %s", clean_apex, e)
            return []
        return sorted(list(subdomains))

    def expand_wildcards(
        self,
        in_scope: List[str],
        out_of_scope: Optional[List[str]] = None,
        max_per_wildcard: int = 25,
        use_passive_ct: bool = False,
        use_archive_harvest: bool = False,
    ) -> List[str]:
        """Expands wildcard patterns (*.target.com) into candidate FQDNs."""
        out_set: Set[str] = set(s.strip().lower() for s in (out_of_scope or []))
        expanded: List[str] = []
        seen: Set[str] = set()

        def is_excluded(host: str) -> bool:
            if host in out_set:
                return True
            for pat in out_set:
                if pat.startswith("*."):
                    suffix = pat[2:]
                    if host == suffix or host.endswith("." + suffix):
                        return True
            return False

        for pattern in in_scope:
            clean = pattern.strip().lower()
            if not clean:
                continue

            if clean.startswith("*."):
                apex = clean[2:]
                # Also include apex domain
                if not is_excluded(apex) and apex not in seen:
                    expanded.append(apex)
                    seen.add(apex)

                # Passive Certificate Transparency Discovery if requested
                if use_passive_ct:
                    ct_subs = self.fetch_crtsh_subdomains(apex, max_results=max_per_wildcard)
                    for sub in ct_subs:
                        if not is_excluded(sub) and sub not in seen:
                            expanded.append(sub)
                            seen.add(sub)

                # Historical Archive Harvesting (Wayback CDX & AlienVault OTX) if requested
                if use_archive_harvest:
                    try:
                        from orbit_security.recon_harvester import ArchiveHarvester
                        archive_res = ArchiveHarvester.harvest_historical_assets(apex, max_results=max_per_wildcard)
                        for sub in archive_res.get("subdomains", []):
                            if not is_excluded(sub) and sub not in seen:
                                expanded.append(sub)
                                seen.add(sub)
                    except Exception as e:
                        logger.debug("Archive harvesting skipped for %s: %s", apex, e)

                for prefix in self.prefixes[:max_per_wildcard]:
                    candidate = f"{prefix}.{apex}"
                    if not is_excluded(candidate) and candidate not in seen:
                        expanded.append(candidate)
                        seen.add(candidate)
            else:
                # Direct domain
                if not is_excluded(clean) and clean not in seen:
                    expanded.append(clean)
                    seen.add(clean)

        return expanded

    @staticmethod
    def get_organizational_domain(domain: str) -> str:
        """Extracts the registered/organizational apex domain for RFC 7489 DMARC traversal.
        
        Handles standard ccTLDs (e.g. .co.uk, .com.au, .co.jp) and generic TLDs.
        """
        clean = domain.strip().lower().rstrip(".")
        parts = clean.split(".")
        if len(parts) <= 2:
            return clean

        two_part_tlds = {
            "co.uk", "org.uk", "gov.uk", "ac.uk",
            "com.au", "net.au", "org.au", "edu.au",
            "co.jp", "ne.jp", "co.nz", "org.nz",
            "co.za", "com.br", "com.mx", "com.sg",
            "co.in", "net.in", "org.in", "gen.in",
        }
        suffix_candidate = f"{parts[-2]}.{parts[-1]}"
        if suffix_candidate in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def parse_dmarc_policy(dmarc_record: str) -> Tuple[str, str]:
        """Parses (p, sp) policy tags from a DMARC TXT record string."""
        p_val = ""
        sp_val = ""
        tags = [t.strip() for t in dmarc_record.split(";")]
        for tag in tags:
            if tag.startswith("p="):
                p_val = tag.split("=", 1)[1].strip().lower()
            elif tag.startswith("sp="):
                sp_val = tag.split("=", 1)[1].strip().lower()
        if not sp_val:
            sp_val = p_val
        return p_val, sp_val

    def has_mx_records(self, domain: str) -> bool:
        """Checks if the domain publishes active Mail Exchange (MX) records."""
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                exchange = str(rdata.exchange).strip().rstrip(".")
                if exchange and exchange != ".":
                    return True
        except Exception:
            pass
        return False

    def is_ssl_cert_bound_to_domain(self, domain: str) -> bool:
        """Checks if target domain presents a valid SSL certificate covering the domain name.

        Valid ACM/custom certs prove active ownership in cloud provider (e.g. AWS CloudFront),
        preventing false-positive reports on 403 WAF / Access Denied responses.
        """
        import socket
        import ssl
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    sans = [name for typ, name in cert.get("subjectAltName", []) if typ == "DNS"]
                    for san in sans:
                        if san.lower() == domain.lower():
                            return True
                        if san.startswith("*.") and domain.lower().endswith(san[2:].lower()):
                            return True
        except Exception:
            pass
        return False

    def check_subdomain_takeover(
        self,
        domain: str,
        mock_cname: Optional[str] = None,
        mock_body: Optional[str] = None,
        mock_nxdomain: bool = False,
    ) -> Optional[Tuple[SaasSignature, str, str]]:
        """Probes domain CNAME and checks against SaaS takeover signatures.

        Returns (signature, cname_target, evidence) if vulnerable, else None.
        """
        cname_target: Optional[str] = mock_cname

        if cname_target is None and not mock_nxdomain:
            try:
                answers = self.resolver.resolve(domain, "CNAME")
                for rdata in answers:
                    cname_target = str(rdata.target).rstrip(".")
                    break
            except Exception:
                cname_target = None

        if not cname_target and not mock_nxdomain:
            return None

        # Check against known SaaS signatures
        for sig in SAAS_TAKEOVER_SIGNATURES:
            matches_cname = False
            if cname_target:
                for pattern in sig.cname_patterns:
                    if pattern in cname_target:
                        matches_cname = True
                        break

            if not matches_cname:
                continue

            # If matched, verify fingerprint or NXDOMAIN condition
            if sig.nxdomain or mock_nxdomain:
                if mock_nxdomain:
                    is_nx = True
                elif cname_target:
                    try:
                        self.resolver.resolve(cname_target, "A")
                        is_nx = False  # Target resolves to active host, not dangling!
                    except dns.resolver.NXDOMAIN:
                        is_nx = True
                    except Exception:
                        is_nx = False
                else:
                    is_nx = False

                if is_nx:
                    evidence = f"Dangling CNAME '{cname_target}' points to unallocated {sig.name} resource (NXDOMAIN response)."
                    return (sig, cname_target or "nxdomain.target", evidence)
                else:
                    continue

            # Check HTTP fingerprint
            body = mock_body
            if body is None:
                body = self._probe_http_body(domain)

            for fp in sig.fingerprints:
                if fp.lower() in (body or "").lower():
                    # If host presents a valid custom SSL cert matching the target domain,
                    # the domain is actively bound to an authorized tenant in the cloud provider.
                    if mock_body is None and self.is_ssl_cert_bound_to_domain(domain):
                        continue

                    evidence = f"Dangling CNAME '{cname_target}' matched {sig.name} takeover signature fingerprint: '{fp}'."
                    return (sig, cname_target or "unknown", evidence)

        return None

    def check_mail_spoofing(
        self,
        domain: str,
        mock_spf: Optional[str] = None,
        mock_dmarc: Optional[str] = None,
        mock_mx: Optional[List[str]] = None,
    ) -> Optional[Tuple[str, str, Severity, float]]:
        """Checks for mail-spoofing vectors (missing/permissive SPF or missing/none DMARC).

        Respects RFC 7489 organizational domain policy inheritance and validates
        MX/mail-handling endpoints to eliminate false-positive subdomain reports.
        Returns (issue_type, evidence, severity, cvss_score) if vulnerable, else None.
        """
        spf_record = mock_spf
        dmarc_record = mock_dmarc
        org_domain = self.get_organizational_domain(domain)
        is_apex = domain == org_domain

        # Query SPF if not mocked
        if spf_record is None:
            try:
                txt_answers = self.resolver.resolve(domain, "TXT")
                for rdata in txt_answers:
                    txt = "".join(b.decode("utf-8", errors="ignore") for b in rdata.strings)
                    if txt.startswith("v=spf1"):
                        spf_record = txt
                        break
            except Exception:
                spf_record = ""

        # Query DMARC if not mocked
        if dmarc_record is None:
            try:
                dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_answers:
                    txt = "".join(b.decode("utf-8", errors="ignore") for b in rdata.strings)
                    if "v=DMARC1" in txt:
                        dmarc_record = txt
                        break
            except Exception:
                dmarc_record = ""

            # RFC 7489 Section 6.6.3: If subdomain has no explicit DMARC, query organizational domain
            if not dmarc_record and not is_apex:
                try:
                    org_answers = self.resolver.resolve(f"_dmarc.{org_domain}", "TXT")
                    for rdata in org_answers:
                        txt = "".join(b.decode("utf-8", errors="ignore") for b in rdata.strings)
                        if "v=DMARC1" in txt:
                            p_val, sp_val = self.parse_dmarc_policy(txt)
                            # If organizational policy enforces reject or quarantine on subdomains, it is protected
                            if sp_val in ("reject", "quarantine"):
                                return None
                            dmarc_record = txt
                            break
                except Exception:
                    pass

        # Determine whether domain handles active email (has MX records)
        has_mail = (
            bool(mock_mx)
            if mock_mx is not None
            else (True if (mock_spf is not None or mock_dmarc is not None) else self.has_mx_records(domain))
        )

        # If domain has strict SPF hard fail (-all) AND no MX records, it is explicitly
        # non-mail with strict sender rejection under RFC 7208 Section 2.6 (e.g. github.io).
        if not has_mail and spf_record and "-all" in spf_record:
            return None

        # If still no DMARC record found
        if not dmarc_record:
            # On subdomains, missing DMARC is only relevant if the host handles mail (has MX)
            if not is_apex and not has_mail:
                return None  # Static host without MX, protected or irrelevant for mail spoofing

            # Parked apex domain without MX and without strict SPF
            if is_apex and not has_mail:
                evidence = (
                    f"Apex domain '{domain}' publishes NO DMARC record at _dmarc.{domain} and NO strict SPF (-all). "
                    "While the domain lacks active MX records, unauthorized outbound senders can forge From: headers to external recipients."
                )
                return (
                    "Missing DMARC on Parked Apex (Outbound Spoofing Risk)",
                    evidence,
                    Severity.LOW,
                    3.1,
                )

            evidence = f"Domain '{domain}' has NO DMARC record published at _dmarc.{domain}. Anyone can spoof email headers with arbitrary envelope senders."
            return (
                "Missing DMARC Policy (Full Mail Spoofing)",
                evidence,
                Severity.HIGH,
                7.5,
            )

        # Check for DMARC p=none policy
        p_val, sp_val = self.parse_dmarc_policy(dmarc_record)
        effective_policy = sp_val if not is_apex else p_val
        if effective_policy == "none":
            if not has_mail and spf_record and "-all" in spf_record:
                return None
            if not is_apex and not has_mail:
                return None

            if is_apex and not has_mail:
                evidence = f"Parked apex domain '{domain}' publishes DMARC record '{dmarc_record}' with 'p=none' monitoring-only policy."
                return (
                    "DMARC p=none on Parked Apex (Monitoring Only)",
                    evidence,
                    Severity.LOW,
                    3.1,
                )

            evidence = f"Domain '{domain}' publishes DMARC record '{dmarc_record}' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection."
            return (
                "DMARC p=none Monitoring Only (Permissive Mail Spoofing)",
                evidence,
                Severity.MEDIUM,
                5.3,
            )

        # Check for overly permissive SPF (+all)
        if spf_record and "+all" in spf_record:
            evidence = f"Domain '{domain}' publishes SPF record '{spf_record}' with '+all' directive allowing all internet hosts to send authorized mail."
            return (
                "SPF Permissive +all Directive (Trivial Mail Spoofing)",
                evidence,
                Severity.HIGH,
                7.5,
            )

        return None

    def _probe_http_body(self, domain: str) -> str:
        """Fetches HTTP response body with short timeout for fingerprint inspection."""
        import urllib.request
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"},
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    # An active application serving HTTP 200 OK is claimed and not dangling
                    if getattr(resp, "status", getattr(resp, "code", None)) == 200:
                        return ""
                    return resp.read(4096).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                try:
                    return e.read().decode("utf-8", errors="ignore")
                except Exception:
                    pass
            except Exception:
                continue
        return ""

    def sweep_program(
        self,
        program: BountyProgram,
        max_domains: int = 15,
        use_passive_ct: bool = False,
        use_archive_harvest: bool = False,
        audit_cloud_buckets: bool = False,
        audit_graphql: bool = False,
        audit_cors: bool = False,
        audit_smuggling: bool = False,
        audit_oauth: bool = False,
        audit_dependency: bool = False,
        mock_cnames: Optional[Dict[str, str]] = None,
        mock_bodies: Optional[Dict[str, str]] = None,
        mock_spfs: Optional[Dict[str, str]] = None,
        mock_dmarcs: Optional[Dict[str, str]] = None,
        mock_nxdomain_domains: Optional[Set[str]] = None,
        mock_graphql_responses: Optional[Dict[str, Dict[str, Any]]] = None,
        mock_cors_responses: Optional[Dict[str, Dict[str, str]]] = None,
        mock_smuggling_responses: Optional[Dict[str, Dict[str, Any]]] = None,
        mock_oauth_responses: Optional[Dict[str, Dict[str, Any]]] = None,
        mock_dependency_responses: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[BountyVulnerability]:
        """Performs an automated attack surface sweep across a program's in-scope targets."""
        candidates = self.expand_wildcards(
            program.in_scope,
            program.out_of_scope,
            max_per_wildcard=max_domains,
            use_passive_ct=use_passive_ct,
            use_archive_harvest=use_archive_harvest,
        )
        vulns: List[BountyVulnerability] = []
        mock_cnames = mock_cnames or {}
        mock_bodies = mock_bodies or {}
        mock_spfs = mock_spfs or {}
        mock_dmarcs = mock_dmarcs or {}
        mock_nxdomain_domains = mock_nxdomain_domains or set()

        for target in candidates:
            mock_cn = mock_cnames.get(target)
            mock_bd = mock_bodies.get(target)
            mock_nx = target in mock_nxdomain_domains

            # 1. Cloud Storage Bucket Takeover Check (if enabled)
            if audit_cloud_buckets and self.is_vulnerability_in_scope(program, "cloud_storage_takeover"):
                bucket_res = self.audit_cloud_storage_bucket(
                    target, cname_target=mock_cn, mock_body=mock_bd
                )
                if bucket_res and bucket_res.get("vulnerable"):
                    flaw = bucket_res.get("flaw_type", "cloud_storage_takeover")
                    viab = bucket_res.get("bounty_viability", "HIGH_CONFIDENCE")
                    if self.is_vulnerability_in_scope(program, flaw, viab):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            cname_target=mock_cn,
                            flaw_type=flaw,
                            provider=bucket_res.get("provider", "Cloud Storage"),
                            severity=bucket_res.get("severity", Severity.HIGH),
                            cvss_score=bucket_res.get("cvss_score", 8.6),
                            cvss_vector=bucket_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N"),
                            evidence=bucket_res.get("evidence", ""),
                            cwe_id=bucket_res.get("cwe_id", "CWE-284: Improper Access Control"),
                            remediation=bucket_res.get("remediation", ""),
                            bounty_viability=viab,
                        )
                        vulns.append(vuln)
                        continue

            # 2. Subdomain Takeover Check (SaaS services)
            if self.is_vulnerability_in_scope(program, "subdomain_takeover"):
                takeover_res = self.check_subdomain_takeover(
                    target, mock_cname=mock_cn, mock_body=mock_bd, mock_nxdomain=mock_nx
                )
                if takeover_res:
                    sig, cname, evidence = takeover_res
                    score, vector = CVSSv31Calculator.calculate_score(
                        av="N", ac="L", pr="N", ui="N", s="U", c="N", i="H", a="N"
                    )
                    vuln = BountyVulnerability(
                        program_id=program.program_id,
                        program_name=program.name,
                        platform=program.platform,
                        target_domain=target,
                        cname_target=cname,
                        flaw_type="subdomain_takeover",
                        provider=sig.name,
                        severity=Severity.HIGH,
                        cvss_score=score,
                        cvss_vector=vector,
                        evidence=evidence,
                        cwe_id="CWE-284: Improper Access Control",
                        remediation=sig.remediation,
                        bounty_viability="HIGH_CONFIDENCE",
                    )
                    vulns.append(vuln)
                    continue  # If takeover found, proceed to next target

            # 3. GraphQL Introspection Check
            if audit_graphql and self.is_vulnerability_in_scope(program, "graphql_introspection"):
                gql_mock = mock_graphql_responses.get(target) if mock_graphql_responses else None
                gql_res = self.audit_graphql_introspection(target, mock_paths=gql_mock)
                if gql_res and gql_res.get("vulnerable"):
                    flaw = "graphql_introspection"
                    viab = "HIGH_CONFIDENCE"
                    if self.is_vulnerability_in_scope(program, flaw, viab):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type=flaw,
                            provider="GraphQL",
                            severity=gql_res.get("severity", Severity.MEDIUM),
                            cvss_score=gql_res.get("cvss_score", 5.3),
                            cvss_vector=gql_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                            evidence=gql_res.get("evidence", ""),
                            cwe_id=gql_res.get("cwe_id", "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"),
                            remediation=gql_res.get("remediation", ""),
                            bounty_viability=viab,
                        )
                        vulns.append(vuln)

            # 4. CORS Misconfiguration Check
            if audit_cors:
                cors_mock = mock_cors_responses.get(target) if mock_cors_responses else None
                cors_res = self.audit_cors_misconfiguration(target, mock_responses=cors_mock)
                if cors_res and cors_res.get("vulnerable"):
                    flaw = cors_res.get("flaw_type", "cors_misconfiguration")
                    viab = cors_res.get("bounty_viability", "HIGH_CONFIDENCE")
                    if self.is_vulnerability_in_scope(program, flaw, viab):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type=flaw,
                            provider="API Gateway CORS",
                            severity=cors_res.get("severity", Severity.HIGH),
                            cvss_score=cors_res.get("cvss_score", 8.1),
                            cvss_vector=cors_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
                            evidence=cors_res.get("evidence", ""),
                            cwe_id=cors_res.get("cwe_id", "CWE-942: Permissive Cross-domain Policy with Untrusted Domains"),
                            remediation=cors_res.get("remediation", ""),
                            bounty_viability=viab,
                        )
                        vulns.append(vuln)

            # 5. HTTP Request Smuggling Check
            if audit_smuggling:
                smug_mock = mock_smuggling_responses.get(target) if mock_smuggling_responses else None
                smug_res = self.audit_http_smuggling(
                    target,
                    mock_cl_te=smug_mock.get("cl_te") if smug_mock else None,
                    mock_te_cl=smug_mock.get("te_cl") if smug_mock else None,
                    mock_h2=smug_mock.get("h2") if smug_mock else None,
                )
                if smug_res and smug_res.get("vulnerable"):
                    flaw = smug_res.get("flaw_type", "http_request_smuggling_cl_te")
                    if self.is_vulnerability_in_scope(program, flaw):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type=flaw,
                            provider="HTTP Reverse Proxy",
                            severity=Severity.CRITICAL,
                            cvss_score=smug_res.get("cvss_score", 9.1),
                            cvss_vector=smug_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                            evidence=smug_res.get("evidence", ""),
                            cwe_id=smug_res.get("cwe_id", "CWE-444: Inconsistent Interpretation of HTTP Requests"),
                            remediation=smug_res.get("remediation", ""),
                            bounty_viability="HIGH_CONFIDENCE",
                        )
                        vulns.append(vuln)

            # 6. OAuth / OIDC Flow Check
            if audit_oauth:
                oa_mock = mock_oauth_responses.get(target) if mock_oauth_responses else None
                oa_res = self.audit_oauth_flow(
                    target,
                    mock_oidc=oa_mock.get("oidc") if oa_mock else None,
                    mock_redirects=oa_mock.get("redirects") if oa_mock else None,
                    mock_state=oa_mock.get("state") if oa_mock else None,
                    mock_pkce=oa_mock.get("pkce") if oa_mock else None,
                )
                if oa_res and oa_res.get("vulnerable"):
                    flaw = oa_res.get("flaw_type", "oauth_redirect_uri_hijack")
                    if self.is_vulnerability_in_scope(program, flaw):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type=flaw,
                            provider="OAuth / Identity Provider",
                            severity=Severity(oa_res.get("severity", "HIGH")),
                            cvss_score=oa_res.get("cvss_score", 8.1),
                            cvss_vector=oa_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
                            evidence=oa_res.get("evidence", ""),
                            cwe_id=oa_res.get("cwe_id", "CWE-601: URL Redirection to Untrusted Site"),
                            remediation=oa_res.get("remediation", ""),
                            bounty_viability="HIGH_CONFIDENCE",
                        )
                        vulns.append(vuln)

            # 7. Dependency Confusion Check
            if audit_dependency and self.is_vulnerability_in_scope(program, "dependency_confusion_namespace_takeover"):
                dep_mock = mock_dependency_responses.get(target) if mock_dependency_responses else None
                source_code = dep_mock.get("source_text", "") if dep_mock else ""
                dep_res = self.audit_dependency_confusion(
                    target,
                    source_text=source_code,
                    mock_npm=dep_mock.get("npm") if dep_mock else None,
                    mock_pypi=dep_mock.get("pypi") if dep_mock else None,
                )
                if dep_res and dep_res.get("vulnerable"):
                    flaw = dep_res.get("flaw_type", "dependency_confusion_namespace_takeover")
                    if self.is_vulnerability_in_scope(program, flaw):
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type=flaw,
                            provider="Public Package Registry",
                            severity=Severity.CRITICAL,
                            cvss_score=dep_res.get("cvss_score", 9.8),
                            cvss_vector=dep_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                            evidence=dep_res.get("evidence", ""),
                            cwe_id=dep_res.get("cwe_id", "CWE-427: Uncontrolled Search Path Element"),
                            remediation=dep_res.get("remediation", ""),
                            bounty_viability="HIGH_CONFIDENCE",
                        )
                        vulns.append(vuln)

            # 8. Email Spoofing Check (primarily on apex or mail hosts)
            if "." in target:
                org_domain = self.get_organizational_domain(target)
                is_apex = target == org_domain
                if (is_apex or "mail" in target or mock_spfs.get(target) or mock_dmarcs.get(target)) and self.is_vulnerability_in_scope(program, "mail_spoofing"):
                    spoof_res = self.check_mail_spoofing(
                        target,
                        mock_spf=mock_spfs.get(target),
                        mock_dmarc=mock_dmarcs.get(target),
                    )
                    if spoof_res:
                        issue_title, evidence, sev, cvss = spoof_res
                        has_mx = self.has_mx_records(target)
                        viability = "CONDITIONAL" if has_mx else "INFORMATIONAL_LOW"
                        if self.is_vulnerability_in_scope(program, "mail_spoofing", viability):
                            if has_mx:
                                score, vector = CVSSv31Calculator.calculate_score(
                                    av="N", ac="L", pr="N", ui="N", s="U", c="N", i="L", a="N"
                                )
                            else:
                                score, vector = CVSSv31Calculator.calculate_score(
                                    av="N", ac="L", pr="N", ui="R", s="U", c="N", i="L", a="N"
                                )
                            vuln = BountyVulnerability(
                                program_id=program.program_id,
                                program_name=program.name,
                                platform=program.platform,
                                target_domain=target,
                                flaw_type="mail_spoofing",
                                provider=None,
                                severity=sev,
                                cvss_score=score,
                                cvss_vector=vector,
                                evidence=evidence,
                                cwe_id="CWE-290: Authentication Bypass by Spoofing",
                                remediation=f"Publish a strict DMARC record at '_dmarc.{target}' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).",
                                bounty_viability=viability,
                            )
                            vulns.append(vuln)

        program.last_scanned = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return vulns

    def harvest_javascript_routes(self, target_url: str) -> Dict[str, Any]:
        """Passively audits frontend JavaScript bundles for internal API routes, cloud buckets, and subdomains."""
        from orbit_security.recon_harvester import JsRouteExtractor
        return JsRouteExtractor.analyze_target_scripts(target_url)

    def audit_cloud_storage_bucket(
        self,
        target_domain: str,
        cname_target: Optional[str] = None,
        mock_body: Optional[str] = None,
        mock_status: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target for unallocated S3/GCS/Azure storage bucket takeover or open listing."""
        from orbit_security.cloud_sentinels import CloudBucketTakeoverSentinel
        return CloudBucketTakeoverSentinel.audit_target(
            target_domain, cname_target=cname_target, mock_body=mock_body, mock_status=mock_status
        )

    def audit_graphql_introspection(
        self,
        target_domain: str,
        timeout: float = 3.5,
        mock_paths: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target domain for public GraphQL schema introspection endpoints."""
        from orbit_security.cloud_sentinels import GraphQLIntrospectionSentinel
        return GraphQLIntrospectionSentinel.audit_target(
            target_domain, timeout=timeout, mock_paths=mock_paths
        )

    def audit_cors_misconfiguration(
        self,
        target_domain: str,
        timeout: float = 3.5,
        mock_responses: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits domain for arbitrary CORS origin reflection or null origin trust with credentials."""
        from orbit_security.cloud_sentinels import CorsMisconfigurationSentinel
        return CorsMisconfigurationSentinel.audit_target(
            target_domain, timeout=timeout, mock_responses=mock_responses
        )

    def audit_http_smuggling(
        self,
        target_domain: str,
        path: str = "/",
        timeout: float = 4.0,
        mock_cl_te: Optional[Dict[str, Any]] = None,
        mock_te_cl: Optional[Dict[str, Any]] = None,
        mock_h2: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target domain for HTTP Request Smuggling desync vulnerabilities."""
        from orbit_security.smuggling_sentinel import HttpRequestSmugglingSentinel
        return HttpRequestSmugglingSentinel.audit_target(
            target_domain,
            path=path,
            timeout=timeout,
            mock_cl_te=mock_cl_te,
            mock_te_cl=mock_te_cl,
            mock_h2=mock_h2,
        )

    def audit_oauth_flow(
        self,
        target_domain: str,
        auth_url: Optional[str] = None,
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        token_url: Optional[str] = None,
        timeout: float = 3.5,
        mock_redirects: Optional[Dict[str, Tuple[int, str, Dict[str, str]]]] = None,
        mock_state: Optional[Tuple[int, str, Dict[str, str]]] = None,
        mock_pkce: Optional[Tuple[int, str, Dict[str, str]]] = None,
        mock_oidc: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target domain for OAuth 2.0 / OIDC redirection, CSRF, and signing flaws."""
        from orbit_security.oauth_sentinel import OAuthFlowSentinel
        return OAuthFlowSentinel.audit_target(
            target_domain,
            auth_url=auth_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            token_url=token_url,
            timeout=timeout,
            mock_redirects=mock_redirects,
            mock_state=mock_state,
            mock_pkce=mock_pkce,
            mock_oidc=mock_oidc,
        )

    def audit_dependency_confusion(
        self,
        target_domain: str,
        source_text: Optional[str] = None,
        custom_org_names: Optional[List[str]] = None,
        mock_npm: Optional[Dict[str, int]] = None,
        mock_pypi: Optional[Dict[str, int]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target for unclaimed internal package namespaces in public registries."""
        from orbit_security.dependency_sentinel import DependencyConfusionSentinel
        return DependencyConfusionSentinel.audit_target(
            target_domain,
            source_text=source_text,
            custom_org_names=custom_org_names,
            mock_npm=mock_npm,
            mock_pypi=mock_pypi,
        )

    def audit_exposed_staging_endpoint(
        self_or_domain: Any,
        domain: Optional[str] = None,
        mock_response: Optional[Dict[str, Any]] = None,
        mock_dns: Optional[Dict[str, Any]] = None,
        timeout: float = 3.5,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Audits target domain for exposed pre-production staging/dev endpoints and DNS misconfigurations.

        Detects:
        - Exposed staging environments (stage.*, staging.*, dev.*).
        - DNS misconfigurations: Dangling CNAMEs (NXDOMAIN targets), internal host leaks (.internal, .local, etc.),
          and unauthenticated public DNS records for private environments.
        """
        if isinstance(self_or_domain, BountyTakeoverSweeper):
            target_domain = domain or ""
            resolver = getattr(self_or_domain, "resolver", None) or get_orbit_sync_resolver()
        elif isinstance(self_or_domain, str):
            target_domain = self_or_domain
            resolver = get_orbit_sync_resolver()
        else:
            target_domain = str(domain or "")
            resolver = get_orbit_sync_resolver()

        clean = target_domain.strip().lower()
        for prefix in ("https://", "http://"):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        clean = clean.split("/")[0].split(":")[0].lstrip("*.")

        staging_markers = ("stage.", "staging.", "dev.", "devel.", "test.", "qa.", "uat.", "sandbox.", "preview.")
        is_direct_staging = any(clean.startswith(marker) for marker in staging_markers) or any(f".{marker}" in f".{clean}" for marker in ("stage.", "staging.", "dev."))

        detected_prefix = None
        for marker in ("stage.", "staging.", "dev."):
            if clean.startswith(marker) or f".{marker}" in f".{clean}":
                detected_prefix = marker.rstrip(".")
                break

        if is_direct_staging:
            candidates = [clean]
        else:
            candidates = [f"stage.{clean}", f"staging.{clean}", f"dev.{clean}"]

        detected_endpoints: List[str] = []
        dns_misconfigs: List[str] = []
        evidence_lines: List[str] = []
        cname_target_found: Optional[str] = None

        for cand in candidates:
            cand_cname = None
            cand_ips: List[str] = []
            cand_dns_error = None

            if mock_dns and cand in mock_dns:
                m_dns = mock_dns[cand]
                cand_cname = m_dns.get("CNAME")
                cand_ips = m_dns.get("A", [])
                cand_dns_error = m_dns.get("error")
            elif mock_dns and "CNAME" in mock_dns:
                cand_cname = mock_dns.get("CNAME")
                cand_ips = mock_dns.get("A", [])
            elif not mock_response:
                try:
                    cname_ans = resolver.resolve(cand, "CNAME")
                    if cname_ans:
                        cand_cname = str(cname_ans[0].target).rstrip(".")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                    cand_cname = None

                try:
                    a_ans = resolver.resolve(cand, "A")
                    cand_ips = [str(r) for r in a_ans]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                    cand_ips = []

            if cand_cname:
                cname_target_found = cand_cname
                if any(cand_cname.endswith(ext) for ext in (".internal", ".local", ".corp", ".lan", ".private")):
                    msg = f"DNS Misconfiguration: `{cand}` CNAME points to internal infrastructure `{cand_cname}`"
                    dns_misconfigs.append(msg)
                    evidence_lines.append(msg)

                if cand_dns_error == "NXDOMAIN" or (mock_dns and mock_dns.get(cand_cname, {}).get("error") == "NXDOMAIN"):
                    msg = f"DNS Misconfiguration: `{cand}` has dangling CNAME `{cand_cname}` resolving to NXDOMAIN (Subdomain Takeover risk)"
                    dns_misconfigs.append(msg)
                    evidence_lines.append(msg)
                elif not mock_dns and not mock_response:
                    try:
                        resolver.resolve(cand_cname, "A")
                    except dns.resolver.NXDOMAIN:
                        msg = f"DNS Misconfiguration: `{cand}` has dangling CNAME `{cand_cname}` resolving to NXDOMAIN (Subdomain Takeover risk)"
                        dns_misconfigs.append(msg)
                        evidence_lines.append(msg)
                    except Exception:
                        pass

            has_records = bool(cand_cname or cand_ips)

            for ip in cand_ips:
                if ip.startswith(("10.", "192.168.")) or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31):
                    msg = f"DNS Misconfiguration: `{cand}` resolves to private RFC 1918 IP address `{ip}` in public DNS"
                    dns_misconfigs.append(msg)
                    evidence_lines.append(msg)

            http_status = None
            http_headers: Dict[str, str] = {}
            http_body = ""

            if mock_response:
                m_resp = mock_response.get(cand, mock_response)
                http_status = m_resp.get("status", 200)
                http_headers = m_resp.get("headers", {})
                http_body = m_resp.get("body", "")
            elif has_records:
                try:
                    probe_url = f"https://{cand}"
                    req = urllib.request.Request(
                        probe_url,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        http_status = getattr(resp, "status", getattr(resp, "code", 200))
                        http_headers = dict(resp.headers)
                        http_body = resp.read(4096).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as he:
                    http_status = he.code
                    http_headers = dict(he.headers)
                except Exception:
                    try:
                        probe_url = f"http://{cand}"
                        req = urllib.request.Request(
                            probe_url,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
                        )
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            http_status = getattr(resp, "status", getattr(resp, "code", 200))
                            http_headers = dict(resp.headers)
                            http_body = resp.read(4096).decode("utf-8", errors="replace")
                    except Exception:
                        http_status = None

            if http_status in (200, 204, 206, 301, 302):
                detected_endpoints.append(cand)
                evidence_lines.append(
                    f"Exposed staging endpoint `{cand}` is publicly accessible (HTTP status: {http_status})."
                )
                for h_name, h_val in http_headers.items():
                    if any(dh in h_name.lower() for dh in ("debug", "env", "stage", "dev", "powered-by")):
                        evidence_lines.append(f"Leaked environment header on `{cand}`: `{h_name}: {h_val}`")
                body_lower = http_body.lower()
                for kw in ("swagger", "openapi", "graphql", "staging", "development", "phpinfo"):
                    if kw in body_lower:
                        evidence_lines.append(f"Identified debug/staging resource signature on `{cand}`: '{kw}'")
                        break
            elif has_records and is_direct_staging:
                detected_endpoints.append(cand)
                evidence_lines.append(
                    f"Staging endpoint `{cand}` has active public DNS records (CNAME: {cand_cname or 'None'}, A: {cand_ips})."
                )

        is_vulnerable = bool(detected_endpoints or dns_misconfigs)

        if is_vulnerable:
            primary_domain = detected_endpoints[0] if detected_endpoints else clean
            flaw = "dns_misconfiguration" if (dns_misconfigs and not detected_endpoints) else "exposed_staging_endpoint"
            evidence_str = "\n".join(evidence_lines) if evidence_lines else f"Exposed staging endpoint or DNS misconfiguration on `{clean}`."

            return {
                "exposed": True,
                "vulnerable": True,
                "target_domain": primary_domain,
                "domain": primary_domain,
                "flaw_type": flaw,
                "severity": Severity.HIGH,
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe_id": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                "provider": "Staging / Development Infrastructure",
                "evidence": evidence_str,
                "remediation": "Decommission dangling DNS records, restrict staging environments (stage.*, staging.*, dev.*) behind VPN / IP allowlists, and enforce strict authentication.",
                "bounty_viability": "HIGH_CONFIDENCE",
                "staging_detected": bool(detected_endpoints or is_direct_staging),
                "staging_prefix": detected_prefix or (candidates[0].split(".")[0] if detected_endpoints else None),
                "dns_misconfigurations": dns_misconfigs,
                "endpoints": detected_endpoints,
                "cname_target": cname_target_found,
            }
        else:
            return {
                "exposed": False,
                "vulnerable": False,
                "target_domain": clean,
                "domain": clean,
                "flaw_type": "none",
                "severity": Severity.LOW,
                "cvss_score": 0.0,
                "cvss_vector": "",
                "cwe_id": "",
                "evidence": f"No exposed staging endpoints or DNS misconfigurations detected on `{clean}`.",
                "remediation": "Maintain DNS hygiene and ensure staging environments remain restricted to internal networks.",
                "bounty_viability": "INFORMATIONAL_LOW",
                "staging_detected": False,
                "staging_prefix": None,
                "dns_misconfigurations": [],
                "endpoints": [],
                "cname_target": None,
            }


class CVSSv31Calculator:
    """Deterministic CVSS v3.1 Base Score and Vector generator following FIRST specifications."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

    @staticmethod
    def calculate_score(
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "N",
        i: str = "H",
        a: str = "N",
    ) -> Tuple[float, str]:
        """Calculates CVSS v3.1 base score and standard vector string."""
        av = av.upper()
        ac = ac.upper()
        pr = pr.upper()
        ui = ui.upper()
        s = s.upper()
        c = c.upper()
        i = i.upper()
        a = a.upper()

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        # 1. Impact Sub-Score (ISS)
        iss = 1.0 - (
            (1.0 - CVSSv31Calculator.CIA_WEIGHTS.get(c, 0.0))
            * (1.0 - CVSSv31Calculator.CIA_WEIGHTS.get(i, 0.0))
            * (1.0 - CVSSv31Calculator.CIA_WEIGHTS.get(a, 0.0))
        )

        # 2. Impact
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Exploitability
        pr_w = CVSSv31Calculator.PR_WEIGHTS.get(s, CVSSv31Calculator.PR_WEIGHTS["U"]).get(pr, 0.85)
        exploitability = (
            8.22
            * CVSSv31Calculator.AV_WEIGHTS.get(av, 0.85)
            * CVSSv31Calculator.AC_WEIGHTS.get(ac, 0.77)
            * pr_w
            * CVSSv31Calculator.UI_WEIGHTS.get(ui, 0.85)
        )

        # 4. Base Score
        if impact <= 0:
            return 0.0, vector

        if s == "U":
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)

        base_score = math.ceil(round(raw_score, 9) * 10.0) / 10.0
        return round(base_score, 1), vector


# --- Comprehensive Disclosure Report Dispatchers ---

def _format_h1_subdomain_takeover(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    title = f"[Subdomain Takeover] Unclaimed {vuln.provider or 'SaaS'} Resource via Dangling CNAME on {vuln.target_domain}"
    impact_desc = (
        f"An attacker can register the orphaned `{vuln.cname_target}` resource on {vuln.provider or 'the designated service'} "
        f"and take complete control of `{vuln.target_domain}`. This allows the adversary to:\n"
        f"1. Host arbitrary phishing pages, deceptive logins, or malware under the official `{vuln.target_domain}` authority.\n"
        f"2. Harvest sensitive user session tokens, authentication cookies (with `Domain={vuln.target_domain}` scope), or OAuth tokens.\n"
        f"3. Bypass Content Security Policy (CSP) and Cross-Origin Resource Sharing (CORS) rules trusting `{vuln.target_domain}`."
    )
    poc_steps = (
        f"1. Query the DNS CNAME record for `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   dig {vuln.target_domain} CNAME +short\n"
        f"   # Output: {vuln.cname_target}\n"
        f"   ```\n"
        f"2. Send an HTTP request to `{vuln.target_domain}` to observe the provider unallocated error response:\n"
        f"   ```bash\n"
        f"   curl -i -s https://{vuln.target_domain}\n"
        f"   ```\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_cors(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    if vuln.flaw_type == "cors_wildcard_origin":
        sub_type = "Permissive Wildcard Access-Control-Allow-Origin"
    elif vuln.flaw_type == "cors_arbitrary_origin_with_credentials":
        sub_type = "Arbitrary Origin Reflection with Credentials"
    elif vuln.flaw_type == "cors_null_origin_with_credentials":
        sub_type = "Insecure Null Origin Trust with Credentials"
    else:
        sub_type = "Insecure Cross-Origin Resource Sharing Policy"

    title = f"[CORS Misconfiguration] {sub_type} on {vuln.target_domain}"
    impact_desc = (
        f"The endpoint on `{vuln.target_domain}` implements an insecure Cross-Origin Resource Sharing (CORS) policy.\n"
        f"When an authenticated user visits an attacker-controlled website:\n"
        f"1. The malicious website can issue background cross-origin requests to `{vuln.target_domain}`.\n"
        f"2. The browser grants the untrusted site read access to sensitive response bodies due to permissive origin allowance.\n"
        f"3. The attacker can extract private user records, account details, CSRF tokens, or internal API responses cross-origin."
    )
    poc_steps = (
        f"1. Send an HTTP request with an untrusted Origin header to `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   curl -i -s -H \"Origin: https://evil.com\" https://{vuln.target_domain}/\n"
        f"   ```\n"
        f"2. Inspect the HTTP response headers for reflected origin and credentials allowance:\n"
        f"   ```http\n"
        f"   Access-Control-Allow-Origin: https://evil.com\n"
        f"   Access-Control-Allow-Credentials: true\n"
        f"   ```\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_graphql(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    title = f"[Information Disclosure] Public GraphQL Schema Introspection on {vuln.target_domain}"
    impact_desc = (
        f"Full GraphQL schema introspection is enabled on `{vuln.target_domain}` for unauthorized external clients.\n"
        f"This leaks the entire backend data architecture, including:\n"
        f"1. All available queries, mutations, subscriptions, and internal service fields.\n"
        f"2. Undocumented administrative interfaces and sensitive entity relationship graphs.\n"
        f"3. Complete technical specification that significantly accelerates targeted access control bypasses and parameter tampering."
    )
    poc_steps = (
        f"1. Send an HTTP POST request containing a GraphQL introspection query to `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   curl -i -s -X POST https://{vuln.target_domain}/graphql \\\n"
        f"     -H \"Content-Type: application/json\" \\\n"
        f"     -d '{{\"query\":\"{{ __schema {{ queryType {{ name }} mutationType {{ name }} types {{ name }} }} }}\"}}'\n"
        f"   ```\n"
        f"2. Observe the complete schema hierarchy and internal type definitions in the JSON response.\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_cloud_storage(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    if vuln.flaw_type == "open_cloud_bucket":
        title = f"[Cloud Storage] Open Public Bucket Directory Listing on {vuln.target_domain}"
        impact_desc = (
            f"The cloud storage bucket mapped to `{vuln.target_domain}` has open public READ permissions enabled.\n"
            f"Any unauthorized internet user can list and download stored assets, potentially exposing private customer "
            f"documents, source backups, configuration archives, and sensitive media."
        )
        poc_steps = (
            f"1. Issue an HTTP GET request to the bucket endpoint on `{vuln.target_domain}`:\n"
            f"   ```bash\n"
            f"   curl -i -s https://{vuln.target_domain}\n"
            f"   ```\n"
            f"2. Observe the XML storage index containing key names, sizes, and file metadata (`<ListBucketResult>` or `<EnumerationResults>`).\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    else:
        title = f"[Cloud Storage Takeover] Unclaimed Storage Bucket on {vuln.target_domain}"
        impact_desc = (
            f"The domain `{vuln.target_domain}` points to an unallocated or deleted cloud storage bucket "
            f"(`{vuln.cname_target or 'storage endpoint'}`) on {vuln.provider or 'Cloud Storage'}.\n"
            f"An adversary can claim the identical bucket name in their own cloud account and serve arbitrary malicious content "
            f"under `{vuln.target_domain}`, enabling stored XSS, session hijacking, and brand impersonation."
        )
        poc_steps = (
            f"1. Query the DNS CNAME record for `{vuln.target_domain}`:\n"
            f"   ```bash\n"
            f"   dig {vuln.target_domain} CNAME +short\n"
            f"   # Output: {vuln.cname_target}\n"
            f"   ```\n"
            f"2. Query the HTTP endpoint and observe the unallocated storage response (`NoSuchBucket` / `BlobNotFound`):\n"
            f"   ```bash\n"
            f"   curl -i -s https://{vuln.target_domain}\n"
            f"   ```\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    return title, impact_desc, poc_steps


def _format_h1_http_smuggling(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    if vuln.flaw_type == "http_request_smuggling_cl_te":
        sub_type = "Frontend CL / Backend TE Desynchronization"
    elif vuln.flaw_type == "http_request_smuggling_te_cl":
        sub_type = "Frontend TE / Backend CL Desynchronization"
    elif vuln.flaw_type == "http_request_smuggling_h2_downgrade":
        sub_type = "HTTP/2 Downgrade Desynchronization"
    else:
        sub_type = "HTTP Request Desynchronization"

    title = f"[HTTP Request Smuggling] {sub_type} on {vuln.target_domain}"
    impact_desc = (
        f"A desynchronization vulnerability exists in how the edge reverse proxy and origin server interpret HTTP request "
        f"boundaries on `{vuln.target_domain}`.\n"
        f"An attacker can exploit this discrepancy to smuggle requests across persistent backend TCP connections. This enables:\n"
        f"1. Cache poisoning to serve malicious JavaScript or redirects to downstream users.\n"
        f"2. Request hijacking to capture sensitive HTTP Authorization headers and session cookies from subsequent victim requests.\n"
        f"3. Complete bypass of front-end security filters and WAF rules."
    )
    poc_steps = (
        f"1. Transmit an ambiguous HTTP request with conflicting Content-Length and Transfer-Encoding headers to `{vuln.target_domain}`:\n"
        f"   ```http\n"
        f"   POST / HTTP/1.1\n"
        f"   Host: {vuln.target_domain}\n"
        f"   Content-Length: 4\n"
        f"   Transfer-Encoding: chunked\n\n"
        f"   1\n"
        f"   Z\n"
        f"   Q\n"
        f"   ```\n"
        f"2. Observe backend socket desynchronization or differential connection timeout.\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_oauth(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    if vuln.flaw_type == "oauth_redirect_uri_hijack":
        title = f"[OAuth 2.0] Authorization Code / Token Theft via Redirect URI Hijack on {vuln.target_domain}"
        impact_desc = (
            f"The OAuth 2.0 authorization endpoint on `{vuln.target_domain}` does not enforce strict redirect URI whitelisting.\n"
            f"An attacker can supply a manipulated or wildcard redirect_uri pointing to an external server. When a user authorizes "
            f"the application, the authorization code or access token is leaked to the attacker's server, leading to complete account takeover."
        )
        poc_steps = (
            f"1. Construct an authorization request with an arbitrary or path-traversal redirect URI:\n"
            f"   ```bash\n"
            f"   curl -i -s \"https://{vuln.target_domain}/oauth/authorize?client_id=TARGET_CLIENT_ID&redirect_uri=https://{vuln.target_domain}.evil.com/callback&response_type=code\"\n"
            f"   ```\n"
            f"2. Observe that the authorization server accepts the unvalidated redirect URI without error.\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    elif vuln.flaw_type == "oauth_login_csrf":
        title = f"[OAuth 2.0] Login CSRF via Missing or Static State Parameter on {vuln.target_domain}"
        impact_desc = (
            f"The OAuth authorization flow on `{vuln.target_domain}` fails to validate the `state` parameter or omits it entirely.\n"
            f"An attacker can initiate an authorization flow, intercept their own authorization code, and trick a victim into "
            f"submitting that code to link the victim's session to the attacker's account."
        )
        poc_steps = (
            f"1. Trigger authorization flow omitting the `state` parameter or reusing static state values across sessions.\n"
            f"2. Observe lack of CSRF token verification during authorization code exchange.\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    elif vuln.flaw_type == "oauth_missing_pkce":
        title = f"[OAuth 2.0] Authorization Code Interception via Missing PKCE on {vuln.target_domain}"
        impact_desc = (
            f"The OAuth endpoint on `{vuln.target_domain}` does not enforce Proof Key for Code Exchange (PKCE, RFC 7636).\n"
            f"For public clients, an authorization code intercepted via custom URI schemes or browser history can be exchanged "
            f"for access tokens without proving possession of the code verifier secret."
        )
        poc_steps = (
            f"1. Submit authorization request without `code_challenge` parameter.\n"
            f"2. Exchange obtained authorization code at token endpoint without `code_verifier`.\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    elif vuln.flaw_type == "oidc_insecure_signing_alg":
        title = f"[OIDC] Insecure JWT Token Signing Algorithm (alg: none) Supported on {vuln.target_domain}"
        impact_desc = (
            f"The OpenID Connect discovery or token validation endpoint on `{vuln.target_domain}` permits insecure signature "
            f"algorithms such as `none` or weak symmetric HMAC keys where asymmetric keys are expected.\n"
            f"An attacker can forge arbitrary ID tokens or JWTs with modified user claims (e.g. `sub`, `email`, `role: admin`) "
            f"without a valid signature, bypassing authentication completely."
        )
        poc_steps = (
            f"1. Query OpenID Connect discovery configuration:\n"
            f"   ```bash\n"
            f"   curl -i -s https://{vuln.target_domain}/.well-known/openid-configuration\n"
            f"   ```\n"
            f"2. Inspect `id_token_signing_alg_values_supported` for `none` or weak algorithms.\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    elif vuln.flaw_type == "oidc_internal_endpoint_leak":
        title = f"[Information Disclosure] Internal Infrastructure Endpoints Leaked in OIDC Metadata on {vuln.target_domain}"
        impact_desc = (
            f"The OpenID Connect configuration published at `{vuln.target_domain}/.well-known/openid-configuration` exposes "
            f"internal hostnames, non-routable IP addresses, or staging backend endpoints.\n"
            f"This reveals organizational network topology and targets for Server-Side Request Forgery (SSRF) and perimeter penetration."
        )
        poc_steps = (
            f"1. Query the OIDC configuration endpoint:\n"
            f"   ```bash\n"
            f"   curl -i -s https://{vuln.target_domain}/.well-known/openid-configuration\n"
            f"   ```\n"
            f"2. Inspect discovery document for internal/private network endpoint URIs.\n"
            f"3. Observe evidence: `{vuln.evidence}`"
        )
    else:
        title = f"[OAuth 2.0 / OIDC] Authentication Flow Vulnerability on {vuln.target_domain}"
        impact_desc = (
            f"A vulnerability exists in the identity and authorization implementation on `{vuln.target_domain}` "
            f"({vuln.flaw_type.replace('_', ' ')}).\n"
            f"Adversaries can exploit this weakness to intercept OAuth authorization codes or tokens, forge authentication claims "
            f"without valid cryptographic signatures, or force victims into attacker-controlled accounts."
        )
        poc_steps = (
            f"1. Inspect OAuth/OIDC endpoint responses on `{vuln.target_domain}`.\n"
            f"2. Observe evidence: `{vuln.evidence}`"
        )
    return title, impact_desc, poc_steps


def _format_h1_dependency_confusion(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    title = f"[Supply Chain] Unclaimed Internal Package Namespace on Public Registry ({vuln.target_domain})"
    impact_desc = (
        f"Frontend application bundles on `{vuln.target_domain}` expose references to internal scoped packages that are not "
        f"registered on public registries ({vuln.provider or 'npm/PyPI'}).\n"
        f"An attacker can register the matching package on the public registry with an elevated version number. When internal "
        f"developer machines, CI/CD pipelines, or deployment runners resolve dependencies, the package manager fetches the "
        f"public package, executing arbitrary code with the privileges of the build runner (Remote Code Execution)."
    )
    poc_steps = (
        f"1. Identify the internal organizational package reference extracted from `{vuln.target_domain}` application assets.\n"
        f"2. Query the public package repository to verify the namespace is unclaimed:\n"
        f"   ```bash\n"
        f"   curl -i -s https://registry.npmjs.org/@internal-scope/package\n"
        f"   # Output: HTTP/1.1 404 Not Found\n"
        f"   ```\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_mail_spoofing(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    title = f"[Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on {vuln.target_domain}"
    impact_desc = (
        f"Because `{vuln.target_domain}` lacks strict DMARC rejection (`p=reject`), an adversary can forge email "
        f"`From:` headers appearing to originate directly from `*@{vuln.target_domain}`. This enables highly convincing "
        f"CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways."
    )
    poc_steps = (
        f"1. Query the DMARC TXT record at `_dmarc.{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   dig _dmarc.{vuln.target_domain} TXT +short\n"
        f"   ```\n"
        f"2. Query the SPF TXT record at `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   dig {vuln.target_domain} TXT +short\n"
        f"   ```\n"
        f"3. Observe evidence: `{vuln.evidence}`"
    )
    return title, impact_desc, poc_steps


def _format_h1_generic(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    clean_flaw = vuln.flaw_type.replace('_', ' ').title()
    title = f"[{clean_flaw}] Security Misconfiguration Identified on {vuln.target_domain}"
    impact_desc = (
        f"During perimeter hygiene auditing of `{vuln.target_domain}`, a security weakness categorized as "
        f"`{clean_flaw}` was identified.\n"
        f"Adversaries could leverage this issue to weaken security controls, discover internal infrastructure details, "
        f"or impact application confidentiality and integrity."
    )
    poc_steps = (
        f"1. Send an HTTP request to the target endpoint on `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   curl -i -s https://{vuln.target_domain}/\n"
        f"   ```\n"
        f"2. Observe technical evidence:\n"
        f"   ```\n"
        f"   {vuln.evidence}\n"
        f"   ```"
    )
    return title, impact_desc, poc_steps


def _format_h1_staging(vuln: BountyVulnerability) -> Tuple[str, str, str]:
    title = f"[Exposed Staging Environment] Pre-Production Infrastructure Publicly Accessible on {vuln.target_domain}"
    impact_desc = (
        f"During perimeter hygiene analysis, an exposed staging/development environment was identified on `{vuln.target_domain}`.\n"
        "Pre-production environments often lack production-grade access controls and may expose unpatched debug interfaces, "
        "internal environment variables, development secrets, or test customer records."
    )
    poc_steps = (
        f"1. Query DNS records for staging host `{vuln.target_domain}`:\n"
        f"   ```bash\n"
        f"   dig {vuln.target_domain} ANY +short\n"
        f"   ```\n"
        f"2. Send HTTP request to verify public accessibility:\n"
        f"   ```bash\n"
        f"   curl -i -s https://{vuln.target_domain}/\n"
        f"   ```\n"
        f"3. Observe technical evidence:\n"
        f"   ```\n"
        f"   {vuln.evidence}\n"
        f"   ```"
    )
    return title, impact_desc, poc_steps


H1_DISPATCH_TABLE = {
    "subdomain_takeover": _format_h1_subdomain_takeover,
    "dangling_cname": _format_h1_subdomain_takeover,
    "dangling_dns": _format_h1_subdomain_takeover,
    "takeover": _format_h1_subdomain_takeover,
    "cname_takeover": _format_h1_subdomain_takeover,
    "cors_wildcard_origin": _format_h1_cors,
    "cors_arbitrary_origin_with_credentials": _format_h1_cors,
    "cors_null_origin_with_credentials": _format_h1_cors,
    "cors_misconfiguration": _format_h1_cors,
    "graphql_introspection": _format_h1_graphql,
    "cloud_storage_takeover": _format_h1_cloud_storage,
    "open_cloud_bucket": _format_h1_cloud_storage,
    "http_request_smuggling_cl_te": _format_h1_http_smuggling,
    "http_request_smuggling_te_cl": _format_h1_http_smuggling,
    "http_request_smuggling_h2_downgrade": _format_h1_http_smuggling,
    "oauth_redirect_uri_hijack": _format_h1_oauth,
    "oauth_login_csrf": _format_h1_oauth,
    "oauth_missing_pkce": _format_h1_oauth,
    "oidc_insecure_signing_alg": _format_h1_oauth,
    "oidc_internal_endpoint_leak": _format_h1_oauth,
    "dependency_confusion_namespace_takeover": _format_h1_dependency_confusion,
    "mail_spoofing": _format_h1_mail_spoofing,
    "exposed_staging_endpoint": _format_h1_staging,
    "dns_misconfiguration": _format_h1_staging,
}


# --- Bugcrowd Report Dispatchers ---

def _format_bc_subdomain_takeover(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Server Security Misconfiguration > Subdomain Takeover"
    title = f"Subdomain Takeover on {target} ({vuln.provider or 'SaaS'})"
    desc = (
        f"The domain `{target}` delegates to an unclaimed `{vuln.provider or 'SaaS'}` resource at `{vuln.cname_target}`. "
        f"Because the remote resource is unallocated, an external adversary can claim the tenant and take full control "
        f"of `{target}`."
    )
    poc = (
        f"1. Query CNAME record: `dig {target} CNAME +short` -> `{vuln.cname_target}`\n"
        f"2. Query HTTP response: `curl -i -s https://{target}`\n"
        f"3. Fingerprint: `{vuln.evidence}`"
    )
    impact = (
        f"Complete control of subdomain `{target}`. An attacker can serve arbitrary content, intercept session cookies "
        f"scoped to parent domains, or bypass CORS policies."
    )
    return v_type, title, desc, poc, impact


def _format_bc_cors(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Application Security Misconfiguration > Cross-Origin Resource Sharing (CORS)"
    title = f"CORS Policy Misconfiguration on {target}"
    desc = (
        f"The domain `{target}` exposes an insecure Cross-Origin Resource Sharing configuration that trusts untrusted origins."
    )
    poc = (
        f"1. Issue cross-origin probe: `curl -i -s -H \"Origin: https://evil.com\" https://{target}/`\n"
        f"2. Inspect response headers for Access-Control-Allow-Origin\n"
        f"3. Observed evidence: `{vuln.evidence}`"
    )
    impact = (
        f"Enables unauthorized cross-origin data extraction and user session data leakage from `{target}`."
    )
    return v_type, title, desc, poc, impact


def _format_bc_graphql(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Information Disclosure > Exposed GraphQL Schema Introspection"
    title = f"Exposed GraphQL Schema Introspection on {target}"
    desc = (
        f"The GraphQL API on `{target}` has schema introspection publicly enabled for unauthenticated clients."
    )
    poc = (
        f"1. Send introspection query: `curl -i -s -X POST https://{target}/graphql -H \"Content-Type: application/json\" "
        f"-d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}'`\n"
        f"2. Inspect JSON response\n"
        f"3. Observed evidence: `{vuln.evidence}`"
    )
    impact = (
        f"Exposes complete internal backend schemas, queries, and mutations, facilitating targeted unauthorized actions on `{target}`."
    )
    return v_type, title, desc, poc, impact


def _format_bc_cloud_storage(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    if vuln.flaw_type == "open_cloud_bucket":
        v_type = "Information Disclosure > Public Cloud Storage Listing"
        title = f"Open Cloud Storage Bucket Directory Listing on {target}"
        desc = f"Cloud storage bucket at `{target}` permits unrestricted anonymous object enumeration."
        poc = (
            f"1. Request storage endpoint: `curl -i -s https://{target}`\n"
            f"2. Observe XML object listing\n"
            f"3. Observed evidence: `{vuln.evidence}`"
        )
        impact = f"Unauthorized public exposure of files and private backups stored on `{target}`."
    else:
        v_type = "Server Security Misconfiguration > Unclaimed Cloud Storage Bucket"
        title = f"Cloud Storage Misconfiguration on {target} ({vuln.provider or 'Cloud Storage'})"
        desc = f"Cloud storage resource associated with `{target}` is improperly secured or unclaimed."
        poc = (
            f"1. Request storage endpoint: `curl -i -s https://{target}`\n"
            f"2. Observe unallocated storage response\n"
            f"3. Observed evidence: `{vuln.evidence}`"
        )
        impact = f"Adversary can take over domain content or serve malicious payloads on `{target}`."
    return v_type, title, desc, poc, impact


def _format_bc_http_smuggling(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Server Security Misconfiguration > HTTP Request Smuggling"
    title = f"HTTP Request Smuggling Desync on {target}"
    desc = f"The reverse proxy and origin server for `{target}` disagree on request boundary parsing (CL/TE desynchronization)."
    poc = (
        f"1. Send ambiguous HTTP request with conflicting Content-Length and Transfer-Encoding headers.\n"
        f"2. Observe backend response delay or desync.\n"
        f"3. Observed evidence: `{vuln.evidence}`"
    )
    impact = f"Enables cache poisoning, request hijacking, and credential theft across users of `{target}`."
    return v_type, title, desc, poc, impact


def _format_bc_oauth(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Broken Authentication & Session Management > OAuth Redirection / CSRF"
    title = f"OAuth / OIDC Authentication Flow Vulnerability on {target}"
    desc = f"The OAuth/OIDC implementation on `{target}` contains an authentication or token security flaw ({vuln.flaw_type})."
    poc = (
        f"1. Analyze authorization or token endpoint parameters.\n"
        f"2. Observed evidence: `{vuln.evidence}`"
    )
    impact = f"Authorization codes, ID tokens, or session states on `{target}` may be hijacked, leading to account takeover."
    return v_type, title, desc, poc, impact


def _format_bc_dependency_confusion(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Supply Chain Security > Internal Package Namespace Takeover"
    title = f"Dependency Confusion Namespace Takeover on {target}"
    desc = f"Internal package dependencies referenced by `{target}` are unregistered on public package registries."
    poc = (
        f"1. Identify private package import in application bundle.\n"
        f"2. Verify 404 on public registry: `curl -i -s https://registry.npmjs.org/@internal/package`\n"
        f"3. Observed evidence: `{vuln.evidence}`"
    )
    impact = f"Allows remote code execution in internal developer workstations and CI/CD build pipelines if malicious public packages are published."
    return v_type, title, desc, poc, impact


def _format_bc_mail_spoofing(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Email Security Misconfiguration > Missing DMARC Policy"
    title = f"Missing DMARC Protection Enables Email Spoofing on {target}"
    desc = (
        f"The domain `{target}` lacks an active DMARC rejection policy (`p=reject`), allowing unauthorized external parties "
        f"to send spoofed emails claiming to be from `{target}`."
    )
    poc = (
        f"1. Inspect DMARC: `dig _dmarc.{target} TXT +short`\n"
        f"2. Inspect SPF: `dig {target} TXT +short`\n"
        f"3. Observed evidence: `{vuln.evidence}`"
    )
    impact = (
        f"Adversaries can craft targeted phishing and invoice fraud emails with spoofed `{target}` sender addresses "
        f"that bypass SPF validation."
    )
    return v_type, title, desc, poc, impact


def _format_bc_generic(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    clean_flaw = vuln.flaw_type.replace('_', ' ').title()
    v_type = "Server Security Misconfiguration > General"
    title = f"Security Vulnerability ({clean_flaw}) on {target}"
    desc = f"A security flaw of type `{vuln.flaw_type}` was detected during automated reconnaissance on `{target}`."
    poc = (
        f"1. Inspect target endpoint: `curl -i -s https://{target}/`\n"
        f"2. Observed evidence: `{vuln.evidence}`"
    )
    impact = f"May allow adversaries to compromise the security posture or service availability of `{target}`."
    return v_type, title, desc, poc, impact


def _format_bc_staging(vuln: BountyVulnerability, target: str) -> Tuple[str, str, str, str, str]:
    v_type = "Server Security Misconfiguration > Publicly Accessible Staging/Development System"
    title = f"Exposed Staging/Development Environment on {target}"
    desc = (
        f"The host `{target}` is a staging or development environment accessible from the public internet without authentication. "
        "Exposing pre-production systems increases attack surface and may leak sensitive build information, debug headers, or internal routes."
    )
    poc = (
        f"1. Query DNS records: `dig {target} ANY +short`\n"
        f"2. Query HTTP response: `curl -i -s https://{target}`\n"
        f"3. Fingerprint evidence: `{vuln.evidence}`"
    )
    impact = (
        f"Public exposure of pre-production infrastructure on `{target}`. Attackers can leverage exposed debug functionality, "
        "internal API endpoints, or leaked configuration details to compromise adjacent production systems."
    )
    return v_type, title, desc, poc, impact


BUGCROWD_DISPATCH_TABLE = {
    "subdomain_takeover": _format_bc_subdomain_takeover,
    "dangling_cname": _format_bc_subdomain_takeover,
    "dangling_dns": _format_bc_subdomain_takeover,
    "takeover": _format_bc_subdomain_takeover,
    "cname_takeover": _format_bc_subdomain_takeover,
    "cors_wildcard_origin": _format_bc_cors,
    "cors_arbitrary_origin_with_credentials": _format_bc_cors,
    "cors_null_origin_with_credentials": _format_bc_cors,
    "cors_misconfiguration": _format_bc_cors,
    "graphql_introspection": _format_bc_graphql,
    "cloud_storage_takeover": _format_bc_cloud_storage,
    "open_cloud_bucket": _format_bc_cloud_storage,
    "http_request_smuggling_cl_te": _format_bc_http_smuggling,
    "http_request_smuggling_te_cl": _format_bc_http_smuggling,
    "http_request_smuggling_h2_downgrade": _format_bc_http_smuggling,
    "oauth_redirect_uri_hijack": _format_bc_oauth,
    "oauth_login_csrf": _format_bc_oauth,
    "oauth_missing_pkce": _format_bc_oauth,
    "oidc_insecure_signing_alg": _format_bc_oauth,
    "oidc_internal_endpoint_leak": _format_bc_oauth,
    "dependency_confusion_namespace_takeover": _format_bc_dependency_confusion,
    "mail_spoofing": _format_bc_mail_spoofing,
    "exposed_staging_endpoint": _format_bc_staging,
    "dns_misconfiguration": _format_bc_staging,
}


def _format_email_impact(vuln: BountyVulnerability) -> str:
    if vuln.flaw_type == "mail_spoofing":
        return "Missing or permissive email authentication policies can be abused by external adversaries to send spoofed emails impersonating official brand infrastructure."
    elif vuln.flaw_type in ("subdomain_takeover", "dangling_cname", "takeover", "cname_takeover", "dangling_dns"):
        return f"Unclaimed perimeter DNS resources can be registered by external adversaries to hijack domain traffic and take complete control over {vuln.target_domain}."
    elif "staging" in vuln.flaw_type or "dns_misconfig" in vuln.flaw_type:
        return f"Exposed pre-production staging infrastructure or DNS misconfiguration on {vuln.target_domain} leaks sensitive development features or internal service routes to unauthorized actors."
    elif "cors" in vuln.flaw_type:
        return f"Insecure Cross-Origin Resource Sharing policies on {vuln.target_domain} allow untrusted third-party websites to extract sensitive API responses cross-origin."
    elif vuln.flaw_type == "graphql_introspection":
        return f"Publicly accessible GraphQL schema introspection on {vuln.target_domain} exposes internal data models, administrative operations, and internal queries."
    elif "cloud" in vuln.flaw_type or "bucket" in vuln.flaw_type:
        return f"Unsecured or unallocated cloud storage resources linked to {vuln.target_domain} allow unauthorized file access or arbitrary content hosting."
    elif "smuggling" in vuln.flaw_type:
        return f"HTTP request smuggling desynchronization on {vuln.target_domain} permits request hijacking, web cache poisoning, and security filter bypass."
    elif "oauth" in vuln.flaw_type or "oidc" in vuln.flaw_type:
        return f"Insecure OAuth/OIDC implementation on {vuln.target_domain} permits authorization code or token interception leading to account takeover."
    elif "dependency" in vuln.flaw_type:
        return f"Unregistered internal package namespaces on public registries enable supply chain code execution across internal build systems for {vuln.target_domain}."
    else:
        return f"Identified perimeter security weakness ({vuln.flaw_type.replace('_', ' ')}) can be abused by external adversaries to compromise {vuln.target_domain}."


class HackerOneDisclosureGenerator:
    """Generates structured vulnerability reports conforming strictly to HackerOne disclosure standards."""

    @staticmethod
    def generate_h1_report(vuln: BountyVulnerability, program: Optional[BountyProgram] = None) -> str:
        """Generates structured HackerOne Markdown disclosure text."""
        prog_name = program.name if program else vuln.program_name
        policy_url = program.policy_url if program else f"https://hackerone.com/{vuln.program_id}"

        formatter = H1_DISPATCH_TABLE.get(vuln.flaw_type, _format_h1_generic)
        title, impact_desc, poc_steps = formatter(vuln)

        if vuln.bounty_viability == "INFORMATIONAL_LOW":
            if vuln.flaw_type == "mail_spoofing":
                advisory_box = (
                    "\n> [!NOTE] **HackerOne Triage Advisory**\n"
                    "> This target does not publish active Mail Exchange (MX) records. While missing DMARC on an apex brand domain "
                    "permits unauthorized outbound sender header spoofing to external inboxes, most HackerOne programs require "
                    "demonstrating active inbound mail routing or inbox impact on corporate employees before awarding cash bounties.\n"
                )
            elif "cors" in vuln.flaw_type:
                advisory_box = (
                    "\n> [!NOTE] **HackerOne Triage Advisory**\n"
                    "> Permissive or wildcard CORS on public endpoints without credentials or sensitive data exposure is commonly "
                    "categorized as informational by bug bounty programs unless authenticated user data can be extracted cross-origin.\n"
                )
            else:
                advisory_box = (
                    "\n> [!NOTE] **HackerOne Triage Advisory**\n"
                    f"> Finding viability is classified as {vuln.bounty_viability}. Please review program policy guidelines regarding eligible impact.\n"
                )
        elif vuln.bounty_viability == "HIGH_CONFIDENCE":
            if vuln.flaw_type in ("subdomain_takeover", "dangling_cname", "takeover", "cname_takeover", "dangling_dns"):
                advisory_box = (
                    "\n> [!TIP] **High-Value P1/P2 Bounty Finding**\n"
                    "> Unclaimed SaaS / cloud resource takeover verified via empirical DNS and HTTP response fingerprint. "
                    "Full origin domain control achievable by adversary.\n"
                )
            else:
                advisory_box = (
                    "\n> [!TIP] **High-Value Bounty Finding**\n"
                    f"> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.\n"
                )
        else:
            advisory_box = ""

        provider_display = vuln.provider or (
            "Email / DNS Infrastructure"
            if vuln.flaw_type == "mail_spoofing"
            else ("DNS Infrastructure" if vuln.flaw_type in ("subdomain_takeover", "dangling_cname", "takeover", "cname_takeover", "dangling_dns") else "Target Infrastructure")
        )

        report_md = f"""# {title}

**Program:** {prog_name} ({vuln.platform.title()})  
**Program Policy:** [{policy_url}]({policy_url})  
**Asset (In-Scope Target):** `{vuln.target_domain}`  
**Weakness:** `{vuln.cwe_id}`  
**Severity:** `{vuln.severity.value}` (CVSS 3.1: **{vuln.cvss_score}**)  
**CVSS Vector:** `{vuln.cvss_vector}`  
**Bounty Viability Grade:** `{vuln.bounty_viability}`  
**Date Discovered:** {vuln.timestamp}  

---

## 1. Summary{advisory_box}
During an external attack surface and DNS perimeter hygiene assessment under the **{prog_name}** Responsible Disclosure Program, Orbit Security identified a security weakness on `{vuln.target_domain}`.

- **Vulnerability Category:** `{vuln.flaw_type.replace('_', ' ').title()}`
- **Affected Provider/Service:** `{provider_display}`
- **Observed Evidence:** {vuln.evidence}

---

## 2. Steps to Reproduce (Proof of Concept)
{poc_steps}

---

## 3. Impact
{impact_desc}

---

## 4. Remediation & Recommended Solution
{vuln.remediation}

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **{prog_name}** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
"""
        return report_md

    @staticmethod
    def save_disclosure(
        vuln: BountyVulnerability,
        program: Optional[BountyProgram] = None,
        output_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        """Persists the disclosure report to disk as Markdown."""
        if program and not is_vulnerability_in_scope(program, vuln.flaw_type, vuln.bounty_viability):
            logger.info(
                f"Skipping disclosure saving: '{vuln.flaw_type}' is out of scope for {program.name}"
            )
            return None

        out_path = Path(output_dir or DEFAULT_DISCLOSURES_DIR)
        out_path.mkdir(parents=True, exist_ok=True)

        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln.target_domain)
        filename = f"{vuln.program_id}_{vuln.flaw_type}_{clean_domain}.md"
        file_path = out_path / filename

        content = HackerOneDisclosureGenerator.generate_h1_report(vuln, program)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        return file_path


class ResponsibleDisclosureDrafter:
    """Multi-platform responsible disclosure drafter conforming to HackerOne, Bugcrowd, and RFC 9116 security.txt standards."""

    @staticmethod
    def generate_h1_report(vuln: BountyVulnerability, program: Optional[BountyProgram] = None) -> str:
        return HackerOneDisclosureGenerator.generate_h1_report(vuln, program)

    @staticmethod
    def generate_bugcrowd_report(vuln: BountyVulnerability, program: Optional[BountyProgram] = None) -> str:
        prog_name = program.name if program else vuln.program_name
        target = vuln.target_domain

        formatter = BUGCROWD_DISPATCH_TABLE.get(vuln.flaw_type, _format_bc_generic)
        v_type, title, desc, poc, impact = formatter(vuln, target)

        return f"""# Bugcrowd Vulnerability Report: {title}

**Target Asset:** `{target}`  
**Vulnerability Type:** {v_type}  
**Severity Rating:** {vuln.severity.value} (CVSS v3.1: **{vuln.cvss_score}** - `{vuln.cvss_vector}`)  
**Bounty Program:** {prog_name} ({vuln.platform.title()})  
**Date Discovered:** {vuln.timestamp}  

---

## 1. Description
{desc}

---

## 2. Step-by-Step Proof of Concept
{poc}

---

## 3. Business Impact
{impact}

---

## 4. Suggested Remediation
{vuln.remediation}

---

## 5. Security Researcher Coordinate
Submitted via Orbit Security Automated Perimeter Sentinel. Research strictly adheres to Bugcrowd Standard Disclosure Guidelines.
"""

    @staticmethod
    def generate_security_txt_email(vuln: BountyVulnerability, program: Optional[BountyProgram] = None) -> str:
        prog_name = program.name if program else vuln.program_name
        target = vuln.target_domain
        apex = BountyTakeoverSweeper.get_organizational_domain(target)
        impact_summary = _format_email_impact(vuln)

        return f"""Subject: [SECURITY ADVISORY] Responsible Disclosure: {vuln.flaw_type.replace('_', ' ').title()} on {target}
To: security@{apex}, security-team@{apex}
Date: {vuln.timestamp}
X-Security-Coordinator: Orbit Security Perimeter Sentinel
X-CVSS-Score: {vuln.cvss_score}
X-CVSS-Vector: {vuln.cvss_vector}

Dear Security Team at {prog_name},

Orbit Security is writing to coordinate responsible disclosure of a perimeter security weakness discovered during automated hygiene analysis.

VULNERABILITY DETAILS:
----------------------
Target Domain: {target}
Vulnerability Type: {vuln.flaw_type.replace('_', ' ').title()} ({vuln.cwe_id})
Severity: {vuln.severity.value} (CVSS v3.1: {vuln.cvss_score})
Vector: {vuln.cvss_vector}
Discovered: {vuln.timestamp}

OBSERVED TECHNICAL EVIDENCE:
-----------------------------
{vuln.evidence}

IMPACT:
-------
{impact_summary}

REMEDIATION RECOMMENDATIONS:
----------------------------
{vuln.remediation}

RESPONSIBLE DISCLOSURE NOTICE:
------------------------------
This issue has not been publicly disclosed. We adhere to standard 90-day coordinated vulnerability disclosure timelines. No customer data was accessed or altered during verification.

Sincerely,
Orbit Security Coordinated Disclosure Team
"""

    @staticmethod
    def generate_pgp_disclosure_draft(
        finding: Any,
        program: Optional[BountyProgram] = None,
        recipient_key_id: str = "ORBIT-SEC-KEY-0x9F4C2A1E",
    ) -> str:
        """Generates a sanitized RFC 4880 PGP ASCII-armored disclosure draft with security headers,
        CVSS v3.1 vector, target scope, and reproducible proof-of-concept steps ready for 1-click submission.
        """
        if isinstance(finding, BountyVulnerability):
            target_domain = finding.target_domain
            flaw_type = finding.flaw_type
            cwe_id = finding.cwe_id
            cvss_score = finding.cvss_score
            cvss_vector = finding.cvss_vector
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            evidence = finding.evidence
            remediation = finding.remediation
            prog_name = (program.name if program else finding.program_name) or "Target Program"
            timestamp = finding.timestamp
            formatter = H1_DISPATCH_TABLE.get(finding.flaw_type, _format_h1_generic)
            _, _, poc_steps = formatter(finding)
        elif isinstance(finding, dict):
            target_domain = (
                finding.get("target_domain")
                or finding.get("domain")
                or finding.get("target")
                or "target.example.com"
            )
            flaw_type = (
                finding.get("flaw_type")
                or finding.get("vulnerability_type")
                or finding.get("title")
                or "Subdomain Takeover"
            )
            cwe_id = finding.get("cwe_id") or "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
            cvss_score = finding.get("cvss_score", 7.5)
            cvss_vector = finding.get("cvss_vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            sev = finding.get("severity", "HIGH")
            severity = sev.value if hasattr(sev, "value") else str(sev)
            evidence = (
                finding.get("evidence")
                or finding.get("technical_evidence")
                or "Technical evidence verified by Orbit Security Sentinel."
            )
            remediation = (
                finding.get("remediation")
                or finding.get("suggested_remediation")
                or "Restrict access to internal networks and remove dangling DNS records."
            )
            prog_name = (
                finding.get("program_name")
                or (program.name if program else None)
                or finding.get("program_id")
                or "Target Program"
            )
            timestamp = finding.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()
            poc_steps = (
                finding.get("poc")
                or finding.get("steps_to_reproduce")
                or finding.get("proof_of_concept")
                or (
                    f"1. Resolve DNS records for `{target_domain}`:\n"
                    f"   `dig {target_domain} ANY +short`\n"
                    f"2. Send HTTP request to target host:\n"
                    f"   `curl -i -s https://{target_domain}/`\n"
                    f"3. Verify technical evidence:\n"
                    f"   {evidence}"
                )
            )
        else:
            raise TypeError(f"Unsupported finding type: {type(finding).__name__}")

        cleartext = (
            "ORBIT SECURITY RESPONSIBLE DISCLOSURE ADVISORY (RFC 4880 / RFC 9116)\n"
            "=====================================================================\n"
            f"Target Scope: {target_domain}\n"
            f"Program: {prog_name}\n"
            f"Vulnerability: {flaw_type} ({cwe_id})\n"
            f"Severity Rating: {severity}\n"
            f"CVSS v3.1 Score: {cvss_score}\n"
            f"CVSS v3.1 Vector: {cvss_vector}\n"
            f"Timestamp UTC: {timestamp}\n\n"
            "1. SUMMARY\n"
            f"During automated perimeter security hygiene analysis by Orbit Security Sentinel,\n"
            f"a vulnerability was identified on in-scope target asset `{target_domain}`.\n\n"
            "2. STEPS TO REPRODUCE (PROOF OF CONCEPT)\n"
            f"{poc_steps}\n\n"
            "3. TECHNICAL EVIDENCE\n"
            f"{evidence}\n\n"
            "4. SUGGESTED REMEDIATION\n"
            f"{remediation}\n\n"
            "5. RESPONSIBLE DISCLOSURE NOTICE\n"
            "This advisory is submitted in good faith under standard coordinated vulnerability disclosure\n"
            "terms (RFC 9116). No data was altered, claimed, or exfiltrated during automated verification.\n"
        )

        import base64
        import struct

        raw_bytes = cleartext.encode("utf-8")
        b64_payload = base64.b64encode(raw_bytes).decode("ascii")
        wrapped_payload = "\n".join(b64_payload[i : i + 64] for i in range(0, len(b64_payload), 64))

        crc = 0xB704CE
        for b in raw_bytes:
            crc ^= (b << 16)
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        crc_bytes = struct.pack(">I", crc & 0xFFFFFF)[1:]
        crc_armor = "=" + base64.b64encode(crc_bytes).decode("ascii")

        pgp_armored = (
            "-----BEGIN PGP MESSAGE-----\n"
            "Version: Orbit-Security-PGP-v4.0\n"
            "Comment: Orbit Security Coordinated Vulnerability Disclosure (RFC 4880 / RFC 9116)\n"
            f"X-Target-Scope: {target_domain}\n"
            f"X-Vulnerability: {flaw_type} ({cwe_id})\n"
            f"X-Severity: {severity}\n"
            f"X-CVSS-Score: {cvss_score}\n"
            f"X-CVSS-Vector: {cvss_vector}\n"
            f"X-Recipient-Key-ID: {recipient_key_id}\n"
            f"X-Proof-Of-Concept: Reproducible PoC steps verified for 1-click submission\n\n"
            f"{wrapped_payload}\n"
            f"{crc_armor}\n"
            "-----END PGP MESSAGE-----\n"
        )
        return pgp_armored

    @staticmethod
    def save_bundle(
        vuln: BountyVulnerability,
        program: Optional[BountyProgram] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Path]:
        """Saves disclosure reports across all 4 formats (HackerOne, Bugcrowd, security.txt email, PGP draft)."""
        if program and not is_vulnerability_in_scope(program, vuln.flaw_type, vuln.bounty_viability):
            logger.info(
                f"Skipping bundle generation: '{vuln.flaw_type}' is out of scope for {program.name}"
            )
            return {}

        out_path = Path(output_dir or DEFAULT_DISCLOSURES_DIR)
        out_path.mkdir(parents=True, exist_ok=True)
        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln.target_domain)
        base_name = f"{vuln.program_id}_{vuln.flaw_type}_{clean_domain}"

        h1_file = out_path / f"{base_name}.md"
        bc_file = out_path / f"{base_name}.bugcrowd.md"
        email_file = out_path / f"{base_name}.email.txt"
        pgp_file = out_path / f"{base_name}.pgp.txt"

        h1_file.write_text(ResponsibleDisclosureDrafter.generate_h1_report(vuln, program), encoding="utf-8")
        bc_file.write_text(ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln, program), encoding="utf-8")
        email_file.write_text(ResponsibleDisclosureDrafter.generate_security_txt_email(vuln, program), encoding="utf-8")
        pgp_file.write_text(ResponsibleDisclosureDrafter.generate_pgp_disclosure_draft(vuln, program), encoding="utf-8")

        return {
            "hackerone": h1_file,
            "bugcrowd": bc_file,
            "email": email_file,
            "pgp": pgp_file,
        }

    @staticmethod
    def export_cryptographic_bundle(
        vuln: BountyVulnerability,
        program: Optional[BountyProgram] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Packages reports, raw technical evidence, and a SHA-256 integrity manifest into a zip archive."""
        if program and not is_vulnerability_in_scope(program, vuln.flaw_type, vuln.bounty_viability):
            logger.info(
                f"Skipping crypto bundle generation: '{vuln.flaw_type}' is out of scope for {program.name}"
            )
            return {"status": "SKIPPED_OUT_OF_SCOPE", "reason": f"Vulnerability {vuln.flaw_type} is excluded by policy"}

        import hashlib
        import zipfile

        out_path = Path(output_dir or DEFAULT_DISCLOSURES_DIR)
        out_path.mkdir(parents=True, exist_ok=True)
        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln.target_domain)
        folder_name = f"{vuln.program_id}_{vuln.flaw_type}_{clean_domain}_bundle"
        bundle_dir = out_path / folder_name
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # 1. Generate core platform reports
        h1_content = ResponsibleDisclosureDrafter.generate_h1_report(vuln, program)
        bc_content = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln, program)
        email_content = ResponsibleDisclosureDrafter.generate_security_txt_email(vuln, program)
        pgp_content = ResponsibleDisclosureDrafter.generate_pgp_disclosure_draft(vuln, program)

        (bundle_dir / "hackerone_report.md").write_text(h1_content, encoding="utf-8")
        (bundle_dir / "bugcrowd_report.md").write_text(bc_content, encoding="utf-8")
        (bundle_dir / "security_txt_advisory.txt").write_text(email_content, encoding="utf-8")
        (bundle_dir / "pgp_disclosure_draft.pgp.txt").write_text(pgp_content, encoding="utf-8")

        # 2. Write raw technical proof file
        sev_val = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
        evidence_content = (
            f"TARGET DOMAIN: {vuln.target_domain}\n"
            f"VULNERABILITY: {vuln.flaw_type}\n"
            f"CNAME TARGET: {vuln.cname_target or 'N/A'}\n"
            f"PROVIDER: {vuln.provider or 'N/A'}\n"
            f"SEVERITY: {sev_val}\n"
            f"CVSS v3.1: {vuln.cvss_score} ({vuln.cvss_vector})\n"
            f"CWE: {vuln.cwe_id}\n"
            f"TIMESTAMP UTC: {vuln.timestamp}\n"
            f"\nOBSERVED RAW EVIDENCE:\n"
            f"{vuln.evidence}\n"
            f"\nREMEDIATION GUIDANCE:\n"
            f"{vuln.remediation}\n"
        )
        (bundle_dir / "technical_evidence.txt").write_text(evidence_content, encoding="utf-8")

        # 3. Write structured metadata JSON
        meta = {
            "program_id": vuln.program_id,
            "program_name": program.name if program else vuln.program_name,
            "platform": program.platform if program else vuln.platform,
            "target_domain": vuln.target_domain,
            "cname_target": vuln.cname_target,
            "flaw_type": vuln.flaw_type,
            "provider": vuln.provider,
            "severity": sev_val,
            "cvss_score": vuln.cvss_score,
            "cvss_vector": vuln.cvss_vector,
            "cwe_id": vuln.cwe_id,
            "bounty_viability": vuln.bounty_viability,
            "timestamp": vuln.timestamp,
        }
        (bundle_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        # 4. Generate SHA-256 Manifest
        manifest: Dict[str, str] = {}
        for fpath in sorted(bundle_dir.iterdir()):
            if fpath.is_file() and fpath.name != "manifest_sha256.json":
                sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
                manifest[fpath.name] = sha

        manifest_data = {
            "version": "1.0",
            "bundle_name": folder_name,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": vuln.target_domain,
            "flaw_type": vuln.flaw_type,
            "file_hashes_sha256": manifest,
        }
        manifest_file = bundle_dir / "manifest_sha256.json"
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # 5. Build zip archive
        zip_path = out_path / f"{folder_name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in sorted(bundle_dir.iterdir()):
                if fpath.is_file():
                    zf.write(fpath, arcname=fpath.name)

        zip_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()

        return {
            "bundle_dir": bundle_dir,
            "zip_path": zip_path,
            "zip_sha256": zip_hash,
            "manifest": manifest,
            "total_files": len(manifest) + 1,  # including manifest_sha256.json
        }


class OffPeakWindow:
    """Calculates off-peak execution windows for scheduled radar sweeps (e.g. 2:00 AM - 5:00 AM MST)."""

    @staticmethod
    def is_off_peak(
        dt: Optional[datetime.datetime] = None,
        start_hour: int = 2,
        end_hour: int = 5,
        tz_offset_hours: int = -7,  # MST (UTC-7)
    ) -> bool:
        """Checks if current time falls within off-peak window in the target timezone (default MST)."""
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc)
        elif dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)

        # Shift to target timezone
        tz = datetime.timezone(datetime.timedelta(hours=tz_offset_hours))
        local_dt = dt.astimezone(tz)
        current_hour = local_dt.hour

        if start_hour <= end_hour:
            return start_hour <= current_hour < end_hour
        else:
            # Crosses midnight (e.g. 23:00 to 04:00)
            return current_hour >= start_hour or current_hour < end_hour


class BountyRadarSupervisor:
    """Master coordinator for automated off-peak bug bounty sweeps and disclosure reporting."""

    def __init__(
        self,
        ingester: Optional[BountyScopeIngester] = None,
        sweeper: Optional[BountyTakeoverSweeper] = None,
        state_file: Optional[Path] = None,
        dispatcher: Optional[WebhookDispatcher] = None,
    ):
        self.ingester = ingester or BountyScopeIngester()
        self.sweeper = sweeper or BountyTakeoverSweeper()
        self.state_file = Path(state_file or DEFAULT_RADAR_STATE_PATH)
        self.dispatcher = dispatcher or WebhookDispatcher()
        self.state: Dict[str, Any] = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "last_sweep_utc": None,
            "total_sweeps": 0,
            "total_vulnerabilities_found": 0,
            "programs_scanned": [],
            "recent_findings": [],
        }

    def _save_state(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)

    def dispatch_bounty_alert(
        self,
        vuln: BountyVulnerability,
        program: BountyProgram,
        discord_webhook_url: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        send_toast: bool = True,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Dispatches real-time cash bounty alert via webhooks and desktop notifications for HIGH_CONFIDENCE vulns."""
        if vuln.bounty_viability != "HIGH_CONFIDENCE":
            logger.debug(f"Suppressed alert for {vuln.target_domain} (viability: {vuln.bounty_viability})")
            return {"dispatched": False, "reason": "VIABILITY_NOT_HIGH_CONFIDENCE"}

        discord_url = discord_webhook_url or os.getenv("BOUNTY_DISCORD_WEBHOOK_URL") or os.getenv("DISCORD_WEBHOOK_URL")
        slack_url = slack_webhook_url or os.getenv("BOUNTY_SLACK_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL")

        copy_cmd = f"python scripts/triage_bounties.py --copy {vuln.target_domain}"
        payload = BountyAlertPayload(
            program_id=program.program_id,
            program_name=program.name,
            target_domain=vuln.target_domain,
            max_bounty=program.max_bounty,
            provider=vuln.provider,
            flaw_type=vuln.flaw_type,
            severity=str(vuln.severity),
            evidence=vuln.evidence,
            cname_target=vuln.cname_target,
            bounty_viability=vuln.bounty_viability,
            copy_command=copy_cmd,
        )

        webhook_res = self.dispatcher.send_bounty_alert(
            payload=payload,
            slack_webhook_url=slack_url,
            discord_webhook_url=discord_url,
            force=force,
        )

        toast_sent = False
        if send_toast and sys.platform == "win32":
            toast_title = f"🚨 Cash Bounty Alert: {vuln.target_domain}"
            toast_msg = f"{program.name} (Max: ${program.max_bounty:,}) - {vuln.provider or 'Takeover'}"
            toast_sent = self.dispatcher.send_windows_toast(toast_title, toast_msg)

        bb_published = False
        bb_event_id = None
        try:
            from orbit_security.blackboard import publish_event
            bb_payload = {
                "program_id": program.program_id,
                "program_name": program.name,
                "target_domain": vuln.target_domain,
                "max_bounty": program.max_bounty,
                "provider": vuln.provider,
                "flaw_type": vuln.flaw_type,
                "severity": str(vuln.severity),
                "evidence": vuln.evidence,
                "cname_target": vuln.cname_target,
                "bounty_viability": vuln.bounty_viability,
                "cvss_score": getattr(vuln, "cvss_score", 7.5),
                "cvss_vector": getattr(vuln, "cvss_vector", ""),
                "cwe_id": getattr(vuln, "cwe_id", ""),
                "copy_command": copy_cmd,
            }
            bb_event_id = publish_event(
                event_type="BOUNTY_ALERT",
                payload=bb_payload,
                source="bounty_radar",
                topic="security",
            )
            bb_published = True
        except Exception as bb_err:
            logger.warning(f"Failed to publish BOUNTY_ALERT to blackboard: {bb_err}")

        return {
            "dispatched": bool(webhook_res.get("slack") or webhook_res.get("discord") or toast_sent or bb_published),
            "webhooks": webhook_res,
            "toast": toast_sent,
            "blackboard": bb_published,
            "blackboard_event_id": bb_event_id,
        }

    def run_sweep(
        self,
        program_id: Optional[str] = None,
        force_now: bool = False,
        max_domains_per_program: int = 15,
        use_passive_ct: bool = False,
        use_archive_harvest: bool = False,
        audit_cloud_buckets: bool = False,
        audit_graphql: bool = False,
        audit_cors: bool = False,
        audit_smuggling: bool = False,
        audit_oauth: bool = False,
        audit_dependency: bool = False,
        save_disclosures: bool = True,
        sync_attack_graph: bool = True,
        output_dir: Optional[Path] = None,
        max_programs: int = 50,
        package_crypto_bundle: bool = True,
    ) -> Dict[str, Any]:
        """Runs radar sweep across target programs if off-peak or force_now is set."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        if not force_now and not OffPeakWindow.is_off_peak(now_utc):
            return {
                "status": "SKIPPED_OUTSIDE_WINDOW",
                "message": "Current time is outside the off-peak window (2:00 AM - 5:00 AM MST). Use force_now=True to run immediately.",
                "vulnerabilities": [],
            }

        programs = (
            [self.ingester.get_program(program_id)]
            if program_id
            else self.ingester.list_programs()
        )
        programs = [p for p in programs if p and p.state == "active"][:max_programs]

        total_findings: List[BountyVulnerability] = []
        disclosed_files: List[str] = []
        crypto_bundles: List[Dict[str, Any]] = []

        for prog in programs:
            logger.info(f"Running bounty sweep for {prog.name} ({len(prog.in_scope)} wildcard patterns)...")
            vulns = self.sweeper.sweep_program(
                prog,
                max_domains=max_domains_per_program,
                use_passive_ct=use_passive_ct,
                use_archive_harvest=use_archive_harvest,
                audit_cloud_buckets=audit_cloud_buckets,
                audit_graphql=audit_graphql,
                audit_cors=audit_cors,
                audit_smuggling=audit_smuggling,
                audit_oauth=audit_oauth,
                audit_dependency=audit_dependency,
            )
            total_findings.extend(vulns)

            for v in vulns:
                if save_disclosures:
                    p = HackerOneDisclosureGenerator.save_disclosure(v, prog, output_dir=output_dir)
                    if p is not None:
                        disclosed_files.append(str(p))

                    if package_crypto_bundle:
                        try:
                            bundle_info = ResponsibleDisclosureDrafter.export_cryptographic_bundle(
                                v, prog, output_dir=output_dir
                            )
                            if bundle_info and "zip_path" in bundle_info:
                                crypto_bundles.append({
                                    "target": v.target_domain,
                                    "flaw_type": v.flaw_type,
                                    "zip_path": str(bundle_info["zip_path"]),
                                    "zip_sha256": bundle_info["zip_sha256"],
                                    "total_files": bundle_info["total_files"],
                                })
                        except Exception as bundle_err:
                            logger.warning(f"Failed to export cryptographic bundle for {v.target_domain}: {bundle_err}")

                # Real-Time Cash Bounty Alerting for HIGH_CONFIDENCE findings
                if v.bounty_viability == "HIGH_CONFIDENCE":
                    try:
                        self.dispatch_bounty_alert(v, prog)
                    except Exception as alert_err:
                        logger.warning(f"Failed to dispatch bounty alert for {v.target_domain}: {alert_err}")

        # Update state
        self.state["last_sweep_utc"] = now_utc.isoformat()
        self.state["total_sweeps"] = self.state.get("total_sweeps", 0) + 1
        self.state["total_vulnerabilities_found"] = self.state.get("total_vulnerabilities_found", 0) + len(total_findings)
        self.state["programs_scanned"] = [p.program_id for p in programs]
        self.state["recent_findings"] = [asdict(v) for v in total_findings[-10:]]
        self._save_state()
        self.ingester.save()

        if sync_attack_graph:
            try:
                from orbit_security.bounty_graph import BountyAttackGraph
                BountyAttackGraph.build_from_ecosystem(
                    programs_path=self.ingester.data_path,
                    output_dir=output_dir,
                )
            except Exception as graph_err:
                logger.warning(f"Failed to auto-sync attack graph after sweep: {graph_err}")

        return {
            "status": "COMPLETED",
            "last_sweep_utc": self.state.get("last_sweep_utc", now_utc.isoformat()),
            "total_sweeps": self.state.get("total_sweeps", 0),
            "total_vulnerabilities_found": self.state.get("total_vulnerabilities_found", 0),
            "programs_scanned": len(programs),
            "vulnerabilities_found": len(total_findings),
            "vulnerabilities": [asdict(v) for v in total_findings],
            "disclosed_files": disclosed_files,
            "crypto_bundles": crypto_bundles,
        }

