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


@dataclass
class BountyProgram:
    program_id: str
    name: str
    platform: str = "hackerone"  # hackerone, bugcrowd, intigriti, direct
    policy_url: str = ""
    in_scope: List[str] = field(default_factory=list)  # e.g. ["*.shopify.com", "*.myshopify.com"]
    out_of_scope: List[str] = field(default_factory=list)
    bounty_tier: str = "cash"  # cash, swag, points
    max_bounty: int = 10000
    state: str = "active"  # active, paused
    last_scanned: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


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


class BountyTakeoverSweeper:
    """Expands wildcard scopes and tests targets for dangling SaaS CNAMEs and mail-spoofing vectors."""

    def __init__(
        self,
        resolver: Optional[dns.resolver.Resolver] = None,
        custom_prefixes: Optional[List[str]] = None,
    ):
        self.resolver = resolver or get_orbit_sync_resolver()
        self.prefixes = custom_prefixes or HIGH_FREQUENCY_PREFIXES

    def fetch_crtsh_subdomains(
        self, apex_domain: str, timeout: float = 4.0, max_results: int = 50
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
        mock_cnames: Optional[Dict[str, str]] = None,
        mock_bodies: Optional[Dict[str, str]] = None,
        mock_spfs: Optional[Dict[str, str]] = None,
        mock_dmarcs: Optional[Dict[str, str]] = None,
        mock_nxdomain_domains: Optional[Set[str]] = None,
        mock_graphql_responses: Optional[Dict[str, Dict[str, Any]]] = None,
        mock_cors_responses: Optional[Dict[str, Dict[str, str]]] = None,
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
            if audit_cloud_buckets:
                bucket_res = self.audit_cloud_storage_bucket(
                    target, cname_target=mock_cn, mock_body=mock_bd
                )
                if bucket_res and bucket_res.get("vulnerable"):
                    vuln = BountyVulnerability(
                        program_id=program.program_id,
                        program_name=program.name,
                        platform=program.platform,
                        target_domain=target,
                        cname_target=mock_cn,
                        flaw_type=bucket_res.get("flaw_type", "cloud_storage_takeover"),
                        provider=bucket_res.get("provider", "Cloud Storage"),
                        severity=bucket_res.get("severity", Severity.HIGH),
                        cvss_score=bucket_res.get("cvss_score", 8.6),
                        cvss_vector=bucket_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N"),
                        evidence=bucket_res.get("evidence", ""),
                        cwe_id=bucket_res.get("cwe_id", "CWE-284: Improper Access Control"),
                        remediation=bucket_res.get("remediation", ""),
                        bounty_viability=bucket_res.get("bounty_viability", "HIGH_CONFIDENCE"),
                    )
                    vulns.append(vuln)
                    continue

            # 2. Subdomain Takeover Check (SaaS services)
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
            if audit_graphql:
                gql_mock = mock_graphql_responses.get(target) if mock_graphql_responses else None
                gql_res = self.audit_graphql_introspection(target, mock_paths=gql_mock)
                if gql_res and gql_res.get("vulnerable"):
                    vuln = BountyVulnerability(
                        program_id=program.program_id,
                        program_name=program.name,
                        platform=program.platform,
                        target_domain=target,
                        flaw_type="graphql_introspection",
                        provider="GraphQL",
                        severity=gql_res.get("severity", Severity.MEDIUM),
                        cvss_score=gql_res.get("cvss_score", 5.3),
                        cvss_vector=gql_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                        evidence=gql_res.get("evidence", ""),
                        cwe_id=gql_res.get("cwe_id", "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"),
                        remediation=gql_res.get("remediation", ""),
                        bounty_viability="HIGH_CONFIDENCE",
                    )
                    vulns.append(vuln)

            # 4. CORS Misconfiguration Check
            if audit_cors:
                cors_mock = mock_cors_responses.get(target) if mock_cors_responses else None
                cors_res = self.audit_cors_misconfiguration(target, mock_responses=cors_mock)
                if cors_res and cors_res.get("vulnerable"):
                    vuln = BountyVulnerability(
                        program_id=program.program_id,
                        program_name=program.name,
                        platform=program.platform,
                        target_domain=target,
                        flaw_type=cors_res.get("flaw_type", "cors_misconfiguration"),
                        provider="API Gateway CORS",
                        severity=cors_res.get("severity", Severity.HIGH),
                        cvss_score=cors_res.get("cvss_score", 8.1),
                        cvss_vector=cors_res.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
                        evidence=cors_res.get("evidence", ""),
                        cwe_id=cors_res.get("cwe_id", "CWE-942: Permissive Cross-domain Policy with Untrusted Domains"),
                        remediation=cors_res.get("remediation", ""),
                        bounty_viability=cors_res.get("bounty_viability", "HIGH_CONFIDENCE"),
                    )
                    vulns.append(vuln)

            # 2. Email Spoofing Check (primarily on apex or mail hosts)
            if "." in target:
                org_domain = self.get_organizational_domain(target)
                is_apex = target == org_domain
                if is_apex or "mail" in target or mock_spfs.get(target) or mock_dmarcs.get(target):
                    spoof_res = self.check_mail_spoofing(
                        target,
                        mock_spf=mock_spfs.get(target),
                        mock_dmarc=mock_dmarcs.get(target),
                    )
                    if spoof_res:
                        issue_title, evidence, sev, cvss = spoof_res
                        has_mx = self.has_mx_records(target)
                        viability = "CONDITIONAL" if has_mx else "INFORMATIONAL_LOW"
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


class HackerOneDisclosureGenerator:
    """Generates structured vulnerability reports conforming strictly to HackerOne disclosure standards."""

    @staticmethod
    def generate_h1_report(vuln: BountyVulnerability, program: Optional[BountyProgram] = None) -> str:
        """Generates structured HackerOne Markdown disclosure text."""
        prog_name = program.name if program else vuln.program_name
        policy_url = program.policy_url if program else f"https://hackerone.com/{vuln.program_id}"

        if vuln.flaw_type == "subdomain_takeover":
            title = f"[Subdomain Takeover] Unclaimed {vuln.provider or 'SaaS'} Resource via Dangling CNAME on {vuln.target_domain}"
            impact_desc = (
                f"An attacker can register the orphaned `{vuln.cname_target}` resource on {vuln.provider} and take complete "
                f"control of `{vuln.target_domain}`. This allows the adversary to:\n"
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
        else:
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

        if vuln.bounty_viability == "INFORMATIONAL_LOW":
            advisory_box = (
                "\n> [!NOTE] **HackerOne Triage Advisory**\n"
                "> This target does not publish active Mail Exchange (MX) records. While missing DMARC on an apex brand domain "
                "permits unauthorized outbound sender header spoofing to external inboxes, most HackerOne programs require "
                "demonstrating active inbound mail routing or inbox impact on corporate employees before awarding cash bounties.\n"
            )
        elif vuln.bounty_viability == "HIGH_CONFIDENCE":
            advisory_box = (
                "\n> [!TIP] **High-Value P1/P2 Bounty Finding**\n"
                "> Unclaimed SaaS / cloud resource takeover verified via empirical DNS and HTTP response fingerprint. "
                "Full origin domain control achievable by adversary.\n"
            )
        else:
            advisory_box = ""

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
- **Affected Provider/Service:** `{vuln.provider or 'DNS / Mail Infrastructure'}`
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
    ) -> Path:
        """Persists the disclosure report to disk as Markdown."""
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

        if vuln.flaw_type == "subdomain_takeover":
            v_type = "Server Security Misconfiguration > Subdomain Takeover"
            title = f"Subdomain Takeover on {target} ({vuln.provider or 'SaaS'})"
            desc = (
                f"The domain `{target}` delegates to an unclaimed `{vuln.provider}` resource at `{vuln.cname_target}`. "
                "Because the remote resource is unallocated, an external adversary can claim the tenant and take full control "
                f"of `{target}`."
            )
            poc = (
                f"1. Query CNAME record: `dig {target} CNAME +short` -> `{vuln.cname_target}`\n"
                f"2. Query HTTP response: `curl -i -s https://{target}`\n"
                f"3. Fingerprint: `{vuln.evidence}`"
            )
            impact = (
                f"Complete control of subdomain `{target}`. An attacker can serve arbitrary content, intercept session cookies "
                "scoped to parent domains, or bypass CORS policies."
            )
        else:
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
                "that bypass SPF validation."
            )

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
        parts = target.split(".")
        apex = parts[-2] + "." + parts[-1] if len(parts) >= 2 else target

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
Unclaimed perimeter resources or missing email authentication policies can be abused by external adversaries to impersonate official brand infrastructure.

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
    def save_bundle(
        vuln: BountyVulnerability,
        program: Optional[BountyProgram] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Path]:
        """Saves disclosure reports across all 3 formats (HackerOne, Bugcrowd, security.txt email)."""
        out_path = Path(output_dir or DEFAULT_DISCLOSURES_DIR)
        out_path.mkdir(parents=True, exist_ok=True)
        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln.target_domain)
        base_name = f"{vuln.program_id}_{vuln.flaw_type}_{clean_domain}"

        h1_file = out_path / f"{base_name}.md"
        bc_file = out_path / f"{base_name}.bugcrowd.md"
        email_file = out_path / f"{base_name}.email.txt"

        h1_file.write_text(ResponsibleDisclosureDrafter.generate_h1_report(vuln, program), encoding="utf-8")
        bc_file.write_text(ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln, program), encoding="utf-8")
        email_file.write_text(ResponsibleDisclosureDrafter.generate_security_txt_email(vuln, program), encoding="utf-8")

        return {"hackerone": h1_file, "bugcrowd": bc_file, "email": email_file}


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

        return {
            "dispatched": bool(webhook_res.get("slack") or webhook_res.get("discord") or toast_sent),
            "webhooks": webhook_res,
            "toast": toast_sent,
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
        save_disclosures: bool = True,
        output_dir: Optional[Path] = None,
        max_programs: int = 25,
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
            )
            total_findings.extend(vulns)

            for v in vulns:
                if save_disclosures:
                    p = HackerOneDisclosureGenerator.save_disclosure(v, prog, output_dir=output_dir)
                    disclosed_files.append(str(p))

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

        return {
            "status": "COMPLETED",
            "last_sweep_utc": self.state.get("last_sweep_utc", now_utc.isoformat()),
            "total_sweeps": self.state.get("total_sweeps", 0),
            "total_vulnerabilities_found": self.state.get("total_vulnerabilities_found", 0),
            "programs_scanned": len(programs),
            "vulnerabilities_found": len(total_findings),
            "vulnerabilities": [asdict(v) for v in total_findings],
            "disclosed_files": disclosed_files,
        }

