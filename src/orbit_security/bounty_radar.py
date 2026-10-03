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
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver

from orbit_security.dns_cache import get_orbit_sync_resolver
from orbit_security.models import Severity
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
                            if line and line.endswith(clean_apex) and line != clean_apex:
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
    ) -> List[str]:
        """Expands wildcard patterns (*.target.com) into candidate FQDNs."""
        out_set: Set[str] = set(s.strip().lower() for s in (out_of_scope or []))
        expanded: List[str] = []
        seen: Set[str] = set()

        for pattern in in_scope:
            clean = pattern.strip().lower()
            if not clean:
                continue

            if clean.startswith("*."):
                apex = clean[2:]
                # Also include apex domain
                if apex not in out_set and apex not in seen:
                    expanded.append(apex)
                    seen.add(apex)

                # Passive Certificate Transparency Discovery if requested
                if use_passive_ct:
                    ct_subs = self.fetch_crtsh_subdomains(apex, max_results=max_per_wildcard)
                    for sub in ct_subs:
                        if sub not in out_set and sub not in seen:
                            expanded.append(sub)
                            seen.add(sub)

                for prefix in self.prefixes[:max_per_wildcard]:
                    candidate = f"{prefix}.{apex}"
                    if candidate not in out_set and candidate not in seen:
                        expanded.append(candidate)
                        seen.add(candidate)
            else:
                # Direct domain
                if clean not in out_set and clean not in seen:
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
        mock_cnames: Optional[Dict[str, str]] = None,
        mock_bodies: Optional[Dict[str, str]] = None,
        mock_spfs: Optional[Dict[str, str]] = None,
        mock_dmarcs: Optional[Dict[str, str]] = None,
        mock_nxdomain_domains: Optional[Set[str]] = None,
    ) -> List[BountyVulnerability]:
        """Performs an automated attack surface sweep across a program's in-scope targets."""
        candidates = self.expand_wildcards(
            program.in_scope,
            program.out_of_scope,
            max_per_wildcard=max_domains,
            use_passive_ct=use_passive_ct,
        )
        vulns: List[BountyVulnerability] = []
        mock_cnames = mock_cnames or {}
        mock_bodies = mock_bodies or {}
        mock_spfs = mock_spfs or {}
        mock_dmarcs = mock_dmarcs or {}
        mock_nxdomain_domains = mock_nxdomain_domains or set()

        for target in candidates:
            # 1. Subdomain Takeover Check
            mock_cn = mock_cnames.get(target)
            mock_bd = mock_bodies.get(target)
            mock_nx = target in mock_nxdomain_domains

            takeover_res = self.check_subdomain_takeover(
                target, mock_cname=mock_cn, mock_body=mock_bd, mock_nxdomain=mock_nx
            )
            if takeover_res:
                sig, cname, evidence = takeover_res
                vuln = BountyVulnerability(
                    program_id=program.program_id,
                    program_name=program.name,
                    platform=program.platform,
                    target_domain=target,
                    cname_target=cname,
                    flaw_type="subdomain_takeover",
                    provider=sig.name,
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    evidence=evidence,
                    cwe_id="CWE-284: Improper Access Control",
                    remediation=sig.remediation,
                    bounty_viability="HIGH_CONFIDENCE",
                )
                vulns.append(vuln)
                continue  # If takeover found, proceed to next target

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
                        vuln = BountyVulnerability(
                            program_id=program.program_id,
                            program_name=program.name,
                            platform=program.platform,
                            target_domain=target,
                            flaw_type="mail_spoofing",
                            provider=None,
                            severity=sev,
                            cvss_score=cvss,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" if sev == Severity.MEDIUM else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                            evidence=evidence,
                            cwe_id="CWE-290: Authentication Bypass by Spoofing",
                            remediation=f"Publish a strict DMARC record at '_dmarc.{target}' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).",
                            bounty_viability=viability,
                        )
                        vulns.append(vuln)

        program.last_scanned = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return vulns


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
    ):
        self.ingester = ingester or BountyScopeIngester()
        self.sweeper = sweeper or BountyTakeoverSweeper()
        self.state_file = Path(state_file or DEFAULT_RADAR_STATE_PATH)
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

    def run_sweep(
        self,
        program_id: Optional[str] = None,
        force_now: bool = False,
        max_domains_per_program: int = 15,
        use_passive_ct: bool = False,
        save_disclosures: bool = True,
        output_dir: Optional[Path] = None,
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
        programs = [p for p in programs if p and p.state == "active"]

        total_findings: List[BountyVulnerability] = []
        disclosed_files: List[str] = []

        for prog in programs:
            logger.info(f"Running bounty sweep for {prog.name} ({len(prog.in_scope)} wildcard patterns)...")
            vulns = self.sweeper.sweep_program(
                prog,
                max_domains=max_domains_per_program,
                use_passive_ct=use_passive_ct,
            )
            total_findings.extend(vulns)

            if save_disclosures:
                for v in vulns:
                    p = HackerOneDisclosureGenerator.save_disclosure(v, prog, output_dir=output_dir)
                    disclosed_files.append(str(p))

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
            "programs_scanned": len(programs),
            "vulnerabilities_found": len(total_findings),
            "vulnerabilities": [asdict(v) for v in total_findings],
            "disclosed_files": disclosed_files,
        }
