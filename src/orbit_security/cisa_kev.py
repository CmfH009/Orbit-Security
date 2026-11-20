"""orbit_security.cisa_kev: CISA Known Exploited Vulnerabilities (KEV) Correlator Engine.
====================================================================================
Cross-references detected external web server banners, software stacks, and versions
against actively weaponized, real-world CVEs in the official CISA KEV catalog.

Features:
- Local 24-hour TTL disk cache (data/cisa_kev_cache.json) to prevent rate limits.
- Built-in offline fixture fallback so tests and disconnected audits never crash.
- Version-bounded matching: bare headers (e.g. 'Server: Apache') NEVER trigger false positives.
- Standardized SQLite WAL Blackboard event publishing (CISA_KEV_MATCH_DETECTED).
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("orbit_security.cisa_kev")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CACHE_PATH = REPO_ROOT / "data" / "cisa_kev_cache.json"

# Built-in essential baseline fixture for offline runs and airgapped environments
BUILTIN_KEV_FALLBACK = {
    "title": "CISA Known Exploited Vulnerabilities Catalog (Embedded Fallback)",
    "catalogVersion": "2026.10",
    "count": 5,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal and Remote Code Execution",
            "dateAdded": "2021-11-03",
            "shortDescription": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-11-17",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Affects 2.4.49",
        },
        {
            "cveID": "CVE-2021-42013",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal and RCE (Incomplete Fix)",
            "dateAdded": "2021-11-03",
            "shortDescription": "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-11-17",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Affects 2.4.50",
        },
        {
            "cveID": "CVE-2024-21887",
            "vendorProject": "Ivanti",
            "product": "Connect Secure",
            "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
            "dateAdded": "2024-01-12",
            "shortDescription": "A command injection vulnerability in web components of Ivanti Connect Secure.",
            "requiredAction": "Apply mitigations per vendor advisory.",
            "dueDate": "2024-01-22",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Affects 9.x, 22.x",
        },
        {
            "cveID": "CVE-2023-38606",
            "vendorProject": "Apple",
            "product": "iOS and macOS",
            "vulnerabilityName": "Apple Multiple Products Memory Corruption Vulnerability",
            "dateAdded": "2023-07-25",
            "shortDescription": "Memory corruption vulnerability in Apple kernel.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2023-08-15",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
        {
            "cveID": "CVE-2023-3519",
            "vendorProject": "Citrix",
            "product": "NetScaler ADC and Gateway",
            "vulnerabilityName": "Citrix NetScaler ADC and Gateway RCE",
            "dateAdded": "2023-07-19",
            "shortDescription": "Unauthenticated remote code execution vulnerability in Citrix NetScaler.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2023-08-09",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
    ],
}

# Critical 0-day / high-severity advisories tracked prior to upstream CISA KEV catalog sync
CRITICAL_ADVISORY_RADAR: List[Dict[str, Any]] = [
    {
        "cveID": "CVE-2026-123007",
        "vendorProject": "NGINX",
        "product": "NGINX (nginx2root)",
        "vulnerabilityName": "NGINX HTTP/2 Integer Overflow to Heap R/W (nginx2root)",
        "dateAdded": "2026-11-19",
        "shortDescription": "Critical HTTP/2 integer overflow leading to heap read/write (CVSS 4.0 9.2, nginx2root).",
        "requiredAction": "Patch to nginx 1.30.7 or 1.31.9.",
        "dueDate": "2026-11-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Affects <1.30.7, 1.31.0-<1.31.9",
    },
    {
        "cveID": "CVE-2026-123633",
        "vendorProject": "NGINX",
        "product": "NGINX (nginx2root)",
        "vulnerabilityName": "NGINX HTTP/2 Use-After-Free (nginx2root)",
        "dateAdded": "2026-11-19",
        "shortDescription": "Critical HTTP/2 use-after-free vulnerability (CVSS 4.0 9.2, nginx2root).",
        "requiredAction": "Patch to nginx 1.30.7 or 1.31.9.",
        "dueDate": "2026-11-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Affects <1.30.7, 1.31.0-<1.31.9",
    },
    {
        "cveID": "CVE-2026-121810",
        "vendorProject": "NGINX",
        "product": "NGINX (nginx2root)",
        "vulnerabilityName": "NGINX HTTP/3 Use-After-Free (nginx2root)",
        "dateAdded": "2026-11-19",
        "shortDescription": "Critical HTTP/3 use-after-free vulnerability (CVSS 4.0 9.2, nginx2root).",
        "requiredAction": "Patch to nginx 1.30.7 or 1.31.9.",
        "dueDate": "2026-11-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Affects <1.30.7, 1.31.0-<1.31.9",
    },
    {
        "cveID": "CVE-2026-123634",
        "vendorProject": "NGINX",
        "product": "NGINX (nginx2root)",
        "vulnerabilityName": "NGINX Resolver + proxy_pass Use-After-Free (nginx2root)",
        "dateAdded": "2026-11-19",
        "shortDescription": "Critical resolver and proxy_pass use-after-free vulnerability (CVSS 4.0 9.2, nginx2root).",
        "requiredAction": "Patch to nginx 1.30.7 or 1.31.9.",
        "dueDate": "2026-11-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Affects <1.30.7, 1.31.0-<1.31.9",
    },
    {
        "cveID": "CVE-2026-113425",
        "vendorProject": "NGINX",
        "product": "NGINX (nginx2root)",
        "vulnerabilityName": "NGINX Mail Proxy Use-After-Free (nginx2root)",
        "dateAdded": "2026-11-19",
        "shortDescription": "Critical mail proxy use-after-free vulnerability (CVSS 4.0 9.2, nginx2root).",
        "requiredAction": "Patch to nginx 1.30.7 or 1.31.9.",
        "dueDate": "2026-11-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Affects <1.30.7, 1.31.0-<1.31.9",
    },
    {
        "cveID": "CVE-2026-121481",
        "vendorProject": "OpenSSL",
        "product": "OpenSSL",
        "vulnerabilityName": "OpenSSL EVP_EncodeBlock() Buffer Overflow Vulnerability",
        "dateAdded": "2026-11-20",
        "shortDescription": "Buffer overflow in OpenSSL EVP_EncodeBlock() (CVSS 9.8, openssl/openssl#33652).",
        "requiredAction": "Apply vendor OpenSSL security patch immediately.",
        "dueDate": "2026-11-27",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "OpenSSL EVP_EncodeBlock() buffer overflow (PR #33652)",
    },
]


@dataclass
class KevVulnerability:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: str
    notes: str = ""


# Regex to extract software name and numerical version (e.g. "Apache/2.4.49", "nginx/1.20.1", "PHP/8.1.0")
_BANNER_TOKEN_REGEX = re.compile(r"([a-zA-Z0-9_\-\.\+]+)(?:/([0-9]+(?:\.[0-9a-zA-Z_\-]+)*))?")


_RANGE_BOUND_REGEX = re.compile(r"(\d+(?:\.\d+)*)-<(\d+(?:\.\d+)*)")
_UPPER_BOUND_REGEX = re.compile(r"(?<![\d.\-])<(\d+(?:\.\d+)*)")


def _parse_semver(ver: str) -> Optional[Tuple[int, ...]]:
    """Extracts a comparable integer version tuple from a version string."""
    match = re.match(r"^(\d+(?:\.\d+)*)", (ver or "").strip())
    if not match:
        return None
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _normalize_vendor_product(raw_name: str, version: Optional[str]) -> Tuple[str, str, Optional[str]]:
    """Maps raw software banner token to canonical (vendor, product, version)."""
    name = raw_name.lower()
    if "apache" in name:
        return "apache", "http_server", version
    if "nginx" in name:
        return "nginx", "nginx", version
    if "openssl" in name:
        return "openssl", "openssl", version
    if "php" in name:
        return "php", "php", version
    if "iis" in name or "microsoft" in name:
        return "microsoft", "iis", version
    if "cloudflare" in name:
        return "cloudflare", "cloudflare", version
    if "ivanti" in name:
        return "ivanti", "connect_secure", version
    if "citrix" in name:
        return "citrix", "netscaler", version
    return name, name, version


def _iter_header_software_versions(header_value: str) -> List[Tuple[str, str, Optional[str]]]:
    """Extracts all (vendor, product, version) tokens from a composite banner header."""
    if not header_value or not isinstance(header_value, str):
        return []
    tokens: List[Tuple[str, str, Optional[str]]] = []
    for match in _BANNER_TOKEN_REGEX.finditer(header_value.strip()):
        raw_name = match.group(1)
        version = match.group(2) if match.group(2) else None
        tokens.append(_normalize_vendor_product(raw_name, version))
    return tokens


def parse_header_software_version(header_value: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extracts software vendor/product and numerical version from a banner string.
    
    Returns:
        (vendor, product, version_str) or (vendor, product, None) if no version is given.
    """
    tokens = _iter_header_software_versions(header_value)
    if not tokens:
        return None, None, None
    return tokens[0]


def _version_matches_advisory(ver: str, vuln: KevVulnerability) -> bool:
    """Checks exact version mentions and bounded `<X.Y.Z` / `A.B.C-<X.Y.Z` ranges in advisory metadata."""
    range_bounds = _RANGE_BOUND_REGEX.findall(vuln.notes or "")
    upper_bounds = _UPPER_BOUND_REGEX.findall(vuln.notes or "")

    if range_bounds or upper_bounds:
        parsed_ver = _parse_semver(ver)
        if parsed_ver is None:
            return False
        for lo_str, hi_str in range_bounds:
            lo = _parse_semver(lo_str)
            hi = _parse_semver(hi_str)
            if lo is not None and hi is not None and lo <= parsed_ver < hi:
                return True
        for hi_str in upper_bounds:
            hi = _parse_semver(hi_str)
            if hi is not None and parsed_ver < hi:
                return True
        return False

    v_desc = f"{vuln.short_description} {vuln.notes}".lower()
    return ver in v_desc or ver in vuln.notes


class CisaKevCatalog:
    """Manages CISA KEV ingestion, local caching, and perimeter threat correlation."""

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        offline_fixture: Optional[Dict[str, Any]] = None,
        auto_load: bool = True,
    ):
        self.cache_file = Path(cache_file or DEFAULT_CACHE_PATH)
        self.offline_fixture = offline_fixture
        self.catalog_data: Dict[str, Any] = {}
        self.vulnerabilities: Dict[str, KevVulnerability] = {}
        if auto_load:
            self.load_catalog()

    def is_cache_valid(self, ttl_seconds: float = 86400.0) -> bool:
        """Returns True if the local disk cache exists and was modified within the TTL window."""
        if not self.cache_file.exists():
            return False
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
            cache_ts = float(raw.get("timestamp", 0.0))
            return (time.time() - cache_ts) < ttl_seconds
        except Exception:
            return False

    def load_catalog(self, force_refresh: bool = False) -> int:
        """Loads vulnerabilities into memory from cache, live feed, or fallback fixture."""
        catalog_data = None

        # 1. Use explicit test fixture if supplied
        if self.offline_fixture:
            catalog_data = self.offline_fixture

        # 2. Use local valid disk cache if fresh and not forced
        elif not force_refresh and self.is_cache_valid():
            try:
                cached = json.loads(self.cache_file.read_text(encoding="utf-8"))
                catalog_data = cached.get("catalog")
            except Exception as ex:
                logger.debug(f"Failed to load KEV cache: {ex}")

        # 3. Attempt live HTTP pull if cache missing or expired
        if not catalog_data and not self.offline_fixture:
            try:
                req = urllib.request.Request(
                    CISA_KEV_URL,
                    headers={"User-Agent": "OrbitSecurity-KEVCorrelator/2.0"},
                )
                with urllib.request.urlopen(req, timeout=6.0) as resp:
                    if resp.status == 200:
                        raw_bytes = resp.read()
                        catalog_data = json.loads(raw_bytes.decode("utf-8"))
                        # Persist to disk cache
                        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                        cache_payload = {
                            "timestamp": time.time(),
                            "catalog": catalog_data,
                        }
                        self.cache_file.write_text(json.dumps(cache_payload), encoding="utf-8")
            except Exception as ex:
                logger.warning(f"CISA KEV live fetch bypassed/failed: {ex}; engaging offline fallback.")

        # 4. Fallback to bundled fixture if live and cache both unavailable
        if not catalog_data:
            catalog_data = BUILTIN_KEV_FALLBACK

        self.catalog_data = catalog_data

        # Parse catalog into structured dict
        self.vulnerabilities.clear()
        items = list(catalog_data.get("vulnerabilities", []))
        if not self.offline_fixture:
            existing_ids = {item.get("cveID") for item in items if item.get("cveID")}
            for adv in CRITICAL_ADVISORY_RADAR:
                if adv.get("cveID") not in existing_ids:
                    items.append(adv)

        for item in items:
            cve_id = item.get("cveID")
            if cve_id:
                vuln = KevVulnerability(
                    cve_id=cve_id,
                    vendor_project=item.get("vendorProject", ""),
                    product=item.get("product", ""),
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded", ""),
                    short_description=item.get("shortDescription", ""),
                    required_action=item.get("requiredAction", ""),
                    due_date=item.get("dueDate", ""),
                    known_ransomware_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                    notes=item.get("notes", ""),
                )
                self.vulnerabilities[cve_id] = vuln

        return len(self.vulnerabilities)

    def correlate_server_headers(
        self,
        headers: Dict[str, str],
        domain: Optional[str] = None,
        blackboard: Any = None,
    ) -> List[KevVulnerability]:
        """Cross-references HTTP server headers against weaponized KEV CVEs with strict version-bounding.
        
        CRITICAL GUARD: Bare headers (e.g. 'Server: Apache') NEVER trigger matches.
        A concrete version number is mandatory to assert an exploit match.
        """
        matches: List[KevVulnerability] = []
        seen_cves: set[str] = set()
        target_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

        for h_name, h_val in headers.items():
            if h_name.lower() not in target_headers:
                continue

            for vendor, product, ver in _iter_header_software_versions(h_val):
                # Guard: If no numerical version is exposed, do NOT match bare banners
                if not ver or not vendor:
                    continue

                for vuln in self.vulnerabilities.values():
                    if vuln.cve_id in seen_cves:
                        continue
                    v_vendor = vuln.vendor_project.lower()

                    # Vendor alignment + strict version-bounded check
                    if (vendor in v_vendor or v_vendor in vendor) and _version_matches_advisory(ver, vuln):
                        seen_cves.add(vuln.cve_id)
                        matches.append(vuln)

                        # Publish to Blackboard SQLite WAL if blackboard is connected
                        if blackboard:
                            try:
                                blackboard.publish(
                                    event_type="CISA_KEV_MATCH_DETECTED",
                                    payload={
                                        "cve_id": vuln.cve_id,
                                        "product": vuln.product,
                                        "vendor": vuln.vendor_project,
                                        "matched_header": f"{h_name}: {h_val}",
                                        "ransomware_flag": vuln.known_ransomware_use,
                                        "action_required": vuln.required_action,
                                        "due_date": vuln.due_date,
                                        "domain": domain or "unknown",
                                    },
                                    source="cisa_kev_correlator",
                                    topic="cve_radar",
                                )
                            except Exception as ex:
                                logger.debug(f"Failed to publish KEV blackboard event: {ex}")

        return matches
