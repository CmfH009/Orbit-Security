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


def parse_header_software_version(header_value: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extracts software vendor/product and numerical version from a banner string.
    
    Returns:
        (vendor, product, version_str) or (vendor, product, None) if no version is given.
    """
    if not header_value or not isinstance(header_value, str):
        return None, None, None

    clean = header_value.strip()
    match = _BANNER_TOKEN_REGEX.search(clean)
    if not match:
        return None, None, None

    raw_name = match.group(1).lower()
    version = match.group(2) if match.group(2) else None

    # Normalization mapping for common web software
    if "apache" in raw_name:
        return "apache", "http_server", version
    elif "nginx" in raw_name:
        return "nginx", "nginx", version
    elif "php" in raw_name:
        return "php", "php", version
    elif "iis" in raw_name or "microsoft" in raw_name:
        return "microsoft", "iis", version
    elif "cloudflare" in raw_name:
        return "cloudflare", "cloudflare", version
    elif "ivanti" in raw_name:
        return "ivanti", "connect_secure", version
    elif "citrix" in raw_name:
        return "citrix", "netscaler", version

    return raw_name, raw_name, version


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

        # Parse catalog into structured dict
        self.vulnerabilities.clear()
        for item in catalog_data.get("vulnerabilities", []):
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
        target_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

        for h_name, h_val in headers.items():
            if h_name.lower() not in target_headers:
                continue

            vendor, product, ver = parse_header_software_version(h_val)
            # Guard: If no numerical version is exposed, do NOT match bare banners
            if not ver or not vendor:
                continue

            for vuln in self.vulnerabilities.values():
                v_vendor = vuln.vendor_project.lower()
                v_desc = (vuln.short_description + " " + vuln.notes).lower()

                # Vendor alignment
                if vendor in v_vendor or v_vendor in vendor:
                    # Version-bounded check: does the vulnerability description specifically target this version?
                    if ver in v_desc or f"{ver}" in vuln.notes:
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
