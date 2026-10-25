"""orbit_security.cert_transparency: Certificate Transparency (CT) Log Sentinel.
=============================================================================
Passively monitors public Certificate Transparency log streams (e.g. crt.sh)
for newly minted SSL/TLS certificates and uncataloged subdomains across target assets.

Features:
- Passive discovery without active port scanning or DNS brute-forcing.
- 24-hour TTL disk cache (data/ct_cache.json) to respect upstream rate limits.
- Built-in offline fixture fallback for airgapped environments and testing.
- Subdomain extraction, wildcard normalization, and anomaly filtering.
- Standardized SQLite WAL Blackboard event publishing (CT_LOG_CERTIFICATE_DISCOVERED,
  CT_LOG_NEW_SUBDOMAIN).
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("orbit_security.cert_transparency")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CT_CACHE_PATH = REPO_ROOT / "data" / "ct_cache.json"
CRTSH_BASE_URL = "https://crt.sh/?q=%.{domain}&output=json"

BUILTIN_CT_FALLBACK: Dict[str, List[Dict[str, Any]]] = {
    "example.com": [
        {
            "id": 10001,
            "logged_at": "2026-10-20T08:00:00",
            "not_before": "2026-10-20T00:00:00",
            "not_after": "2027-01-18T23:59:59",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com\nstaging.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "serial_number": "03a1b2c3d4e5f67890",
        },
        {
            "id": 10002,
            "logged_at": "2026-10-22T14:30:00",
            "not_before": "2026-10-22T00:00:00",
            "not_after": "2027-01-20T23:59:59",
            "common_name": "*.assets.example.com",
            "name_value": "*.assets.example.com\nassets.example.com",
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global G2",
            "serial_number": "04b2c3d4e5f6789012",
        },
    ]
}


@dataclass
class CertificateEntry:
    cert_id: int
    common_name: str
    issuer: str
    logged_at: str
    not_before: str
    not_after: str
    san_domains: List[str]
    serial_number: str = ""


class CertificateTransparencyMonitor:
    """Monitors CT log feeds and correlates new perimeter subdomains."""

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        offline_fixtures: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ):
        self.cache_file = Path(cache_file or DEFAULT_CT_CACHE_PATH)
        self.offline_fixtures = offline_fixtures or BUILTIN_CT_FALLBACK
        self.known_subdomains: Dict[str, Set[str]] = {}

    def is_cache_valid(self, domain: str, ttl_seconds: float = 86400.0) -> bool:
        """Checks if cached CT query for domain is fresh."""
        if not self.cache_file.exists():
            return False
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            domain_cache = data.get(domain.lower(), {})
            ts = float(domain_cache.get("timestamp", 0.0))
            return (time.time() - ts) < ttl_seconds
        except Exception:
            return False

    def load_from_cache(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        """Loads cached CT query results for domain."""
        if not self.cache_file.exists():
            return None
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            domain_cache = data.get(domain.lower(), {})
            return domain_cache.get("records")
        except Exception:
            return None

    def save_to_cache(self, domain: str, records: List[Dict[str, Any]]):
        """Saves CT query results for domain to disk cache."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            existing = {}
            if self.cache_file.exists():
                try:
                    existing = json.loads(self.cache_file.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}

            existing[domain.lower()] = {
                "timestamp": time.time(),
                "records": records,
            }
            self.cache_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        except Exception as ex:
            logger.debug(f"Failed to save CT cache: {ex}")

    def fetch_certificates(
        self,
        domain: str,
        force_refresh: bool = False,
    ) -> List[CertificateEntry]:
        """Fetches certificates for domain from cache, live API, or fallback fixture."""
        clean_domain = domain.strip().lower()
        records: Optional[List[Dict[str, Any]]] = None

        # 1. Use explicit test fixture if defined
        if clean_domain in self.offline_fixtures:
            records = self.offline_fixtures[clean_domain]

        # 2. Use disk cache if fresh
        elif not force_refresh and self.is_cache_valid(clean_domain):
            records = self.load_from_cache(clean_domain)

        # 3. Live network pull if no cache or fixture
        if records is None:
            domain_regex = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
            if not domain_regex.match(clean_domain):
                logger.warning(f"Invalid domain rejected for CT scan: {clean_domain}")
                records = []
            else:
                encoded_domain = urllib.parse.quote(clean_domain)
                url = f"https://crt.sh/?q=%.{encoded_domain}&output=json"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "OrbitSecurity-CTMonitor/1.0", "Accept": "application/json"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=6.0) as resp:
                        if resp.status == 200:
                            records = json.loads(resp.read().decode("utf-8"))
                            self.save_to_cache(clean_domain, records)
                except Exception as ex:
                    logger.warning(f"Live CT pull failed for {clean_domain}: {ex}; checking fallback")

        # 4. Fallback if network failed
        if records is None:
            records = self.offline_fixtures.get(clean_domain, [])

        results: List[CertificateEntry] = []
        for r in records:
            name_val = r.get("name_value", "")
            cn = str(r.get("common_name", "")).strip()
            # Split SANs by whitespace or newline
            sans: List[str] = []
            candidates = list(re.split(r"[\s\r\n]+", name_val))
            if cn:
                candidates.append(cn)

            for item in candidates:
                clean_item = item.strip().lower()
                if clean_item.startswith("*."):
                    clean_item = clean_item[2:]
                elif clean_item.startswith("."):
                    clean_item = clean_item.lstrip(".")

                # Strict boundary check: must be the apex domain or end with dot-apex
                if clean_item and (clean_item == clean_domain or clean_item.endswith(f".{clean_domain}")):
                    if clean_item not in sans:
                        sans.append(clean_item)

            entry = CertificateEntry(
                cert_id=int(r.get("id") or 0),
                common_name=str(r.get("common_name", "")),
                issuer=str(r.get("issuer_name", "")),
                logged_at=str(r.get("entry_timestamp", r.get("logged_at", ""))),
                not_before=str(r.get("not_before", "")),
                not_after=str(r.get("not_after", "")),
                san_domains=sans,
                serial_number=str(r.get("serial_number", "")),
            )
            results.append(entry)

        return results

    def discover_subdomains(
        self,
        domain: str,
        known_baselines: Optional[Set[str]] = None,
        blackboard: Any = None,
    ) -> Dict[str, Any]:
        """Extracts unique subdomains and publishes newly discovered perimeter assets to Blackboard."""
        clean_domain = domain.strip().lower()
        certs = self.fetch_certificates(clean_domain)

        all_subdomains: Set[str] = set()
        for cert in certs:
            for san in cert.san_domains:
                all_subdomains.add(san)

        baseline = set(known_baselines or self.known_subdomains.get(clean_domain, set()))
        new_discoveries = sorted(list(all_subdomains - baseline))

        # Update known state
        if clean_domain not in self.known_subdomains:
            self.known_subdomains[clean_domain] = set()
        self.known_subdomains[clean_domain].update(all_subdomains)

        # Publish events to SQLite WAL Blackboard if connected
        if blackboard and new_discoveries:
            for sub in new_discoveries:
                try:
                    blackboard.publish(
                        event_type="CT_LOG_NEW_SUBDOMAIN",
                        payload={
                            "subdomain": sub,
                            "apex_domain": clean_domain,
                            "source_feed": "certificate_transparency",
                            "discovered_at": time.time(),
                        },
                        source="cert_transparency_monitor",
                        topic="threat_intel",
                    )
                except Exception as ex:
                    logger.debug(f"Failed to publish CT subdomain event: {ex}")

        return {
            "domain": clean_domain,
            "total_certificates": len(certs),
            "total_subdomains": len(all_subdomains),
            "new_subdomains": new_discoveries,
            "subdomains": sorted(list(all_subdomains)),
        }
