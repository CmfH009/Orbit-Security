"""Orbit Security: Passive Reconnaissance & Archive Harvester (recon_harvester.py).

Provides Phase A chained reconnaissance capabilities:
1. CertificateTransparencyStreamer: Multi-source CT log retrieval (crt.sh) and live TLS SAN socket parsing.
2. ArchiveHarvester: Historical asset discovery via Wayback Machine CDX and AlienVault OTX passive DNS.
3. JsRouteExtractor: Static JavaScript bundle analysis for internal API routes, cloud storage buckets, and subdomains.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.recon_harvester")


class CertificateTransparencyStreamer:
    """Passively harvests subdomains from public Certificate Transparency logs and TLS SAN certificates."""

    @staticmethod
    def normalize_host(host: str) -> Optional[str]:
        """Normalizes a hostname or wildcard pattern."""
        h = (host or "").strip().lower().lstrip("*.")
        h = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
        if not h or " " in h or "." not in h:
            return None
        if re.fullmatch(r"[\d.]+", h):
            return None
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", h):
            return None
        return h

    @staticmethod
    def fetch_crtsh(apex_domain: str, timeout: float = 4.0, max_results: int = 100) -> List[str]:
        """Queries crt.sh JSON API for known subdomains belonging to apex_domain."""
        clean_apex = (apex_domain or "").strip().lower().lstrip("*.")
        if not clean_apex:
            return []

        url = f"https://crt.sh/?q=%.{clean_apex}&output=json"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        found: Set[str] = set()

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", None))
                if status == 200:
                    entries = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            clean = CertificateTransparencyStreamer.normalize_host(line)
                            if clean and clean.endswith("." + clean_apex):
                                found.add(clean)
                                if len(found) >= max_results:
                                    break
                        if len(found) >= max_results:
                            break
        except Exception as e:
            logger.debug("crt.sh lookup skipped for %s: %s", clean_apex, e)

        return sorted(list(found))

    @staticmethod
    def probe_tls_sans(host: str, port: int = 443, timeout: float = 3.0) -> List[str]:
        """Connects via TLS SNI handshake and extracts Subject Alternative Names (SANs) from peer certificate."""
        clean_host = (host or "").strip().lower()
        if not clean_host or not is_safe_host(clean_host):
            return []

        sans: Set[str] = set()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((clean_host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert and "subjectAltName" in cert:
                        for entry in cert["subjectAltName"]:
                            if entry[0] == "DNS":
                                normalized = CertificateTransparencyStreamer.normalize_host(entry[1])
                                if normalized:
                                    sans.add(normalized)
        except Exception as e:
            logger.debug("TLS SAN probe skipped for %s:%d: %s", clean_host, port, e)

        return sorted(list(sans))

    @classmethod
    def discover_subdomains(
        cls,
        apex_domain: str,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        probe_tls: bool = True,
        max_results: int = 100,
    ) -> List[str]:
        """Orchestrates CT log queries and TLS SAN harvesting with in-scope/out-of-scope filtering."""
        clean_apex = (apex_domain or "").strip().lower().lstrip("*.")
        discovered: Set[str] = set(cls.fetch_crtsh(clean_apex, max_results=max_results))

        if probe_tls and is_safe_host(clean_apex):
            sans = cls.probe_tls_sans(clean_apex)
            for s in sans:
                if s.endswith("." + clean_apex):
                    discovered.add(s)

        out_set: Set[str] = set(s.strip().lower() for s in (out_of_scope or []))

        def is_excluded(target: str) -> bool:
            if target in out_set:
                return True
            for pat in out_set:
                if pat.startswith("*."):
                    suffix = pat[2:]
                    if target == suffix or target.endswith("." + suffix):
                        return True
            return False

        filtered: List[str] = []
        for candidate in sorted(discovered):
            if is_excluded(candidate):
                continue
            if in_scope:
                matches_scope = False
                for s in in_scope:
                    clean_s = s.strip().lower()
                    if clean_s.startswith("*."):
                        apex = clean_s[2:]
                        if candidate == apex or candidate.endswith("." + apex):
                            matches_scope = True
                            break
                    elif candidate == clean_s:
                        matches_scope = True
                        break
                if not matches_scope:
                    continue
            filtered.append(candidate)
            if len(filtered) >= max_results:
                break

        return filtered


class ArchiveHarvester:
    """Mines historical URL archives (Wayback Machine CDX & AlienVault OTX) for legacy perimeter assets."""

    @staticmethod
    def query_wayback_cdx(apex_domain: str, timeout: float = 5.0, max_results: int = 100) -> List[str]:
        """Queries the Wayback Machine CDX API for historical subdomains."""
        clean_apex = (apex_domain or "").strip().lower().lstrip("*.")
        if not clean_apex:
            return []

        url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_apex}/*&output=json&fl=original&collapse=urlkey&limit={max_results}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        found_subs: Set[str] = set()

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", None)) == 200:
                    raw_data = resp.read().decode("utf-8", errors="ignore")
                    rows = json.loads(raw_data)
                    for row in rows:
                        if isinstance(row, list) and row:
                            target_url = str(row[0])
                            parsed = urllib.parse.urlparse(target_url)
                            host = CertificateTransparencyStreamer.normalize_host(parsed.netloc or parsed.path)
                            if host and host.endswith("." + clean_apex):
                                found_subs.add(host)
                                if len(found_subs) >= max_results:
                                    break
        except Exception as e:
            logger.debug("Wayback CDX lookup skipped for %s: %s", clean_apex, e)

        return sorted(list(found_subs))

    @staticmethod
    def query_alienvault_otx(apex_domain: str, timeout: float = 5.0, max_results: int = 100) -> List[str]:
        """Queries AlienVault OTX passive DNS indicators for domain subdomains."""
        clean_apex = (apex_domain or "").strip().lower().lstrip("*.")
        if not clean_apex:
            return []

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_apex}/passive_dns"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        found_subs: Set[str] = set()

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", None)) == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        clean = CertificateTransparencyStreamer.normalize_host(hostname)
                        if clean and clean.endswith("." + clean_apex):
                            found_subs.add(clean)
                            if len(found_subs) >= max_results:
                                break
        except Exception as e:
            logger.debug("AlienVault OTX lookup skipped for %s: %s", clean_apex, e)

        return sorted(list(found_subs))

    @classmethod
    def harvest_historical_assets(
        cls, apex_domain: str, max_results: int = 100
    ) -> Dict[str, Any]:
        """Aggregates historical subdomains from Wayback Machine CDX and AlienVault OTX."""
        wayback = cls.query_wayback_cdx(apex_domain, max_results=max_results)
        otx = cls.query_alienvault_otx(apex_domain, max_results=max_results)

        combined = sorted(list(set(wayback + otx)))
        return {
            "apex_domain": apex_domain,
            "total_historical_subdomains": len(combined),
            "sources": {
                "wayback_count": len(wayback),
                "otx_count": len(otx),
            },
            "subdomains": combined[:max_results],
        }


class JsRouteExtractor:
    """Parses static JavaScript files for internal API routes, cloud buckets, and hidden subdomains."""

    CLOUD_STORAGE_PATTERNS = [
        re.compile(r"https?://([a-zA-Z0-9_\-\.]+?\.s3(?:[\.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com)", re.IGNORECASE),
        re.compile(r"https?://([a-zA-Z0-9_\-\.]+?\.storage\.googleapis\.com)", re.IGNORECASE),
        re.compile(r"https?://([a-zA-Z0-9_\-\.]+?\.blob\.core\.windows\.net)", re.IGNORECASE),
        re.compile(r"https?://([a-zA-Z0-9_\-\.]+?\.digitaloceanspaces\.com)", re.IGNORECASE),
    ]

    API_ROUTE_PATTERN = re.compile(
        r"['\"](/(?:api|v[0-9]|graphql|auth|internal|rest|admin)/[a-zA-Z0-9_\-\./]+)['\"]"
    )

    ENV_KEY_PATTERN = re.compile(
        r"['\"]?([A-Z0-9_]*(?:API_KEY|AUTH_TOKEN|SECRET|CLIENT_ID|FIREBASE|ACCESS_KEY)[A-Z0-9_]*)['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
    )

    @staticmethod
    def extract_script_urls(html_content: str, base_url: str) -> List[str]:
        """Extracts and normalizes script src URLs from HTML content."""
        if not html_content:
            return []

        script_srcs: List[str] = []
        matches = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html_content, re.IGNORECASE)
        for m in matches:
            resolved = urllib.parse.urljoin(base_url, m.strip())
            script_srcs.append(resolved)

        return script_srcs

    @classmethod
    def extract_endpoints_and_assets(cls, js_content: str, target_domain: str) -> Dict[str, Any]:
        """Analyzes JavaScript source string and extracts API routes, cloud storage, and internal subdomains."""
        if not js_content:
            return {"api_routes": [], "cloud_storage": [], "internal_subdomains": [], "potential_env_keys": []}

        clean_target = (target_domain or "").strip().lower().lstrip("*.")

        # 1. API routes
        routes = sorted(list(set(cls.API_ROUTE_PATTERN.findall(js_content))))

        # 2. Cloud storage buckets
        cloud_assets: Set[str] = set()
        for pat in cls.CLOUD_STORAGE_PATTERNS:
            for match in pat.findall(js_content):
                cloud_assets.add(match)

        # 3. Discovered internal subdomains
        subdomain_pat = re.compile(r"(?:https?://)?([a-zA-Z0-9_\-\.]+\." + re.escape(clean_target) + r")", re.IGNORECASE)
        discovered_subs: Set[str] = set()
        for sub in subdomain_pat.findall(js_content):
            clean = CertificateTransparencyStreamer.normalize_host(sub)
            if clean and clean.endswith("." + clean_target):
                discovered_subs.add(clean)

        # 4. Environment keys
        env_keys: List[Dict[str, str]] = []
        for key, val in cls.ENV_KEY_PATTERN.findall(js_content)[:10]:
            env_keys.append({"key": key, "masked_val": val[:4] + "..." + val[-2:] if len(val) > 6 else "***"})

        return {
            "api_routes": routes[:50],
            "cloud_storage": sorted(list(cloud_assets)),
            "internal_subdomains": sorted(list(discovered_subs)),
            "potential_env_keys": env_keys,
        }

    @classmethod
    def analyze_target_scripts(
        cls, target_url: str, timeout: float = 5.0, max_scripts: int = 5
    ) -> Dict[str, Any]:
        """Fetches page HTML, downloads referenced scripts, and aggregates extracted endpoints."""
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.netloc.split(":")[0]
        if not is_safe_host(host):
            return {"error": "Target host blocked by SSRF filter", "url": target_url}

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        all_routes: Set[str] = set()
        all_cloud: Set[str] = set()
        all_subs: Set[str] = set()
        all_keys: List[Dict[str, str]] = []

        try:
            req = urllib.request.Request(target_url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                script_urls = cls.extract_script_urls(html, target_url)

                for s_url in script_urls[:max_scripts]:
                    s_parsed = urllib.parse.urlparse(s_url)
                    s_host = s_parsed.netloc.split(":")[0]
                    if not is_safe_host(s_host):
                        continue

                    try:
                        s_req = urllib.request.Request(s_url, headers=headers)
                        with urllib.request.urlopen(s_req, timeout=timeout) as s_resp:
                            js_text = s_resp.read().decode("utf-8", errors="ignore")
                            res = cls.extract_endpoints_and_assets(js_text, host)
                            all_routes.update(res["api_routes"])
                            all_cloud.update(res["cloud_storage"])
                            all_subs.update(res["internal_subdomains"])
                            all_keys.extend(res["potential_env_keys"])
                    except Exception:
                        continue
        except Exception as e:
            return {"error": str(e), "url": target_url}

        return {
            "target_url": target_url,
            "api_routes": sorted(list(all_routes)),
            "cloud_storage": sorted(list(all_cloud)),
            "internal_subdomains": sorted(list(all_subs)),
            "potential_env_keys": all_keys[:10],
        }
