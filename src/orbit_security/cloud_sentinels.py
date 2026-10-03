"""Orbit Security: Cloud Perimeter & Misconfiguration Sentinels (cloud_sentinels.py).

Provides Phase B detection capabilities:
1. CloudBucketTakeoverSentinel: Identifies dangling AWS S3, Google Cloud Storage, and Azure Blob storage buckets.
2. GraphQLIntrospectionSentinel: Detects exposed production GraphQL schema introspection.
3. CorsMisconfigurationSentinel: Audits permissive and dangerous Cross-Origin Resource Sharing (CORS) reflections.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from orbit_security.models import Severity
from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.cloud_sentinels")


class CloudBucketTakeoverSentinel:
    """Detects dangling, unallocated cloud storage buckets referenced by DNS CNAME or endpoints."""

    BUCKET_CNAME_PATTERNS = {
        "AWS S3": [
            r"s3\.amazonaws\.com",
            r"s3-website[.-]",
            r"\.s3\.[a-z0-9-]+\.amazonaws\.com",
            r"\.s3\.amazonaws\.com",
        ],
        "Google Cloud Storage": [
            r"storage\.googleapis\.com",
            r"c\.storage\.googleapis\.com",
        ],
        "Azure Blob Storage": [
            r"blob\.core\.windows\.net",
            r"web\.core\.windows\.net",
        ],
        "DigitalOcean Spaces": [
            r"digitaloceanspaces\.com",
        ],
    }

    TAKEOVER_FINGERPRINTS = {
        "AWS S3": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "<Code>NoSuchBucket</Code>",
        ],
        "Google Cloud Storage": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "Azure Blob Storage": [
            "BlobNotFound",
            "The specified blob does not exist",
            "ServerNotFound",
            "ContainerNotFound",
            "The specified account does not exist",
        ],
        "DigitalOcean Spaces": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
    }

    OPEN_LISTING_FINGERPRINTS = [
        "<ListBucketResult",
        "<ListAllMyBucketsResult",
    ]

    @classmethod
    def identify_provider_from_cname(cls, cname: str) -> Optional[str]:
        """Matches a CNAME target against known cloud storage providers."""
        if not cname:
            return None
        cname_lower = cname.lower().strip().rstrip(".")
        for provider, patterns in cls.BUCKET_CNAME_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, cname_lower):
                    return provider
        return None

    @classmethod
    def probe_http_body(cls, domain_or_url: str, timeout: float = 3.5) -> Tuple[int, str]:
        """Fetches HTTP response status and body safely with SSRF protections."""
        url = domain_or_url if domain_or_url.startswith(("http://", "https://")) else f"https://{domain_or_url}"
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]

        if not is_safe_host(host):
            return (0, "")

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        for scheme in ("https", "http"):
            target = f"{scheme}://{host}"
            try:
                req = urllib.request.Request(target, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = getattr(resp, "status", getattr(resp, "code", 200))
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                    return (status, body)
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(4096).decode("utf-8", errors="ignore")
                    return (e.code, body)
                except Exception:
                    return (e.code, "")
            except Exception:
                continue

        return (0, "")

    @classmethod
    def audit_target(
        cls,
        target_domain: str,
        cname_target: Optional[str] = None,
        mock_body: Optional[str] = None,
        mock_status: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits target for orphaned cloud storage bucket takeover or public listing."""
        provider = cls.identify_provider_from_cname(cname_target or "")
        body = mock_body
        status = mock_status

        if body is None:
            status, body = cls.probe_http_body(target_domain)

        if not body:
            return None

        # Check for Open Public Bucket Listing (Data Exposure)
        for open_fp in cls.OPEN_LISTING_FINGERPRINTS:
            if open_fp.lower() in body.lower():
                return {
                    "vulnerable": True,
                    "flaw_type": "open_cloud_bucket",
                    "provider": provider or "Cloud Storage",
                    "cname_target": cname_target,
                    "target_domain": target_domain,
                    "severity": Severity.HIGH,
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-284: Improper Access Control",
                    "evidence": f"Public cloud storage bucket listing is exposed on '{target_domain}'. Signature match: '{open_fp}'.",
                    "remediation": "Disable public READ permissions on the cloud storage bucket and remove 'AllUsers' / 'AllAuthenticatedUsers' ACL grants.",
                    "bounty_viability": "HIGH_CONFIDENCE",
                }

        # Check for Orphaned / Dangling Bucket Takeover
        providers_to_check = [provider] if provider else list(cls.TAKEOVER_FINGERPRINTS.keys())
        for prov in providers_to_check:
            fps = cls.TAKEOVER_FINGERPRINTS.get(prov, [])
            for fp in fps:
                if fp.lower() in body.lower():
                    cname_str = f" pointing to '{cname_target}'" if cname_target else ""
                    evidence = (
                        f"Dangling {prov} storage bucket detected on '{target_domain}'{cname_str}. "
                        f"Response body matches unallocated bucket signature: '{fp}'."
                    )
                    remediation = (
                        f"Either create/claim the matching {prov} bucket name in your cloud account to prevent third-party "
                        "registration, or remove the dangling DNS CNAME record."
                    )
                    return {
                        "vulnerable": True,
                        "flaw_type": "cloud_storage_takeover",
                        "provider": prov,
                        "cname_target": cname_target,
                        "target_domain": target_domain,
                        "severity": Severity.HIGH,
                        "cvss_score": 8.6,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N",
                        "cwe_id": "CWE-284: Improper Access Control",
                        "evidence": evidence,
                        "remediation": remediation,
                        "bounty_viability": "HIGH_CONFIDENCE",
                    }

        return None


class GraphQLIntrospectionSentinel:
    """Audits targets for publicly accessible GraphQL schema introspection endpoints."""

    COMMON_GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/__graphql",
        "/console/graphql",
        "/query",
    ]

    INTROSPECTION_QUERY = json.dumps({"query": "{ __schema { queryType { name } } }"}).encode("utf-8")

    @classmethod
    def audit_target(
        cls,
        target_domain: str,
        timeout: float = 3.5,
        mock_paths: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Probes common GraphQL endpoints for active schema introspection."""
        host = target_domain.split(":")[0].strip().lower()
        if not is_safe_host(host):
            return None

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Handle Mocked Paths for deterministic testing
        if mock_paths is not None:
            for path, resp_dict in mock_paths.items():
                data = resp_dict.get("data", {})
                if isinstance(data, dict) and "__schema" in data:
                    return cls._build_vulnerability(target_domain, path, data)
            return None

        # Live Probing
        for path in cls.COMMON_GRAPHQL_PATHS:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, data=cls.INTROSPECTION_QUERY, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if getattr(resp, "status", getattr(resp, "code", 0)) == 200:
                        raw = resp.read().decode("utf-8", errors="ignore")
                        data_json = json.loads(raw)
                        data_obj = data_json.get("data")
                        if isinstance(data_obj, dict) and "__schema" in data_obj:
                            return cls._build_vulnerability(target_domain, path, data_obj)
            except Exception:
                continue

        return None

    @classmethod
    def _build_vulnerability(cls, target_domain: str, path: str, schema_data: Dict[str, Any]) -> Dict[str, Any]:
        query_type = schema_data.get("__schema", {}).get("queryType", {}).get("name", "Query")
        evidence = (
            f"Production GraphQL schema introspection is enabled at 'https://{target_domain}{path}'. "
            f"Root Query type '{query_type}' and full schema definition retrieved via public POST request."
        )
        remediation = (
            "Disable schema introspection in production deployments. For Apollo Server, set `introspection: false`. "
            "For GraphQL Yoga or Envelop, enable the `useDisableIntrospection()` plugin for unauthenticated requests."
        )
        return {
            "vulnerable": True,
            "flaw_type": "graphql_introspection",
            "provider": "GraphQL",
            "target_domain": target_domain,
            "endpoint_path": path,
            "severity": Severity.MEDIUM,
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            "evidence": evidence,
            "remediation": remediation,
            "bounty_viability": "HIGH_CONFIDENCE",
        }


class CorsMisconfigurationSentinel:
    """Audits HTTP APIs for arbitrary origin reflection and credential exposure."""

    TEST_ORIGIN = "https://untrusted-adversary.com"
    NULL_ORIGIN = "null"

    @classmethod
    def probe_cors_headers(
        cls, url: str, origin: str, timeout: float = 3.5
    ) -> Dict[str, str]:
        """Sends an OPTIONS / GET request with an arbitrary Origin header and records CORS responses."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]
        if not is_safe_host(host):
            return {}

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0",
            "Origin": origin,
        }
        res_headers: Dict[str, str] = {}

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                for k, v in resp.headers.items():
                    res_headers[k.lower()] = v
        except urllib.error.HTTPError as e:
            for k, v in e.headers.items():
                res_headers[k.lower()] = v
        except Exception:
            pass

        return res_headers

    @classmethod
    def audit_target(
        cls,
        target_domain: str,
        timeout: float = 3.5,
        mock_responses: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Audits domain for arbitrary CORS reflection with credentials."""
        host = target_domain.split(":")[0].strip().lower()
        if not is_safe_host(host):
            return None

        url = f"https://{host}"

        # 1. Test Arbitrary Untrusted Origin Reflection
        if mock_responses and cls.TEST_ORIGIN in mock_responses:
            headers_origin = mock_responses[cls.TEST_ORIGIN]
        else:
            headers_origin = cls.probe_cors_headers(url, cls.TEST_ORIGIN, timeout=timeout)

        acao_origin = headers_origin.get("access-control-allow-origin", "").strip()
        acac_origin = headers_origin.get("access-control-allow-credentials", "").strip().lower()

        if acao_origin == cls.TEST_ORIGIN and acac_origin == "true":
            evidence = (
                f"Vulnerable CORS policy on '{target_domain}': Server blindly reflects untrusted Origin '{cls.TEST_ORIGIN}' "
                "in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true. "
                "Any third-party website can forge cross-origin requests with user session cookies and read responses."
            )
            remediation = (
                "Do not dynamically reflect untrusted Origin header values. Validate incoming Origin headers against an explicit, "
                "strict server-side whitelist before echoing in Access-Control-Allow-Origin. Never enable Access-Control-Allow-Credentials "
                "for untrusted or dynamic origins."
            )
            return {
                "vulnerable": True,
                "flaw_type": "cors_arbitrary_origin_with_credentials",
                "provider": "API Gateway CORS",
                "target_domain": target_domain,
                "severity": Severity.HIGH,
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "cwe_id": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
                "evidence": evidence,
                "remediation": remediation,
                "bounty_viability": "HIGH_CONFIDENCE",
            }

        # 2. Test Null Origin Trust
        if mock_responses and cls.NULL_ORIGIN in mock_responses:
            headers_null = mock_responses[cls.NULL_ORIGIN]
        else:
            headers_null = cls.probe_cors_headers(url, cls.NULL_ORIGIN, timeout=timeout)

        acao_null = headers_null.get("access-control-allow-origin", "").strip()
        acac_null = headers_null.get("access-control-allow-credentials", "").strip().lower()

        if acao_null == "null" and acac_null == "true":
            evidence = (
                f"Dangerous CORS policy on '{target_domain}': Server explicitly trusts Origin 'null' "
                "with Access-Control-Allow-Credentials set to true. "
                "Sandboxed iframes (e.g. <iframe sandbox='allow-scripts'>) and local file contexts send Origin: null, "
                "allowing attackers to bypass same-origin protections."
            )
            remediation = (
                "Remove 'null' from trusted origin lists. 'null' origins can be easily generated by sandboxed iframes and "
                "attacker-controlled data URI contexts."
            )
            return {
                "vulnerable": True,
                "flaw_type": "cors_null_origin_with_credentials",
                "provider": "API Gateway CORS",
                "target_domain": target_domain,
                "severity": Severity.HIGH,
                "cvss_score": 7.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                "cwe_id": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
                "evidence": evidence,
                "remediation": remediation,
                "bounty_viability": "HIGH_CONFIDENCE",
            }

        # 3. Informational Wildcard with sensitive header
        if acao_origin == "*":
            return {
                "vulnerable": True,
                "flaw_type": "cors_wildcard_origin",
                "provider": "API Gateway CORS",
                "target_domain": target_domain,
                "severity": Severity.LOW,
                "cvss_score": 3.7,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe_id": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
                "evidence": f"Domain '{target_domain}' publishes wildcard Access-Control-Allow-Origin: * on endpoint.",
                "remediation": "Restrict Access-Control-Allow-Origin to authorized domain list if this endpoint handles authenticated user data.",
                "bounty_viability": "INFORMATIONAL_LOW",
            }

        return None
