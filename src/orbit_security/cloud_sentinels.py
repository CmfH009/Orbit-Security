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

    @classmethod
    def sweep_cloud_fleet(
        cls,
        targets: List[Dict[str, Any]],
        blackboard: Any = None,
    ) -> Dict[str, Any]:
        """Autonomous Dangling Cloud Resource Sweeper across a multi-domain fleet (Project #11)."""
        findings: List[Dict[str, Any]] = []
        for item in targets or []:
            domain = str(item.get("domain", "") or "").strip()
            if not domain:
                continue
            cname_target = item.get("cname_target")
            mock_body = item.get("mock_body")
            mock_status = item.get("mock_status")
            res = cls.audit_target(
                target_domain=domain,
                cname_target=cname_target,
                mock_body=mock_body,
                mock_status=mock_status,
            )
            if res and res.get("vulnerable"):
                findings.append(res)
                if blackboard is not None:
                    try:
                        blackboard.publish(
                            event_type="DANGLING_CLOUD_RESOURCE_DETECTED",
                            payload={
                                "domain": domain,
                                "provider": res.get("provider"),
                                "cname_target": cname_target,
                                "flaw_type": res.get("flaw_type"),
                                "severity": str(getattr(res.get("severity"), "value", res.get("severity"))),
                                "evidence": res.get("evidence"),
                            },
                            source="cloud_resource_sweeper",
                            topic="perimeter",
                        )
                    except Exception as exc:
                        logger.debug(f"Blackboard publish error in sweep_cloud_fleet: {exc}")

        return {
            "total_swept": len(targets or []),
            "vulnerable_count": len(findings),
            "findings": findings,
        }


class PassiveTlsCipherSentinel:
    """Passive TLS / SSL Cipher Suite & Expiry Sentinel (Project #15)."""

    DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
    WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")

    @classmethod
    def _hostname_matches_san(cls, domain: str, san_domains: List[str]) -> bool:
        clean_dom = (domain or "").strip().lower()
        for san in san_domains or []:
            s = san.strip().lower()
            if s == clean_dom:
                return True
            if s.startswith("*."):
                suffix = s[2:]
                if clean_dom.endswith(f".{suffix}") and clean_dom.count(".") == suffix.count(".") + 1:
                    return True
        return False

    @classmethod
    def evaluate_tls_posture(
        cls,
        domain: str,
        tls_version: str = "TLSv1.3",
        cipher_suite: str = "TLS_AES_256_GCM_SHA384",
        days_remaining: Optional[int] = 90,
        san_domains: Optional[List[str]] = None,
        blackboard: Any = None,
    ) -> Dict[str, Any]:
        """Evaluates a host's TLS version, negotiated cipher suite, expiry window, and SAN coverage."""
        clean_domain = (domain or "").strip().lower()
        issues: List[Dict[str, Any]] = []

        proto = (tls_version or "").strip()
        if proto in cls.DEPRECATED_PROTOCOLS:
            issues.append({
                "code": "DEPRECATED_TLS_PROTOCOL",
                "severity": "HIGH",
                "detail": f"Host negotiated deprecated protocol '{proto}'. Enforce TLSv1.2 minimum and prefer TLSv1.3.",
            })

        cipher_up = (cipher_suite or "").upper()
        if any(tok in cipher_up for tok in cls.WEAK_CIPHER_TOKENS):
            issues.append({
                "code": "WEAK_CIPHER_SUITE",
                "severity": "HIGH",
                "detail": f"Weak cipher suite '{cipher_suite}' negotiated. Disable legacy stream/block ciphers and require ECDHE + AEAD (AES-GCM / CHACHA20-POLY1305).",
            })

        if days_remaining is not None:
            if days_remaining < 0:
                issues.append({
                    "code": "CERTIFICATE_EXPIRED",
                    "severity": "CRITICAL",
                    "detail": f"TLS certificate expired {abs(days_remaining)} day(s) ago.",
                })
            elif days_remaining <= 14:
                issues.append({
                    "code": "CERTIFICATE_EXPIRING_CRITICAL",
                    "severity": "HIGH",
                    "detail": f"TLS certificate expires in {days_remaining} day(s) (<= 14d threshold).",
                })
            elif days_remaining <= 30:
                issues.append({
                    "code": "CERTIFICATE_EXPIRING_SOON",
                    "severity": "MEDIUM",
                    "detail": f"TLS certificate expires in {days_remaining} day(s) (<= 30d threshold).",
                })

        if san_domains is not None and not cls._hostname_matches_san(clean_domain, san_domains):
            issues.append({
                "code": "SAN_HOSTNAME_MISMATCH",
                "severity": "HIGH",
                "detail": f"Domain '{clean_domain}' is not covered by certificate SANs: {san_domains}.",
            })

        severities = {i["severity"] for i in issues}
        overall_sev = (
            "CRITICAL" if "CRITICAL" in severities
            else ("HIGH" if "HIGH" in severities else ("MEDIUM" if "MEDIUM" in severities else "SAFE"))
        )

        result = {
            "domain": clean_domain,
            "vulnerable": len(issues) > 0,
            "severity": overall_sev,
            "tls_version": proto,
            "cipher_suite": cipher_suite,
            "days_remaining": days_remaining,
            "issues": issues,
        }

        if issues and blackboard is not None:
            try:
                blackboard.publish(
                    event_type="TLS_POSTURE_ANOMALY",
                    payload=result,
                    source="passive_tls_sentinel",
                    topic="perimeter",
                )
            except Exception as exc:
                logger.debug(f"Blackboard publish error in evaluate_tls_posture: {exc}")

        return result


class EmailAuthPolicyAnalyzer:
    """Autonomous Email Security SPF / DKIM / DMARC / MTA-STS / BIMI Policy Analyzer (Project #22)."""

    DNS_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")

    @classmethod
    def _count_spf_lookups(cls, spf_record: str) -> int:
        tokens = (spf_record or "").lower().split()
        count = 0
        for tok in tokens:
            t = tok.lstrip("+-~?")
            if (
                t.startswith("include:")
                or t.startswith("exists:")
                or t.startswith("redirect=")
                or t in ("a", "mx", "ptr")
                or t.startswith("a:")
                or t.startswith("a/")
                or t.startswith("mx:")
                or t.startswith("mx/")
                or t.startswith("ptr:")
            ):
                count += 1
        return count

    @classmethod
    def analyze_email_security_posture(
        cls,
        domain: str,
        spf_record: Optional[str] = None,
        dmarc_record: Optional[str] = None,
        dkim_selectors: Optional[Dict[str, str]] = None,
        mta_sts_record: Optional[str] = None,
        bimi_record: Optional[str] = None,
        blackboard: Any = None,
    ) -> Dict[str, Any]:
        """Evaluates SPF, DMARC, DKIM, MTA-STS, and BIMI records for spoofing and RFC 7208/7489 flaws."""
        clean_domain = str(domain or "").strip().lower()[:253]
        findings: List[Dict[str, Any]] = []
        spf = str(spf_record or "").strip()[:2048] if spf_record is not None else ""
        dmarc = str(dmarc_record or "").strip()[:2048] if dmarc_record is not None else ""
        dkim_map = dkim_selectors if isinstance(dkim_selectors, dict) else {}

        # 1. SPF Analysis (RFC 7208)
        spf_lookups = cls._count_spf_lookups(spf) if spf else 0
        if not spf or not spf.lower().startswith("v=spf1"):
            findings.append({
                "code": "SPF_MISSING",
                "severity": "HIGH",
                "detail": "No valid v=spf1 TXT record published on apex domain.",
            })
        else:
            spf_lower = spf.lower()
            if "+all" in spf_lower:
                findings.append({
                    "code": "SPF_PERMISSIVE_PLUS_ALL",
                    "severity": "CRITICAL",
                    "detail": "SPF record contains '+all', authorizing any IPv4/IPv6 host on the Internet to send mail as this domain.",
                })
            elif "?all" in spf_lower:
                findings.append({
                    "code": "SPF_NEUTRAL_QUESTION_ALL",
                    "severity": "HIGH",
                    "detail": "SPF record ends with neutral '?all', providing zero spoofing enforcement.",
                })
            if spf_lookups > 10:
                findings.append({
                    "code": "SPF_LOOKUP_LIMIT_EXCEEDED",
                    "severity": "MEDIUM",
                    "detail": f"SPF record requires {spf_lookups} DNS mechanisms (>10 RFC 7208 limit), causing PermError at receivers.",
                })

        # 2. DMARC Analysis (RFC 7489)
        if not dmarc or "v=dmarc1" not in dmarc.lower():
            findings.append({
                "code": "DMARC_MISSING",
                "severity": "HIGH",
                "detail": "No _dmarc TXT record found. Domain is vulnerable to direct From-header spoofing.",
            })
        else:
            dmarc_lower = dmarc.lower()
            if re.search(r"\bp\s*=\s*none\b", dmarc_lower):
                findings.append({
                    "code": "DMARC_POLICY_NONE",
                    "severity": "HIGH",
                    "detail": "DMARC policy is set to 'p=none' (monitoring only); spoofed messages are not quarantined or rejected.",
                })
            pct_match = re.search(r"\bpct\s*=\s*(\d+)", dmarc_lower)
            if pct_match and int(pct_match.group(1)) < 100:
                findings.append({
                    "code": "DMARC_PARTIAL_PCT",
                    "severity": "MEDIUM",
                    "detail": f"DMARC policy only applies to {pct_match.group(1)}% of messages (pct<100).",
                })

        # 3. DKIM Selector Verification
        valid_dkim = [
            str(sel)
            for sel, rec in dkim_map.items()
            if isinstance(rec, str) and "p=" in rec and len(rec.split("p=")[-1].split(";")[0].strip()) >= 64
        ]
        if not valid_dkim:
            findings.append({
                "code": "DKIM_NO_VALID_SELECTORS",
                "severity": "MEDIUM",
                "detail": "No active DKIM public key selectors verified.",
            })

        severities = {f["severity"] for f in findings}
        overall_sev = (
            "CRITICAL" if "CRITICAL" in severities
            else ("HIGH" if "HIGH" in severities else ("MEDIUM" if "MEDIUM" in severities else "SAFE"))
        )
        spoofable = any(
            f["code"] in ("SPF_MISSING", "SPF_PERMISSIVE_PLUS_ALL", "SPF_NEUTRAL_QUESTION_ALL", "DMARC_MISSING", "DMARC_POLICY_NONE")
            for f in findings
        )

        result = {
            "domain": clean_domain,
            "spoofable": spoofable,
            "severity": overall_sev,
            "spf_dns_lookups": spf_lookups,
            "spf_lookup_count": spf_lookups,
            "valid_dkim_selectors": valid_dkim,
            "has_mta_sts": bool(isinstance(mta_sts_record, str) and "v=stsv1" in mta_sts_record.lower()),
            "has_bimi": bool(isinstance(bimi_record, str) and "v=bimi1" in bimi_record.lower()),
            "findings": findings,
        }

        if blackboard is not None:
            try:
                blackboard.publish(
                    event_type="EMAIL_AUTH_POSTURE_EVALUATED",
                    payload=result,
                    source="email_auth_analyzer",
                    topic="perimeter",
                )
            except Exception as exc:
                logger.debug(f"Blackboard publish error in analyze_email_security_posture: {exc}")

        return result


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
