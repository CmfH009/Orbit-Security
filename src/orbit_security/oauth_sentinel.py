"""Orbit Security: Smart OAuth 2.0 & OpenID Connect Flow Sentinel (oauth_sentinel.py).

Provides Phase F detection capabilities:
1. Redirect URI Permutation & Hijack Audit (subdomain wildcard, regex dot evasion, path traversal, cleartext downgrade).
2. OAuth Login CSRF (missing or unenforced state parameter).
3. PKCE Enforcement (missing code_challenge/code_verifier on public clients).
4. OIDC Metadata Configuration Audit (insecure signing algs like 'none', internal endpoint exposure).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import enum
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from orbit_security.models import Severity
from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.oauth_sentinel")


class OAuthFlawType(str, enum.Enum):
    REDIRECT_URI_HIJACK = "oauth_redirect_uri_hijack"
    LOGIN_CSRF = "oauth_login_csrf"
    MISSING_PKCE = "oauth_missing_pkce"
    OIDC_INSECURE_SIGNING = "oidc_insecure_signing_alg"
    OIDC_INTERNAL_LEAK = "oidc_internal_endpoint_leak"


@dataclass
class OAuthFinding:
    """Represents a validated OAuth 2.0 or OIDC security finding."""

    vulnerable: bool
    flaw_type: str
    target_domain: str
    auth_endpoint: str
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    variant: str = ""
    severity: Severity = Severity.HIGH
    cvss_score: float = 8.1
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    cwe_id: str = "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
    evidence: str = ""
    remediation: str = (
        "Enforce strict exact-string matching for registered redirect URIs. "
        "Reject wildcard subdomains, regex-based suffix matching, and path traversals. "
        "Mandate cryptographically random state parameters bound to session cookies, "
        "and require PKCE with S256 challenges across all client flows."
    )
    bounty_viability: str = "HIGH_CONFIDENCE"
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding to dictionary representation."""
        data = asdict(self)
        if isinstance(self.severity, Severity):
            data["severity"] = self.severity.value
        return data


class OAuthFlowSentinel:
    """Audits OAuth 2.0 and OpenID Connect authorization servers for authorization flaws."""

    WELL_KNOWN_OIDC_PATHS = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]

    INTERNAL_IP_REGEX = re.compile(
        r"(https?://)?(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|\b[a-z0-9-]+\.internal\b|\b[a-z0-9-]+\.local\b)",
        re.IGNORECASE,
    )

    @classmethod
    def _safe_http_get(
        cls, url: str, timeout: float = 3.5, headers: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, Dict[str, str]]:
        """Performs a safe HTTP GET request without following redirects, returning status, body, headers."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]
        if not is_safe_host(host):
            return 0, "", {}

        req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"}
        if headers:
            req_headers.update(headers)

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirectHandler)
        req = urllib.request.Request(url, headers=req_headers)

        try:
            with opener.open(req, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                body = resp.read(4096).decode("utf-8", errors="ignore")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return status, body, resp_headers
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
            try:
                body = e.read(4096).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body, resp_headers
        except Exception as exc:
            logger.debug("HTTP GET error against %s: %s", url, exc)
            return 0, "", {}

    @classmethod
    def audit_redirect_uri_flexibility(
        cls,
        auth_url: str,
        valid_client_id: str,
        base_redirect: str,
        timeout: float = 3.5,
        mock_responses: Optional[Dict[str, Tuple[int, str, Dict[str, str]]]] = None,
    ) -> List[OAuthFinding]:
        """Tests authorization endpoint for improper redirect URI validation.

        Variants tested:
        1. Subdomain wildcarding: https://attacker.victim.com/callback
        2. Suffix evasion: https://victim.com.attacker.com/callback
        3. Path traversal: https://victim.com/callback/../../open-redirect
        4. Protocol downgrade: http://victim.com/callback
        """
        findings: List[OAuthFinding] = []
        parsed_base = urllib.parse.urlparse(base_redirect)
        base_domain = parsed_base.netloc
        base_path = parsed_base.path or "/callback"

        parsed_auth = urllib.parse.urlparse(auth_url)
        target_domain = parsed_auth.netloc.split(":")[0]

        # Define candidate permutations
        variants: List[Tuple[str, str]] = [
            ("subdomain_injection", f"https://attacker.{base_domain}{base_path}"),
            ("suffix_evasion", f"https://{base_domain}.attacker.com{base_path}"),
            ("path_traversal", f"https://{base_domain}{base_path}/../../open-redirect"),
            ("protocol_downgrade", f"http://{base_domain}{base_path}"),
        ]

        for variant_key, test_uri in variants:
            # Construct query params
            params = {
                "client_id": valid_client_id,
                "response_type": "code",
                "redirect_uri": test_uri,
                "scope": "openid email profile",
                "state": "anti_csrf_probe_token_12345",
            }
            query_str = urllib.parse.urlencode(params)
            sep = "&" if "?" in auth_url else "?"
            full_test_url = f"{auth_url}{sep}{query_str}"

            if mock_responses and variant_key in mock_responses:
                status, body, headers = mock_responses[variant_key]
            else:
                status, body, headers = cls._safe_http_get(full_test_url, timeout=timeout)

            # Check if IdP accepted the redirect (302 redirect with Location matching test_uri, or 200 without error)
            location = headers.get("location", "")
            is_redirect_accepted = False

            if status in (301, 302, 303, 307, 308) and location:
                # If location starts with test_uri or contains code/token redirected to test_uri
                if location.startswith(test_uri) or (test_uri in location and "code=" in location):
                    is_redirect_accepted = True
            elif status == 200 and "error" not in body.lower() and "invalid_redirect" not in body.lower():
                # Server accepted without showing an invalid_redirect_uri error
                if f"redirect_uri={urllib.parse.quote(test_uri, safe='')}" in body or "allow" in body.lower():
                    is_redirect_accepted = True

            if is_redirect_accepted:
                evidence = (
                    f"OAuth authorization server on '{target_domain}' accepted insecure redirect URI "
                    f"under variant '{variant_key}'. Tested URI: '{test_uri}'. "
                    f"Server responded with HTTP {status} and Location '{location}'."
                )
                finding = OAuthFinding(
                    vulnerable=True,
                    flaw_type=OAuthFlawType.REDIRECT_URI_HIJACK.value,
                    target_domain=target_domain,
                    auth_endpoint=auth_url,
                    client_id=valid_client_id,
                    redirect_uri=test_uri,
                    variant=variant_key,
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
                    evidence=evidence,
                )
                findings.append(finding)

        return findings

    @classmethod
    def audit_state_parameter_enforcement(
        cls,
        auth_url: str,
        client_id: str,
        redirect_uri: str,
        timeout: float = 3.5,
        mock_response: Optional[Tuple[int, str, Dict[str, str]]] = None,
    ) -> Optional[OAuthFinding]:
        """Audits authorization endpoint for missing state parameter enforcement (OAuth Login CSRF)."""
        parsed_auth = urllib.parse.urlparse(auth_url)
        target_domain = parsed_auth.netloc.split(":")[0]

        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "openid email",
            # Intentionally omit state parameter
        }
        query_str = urllib.parse.urlencode(params)
        sep = "&" if "?" in auth_url else "?"
        test_url = f"{auth_url}{sep}{query_str}"

        if mock_response is not None:
            status, body, headers = mock_response
        else:
            status, body, headers = cls._safe_http_get(test_url, timeout=timeout)

        location = headers.get("location", "")
        # If server redirects with code or presents login without requiring state
        if (status in (301, 302, 303, 307, 308) and "code=" in location) or (
            status == 200 and "error" not in body.lower() and "missing_state" not in body.lower()
        ):
            evidence = (
                f"OAuth authorization endpoint on '{target_domain}' processed request without requiring "
                f"a 'state' parameter. HTTP Status: {status}. Allows OAuth Login CSRF account linking attacks."
            )
            return OAuthFinding(
                vulnerable=True,
                flaw_type=OAuthFlawType.LOGIN_CSRF.value,
                target_domain=target_domain,
                auth_endpoint=auth_url,
                client_id=client_id,
                redirect_uri=redirect_uri,
                variant="missing_state_parameter",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-352: Cross-Site Request Forgery (CSRF)",
                evidence=evidence,
                remediation=(
                    "Mandate cryptographically secure, unguessable 'state' parameters on every authorization "
                    "request and strictly verify the returned state against user session cookies upon callback."
                ),
            )

        return None

    @classmethod
    def audit_pkce_enforcement(
        cls,
        token_url: str,
        client_id: str,
        auth_url: Optional[str] = None,
        timeout: float = 3.5,
        mock_response: Optional[Tuple[int, str, Dict[str, str]]] = None,
    ) -> Optional[OAuthFinding]:
        """Audits authorization/token endpoints for missing PKCE enforcement on public clients."""
        parsed_token = urllib.parse.urlparse(token_url)
        target_domain = parsed_token.netloc.split(":")[0]

        # Simulate exchange without code_verifier
        if mock_response is not None:
            status, body, headers = mock_response
        else:
            # Safe probe of token endpoint with dummy grant without PKCE
            data = urllib.parse.urlencode({
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": "test_probe_dummy_code_9988",
                "redirect_uri": "https://localhost/callback",
            }).encode("utf-8")
            req = urllib.request.Request(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "OrbitSecurity/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = getattr(resp, "status", getattr(resp, "code", 200))
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                status = e.code
                headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
                try:
                    body = e.read(4096).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
            except Exception:
                return None

        # If server complains about missing code_verifier, PKCE is enforced!
        # If server rejects only for invalid_code without requiring code_verifier, PKCE may be optional.
        if "code_verifier" in body.lower() or "pkce" in body.lower():
            return None

        if "invalid_grant" in body.lower() or "invalid_code" in body.lower() or status == 400:
            # If server accepted token request structure without mandating code_verifier
            evidence = (
                f"Token endpoint '{token_url}' does not mandate PKCE (code_verifier / RFC 7636). "
                "Public clients remain vulnerable to authorization code interception."
            )
            return OAuthFinding(
                vulnerable=True,
                flaw_type=OAuthFlawType.MISSING_PKCE.value,
                target_domain=target_domain,
                auth_endpoint=token_url,
                client_id=client_id,
                variant="pkce_not_enforced",
                severity=Severity.HIGH,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                cwe_id="CWE-306: Missing Authentication for Critical Function",
                evidence=evidence,
                remediation="Enforce mandatory RFC 7636 PKCE (S256 code challenge) across all authorization and token exchanges.",
            )

        return None

    @classmethod
    def audit_oidc_metadata(
        cls,
        domain: str,
        timeout: float = 3.5,
        mock_config: Optional[Dict[str, Any]] = None,
    ) -> List[OAuthFinding]:
        """Audits OpenID Connect discovery metadata for insecure algorithms and internal endpoint leaks."""
        findings: List[OAuthFinding] = []
        host = domain.strip().lower().split(":")[0]
        if not is_safe_host(host):
            return []

        config: Optional[Dict[str, Any]] = mock_config

        if config is None:
            for path in cls.WELL_KNOWN_OIDC_PATHS:
                url = f"https://{host}{path}"
                status, body, _ = cls._safe_http_get(url, timeout=timeout)
                if status == 200 and body:
                    try:
                        config = json.loads(body)
                        break
                    except json.JSONDecodeError:
                        continue

        if not config or not isinstance(config, dict):
            return []

        # 1. Insecure Signing Algorithms Check ('none' or algorithm confusion)
        alg_keys = [
            "id_token_signing_alg_values_supported",
            "userinfo_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
        ]
        insecure_algs_found = []
        for key in alg_keys:
            algs = config.get(key, [])
            if isinstance(algs, list):
                for alg in algs:
                    if str(alg).lower() == "none" or str(alg).lower() == "hs256" and "rs256" in [str(a).lower() for a in algs]:
                        insecure_algs_found.append(f"{key}:{alg}")

        if any(":none" in a for a in insecure_algs_found):
            evidence = (
                f"OpenID Connect discovery configuration on '{host}' advertises support for the 'none' "
                f"signature algorithm: {', '.join(insecure_algs_found)}. Allows arbitrary token forgery."
            )
            findings.append(
                OAuthFinding(
                    vulnerable=True,
                    flaw_type=OAuthFlawType.OIDC_INSECURE_SIGNING.value,
                    target_domain=host,
                    auth_endpoint=config.get("authorization_endpoint", f"https://{host}/oauth/authorize"),
                    variant="oidc_none_algorithm",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-347: Improper Verification of Cryptographic Signature",
                    evidence=evidence,
                    remediation="Disable and reject the 'none' signature algorithm on the authorization server.",
                )
            )

        # 2. Internal or Leaked Endpoint Check
        for endpoint_key, endpoint_val in config.items():
            if isinstance(endpoint_val, str) and ("_endpoint" in endpoint_key or "issuer" in endpoint_key):
                match = cls.INTERNAL_IP_REGEX.search(endpoint_val)
                if match:
                    leaked_target = match.group(0)
                    evidence = (
                        f"OpenID Connect discovery metadata on '{host}' exposes an internal/non-routable address "
                        f"in '{endpoint_key}': '{endpoint_val}' (matched: '{leaked_target}')."
                    )
                    findings.append(
                        OAuthFinding(
                            vulnerable=True,
                            flaw_type=OAuthFlawType.OIDC_INTERNAL_LEAK.value,
                            target_domain=host,
                            auth_endpoint=endpoint_val,
                            variant=f"internal_leak_{endpoint_key}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                            evidence=evidence,
                            remediation="Ensure public OpenID Connect discovery documents only publish public, externally resolvable URLs.",
                        )
                    )

        return findings

    @classmethod
    def audit_target(
        cls,
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
        """Unified audit entry point returning highest-priority OAuth/OIDC finding."""
        all_findings: List[OAuthFinding] = []

        # 1. Audit OIDC metadata
        oidc_findings = cls.audit_oidc_metadata(target_domain, timeout=timeout, mock_config=mock_oidc)
        all_findings.extend(oidc_findings)

        # 2. Audit Redirect URI Flexibility if auth_url provided
        if auth_url and client_id and redirect_uri:
            redirect_findings = cls.audit_redirect_uri_flexibility(
                auth_url=auth_url,
                valid_client_id=client_id,
                base_redirect=redirect_uri,
                timeout=timeout,
                mock_responses=mock_redirects,
            )
            all_findings.extend(redirect_findings)

            # 3. Audit State Parameter Enforcement
            state_finding = cls.audit_state_parameter_enforcement(
                auth_url=auth_url,
                client_id=client_id,
                redirect_uri=redirect_uri,
                timeout=timeout,
                mock_response=mock_state,
            )
            if state_finding:
                all_findings.append(state_finding)

        # 4. Audit PKCE Enforcement
        if token_url and client_id:
            pkce_finding = cls.audit_pkce_enforcement(
                token_url=token_url,
                client_id=client_id,
                auth_url=auth_url,
                timeout=timeout,
                mock_response=mock_pkce,
            )
            if pkce_finding:
                all_findings.append(pkce_finding)

        if not all_findings:
            return None

        # Return the highest-severity finding
        sorted_findings = sorted(all_findings, key=lambda f: f.cvss_score, reverse=True)
        return sorted_findings[0].to_dict()
