import asyncio
import datetime
import ipaddress
import socket
import ssl
from typing import List, Optional, Set
from urllib.parse import urlparse
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from orbit_security.models import AgencyBranding, DomainAuditResult, Finding, Severity
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES
from orbit_security.dns_cache import get_orbit_async_resolver
from orbit_security.network_bonding import create_bonded_http_client


STATIC_HOST_SUFFIXES = (
    ".github.io",
    ".pages.dev",
    ".vercel.app",
    ".netlify.app",
    ".gitlab.io",
    ".azurewebsites.net",
    ".render.com",
    ".onrender.com",
    ".fly.dev",
    ".webflow.io",
    ".surge.sh",
    ".firebaseapp.com",
    ".web.app",
)


def is_static_hosting_domain(domain: str) -> bool:
    clean = (domain or "").strip().lower()
    return clean == "github.io" or any(clean.endswith(s) for s in STATIC_HOST_SUFFIXES)


def is_safe_ip(ip_str: str) -> bool:
    """Verifies that an IP is a public, routable Internet address.

    Blocks private RFC 1918, loopback, link-local, carrier-grade NAT, multicast,
    and cloud metadata endpoints (AWS, GCP, Azure, Alibaba).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        # Specific cloud metadata IP addresses
        if str(ip) in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"):
            return False
        return True
    except ValueError:
        return False


def is_safe_host(hostname: str) -> bool:
    """Validates that a hostname does not resolve to an internal, loopback, or cloud metadata address."""
    if not hostname:
        return False
    host = hostname.split(":")[0].strip("[]").strip().lower()
    if not host:
        return False

    # Check if host is direct IP
    try:
        ipaddress.ip_address(host)
        return is_safe_ip(host)
    except ValueError:
        pass

    # Block explicit internal/metadata hostnames
    if host in ("localhost", "metadata.google.internal", "instance-data", "metadata"):
        return False
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".localhost"):
        return False

    try:
        addr_info = socket.getaddrinfo(host, None)
        if not addr_info:
            return False
        for _, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if not is_safe_ip(ip):
                return False
        return True
    except socket.gaierror:
        # If hostname cannot be resolved, it does not point to an internal IP
        return True
    except Exception:
        return False


async def async_is_safe_host(hostname: str) -> bool:
    """Non-blocking async variant of is_safe_host resolving DNS on the running event loop."""
    if not hostname:
        return False

    host = hostname.split(":")[0].strip("[]").strip().lower()
    if not host:
        return False

    # Check if host is direct IP
    try:
        ipaddress.ip_address(host)
        return is_safe_ip(host)
    except ValueError:
        pass

    if host in ("localhost", "metadata.google.internal", "instance-data", "metadata"):
        return False
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".localhost"):
        return False

    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(host, None)
        if not addr_info:
            return False
        for _, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if not is_safe_ip(ip):
                return False
        return True
    except socket.gaierror:
        return True
    except Exception:
        return False


class OrbitSecurityScanner:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.resolver = get_orbit_async_resolver(timeout=timeout)

    @staticmethod
    async def _check_redirect_ssrf(response: httpx.Response):
        """Event hook to prevent SSRF via open redirect chains."""
        if response.is_redirect:
            location = response.headers.get("location")
            if location:
                target_url = str(response.url.join(location))
                parsed = urlparse(target_url)
                if parsed.hostname and not await async_is_safe_host(parsed.hostname):
                    raise httpx.RequestError(
                        f"SSRF blocked: Redirect to internal/private host '{parsed.hostname}' prohibited."
                    )

    def create_http_client(
        self, verify_ssl: bool = True, use_proxy: Optional[bool] = None
    ) -> httpx.AsyncClient:
        """Creates a hardened, pooled AsyncClient with SSRF redirect guards and multi-adapter bonding.

        Args:
            verify_ssl: Whether to verify SSL/TLS certificates. Defaults to True for security
                        hygiene. Callers conducting exploratory probes can set False if explicitly needed.
            use_proxy: Explicitly enable or disable Multi-Adapter proxy routing (:8989). If None,
                       auto-detects if proxy is active.
        """
        return create_bonded_http_client(
            timeout=self.timeout,
            verify_ssl=verify_ssl,
            use_proxy=use_proxy,
            event_hooks={"response": [self._check_redirect_ssrf]},
        )

    async def fetch_subdomains_from_crtsh(
        self, domain: str, client: Optional[httpx.AsyncClient] = None
    ) -> List[str]:
        """Discovers all subdomains registered via Certificate Transparency logs (crt.sh)."""
        if not await async_is_safe_host(domain):
            return []

        discovered: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        should_close = False
        if client is None:
            client = self.create_http_client()
            should_close = True

        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for raw_name in name_value.split("\n"):
                        clean_name = raw_name.strip().lower()
                        if clean_name.startswith("*."):
                            clean_name = clean_name[2:]
                        if clean_name.endswith(f".{domain}"):
                            discovered.add(clean_name)
        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()

        return sorted(list(discovered))

    async def audit_dmarc(self, domain: str) -> Optional[Finding]:
        target = f"_dmarc.{domain}"
        try:
            answers = await self.resolver.resolve(target, "TXT")
            records = []
            for rdata in answers:
                # RFC 1035 / RFC 7208: Concatenate multi-chunk TXT records
                full_txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                records.append(full_txt)

            dmarc_record = next((r for r in records if r.startswith("v=DMARC1")), None)

            if not dmarc_record:
                labels = domain.split(".")
                is_sub = len(labels) > 2
                org_domain = ".".join(labels[-2:]) if is_sub else domain
                if is_sub:
                    try:
                        org_answers = await self.resolver.resolve(f"_dmarc.{org_domain}", "TXT")
                        org_records = [b"".join(rd.strings).decode("utf-8", errors="ignore") for rd in org_answers]
                        org_dmarc = next((r for r in org_records if r.startswith("v=DMARC1")), None)
                        if org_dmarc and ("p=reject" in org_dmarc or "p=quarantine" in org_dmarc):
                            return None
                    except Exception:
                        pass

                if is_static_hosting_domain(domain):
                    return None

                return Finding(
                    title="Missing DMARC Email Protection",
                    severity=Severity.HIGH,
                    category="Email Authentication",
                    description=f"Domain {domain} lacks a valid DMARC record. Attackers can forge emails from this domain to execute phishing attacks.",
                    remediation=f"Add a TXT record for `_dmarc.{domain}` with at least `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`.",
                    target=target,
                    evidence="No v=DMARC1 TXT record found.",
                )

            if "p=none" in dmarc_record:
                return Finding(
                    title="DMARC Policy in Inactive Monitoring Mode (p=none)",
                    severity=Severity.MEDIUM,
                    category="Email Authentication",
                    description="The DMARC policy is set to `p=none`. Spoofed emails from attackers are still delivered to recipient inboxes without rejection or quarantine.",
                    remediation="Upgrade policy from `p=none` to `p=quarantine` or `p=reject` after reviewing authentication reports.",
                    target=target,
                    evidence=dmarc_record,
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError) as e:
            if is_static_hosting_domain(domain):
                return None
            return Finding(
                title="DNS Resolution Timeout (_dmarc)",
                severity=Severity.LOW,
                category="Email Authentication",
                description=f"DNS query for `_dmarc.{domain}` timed out after {self.timeout}s. Network latency or upstream resolver rate limits prevented verification. Re-scan to verify.",
                remediation="Check authoritative nameserver latency and re-run scan.",
                target=target,
                evidence=f"DNS Timeout: {e}",
            )
        except Exception as e:
            if is_static_hosting_domain(domain):
                return None
            return Finding(
                title="Missing DMARC Email Protection",
                severity=Severity.HIGH,
                category="Email Authentication",
                description=f"No DMARC record found for {domain}. Fraudsters can impersonate your brand in executive or billing phishing schemes.",
                remediation=f"Add a DNS TXT record for `_dmarc.{domain}` with policy `p=quarantine` or `p=reject`.",
                target=target,
                evidence=str(e),
            )

    async def audit_spf(self, domain: str) -> Optional[Finding]:
        try:
            answers = await self.resolver.resolve(domain, "TXT")
            records = []
            for rdata in answers:
                # RFC 1035 / RFC 7208: Concatenate multi-chunk TXT records
                full_txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                records.append(full_txt)

            spf_record = next((r for r in records if r.startswith("v=spf1")), None)

            if not spf_record:
                labels = domain.split(".")
                is_sub = len(labels) > 2
                org_domain = ".".join(labels[-2:]) if is_sub else domain
                if is_sub:
                    try:
                        org_answers = await self.resolver.resolve(org_domain, "TXT")
                        org_records = [b"".join(rd.strings).decode("utf-8", errors="ignore") for rd in org_answers]
                        org_spf = next((r for r in org_records if r.startswith("v=spf1")), None)
                        if org_spf and ("-all" in org_spf or "~all" in org_spf):
                            return None
                    except Exception:
                        pass

                if is_static_hosting_domain(domain):
                    return None

                return Finding(
                    title="Missing SPF Record",
                    severity=Severity.HIGH,
                    category="Email Authentication",
                    description=f"Domain {domain} does not have an SPF (Sender Policy Framework) record published.",
                    remediation="Define an authorized list of mail servers using a TXT record `v=spf1 ... -all`.",
                    target=domain,
                    evidence="No v=spf1 TXT record located.",
                )

            if "+all" in spf_record:
                return Finding(
                    title="Dangerously Permissive SPF (+all)",
                    severity=Severity.CRITICAL,
                    category="Email Authentication",
                    description="SPF record explicitly authorizes all IP addresses on the internet to send mail on behalf of this domain.",
                    remediation="Replace `+all` with `~all` or `-all`.",
                    target=domain,
                    evidence=spf_record,
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError) as e:
            if is_static_hosting_domain(domain):
                return None
            return Finding(
                title="DNS Resolution Timeout (SPF)",
                severity=Severity.LOW,
                category="Email Authentication",
                description=f"DNS query for `{domain}` SPF records timed out after {self.timeout}s.",
                remediation="Check authoritative nameserver latency and re-run scan.",
                target=domain,
                evidence=f"DNS Timeout: {e}",
            )
        except Exception as e:
            if is_static_hosting_domain(domain):
                return None
            return Finding(
                title="Missing SPF Record",
                severity=Severity.HIGH,
                category="Email Authentication",
                description=f"Unable to resolve SPF record for {domain}.",
                remediation=f"Publish a TXT record starting with `v=spf1` on {domain}.",
                target=domain,
                evidence=str(e),
            )

    async def audit_bimi(self, domain: str) -> Optional[Finding]:
        """Audits BIMI (Brand Indicators for Message Identification - RFC 8617)."""
        if is_static_hosting_domain(domain):
            return None
        target = f"default._bimi.{domain}"
        try:
            answers = await self.resolver.resolve(target, "TXT")
            records = []
            for rdata in answers:
                full_txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                records.append(full_txt)

            bimi_record = next((r for r in records if r.strip().startswith("v=BIMI1")), None)
            if not bimi_record:
                return Finding(
                    title="Missing BIMI Brand Indicator (RFC 8617)",
                    severity=Severity.LOW,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} does not have a BIMI record configured at `{target}`. "
                        "BIMI displays verified agency/client logos next to emails in Gmail and Apple Mail, "
                        "improving recipient open rates and preventing brand impersonation."
                    ),
                    remediation=f"Publish a TXT record for `{target}` with `v=BIMI1; l=https://{domain}/logo.svg;` once DMARC is enforced.",
                    target=target,
                    evidence="No v=BIMI1 record found.",
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return None
        except Exception:
            return Finding(
                title="Missing BIMI Brand Indicator (RFC 8617)",
                severity=Severity.LOW,
                category="Email Authentication",
                description=(
                    f"No BIMI record discovered at `{target}`. Implementing BIMI authenticates brand logos "
                    "in supporting inboxes (Gmail, Apple Mail, Yahoo) and prevents visual brand spoofing."
                ),
                remediation=f"Configure a DNS TXT record at `{target}` with `v=BIMI1; l=https://{domain}/logo.svg;`.",
                target=target,
                evidence="No BIMI TXT record located.",
            )

    async def audit_mta_sts(self, domain: str) -> Optional[Finding]:
        """Audits MTA-STS (SMTP Mail Transfer Agent Strict Transport Security - RFC 8461)."""
        if is_static_hosting_domain(domain):
            return None
        target = f"_mta-sts.{domain}"
        try:
            answers = await self.resolver.resolve(target, "TXT")
            records = []
            for rdata in answers:
                full_txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                records.append(full_txt)

            sts_record = next((r for r in records if r.strip().startswith("v=STSv1")), None)
            if not sts_record:
                return Finding(
                    title="Missing MTA-STS Transport Security (RFC 8461)",
                    severity=Severity.LOW,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} lacks an MTA-STS policy at `{target}`. Mail transfer agents can be manipulated "
                        "via downgrade attacks (e.g. STRIPTLS) to deliver mail in unencrypted plaintext."
                    ),
                    remediation=(
                        f"Publish a DNS TXT record at `{target}` with `v=STSv1; id=20260101;` and host your policy file at "
                        f"`https://mta-sts.{domain}/.well-known/mta-sts.txt`."
                    ),
                    target=target,
                    evidence="No v=STSv1 record found.",
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return None
        except Exception:
            return Finding(
                title="Missing MTA-STS Transport Security (RFC 8461)",
                severity=Severity.LOW,
                category="Email Authentication",
                description=(
                    f"Domain {domain} has no MTA-STS DNS record. Inbound emails remain vulnerable "
                    "to SMTP TLS downgrade attacks and eavesdropping."
                ),
                remediation=f"Publish `_mta-sts.{domain}` TXT record and establish mta-sts.txt policy endpoint.",
                target=target,
                evidence="No MTA-STS record located.",
            )

    async def audit_tls_rpt(self, domain: str) -> Optional[Finding]:
        """Audits TLS-RPT (SMTP TLS Reporting - RFC 8460)."""
        if is_static_hosting_domain(domain):
            return None
        target = f"_smtp._tls.{domain}"
        try:
            answers = await self.resolver.resolve(target, "TXT")
            records = []
            for rdata in answers:
                full_txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                records.append(full_txt)

            tls_record = next((r for r in records if r.strip().startswith("v=TLSRPTv1")), None)
            if not tls_record:
                return Finding(
                    title="Missing SMTP TLS Reporting (TLS-RPT RFC 8460)",
                    severity=Severity.INFO,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} has no TLS-RPT policy at `{target}`. Sending mail servers cannot deliver automated "
                        "diagnostic reports when TLS handshakes fail."
                    ),
                    remediation=f"Publish a TXT record for `{target}` with `v=TLSRPTv1; rua=mailto:tls-reports@{domain}`.",
                    target=target,
                    evidence="No v=TLSRPTv1 record found.",
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return None
        except Exception:
            return Finding(
                title="Missing SMTP TLS Reporting (TLS-RPT RFC 8460)",
                severity=Severity.INFO,
                category="Email Authentication",
                description=f"No TLS-RPT record found for {domain}. Diagnostic telemetry on MTA transport security is unavailable.",
                remediation=f"Publish `_smtp._tls.{domain}` TXT record with `v=TLSRPTv1; rua=mailto:...`.",
                target=target,
                evidence="No TLS-RPT record located.",
            )

    async def audit_caa(self, domain: str) -> Optional[Finding]:
        """Audits DNS CAA (Certification Authority Authorization - RFC 8659 / RFC 6844)."""
        target = domain
        try:
            answers = await self.resolver.resolve(domain, "CAA")
            records = [str(rdata).strip() for rdata in answers]
            if not records:
                return Finding(
                    title="Missing DNS CAA Policy (RFC 8659)",
                    severity=Severity.LOW,
                    category="Transport Security",
                    description=(
                        f"Domain {domain} does not publish a Certification Authority Authorization (CAA) record. "
                        "Any globally recognized Certificate Authority is permitted to issue SSL/TLS certificates "
                        "for this domain, increasing exposure to rogue or compromised CAs."
                    ),
                    remediation=(
                        f"Publish a DNS CAA record for `{domain}` specifying authorized CAs "
                        f"(e.g. `0 issue \"letsencrypt.org\"`, `0 issuewild \";\"`, `0 iodef \"mailto:security@{domain}\"`)."
                    ),
                    target=target,
                    evidence="No CAA resource records found.",
                )
            return None
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return None
        except Exception as e:
            return Finding(
                title="Missing DNS CAA Policy (RFC 8659)",
                severity=Severity.LOW,
                category="Transport Security",
                description=(
                    f"Domain {domain} has no DNS CAA policy configured. "
                    "Any globally trusted CA can issue certificates for this domain without restriction."
                ),
                remediation=f"Publish a DNS CAA record for `{domain}` restricting issuance to approved Certificate Authorities.",
                target=target,
                evidence=f"No CAA records found in DNS zone ({e}).",
            )

    async def audit_security_txt(
        self, base_url: str, client: Optional[httpx.AsyncClient] = None
    ) -> Optional[Finding]:
        """Audits RFC 9116 Vulnerability Disclosure standard (security.txt)."""
        parsed = urlparse(base_url)
        domain = parsed.hostname or base_url
        if not await async_is_safe_host(domain):
            return None

        should_close = False
        if client is None:
            client = self.create_http_client()
            should_close = True

        paths = ["/.well-known/security.txt", "/security.txt"]
        found_txt = None

        try:
            for path in paths:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = await client.get(url)
                    if getattr(resp, "status_code", 0) == 200:
                        content_type = getattr(resp, "headers", {}).get("content-type", "").lower()
                        if "text/html" not in content_type:
                            text = getattr(resp, "text", "")
                            if "contact:" in text.lower():
                                found_txt = text
                                break
                except Exception:
                    continue

            if not found_txt:
                is_static = is_static_hosting_domain(domain)
                return Finding(
                    title="Missing RFC 9116 Security Disclosure (security.txt)",
                    severity=Severity.INFO if is_static else Severity.LOW,
                    category="Application Security",
                    description=(
                        f"Domain {domain} does not publish a standardized vulnerability disclosure policy "
                        "at `/.well-known/security.txt` per IETF RFC 9116. Ethical security researchers and bug bounty reporters "
                        "lack a designated, confidential channel to report zero-day vulnerabilities."
                    ),
                    remediation=(
                        f"Deploy a `security.txt` file at `https://{domain}/.well-known/security.txt` declaring "
                        f"`Contact: mailto:security@{domain}` and a valid `Expires:` date."
                    ),
                    target=f"{base_url.rstrip('/')}/.well-known/security.txt",
                    evidence="No valid security.txt discovered with Contact: directive.",
                )
            return None
        finally:
            if should_close and client:
                await client.aclose()

    async def check_subdomain_takeover(
        self, subdomain: str, client: Optional[httpx.AsyncClient] = None
    ) -> Optional[Finding]:
        if not await async_is_safe_host(subdomain):
            return None

        try:
            answers = await self.resolver.resolve(subdomain, "CNAME")
            cnames = [rdata.target.to_text().rstrip(".").lower() for rdata in answers]
        except Exception:
            return None

        if not cnames:
            return None

        for cname in cnames:
            for sig in SAAS_TAKEOVER_SIGNATURES:
                if any(pattern in cname for pattern in sig.cname_patterns):
                    # Check NXDOMAIN vulnerability if specified
                    if getattr(sig, "nxdomain", False):
                        try:
                            await self.resolver.resolve(cname, "A")
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            return Finding(
                                title=f"Dangling CNAME / Subdomain Takeover Risk (NXDOMAIN {sig.name})",
                                severity=Severity.CRITICAL,
                                category="Subdomain & DNS",
                                description=(
                                    f"Subdomain {subdomain} points via CNAME to {cname} ({sig.name}), which does not resolve (NXDOMAIN). "
                                    "An adversary can claim this orphaned cloud resource and seize control of the subdomain."
                                ),
                                remediation=sig.remediation,
                                target=subdomain,
                                evidence=f"CNAME: {cname} | Status: NXDOMAIN (Dangling {sig.name} resource)",
                            )
                        except Exception:
                            pass

                    # Check HTTP fingerprint matching
                    if sig.fingerprints:
                        try:
                            should_close = False
                            if client is None:
                                client = self.create_http_client()
                                should_close = True

                            for proto in ["https", "http"]:
                                try:
                                    url = f"{proto}://{subdomain}"
                                    resp = await client.get(url)
                                    for fp in sig.fingerprints:
                                        if fp.lower() in resp.text.lower():
                                            return Finding(
                                                title=f"Dangling CNAME / Subdomain Takeover Risk ({sig.name})",
                                                severity=Severity.CRITICAL,
                                                category="Subdomain & DNS",
                                                description=f"Subdomain {subdomain} points via CNAME to {cname} ({sig.name}), but the service account appears deleted or unattached. An adversary can register this endpoint and hijack the subdomain.",
                                                remediation=sig.remediation,
                                                target=subdomain,
                                                evidence=f"CNAME: {cname} | Matched fingerprint: '{fp}' (Status: {resp.status_code})",
                                            )
                                except Exception:
                                    continue
                        finally:
                            if should_close and client:
                                await client.aclose()
        return None

    async def audit_exposures(
        self, base_url: str, client: Optional[httpx.AsyncClient] = None
    ) -> List[Finding]:
        parsed_base = urlparse(base_url)
        if parsed_base.hostname and not await async_is_safe_host(parsed_base.hostname):
            return []

        findings: List[Finding] = []
        checks = [
            (
                "/.env",
                ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SECRET_KEY", "DATABASE_URL", "API_KEY", "REDIS_PASSWORD"],
                "Exposed Environment Secrets (.env)",
                Severity.CRITICAL,
                "The environment secrets file is publicly readable on the web root. Credentials, API keys, and database passwords are exposed.",
                "Immediately block web access to dotfiles (`/.env`) in web server configuration and rotate all exposed credentials.",
            ),
            (
                "/.git/HEAD",
                ["ref: refs/heads/", "ref: refs/tags/"],
                "Exposed Git Repository Metadata (/.git)",
                Severity.CRITICAL,
                "The `.git` metadata folder is publicly accessible, allowing automated tooling to reconstruct full source code and commit history.",
                "Deny access to `/.git` in your web server config or remove the `.git` directory from the production web root.",
            ),
            (
                "/.git/config",
                ["[core]", "[remote \"origin\"]", "url = "],
                "Exposed Git Configuration (/.git/config)",
                Severity.CRITICAL,
                "The internal git configuration file is exposed, disclosing repository origin URLs, tokens, and branch structure.",
                "Block web access to all `.git` paths.",
            ),
            (
                "/wp-config.php.bak",
                ["DB_PASSWORD", "DB_NAME", "table_prefix", "AUTH_KEY"],
                "Exposed WordPress Configuration Backup",
                Severity.CRITICAL,
                "A plaintext backup file of wp-config.php was left on the web server, leaking database credentials and secret authentication keys.",
                "Delete `.bak` and `.old` files from production web server roots immediately.",
            ),
            (
                "/docker-compose.yml",
                ["version:", "services:", "image:", "environment:"],
                "Exposed Docker Compose File",
                Severity.HIGH,
                "A docker-compose file is exposed on the web root, leaking internal container architecture, ports, and environment variables.",
                "Remove container definition files from the public web root.",
            ),
            (
                "/.env.local",
                ["DB_PASSWORD", "AWS_SECRET", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
                "Exposed Local Environment Secrets (.env.local)",
                Severity.CRITICAL,
                "Local environment development file is exposed on the public web root, disclosing secrets and development keys.",
                "Remove `.env.local` from production and block dotfiles in web server configuration.",
            ),
            (
                "/.git/index",
                ["DIRC"],
                "Exposed Git Index Metadata (/.git/index)",
                Severity.CRITICAL,
                "The binary git index file is publicly readable, disclosing the entire project file list and commit tree structure.",
                "Deny access to `/.git` entirely in web server configuration.",
            ),
            (
                "/wp-config.php.old",
                ["DB_PASSWORD", "DB_NAME", "AUTH_KEY", "table_prefix"],
                "Exposed WordPress Configuration Backup (.old)",
                Severity.CRITICAL,
                "An unparsed backup of wp-config.php was left on the web server, exposing database credentials.",
                "Delete `.old` backup files from the production web root.",
            ),
            (
                "/phpinfo.php",
                ["phpinfo()", "PHP Version", "Configuration File (php.ini) Path"],
                "Exposed PHP Diagnostic File (phpinfo)",
                Severity.HIGH,
                "A phpinfo diagnostic file is exposed, disclosing PHP environment variables, server extensions, modules, and paths.",
                "Remove `phpinfo.php` immediately from production.",
            ),
            (
                "/.DS_Store",
                ["Bud1"],
                "Exposed macOS .DS_Store Metadata",
                Severity.LOW,
                "Directory metadata file left by macOS Finder is accessible, revealing internal file and folder names.",
                "Remove .DS_Store files and add them to `.gitignore` and web server block lists.",
            ),
        ]

        should_close = False
        if client is None:
            client = self.create_http_client()
            should_close = True

        try:
            clean_base = base_url.rstrip("/")
            max_bytes = 128 * 1024  # 128 KB memory streaming cap (tuned for PC specs)

            for path, needles, title, severity, desc, remed in checks:
                url = f"{clean_base}{path}"
                try:
                    # Handle both real httpx.AsyncClient streaming and mock clients
                    if isinstance(client, httpx.AsyncClient):
                        async with client.stream("GET", url) as resp:
                            if resp.status_code != 200:
                                continue
                            content_type = resp.headers.get("content-type", "").lower()
                            # SPA Guard: Sensitive configuration/dotfiles are never text/html
                            if "text/html" in content_type and not path.endswith((".html", ".htm")):
                                continue

                            chunks = []
                            bytes_read = 0
                            async for chunk in resp.aiter_bytes(chunk_size=8192):
                                chunks.append(chunk)
                                bytes_read += len(chunk)
                                if bytes_read >= max_bytes:
                                    break
                            body_text = b"".join(chunks).decode("utf-8", errors="ignore")
                    else:
                        resp = await client.get(url)
                        if getattr(resp, "status_code", 0) != 200:
                            continue
                        content_type = getattr(resp, "headers", {}).get("content-type", "").lower()
                        if "text/html" in content_type and not path.endswith((".html", ".htm")):
                            continue
                        raw_text = getattr(resp, "text", "")
                        body_text = raw_text[:max_bytes]

                    # HTML Guard: Reject client-side 404 rewrite pages returning HTML doctypes
                    stripped = body_text.strip().lower()
                    if not path.endswith((".html", ".htm")) and (
                        stripped.startswith("<!doctype html") or stripped.startswith("<html")
                    ):
                        continue

                    matched = [n for n in needles if n in body_text]
                    if matched:
                        findings.append(
                            Finding(
                                title=title,
                                severity=severity,
                                category="Exposed Assets",
                                description=desc,
                                remediation=remed,
                                target=url,
                                evidence=f"HTTP 200 OK | Matches: {', '.join(matched)}",
                            )
                        )
                except Exception:
                    continue
        finally:
            if should_close:
                await client.aclose()

        return findings

    async def audit_security_headers(
        self, base_url: str, client: Optional[httpx.AsyncClient] = None
    ) -> List[Finding]:
        parsed_base = urlparse(base_url)
        if parsed_base.hostname and not await async_is_safe_host(parsed_base.hostname):
            return []

        domain = parsed_base.hostname or ""
        is_static = is_static_hosting_domain(domain)
        findings: List[Finding] = []
        should_close = False
        if client is None:
            client = self.create_http_client()
            should_close = True

        try:
            resp = await client.get(base_url)
            headers = resp.headers

            if "Strict-Transport-Security" not in headers:
                findings.append(
                    Finding(
                        title="Missing HSTS Header (HTTP Strict Transport Security)",
                        severity=Severity.INFO if is_static else Severity.MEDIUM,
                        category="Transport Security",
                        description=(
                            "Managed static host edge (HSTS managed at CDN level)."
                            if is_static
                            else "HSTS is not configured. Browsers can be downgraded to unencrypted HTTP via man-in-the-middle attacks."
                        ),
                        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header to web server responses.",
                        target=base_url,
                        evidence="Header 'Strict-Transport-Security' not present.",
                    )
                )
            else:
                hsts_val = headers.get("Strict-Transport-Security", "").lower()
                if "includesubdomains" not in hsts_val or "preload" not in hsts_val:
                    findings.append(
                        Finding(
                            title="HSTS Header Incomplete (Subdomains or Preload)",
                            severity=Severity.INFO,
                            category="Transport Security",
                            description=(
                                "HSTS header is active but does not declare `includeSubDomains` or `preload`. "
                                "Subdomains may remain susceptible to SSL stripping."
                            ),
                            remediation="Strengthen HSTS header to `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
                            target=base_url,
                            evidence=f"Current HSTS: {headers.get('Strict-Transport-Security')}",
                        )
                    )

            if "Content-Security-Policy" not in headers:
                findings.append(
                    Finding(
                        title="Missing Content Security Policy (CSP)",
                        severity=Severity.INFO if is_static else Severity.LOW,
                        category="Application Security",
                        description="CSP header is absent. Restricting sources of scripts, images, and frames prevents cross-site scripting (XSS) and data injection.",
                        remediation="Define a baseline `Content-Security-Policy` header allowing only trusted asset origins.",
                        target=base_url,
                        evidence="Header 'Content-Security-Policy' not present.",
                    )
                )

            if "X-Frame-Options" not in headers:
                findings.append(
                    Finding(
                        title="Missing X-Frame-Options (Clickjacking Protection)",
                        severity=Severity.INFO if is_static else Severity.LOW,
                        category="Application Security",
                        description="Missing clickjacking protection. Third-party sites can embed this application inside an iframe to hijack user interactions.",
                        remediation="Set `X-Frame-Options: SAMEORIGIN` or `DENY`.",
                        target=base_url,
                        evidence="Header 'X-Frame-Options' not present.",
                    )
                )

            if "X-Content-Type-Options" not in headers:
                findings.append(
                    Finding(
                        title="Missing X-Content-Type-Options (MIME Sniffing Defense)",
                        severity=Severity.INFO if is_static else Severity.LOW,
                        category="Application Security",
                        description=(
                            "The `X-Content-Type-Options: nosniff` header is missing. "
                            "Browsers may ignore MIME types and execute non-script assets as executable code."
                        ),
                        remediation="Add `X-Content-Type-Options: nosniff` header to web server configuration.",
                        target=base_url,
                        evidence="Header 'X-Content-Type-Options' not present.",
                    )
                )

            if "Referrer-Policy" not in headers:
                findings.append(
                    Finding(
                        title="Missing Referrer-Policy Header",
                        severity=Severity.INFO if is_static else Severity.LOW,
                        category="Application Security",
                        description=(
                            "No Referrer-Policy header is defined. Browsers may leak confidential URLs "
                            "and query parameters in the Referer header to external destinations."
                        ),
                        remediation="Set `Referrer-Policy: strict-origin-when-cross-origin`.",
                        target=base_url,
                        evidence="Header 'Referrer-Policy' not present.",
                    )
                )

            if "Permissions-Policy" not in headers:
                findings.append(
                    Finding(
                        title="Missing Permissions-Policy Header",
                        severity=Severity.INFO,
                        category="Application Security",
                        description=(
                            "Permissions-Policy is missing. Modern web applications should explicitly restrict "
                            "unnecessary browser features (camera, microphone, geolocation, payment)."
                        ),
                        remediation="Configure `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
                        target=base_url,
                        evidence="Header 'Permissions-Policy' not present.",
                    )
                )

            if "Cross-Origin-Opener-Policy" not in headers:
                findings.append(
                    Finding(
                        title="Missing Cross-Origin-Opener-Policy (COOP)",
                        severity=Severity.INFO,
                        category="Application Security",
                        description=(
                            "COOP header is not set. Isolating top-level browsing contexts prevents "
                            "cross-origin Spectre and XS-Leak interactions."
                        ),
                        remediation="Configure `Cross-Origin-Opener-Policy: same-origin` or `same-origin-allow-popups`.",
                        target=base_url,
                        evidence="Header 'Cross-Origin-Opener-Policy' not present.",
                    )
                )

            # Server & Tech Stack Version Disclosure Audit
            server_hdr = headers.get("Server", "")
            powered_by = headers.get("X-Powered-By", "")
            disclosures = []
            if server_hdr and any(c.isdigit() for c in server_hdr):
                disclosures.append(f"Server: {server_hdr}")
            if powered_by:
                disclosures.append(f"X-Powered-By: {powered_by}")

            if disclosures:
                findings.append(
                    Finding(
                        title="Server / Tech Stack Version Disclosure",
                        severity=Severity.LOW,
                        category="Information Disclosure",
                        description=(
                            "The web server discloses detailed software or runtime version numbers in response headers. "
                            "Adversaries use these banners to map known CVEs to your environment."
                        ),
                        remediation=(
                            "Suppress detailed version numbers in server headers (e.g. 'ServerTokens Prod' in Apache, "
                            "'server_tokens off;' in Nginx, and disable 'X-Powered-By' in runtime configuration)."
                        ),
                        target=base_url,
                        evidence=" | ".join(disclosures),
                    )
                )
        except (ssl.SSLCertVerificationError, httpx.ConnectError) as e:
            err_str = str(e).lower()
            if "certificate" in err_str or "ssl" in err_str or "cert" in err_str:
                findings.append(
                    Finding(
                        title="SSL/TLS Certificate Verification Failure",
                        severity=Severity.HIGH,
                        category="Transport Security",
                        description=f"Automated HTTP TLS handshake failed certificate validation: {e}",
                        remediation="Deploy a valid, unexpired CA-signed SSL/TLS certificate for this domain.",
                        target=base_url,
                        evidence=str(e),
                    )
                )
        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()

        return findings

    def audit_ssl(self, domain: str, port: int = 443) -> Optional[Finding]:
        if not is_safe_host(domain):
            return Finding(
                title="Target Disallowed (SSRF / Internal Target)",
                severity=Severity.HIGH,
                category="Transport Security",
                description=f"Target {domain} resolves to private, loopback, or cloud metadata address.",
                remediation="Only public Internet domains can be audited.",
                target=domain,
                evidence=f"Blocked internal target: {domain}",
            )

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after_str = cert["notAfter"]
                    expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    days_remaining = (expiry_date - now).days

                    if days_remaining <= 0:
                        return Finding(
                            title="SSL/TLS Certificate Expired",
                            severity=Severity.CRITICAL,
                            category="Transport Security",
                            description=f"The SSL/TLS certificate for {domain} expired {abs(days_remaining)} days ago. Visitors receive security warnings and browsers block access.",
                            remediation="Renew and re-deploy the SSL/TLS certificate immediately.",
                            target=domain,
                            evidence=f"Expired on: {not_after_str}",
                        )
                    elif days_remaining <= 14:
                        return Finding(
                            title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} days left)",
                            severity=Severity.HIGH,
                            category="Transport Security",
                            description=f"Certificate for {domain} expires in {days_remaining} days.",
                            remediation="Ensure automated certificate renewal (Let's Encrypt / Certbot / Cloudflare) is active.",
                            target=domain,
                            evidence=f"Expires on: {not_after_str}",
                        )
            return None
        except Exception as e:
            return Finding(
                title="SSL/TLS Connection Failure",
                severity=Severity.HIGH,
                category="Transport Security",
                description=f"Could not establish a secure SSL/TLS connection to {domain}:{port}.",
                remediation="Verify web server HTTPS binding and certificate validity.",
                target=domain,
                evidence=str(e),
            )

    async def scan_domain(
        self,
        domain: str,
        subdomains: Optional[List[str]] = None,
        agency_branding: Optional[AgencyBranding] = None,
        use_crtsh: bool = True,
    ) -> DomainAuditResult:
        branding = agency_branding or AgencyBranding()
        result = DomainAuditResult(domain=domain, agency_branding=branding)

        # Pre-flight SSRF Validation
        if not await async_is_safe_host(domain):
            result.findings.append(
                Finding(
                    title="Target Disallowed (SSRF / Internal IP)",
                    severity=Severity.HIGH,
                    category="Input Validation",
                    description=f"Scanning internal, loopback, or cloud metadata target '{domain}' is blocked by Orbit Security SSRF guards.",
                    remediation="Provide a public fully-qualified domain name (FQDN).",
                    target=domain,
                    evidence=f"Target resolves to private or metadata space: {domain}",
                )
            )
            result.calculate_grade_and_score()
            return result

        subs_to_check = set(subdomains or [])

        # Hardened discovery: Certificate Transparency logs with pooled client
        async with self.create_http_client() as shared_client:
            if use_crtsh:
                ct_subs = await self.fetch_subdomains_from_crtsh(domain, client=shared_client)
                for s in ct_subs:
                    subs_to_check.add(s)

            # Baseline common candidates
            default_candidates = [
                f"staging.{domain}",
                f"dev.{domain}",
                f"test.{domain}",
                f"promo.{domain}",
                f"blog.{domain}",
                f"app.{domain}",
                f"shop.{domain}",
                f"vpn.{domain}",
                f"mail.{domain}",
            ]
            for s in default_candidates:
                subs_to_check.add(s)

            result.subdomains_scanned = sorted(list(subs_to_check))

            # Run mail audits (SPF, DMARC, BIMI, MTA-STS, TLS-RPT)
            dmarc_finding = await self.audit_dmarc(domain)
            if dmarc_finding:
                result.findings.append(dmarc_finding)

            spf_finding = await self.audit_spf(domain)
            if spf_finding:
                result.findings.append(spf_finding)

            bimi_finding = await self.audit_bimi(domain)
            if bimi_finding:
                result.findings.append(bimi_finding)

            mta_sts_finding = await self.audit_mta_sts(domain)
            if mta_sts_finding:
                result.findings.append(mta_sts_finding)

            tls_rpt_finding = await self.audit_tls_rpt(domain)
            if tls_rpt_finding:
                result.findings.append(tls_rpt_finding)

            # Audit CAA policy (RFC 8659)
            caa_finding = await self.audit_caa(domain)
            if caa_finding:
                result.findings.append(caa_finding)

            # Run exposure and header audits on apex domain
            base_url = f"https://{domain}"
            exposure_findings = await self.audit_exposures(base_url, client=shared_client)
            result.findings.extend(exposure_findings)

            header_findings = await self.audit_security_headers(base_url, client=shared_client)
            result.findings.extend(header_findings)

            # Audit RFC 9116 security.txt disclosure
            security_txt_finding = await self.audit_security_txt(base_url, client=shared_client)
            if security_txt_finding:
                result.findings.append(security_txt_finding)

            # Run SSL check on apex in worker thread to prevent event loop blocking
            ssl_finding = await asyncio.to_thread(self.audit_ssl, domain)
            if ssl_finding:
                result.findings.append(ssl_finding)

            # Run subdomain takeover checks concurrently with bounded semaphore (tuned for 8 logical threads)
            sem = asyncio.Semaphore(8)

            async def bounded_takeover(sub: str):
                async with sem:
                    return await self.check_subdomain_takeover(sub, client=shared_client)

            takeover_tasks = [bounded_takeover(sub) for sub in result.subdomains_scanned]
            takeover_results = await asyncio.gather(*takeover_tasks, return_exceptions=True)
            for res in takeover_results:
                if isinstance(res, Finding):
                    result.findings.append(res)

        result.calculate_grade_and_score()
        return result


# Backward compatibility alias
AgencySentryScanner = OrbitSecurityScanner
