import asyncio
import datetime
import socket
import ssl
from typing import List, Optional, Set
import dns.asyncresolver
import httpx

from orbit_security.models import AgencyBranding, DomainAuditResult, Finding, Severity
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES


class OrbitSecurityScanner:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout

    async def fetch_subdomains_from_crtsh(
        self, domain: str, client: Optional[httpx.AsyncClient] = None
    ) -> List[str]:
        """Discovers all subdomains registered via Certificate Transparency logs (crt.sh)."""
        discovered: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False)
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
                        if clean_name.endswith(domain) and clean_name != domain:
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
                for string in rdata.strings:
                    records.append(string.decode("utf-8", errors="ignore"))
            dmarc_record = next((r for r in records if r.startswith("v=DMARC1")), None)

            if not dmarc_record:
                return Finding(
                    title="Missing DMARC Email Protection",
                    severity=Severity.HIGH,
                    category="Email Authentication",
                    description=f"Domain {domain} lacks a valid DMARC record. Attackers can forge emails from this domain to execute phishing attacks.",
                    remediation=f"Add a TXT record for `_dmarc.{domain}` with at least `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`.",
                    target=target,
                    evidence="No v=DMARC1 TXT record found."
                )

            if "p=none" in dmarc_record:
                return Finding(
                    title="DMARC Policy in Inactive Monitoring Mode (p=none)",
                    severity=Severity.MEDIUM,
                    category="Email Authentication",
                    description="The DMARC policy is set to `p=none`. Spoofed emails from attackers are still delivered to recipient inboxes without rejection or quarantine.",
                    remediation="Upgrade policy from `p=none` to `p=quarantine` or `p=reject` after reviewing authentication reports.",
                    target=target,
                    evidence=dmarc_record
                )
            return None
        except Exception as e:
            return Finding(
                title="Missing DMARC Email Protection",
                severity=Severity.HIGH,
                category="Email Authentication",
                description=f"No DMARC record found for {domain}. Fraudsters can impersonate your brand in executive or billing phishing schemes.",
                remediation=f"Add a DNS TXT record for `_dmarc.{domain}` with policy `p=quarantine` or `p=reject`.",
                target=target,
                evidence=str(e)
            )

    async def audit_spf(self, domain: str) -> Optional[Finding]:
        try:
            answers = await self.resolver.resolve(domain, "TXT")
            records = []
            for rdata in answers:
                for string in rdata.strings:
                    records.append(string.decode("utf-8", errors="ignore"))
            spf_record = next((r for r in records if r.startswith("v=spf1")), None)

            if not spf_record:
                return Finding(
                    title="Missing SPF Record",
                    severity=Severity.HIGH,
                    category="Email Authentication",
                    description=f"Domain {domain} does not have an SPF (Sender Policy Framework) record published.",
                    remediation="Define an authorized list of mail servers using a TXT record `v=spf1 ... -all`.",
                    target=domain,
                    evidence="No v=spf1 TXT record located."
                )

            if "+all" in spf_record:
                return Finding(
                    title="Dangerously Permissive SPF (+all)",
                    severity=Severity.CRITICAL,
                    category="Email Authentication",
                    description="SPF record explicitly authorizes all IP addresses on the internet to send mail on behalf of this domain.",
                    remediation="Replace `+all` with `~all` or `-all`.",
                    target=domain,
                    evidence=spf_record
                )
            return None
        except Exception as e:
            return Finding(
                title="Missing SPF Record",
                severity=Severity.HIGH,
                category="Email Authentication",
                description=f"Unable to resolve SPF record for {domain}.",
                remediation=f"Publish a TXT record starting with `v=spf1` on {domain}.",
                target=domain,
                evidence=str(e)
            )

    async def check_subdomain_takeover(
        self, subdomain: str, client: Optional[httpx.AsyncClient] = None
    ) -> Optional[Finding]:
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
                    try:
                        should_close = False
                        if client is None:
                            client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False)
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
                                            evidence=f"CNAME: {cname} | Matched fingerprint: '{fp}' (Status: {resp.status_code})"
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
        findings: List[Finding] = []
        checks = [
            (
                "/.env",
                ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SECRET_KEY", "DATABASE_URL", "API_KEY", "REDIS_PASSWORD"],
                "Exposed Environment Secrets (.env)",
                Severity.CRITICAL,
                "The environment secrets file is publicly readable on the web root. Credentials, API keys, and database passwords are exposed.",
                "Immediately block web access to dotfiles (`/.env`) in web server configuration and rotate all exposed credentials."
            ),
            (
                "/.git/HEAD",
                ["ref: refs/heads/", "ref: refs/tags/"],
                "Exposed Git Repository Metadata (/.git)",
                Severity.CRITICAL,
                "The `.git` metadata folder is publicly accessible, allowing automated tooling to reconstruct full source code and commit history.",
                "Deny access to `/.git` in your web server config or remove the `.git` directory from the production web root."
            ),
            (
                "/.git/config",
                ["[core]", "[remote \"origin\"]", "url = "],
                "Exposed Git Configuration (/.git/config)",
                Severity.CRITICAL,
                "The internal git configuration file is exposed, disclosing repository origin URLs, tokens, and branch structure.",
                "Block web access to all `.git` paths."
            ),
            (
                "/wp-config.php.bak",
                ["DB_PASSWORD", "DB_NAME", "table_prefix", "AUTH_KEY"],
                "Exposed WordPress Configuration Backup",
                Severity.CRITICAL,
                "A plaintext backup file of wp-config.php was left on the web server, leaking database credentials and secret authentication keys.",
                "Delete `.bak` and `.old` files from production web server roots immediately."
            ),
            (
                "/docker-compose.yml",
                ["version:", "services:", "image:", "environment:"],
                "Exposed Docker Compose File",
                Severity.HIGH,
                "A docker-compose file is exposed on the web root, leaking internal container architecture, ports, and environment variables.",
                "Remove container definition files from the public web root."
            ),
            (
                "/.DS_Store",
                ["Bud1"],
                "Exposed macOS .DS_Store Metadata",
                Severity.LOW,
                "Directory metadata file left by macOS Finder is accessible, revealing internal file and folder names.",
                "Remove .DS_Store files and add them to `.gitignore` and web server block lists."
            ),
        ]

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False)
            should_close = True

        try:
            clean_base = base_url.rstrip("/")
            for path, needles, title, severity, desc, remed in checks:
                url = f"{clean_base}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        matched = [n for n in needles if n in resp.text]
                        if matched:
                            findings.append(
                                Finding(
                                    title=title,
                                    severity=severity,
                                    category="Exposed Assets",
                                    description=desc,
                                    remediation=remed,
                                    target=url,
                                    evidence=f"HTTP 200 OK | Matches: {', '.join(matched)}"
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
        findings: List[Finding] = []
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False)
            should_close = True

        try:
            resp = await client.get(base_url)
            headers = resp.headers

            if "Strict-Transport-Security" not in headers:
                findings.append(
                    Finding(
                        title="Missing HSTS Header (HTTP Strict Transport Security)",
                        severity=Severity.MEDIUM,
                        category="Transport Security",
                        description="HSTS is not configured. Browsers can be downgraded to unencrypted HTTP via man-in-the-middle attacks.",
                        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header to web server responses.",
                        target=base_url,
                        evidence="Header 'Strict-Transport-Security' not present."
                    )
                )

            if "Content-Security-Policy" not in headers:
                findings.append(
                    Finding(
                        title="Missing Content Security Policy (CSP)",
                        severity=Severity.LOW,
                        category="Application Security",
                        description="CSP header is absent. Restricting sources of scripts, images, and frames prevents cross-site scripting (XSS) and data injection.",
                        remediation="Define a baseline `Content-Security-Policy` header allowing only trusted asset origins.",
                        target=base_url,
                        evidence="Header 'Content-Security-Policy' not present."
                    )
                )

            if "X-Frame-Options" not in headers:
                findings.append(
                    Finding(
                        title="Missing X-Frame-Options (Clickjacking Protection)",
                        severity=Severity.LOW,
                        category="Application Security",
                        description="Missing clickjacking protection. Third-party sites can embed this application inside an iframe to hijack user interactions.",
                        remediation="Set `X-Frame-Options: SAMEORIGIN` or `DENY`.",
                        target=base_url,
                        evidence="Header 'X-Frame-Options' not present."
                    )
                )
        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()

        return findings

    def audit_ssl(self, domain: str, port: int = 443) -> Optional[Finding]:
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
                            evidence=f"Expired on: {not_after_str}"
                        )
                    elif days_remaining <= 14:
                        return Finding(
                            title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} days left)",
                            severity=Severity.HIGH,
                            category="Transport Security",
                            description=f"Certificate for {domain} expires in {days_remaining} days.",
                            remediation="Ensure automated certificate renewal (Let's Encrypt / Certbot / Cloudflare) is active.",
                            target=domain,
                            evidence=f"Expires on: {not_after_str}"
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
                evidence=str(e)
            )

    async def scan_domain(
        self,
        domain: str,
        subdomains: Optional[List[str]] = None,
        agency_branding: Optional[AgencyBranding] = None,
        use_crtsh: bool = True
    ) -> DomainAuditResult:
        branding = agency_branding or AgencyBranding()
        result = DomainAuditResult(domain=domain, agency_branding=branding)

        subs_to_check = set(subdomains or [])

        # Hardened discovery: Certificate Transparency logs
        if use_crtsh:
            ct_subs = await self.fetch_subdomains_from_crtsh(domain)
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

        # Run mail audits
        dmarc_finding = await self.audit_dmarc(domain)
        if dmarc_finding:
            result.findings.append(dmarc_finding)

        spf_finding = await self.audit_spf(domain)
        if spf_finding:
            result.findings.append(spf_finding)

        # Run exposure and header audits on apex domain
        base_url = f"https://{domain}"
        exposure_findings = await self.audit_exposures(base_url)
        result.findings.extend(exposure_findings)

        header_findings = await self.audit_security_headers(base_url)
        result.findings.extend(header_findings)

        # Run SSL check on apex
        ssl_finding = self.audit_ssl(domain)
        if ssl_finding:
            result.findings.append(ssl_finding)

        # Run subdomain takeover checks concurrently
        takeover_tasks = [self.check_subdomain_takeover(sub) for sub in result.subdomains_scanned]
        takeover_results = await asyncio.gather(*takeover_tasks, return_exceptions=True)
        for res in takeover_results:
            if isinstance(res, Finding):
                result.findings.append(res)

        result.calculate_grade_and_score()
        return result


# Backward compatibility alias
AgencySentryScanner = OrbitSecurityScanner
