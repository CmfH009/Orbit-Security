"""Orbit Security Automated DNS Remediation Generator (remediation.py).

Produces exact copy-paste DNS records and Terraform HCL blocks
for Cloudflare, AWS Route 53, GoDaddy, and Namecheap to resolve
dangling CNAME takeovers, missing/weak DMARC, and permissive SPF records.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import re


@dataclass
class RemediationSnippet:
    provider: str
    record_type: str
    host_name: str
    record_value: str
    ttl: int
    instructions: str
    terraform_hcl: str


class DnsRemediationGenerator:
    """Generates precise copy-paste remediation instructions for common perimeter vulnerabilities."""

    @staticmethod
    def generate_dmarc_fix(
        domain: str,
        policy: str = "quarantine",
        report_email: Optional[str] = None,
    ) -> List[RemediationSnippet]:
        """Generates DMARC TXT record remediation for all major DNS providers."""
        target_host = f"_dmarc.{domain}".strip(".")
        report_tag = f" rua=mailto:{report_email};" if report_email else ""
        dmarc_txt = f"v=DMARC1; p={policy}; sp={policy}; adkim=r; aspf=r;{report_tag}"

        cloudflare = RemediationSnippet(
            provider="Cloudflare",
            record_type="TXT",
            host_name="_dmarc",
            record_value=f'"{dmarc_txt}"',
            ttl=1,  # Auto
            instructions="In Cloudflare Dashboard -> DNS Records -> Add Record -> Type: TXT, Name: _dmarc, Content: paste the record value below. Proxy status: DNS only.",
            terraform_hcl=f'''resource "cloudflare_record" "dmarc" {{
  zone_id = var.cloudflare_zone_id
  name    = "_dmarc"
  content = "{dmarc_txt}"
  type    = "TXT"
  ttl     = 1
}}''',
        )

        route53 = RemediationSnippet(
            provider="AWS Route 53",
            record_type="TXT",
            host_name=f"_dmarc.{domain}",
            record_value=f'"{dmarc_txt}"',
            ttl=300,
            instructions="In AWS Route 53 Console -> Hosted Zones -> select domain -> Create record -> Record name: _dmarc, Record type: TXT, Value: paste in quotes.",
            terraform_hcl=f'''resource "aws_route53_record" "dmarc" {{
  zone_id = var.route53_zone_id
  name    = "_dmarc.{domain}"
  type    = "TXT"
  ttl     = 300
  records = ["{dmarc_txt}"]
}}''',
        )

        godaddy = RemediationSnippet(
            provider="GoDaddy",
            record_type="TXT",
            host_name="_dmarc",
            record_value=dmarc_txt,
            ttl=3600,
            instructions="In GoDaddy Domain Management -> DNS Records -> Add -> Type: TXT, Name: _dmarc, Value: paste the string, TTL: 1 Hour.",
            terraform_hcl="# GoDaddy does not have an official Terraform provider.",
        )

        namecheap = RemediationSnippet(
            provider="Namecheap",
            record_type="TXT Record",
            host_name="_dmarc",
            record_value=dmarc_txt,
            ttl=1800,
            instructions="In Namecheap Advanced DNS -> Add New Record -> TXT Record, Host: _dmarc, Value: paste string, TTL: Automatic (or 30 min).",
            terraform_hcl="# Namecheap provider optional.",
        )

        return [cloudflare, route53, godaddy, namecheap]

    @staticmethod
    def generate_spf_fix(
        domain: str,
        include_providers: Optional[List[str]] = None,
        hard_fail: bool = True,
    ) -> List[RemediationSnippet]:
        """Generates SPF TXT record remediation."""
        includes = include_providers or ["_spf.google.com"]
        include_str = " ".join([f"include:{inc.strip()}" for inc in includes])
        qualifier = "-all" if hard_fail else "~all"
        spf_txt = f"v=spf1 {include_str} {qualifier}"

        cloudflare = RemediationSnippet(
            provider="Cloudflare",
            record_type="TXT",
            host_name="@",
            record_value=f'"{spf_txt}"',
            ttl=1,
            instructions="In Cloudflare Dashboard -> DNS Records -> Add Record -> Type: TXT, Name: @, Content: paste the record value below.",
            terraform_hcl=f'''resource "cloudflare_record" "spf" {{
  zone_id = var.cloudflare_zone_id
  name    = "@"
  content = "{spf_txt}"
  type    = "TXT"
  ttl     = 1
}}''',
        )

        route53 = RemediationSnippet(
            provider="AWS Route 53",
            record_type="TXT",
            host_name=domain,
            record_value=f'"{spf_txt}"',
            ttl=300,
            instructions="In AWS Route 53 Console -> Create record -> Record name: [blank/apex], Record type: TXT, Value: paste in quotes.",
            terraform_hcl=f'''resource "aws_route53_record" "spf" {{
  zone_id = var.route53_zone_id
  name    = "{domain}"
  type    = "TXT"
  ttl     = 300
  records = ["{spf_txt}"]
}}''',
        )

        return [cloudflare, route53]

    @staticmethod
    def generate_takeover_remediation(
        subdomain: str,
        saas_provider: str,
        cname_target: str,
    ) -> Dict[str, str]:
        """Generates specific step-by-step instructions to eliminate dangling CNAME takeover risk."""
        return {
            "subdomain": subdomain,
            "saas_provider": saas_provider,
            "cname_target": cname_target,
            "action_immediate": f"Delete the dangling CNAME DNS record for `{subdomain}` pointing to `{cname_target}` immediately.",
            "option_reclaim": f"If this subdomain is still needed, log into {saas_provider} and configure custom domain binding for `{subdomain}` to claim ownership before third parties.",
            "option_decommission": f"If the marketing campaign or app was retired, delete the DNS record `{subdomain} CNAME {cname_target}` in your DNS manager.",
            "cli_verification": f"orbit-recon {subdomain}",
        }

    @staticmethod
    def generate_caa_fix(
        domain: str,
        ca_list: Optional[List[str]] = None,
        alert_email: Optional[str] = None,
    ) -> List[RemediationSnippet]:
        """Generates DNS CAA (RFC 8659) remediation snippets for Cloudflare and Route 53."""
        cas = ca_list or ["letsencrypt.org", "digicert.com"]
        iodef = f'0 iodef "mailto:{alert_email}"' if alert_email else ""

        caa_records_cf = []
        caa_records_r53 = []
        for ca in cas:
            caa_records_cf.append(f'0 issue "{ca}"')
            caa_records_r53.append(f'0 issue "{ca}"')
        if iodef:
            caa_records_cf.append(iodef)
            caa_records_r53.append(iodef)

        cf_val = " | ".join(caa_records_cf)
        r53_formatted = ", ".join([f'"{r}"' for r in caa_records_r53])

        cloudflare = RemediationSnippet(
            provider="Cloudflare",
            record_type="CAA",
            host_name="@",
            record_value=cf_val,
            ttl=1,
            instructions="In Cloudflare Dashboard -> DNS Records -> Add Record -> Type: CAA, Name: @, Tag: Only allow specific CAs (issue), CA Domain: paste approved CAs.",
            terraform_hcl=f'''resource "cloudflare_record" "caa" {{
  zone_id = var.cloudflare_zone_id
  name    = "@"
  data {{
    flags = "0"
    tag   = "issue"
    value = "{cas[0]}"
  }}
  type    = "CAA"
  ttl     = 1
}}''',
        )

        route53 = RemediationSnippet(
            provider="AWS Route 53",
            record_type="CAA",
            host_name=domain,
            record_value=f"[{r53_formatted}]",
            ttl=300,
            instructions="In AWS Route 53 Console -> Create record -> Record name: [apex], Record type: CAA, Value: list each rule per line.",
            terraform_hcl=f'''resource "aws_route53_record" "caa" {{
  zone_id = var.route53_zone_id
  name    = "{domain}"
  type    = "CAA"
  ttl     = 300
  records = [{r53_formatted}]
}}''',
        )

        return [cloudflare, route53]

    @staticmethod
    def generate_security_txt(
        domain: str,
        contact_email: Optional[str] = None,
        policy_url: Optional[str] = None,
        days_valid: int = 365,
    ) -> str:
        """Generates RFC 9116 compliant security.txt content."""
        from datetime import datetime, timezone, timedelta

        email = contact_email or f"security@{domain}"
        expiry = datetime.now(timezone.utc) + timedelta(days=days_valid)
        expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = policy_url or f"https://{domain}/security"

        lines = [
            "# Orbit Security: RFC 9116 Vulnerability Disclosure Standard",
            f"Contact: mailto:{email}",
            f"Expires: {expiry_str}",
            "Preferred-Languages: en",
            f"Canonical: https://{domain}/.well-known/security.txt",
            f"Policy: {policy}",
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def generate_nginx_php_teapot_shield(domain: str = "example.com") -> str:
        """Generates Nginx HTTP 418 'I'm a teapot' sinkhole rules & php.ini hardening for PHP bot scanners.

        Neutralizes:
        1. Exposed Composer / PHPUnit RCE (`eval-stdin.php` / CVE-2017-9841)
        2. ThinkPHP `invokefunction` / `call_user_func_array` RCE probes
        3. PEAR `pearcmd.php` Local File Inclusion (LFI) / RCE (`register_argc_argv`)
        """
        return f"""# Orbit Security: Nginx HTTP 418 ("I'm a teapot") PHP Bot Sinkhole & Perimeter Shield
# Target Domain: {domain}

# 1. Block public access to Composer /vendor/, PHPUnit eval-stdin.php (CVE-2017-9841), and dotfiles
location ~* (?:/vendor/|eval-stdin\\.php|/\\.(?:env|git|DS_Store)|wp-config\\.php\\.(?:bak|old)|phpinfo\\.php) {{
    access_log /var/log/nginx/orbit_teapot_sinkhole.log;
    return 418;
}}

# 2. Sinkhole ThinkPHP invokefunction RCE & pearcmd.php LFI/RCE query-string probes with HTTP 418
if ($query_string ~* "(?:invokefunction|call_user_func_array|pearcmd|\\+config-create\\+|\\.\\./\\.\\./)") {{
    return 418;
}}

# 3. php.ini Runtime Hardening (neutralizes pearcmd CLI argument injection & X-Powered-By fingerprinting)
# Add to /etc/php/php.ini:
# expose_php = Off
# register_argc_argv = Off
# allow_url_include = Off
"""

    @classmethod
    def generate_full_package(
        cls,
        domain: str,
        output_dir: Optional[Path] = None,
        policy: str = "quarantine",
        report_email: Optional[str] = None,
        generate_pdf: bool = False,
    ) -> Dict[str, Any]:
        """Generates all 5 remediation deliverables: .zone, .tf, security.txt, summary.txt, and PDF."""
        import datetime
        out = output_dir or (Path("outbound_campaigns") / domain.replace(".", "_"))
        out.mkdir(parents=True, exist_ok=True)

        dmarc_snippets = cls.generate_dmarc_fix(domain, policy=policy, report_email=report_email)
        spf_snippets = cls.generate_spf_fix(domain, hard_fail=True)
        caa_snippets = cls.generate_caa_fix(domain, alert_email=report_email)
        sec_txt = cls.generate_security_txt(domain, contact_email=report_email)

        # 1. BIND Zone File (Cloudflare DNS 1-click importable)
        zone_lines = [
            f"; Orbit Security RFC 1035 BIND Zone Remediation File for {domain}",
            f"; Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            "$ORIGIN " + domain + ".",
            "$TTL 300",
            f'_dmarc\tIN\tTXT\t{dmarc_snippets[0].record_value}',
            f'@\tIN\tTXT\t{spf_snippets[0].record_value}',
            f'@\tIN\tCAA\t0 issue "letsencrypt.org"',
            f'@\tIN\tCAA\t0 issue "digicert.com"',
        ]
        zone_path = out / "remediation.zone"
        zone_path.write_text("\n".join(zone_lines) + "\n", encoding="utf-8")

        # 2. Terraform HCL
        tf_blocks = [
            "# Orbit Security: Terraform DNS Remediation Blueprint",
            dmarc_snippets[0].terraform_hcl,
            spf_snippets[0].terraform_hcl,
            caa_snippets[0].terraform_hcl,
        ]
        tf_path = out / "remediation.tf"
        tf_path.write_text("\n\n".join(tf_blocks) + "\n", encoding="utf-8")

        # 3. security.txt
        sec_path = out / "security.txt"
        sec_path.write_text(sec_txt, encoding="utf-8")

        # 4. remediation_summary.txt
        summary_lines = [
            f"=== ORBIT SECURITY REMEDIATION BLUEPRINT: {domain} ===",
            f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            "",
            "1. DMARC POLICY ENFORCEMENT:",
            f"   Record: _dmarc.{domain} TXT {dmarc_snippets[0].record_value}",
            f"   Action: {dmarc_snippets[0].instructions}",
            "",
            "2. SPF STRICT HARD-FAIL:",
            f"   Record: {domain} TXT {spf_snippets[0].record_value}",
            f"   Action: {spf_snippets[0].instructions}",
            "",
            "3. CAA RESTRICTION:",
            f"   Record: {domain} CAA 0 issue \"letsencrypt.org\"",
            "",
            "Files Generated:",
            f" - {zone_path.name} (BIND zone file importable in Cloudflare DNS)",
            f" - {tf_path.name} (Terraform HCL infrastructure-as-code)",
            f" - {sec_path.name} (RFC 9116 security policy)",
        ]
        summary_path = out / "remediation_summary.txt"
        summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

        # 5. Optional PDF report
        pdf_path = None
        if generate_pdf:
            try:
                from orbit_security.reporter import ReportGenerator
                from orbit_security.models import DomainAuditResult, VulnerabilityFinding, Severity
                pdf_file = out / f"{domain.replace('.', '_')}_dns_remediation.pdf"
                dummy_audit = DomainAuditResult(
                    domain=domain,
                    score=75,
                    grade="C",
                    findings=[
                        VulnerabilityFinding(
                            title="Missing DMARC Policy Enforcement",
                            severity=Severity.HIGH,
                            description=f"Domain {domain} lacks strict DMARC quarantine/reject policy.",
                            remediation=dmarc_snippets[0].instructions,
                            evidence="p=none or missing",
                        )
                    ],
                )
                ReportGenerator.generate_pdf(dummy_audit, output_path=pdf_file)
                pdf_path = pdf_file
            except Exception as e:
                import logging
                logging.getLogger("orbit_security.remediation").warning(f"Failed to generate remediation PDF: {e}")

        return {
            "domain": domain,
            "output_dir": str(out),
            "zone_file": str(zone_path),
            "terraform_file": str(tf_path),
            "security_txt": str(sec_path),
            "summary_file": str(summary_path),
            "pdf_file": str(pdf_path) if pdf_path else None,
        }

