"""Orbit Security Automated DNS Remediation Generator (remediation.py).

Produces exact copy-paste DNS records and Terraform HCL blocks
for Cloudflare, AWS Route 53, GoDaddy, and Namecheap to resolve
dangling CNAME takeovers, missing/weak DMARC, and permissive SPF records.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
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
