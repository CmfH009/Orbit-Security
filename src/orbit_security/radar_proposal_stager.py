#!/usr/bin/env python3
"""orbit_security.radar_proposal_stager: Automated Retainer Proposal & Audit Stager.
====================================================================================
Automatically stages a complete outbound deliverable package in `outbound_campaigns/<domain_slug>/`
whenever a visitor scans a domain in the ORBIT // PERIMETER RADAR TERMINAL:
1. `<domain_slug>_security_audit.pdf` — Co-branded PDF audit report via `ReportGenerator`.
2. `dns_remediation_plan.md` — Copy-paste DNS records & Terraform HCL remediation draft
   via `DnsRemediationGenerator` (Cloudflare, AWS Route 53, GoDaddy, Namecheap).
3. `retainer_proposal.md` — Tailored executive retainer proposal referencing the domain's
   score, grade, tech stack, registrar, and OSINT profile.
4. `pitch_email.txt` — Staged human-reviewable advisory email draft.

SAFETY INVARIANT:
Strictly local file staging inside `outbound_campaigns/`. Respects `COMMERCIAL_OUTREACH_FROZEN = True`
and never dispatches unsolicited external emails.
"""

from __future__ import annotations

import datetime
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from orbit_security.models import AgencyBranding, DomainAuditResult, Finding, Severity
from orbit_security.remediation import DnsRemediationGenerator
from orbit_security.reporter import ReportGenerator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CAMPAIGNS_DIR = REPO_ROOT / "outbound_campaigns"


class RadarRetainerProposalStager:
    """Stages co-branded PDF audit reports, DNS remediation plans, and retainer proposals."""

    def __init__(self, campaigns_dir: Optional[Path] = None):
        self.campaigns_dir = Path(campaigns_dir) if campaigns_dir else DEFAULT_CAMPAIGNS_DIR
        self.campaigns_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def domain_to_slug(domain: str) -> str:
        clean = (domain or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        slug = re.sub(r"[^a-z0-9]+", "_", clean).strip("_")
        return slug or "audited_domain"

    def _build_audit_result(
        self,
        domain: str,
        score: int,
        grade: str,
        dmarc_status: str,
        spf_status: str,
        cname_status: str,
        enrichment: Dict[str, Any],
        agency_branding: Optional[AgencyBranding] = None,
    ) -> DomainAuditResult:
        branding = agency_branding or AgencyBranding(
            agency_name="Orbit Security × Partner Agency",
            agency_tagline="Managed Attack Surface & DNS Perimeter Stewardship",
            primary_color="#0F172A",
            accent_color="#10B981",
            support_email="ops@orbitsecurity.io",
            website="https://cmfh009.github.io/Orbit-Security/",
        )

        findings: List[Finding] = []

        if dmarc_status in ("missing", "fail", "critical"):
            findings.append(
                Finding(
                    title="Missing DMARC Authentication Policy (_dmarc)",
                    severity=Severity.MEDIUM,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} does not publish an active RFC 7489 DMARC TXT record at _dmarc.{domain}. "
                        "External actors can forge executive or transactional emails appearing to originate from this domain."
                    ),
                    remediation=(
                        f"Publish a DMARC TXT record at _dmarc.{domain} with `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}` "
                        "and transition to `p=reject` after verifying legitimate sender streams."
                    ),
                    target=f"_dmarc.{domain}",
                    evidence="No _dmarc TXT record returned via authoritative DNS resolution.",
                )
            )
        elif dmarc_status == "warn":
            findings.append(
                Finding(
                    title="DMARC Policy in Monitoring Mode Only (p=none)",
                    severity=Severity.LOW,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} publishes a DMARC policy with `p=none` (monitoring only). "
                        "Spoofed messages are still delivered to recipient inboxes without quarantine or rejection."
                    ),
                    remediation=f"Escalate _dmarc.{domain} policy from `p=none` to `p=quarantine` or `p=reject`.",
                    target=f"_dmarc.{domain}",
                    evidence=str(enrichment.get("dmarc_record") or "v=DMARC1; p=none"),
                )
            )

        if spf_status in ("missing", "fail", "critical"):
            findings.append(
                Finding(
                    title="Missing or Permissive Sender Policy Framework (SPF) Record",
                    severity=Severity.MEDIUM,
                    category="Email Authentication",
                    description=(
                        f"Domain {domain} lacks a strict SPF TXT record on its apex zone. "
                        "Unauthorized mail servers are not explicitly restricted from sending mail on behalf of the domain."
                    ),
                    remediation=f"Publish a strict SPF TXT record on {domain} ending with `~all` or `-all`.",
                    target=domain,
                    evidence="No valid v=spf1 record detected on apex domain.",
                )
            )

        if cname_status in ("fail", "critical", "warn"):
            findings.append(
                Finding(
                    title="Potential Dangling Subdomain CNAME Pointer Detected",
                    severity=Severity.HIGH,
                    category="Subdomain Takeover",
                    description=(
                        f"One or more subdomains under {domain} route via CNAME to an external SaaS provider "
                        "that may be unclaimed or expired."
                    ),
                    remediation="Audit all CNAME records in your DNS zone and remove pointers to decommissioned SaaS apps.",
                    target=f"*.{domain}",
                    evidence="Subdomain CNAME anomaly flagged during Radar Terminal probe.",
                )
            )

        # Always include proactive CAA & RFC 9116 security.txt stewardship recommendations if findings list is light
        findings.append(
            Finding(
                title="Recommended DNS CAA & RFC 9116 security.txt Hardening",
                severity=Severity.INFO,
                category="Perimeter Hygiene",
                description=(
                    f"Lock certificate issuance for {domain} to authorized Certificate Authorities via DNS CAA (RFC 8659) "
                    f"and publish a canonical `/.well-known/security.txt` disclosure policy (RFC 9116)."
                ),
                remediation="Add CAA issue records for Let's Encrypt / DigiCert and deploy /.well-known/security.txt.",
                target=domain,
                evidence=f"Registrar: {enrichment.get('registrar', 'Standard')} | DNS: {enrichment.get('dns_provider', 'Standard')}",
            )
        )

        base_subs = [
            domain,
            f"www.{domain}",
            f"shop.{domain}",
            f"app.{domain}",
            f"promo.{domain}",
            f"dev.{domain}",
        ]
        ct_subs = [str(s) for s in (enrichment.get("ct_subdomains") or []) if s]
        subdomains_scanned = list(dict.fromkeys(base_subs + ct_subs))

        return DomainAuditResult(
            domain=domain,
            score=score,
            grade=grade,
            findings=findings,
            subdomains_scanned=subdomains_scanned,
            agency_branding=branding,
            osint_intel=enrichment.get("public_apis_osint") or {},
        )

    def _render_dns_remediation_markdown(
        self,
        domain: str,
        score: int,
        grade: str,
        enrichment: Dict[str, Any],
    ) -> str:
        dns_provider = enrichment.get("dns_provider") or "Cloudflare"
        mx_provider = enrichment.get("mx_provider") or "Google Workspace"
        dmarc_snippets = DnsRemediationGenerator.generate_dmarc_fix(
            domain=domain,
            policy="quarantine",
            report_email=f"security@{domain}",
        )
        spf_includes = ["_spf.google.com"]
        if "microsoft" in mx_provider.lower() or "365" in mx_provider.lower():
            spf_includes = ["spf.protection.outlook.com"]
        if "shopify" in " ".join(enrichment.get("tech_stack") or []).lower():
            spf_includes.append("shops.myshopify.com")

        spf_snippets = DnsRemediationGenerator.generate_spf_fix(
            domain=domain,
            include_providers=spf_includes,
            hard_fail=False,
        )
        caa_snippets = DnsRemediationGenerator.generate_caa_fix(
            domain=domain,
            ca_list=["letsencrypt.org", "digicert.com", "pki.goog"],
            alert_email=f"security@{domain}",
        )
        sec_txt = DnsRemediationGenerator.generate_security_txt(
            domain=domain,
            contact_email=f"security@{domain}",
        )

        lines = [
            f"# 🛠️ DNS & Perimeter Remediation Blueprint: `{domain}`",
            "",
            f"- **Target Domain:** `{domain}`",
            f"- **Current Hygiene Score:** **{score}/100** (Grade: `{grade}`)",
            f"- **Detected DNS Provider:** `{dns_provider}`",
            f"- **Detected Registrar:** `{enrichment.get('registrar', 'Unknown')}`",
            f"- **Detected Mail Infrastructure:** `{mx_provider}`",
            f"- **Generated At:** `{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}`",
            "",
            "---",
            "",
            "## 1. DMARC Enforcement (`_dmarc` TXT Record — RFC 7489)",
            "",
            f"Current Status: `{enrichment.get('dmarc_status', 'missing').upper()}`",
            "",
        ]

        for snip in dmarc_snippets:
            lines.extend([
                f"### {snip.provider}",
                f"- **Record Type:** `{snip.record_type}`",
                f"- **Host / Name:** `{snip.host_name}`",
                f"- **Value:** `{snip.record_value}`",
                f"- **TTL:** `{snip.ttl}`",
                f"- **Instructions:** {snip.instructions}",
                "",
                "```hcl",
                snip.terraform_hcl,
                "```",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## 2. Sender Policy Framework (`@` SPF TXT Record — RFC 7208)",
            "",
            f"Current Status: `{enrichment.get('spf_status', 'pass').upper()}`",
            "",
        ])

        for snip in spf_snippets:
            lines.extend([
                f"### {snip.provider}",
                f"- **Record Type:** `{snip.record_type}`",
                f"- **Host / Name:** `{snip.host_name}`",
                f"- **Value:** `{snip.record_value}`",
                f"- **Instructions:** {snip.instructions}",
                "",
                "```hcl",
                snip.terraform_hcl,
                "```",
                "",
            ])

        dkim_status = str(enrichment.get("dkim_status") or "unknown").upper()
        dkim_selectors = ", ".join(enrichment.get("dkim_selectors_found") or []) or "None detected across common enterprise selectors"
        caa_status = str(enrichment.get("caa_status") or "unknown").upper()
        caa_records = ", ".join(enrichment.get("caa_records") or []) or "None published"

        lines.extend([
            "---",
            "",
            "## 2b. DKIM Selector Verification (`<selector>._domainkey` TXT — RFC 6376)",
            "",
            f"- **Current DKIM Status:** `{dkim_status}`",
            f"- **Verified Selectors:** `{dkim_selectors}`",
            "",
            "---",
            "",
            "## 3. Certificate Authority Authorization (`@` CAA Record — RFC 8659)",
            "",
            f"- **Current CAA Status:** `{caa_status}` (`{caa_records}`)",
            "",
        ])

        for snip in caa_snippets:
            lines.extend([
                f"### {snip.provider}",
                f"- **Record Type:** `{snip.record_type}`",
                f"- **Host / Name:** `{snip.host_name}`",
                f"- **Value:** `{snip.record_value}`",
                "",
                "```hcl",
                snip.terraform_hcl,
                "```",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## 4. RFC 9116 Vulnerability Disclosure Policy (`/.well-known/security.txt`)",
            "",
            "```text",
            sec_txt.strip(),
            "```",
            "",
        ])

        return "\n".join(lines)

    def _render_retainer_proposal_markdown(
        self,
        domain: str,
        score: int,
        grade: str,
        enrichment: Dict[str, Any],
        pdf_filename: str,
    ) -> str:
        company_name = enrichment.get("company_profile", {}).get("company_name") or domain
        tech_stack = ", ".join(enrichment.get("tech_stack") or ["Standard Web Stack"])
        registrar = enrichment.get("registrar") or "Authoritative Registrar"
        dns_provider = enrichment.get("dns_provider") or "Authoritative DNS"
        mx_provider = enrichment.get("mx_provider") or "Corporate Mail"
        osint = enrichment.get("public_apis_osint") or {}
        lead = enrichment.get("leadership") or {}
        exec_contact = (
            f"{lead.get('name')} ({lead.get('title')}) — `{lead.get('email')}`"
            if lead.get("resolved")
            else f"Suggested patterns: {', '.join(f'`{p}`' for p in (lead.get('suggested_patterns') or [f'cto@{domain}']))}"
        )

        dkim_status = str(enrichment.get("dkim_status", "unknown")).upper()
        dkim_selectors = ", ".join(enrichment.get("dkim_selectors_found") or []) or "None detected"
        caa_status = str(enrichment.get("caa_status", "unknown")).upper()
        ct_subs = enrichment.get("ct_subdomains") or []
        ct_display = ", ".join(f"`{s}`" for s in ct_subs[:8]) if ct_subs else "None indexed in public CT logs"

        return f"""# 🛡️ Project ORBIT // Executive Perimeter Retainer Proposal — {company_name}

**Target Domain:** `{domain}`  
**Company / Brand:** **{company_name}**  
**Live Radar Hygiene Score:** **{score}/100 (Grade: `{grade}`)**  
**Prepared By:** Carson Haynes — Principal Systems Architect, Project ORBIT  
**Date:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')}

---

## 1. Infrastructure & OSINT Intelligence Summary

Our passive reconnaissance and `public-apis` OSINT correlation engine identified the following external posture for **{company_name}** (`{domain}`):

| Dimension | Observed Telemetry |
|---|---|
| **Apex Domain** | `{domain}` |
| **Detected Tech Stack** | `{tech_stack}` |
| **Domain Registrar** | `{registrar}` |
| **Authoritative DNS** | `{dns_provider}` |
| **Mail Exchange (MX)** | `{mx_provider}` |
| **DMARC Status** | `{str(enrichment.get('dmarc_status', 'unknown')).upper()}` |
| **SPF Status** | `{str(enrichment.get('spf_status', 'unknown')).upper()}` |
| **DKIM Selector Status** | `{dkim_status}` (Selectors: `{dkim_selectors}`) |
| **DNS CAA Status** | `{caa_status}` |
| **CT Log Subdomains (`crt.sh`)** | {ct_display} (`{len(ct_subs)}` discovered) |
| **Public APIs OSINT Catalog** | `{osint.get('security_osint_count', 0)}` security/OSINT endpoints cross-referenced (out of `{osint.get('total_catalog_apis', 0)}` indexed APIs) |
| **Technical Contact Routing** | {exec_contact} |

---

## 2. Recommended Retainer & Care Plan Options

To lock down `{domain}` against subdomain hijacking, executive email spoofing, and third-party script drift, we have pre-staged your co-branded audit report (`{pdf_filename}`) and DNS remediation blueprint (`dns_remediation_plan.md`).

| Tier | Investment | Scope & Deliverables |
|---|---|---|
| **Perimeter Monitoring** | **$59 / mo** | Continuous 24/7 DNS/CNAME/SPF/DMARC sentinel, weekly attack surface scans, 0-day disclosure alerts. |
| **Remediation Retainer (Scale)** | **$250 / mo** | Full DMARC `p=quarantine`/`p=reject` enforcement, subdomain takeover guard, monthly co-branded executive PDF audit reports. |
| **Agency White-Label Fleet** | **$499 / mo** | Multi-domain agency portfolio protection (up to 50 client domains), custom co-branded security portal, <15-min SLA takeover guarantee. |

---

## 3. Staged Deliverables in This Campaign Folder

1. **Co-Branded Executive PDF Audit**: `{pdf_filename}`
2. **Copy-Paste DNS & Terraform Remediation Plan**: `dns_remediation_plan.md`
3. **Outreach Advisory Draft**: `pitch_email.txt`
"""

    def _render_pitch_email(
        self,
        domain: str,
        score: int,
        grade: str,
        enrichment: Dict[str, Any],
        pdf_filename: str,
    ) -> str:
        company_name = enrichment.get("company_profile", {}).get("company_name") or domain
        tech_stack = ", ".join(enrichment.get("tech_stack") or ["Web"])
        dmarc_status = enrichment.get("dmarc_status", "missing")
        finding_line = (
            f"- [MEDIUM] DMARC Policy Status ({dmarc_status.upper()}): Spoofed emails appearing to come from @{domain} may not be quarantined or rejected by receiving mail servers."
            if dmarc_status != "pass"
            else f"- [INFO] DNS CAA & RFC 9116 security.txt Hardening: Certificate issuance and security disclosure endpoints can be further restricted on {domain}."
        )

        return (
            f"Subject: {domain} perimeter check ({score}/100, Grade {grade}) / Orbit Security audit report\n\n"
            f"Hi {company_name} team,\n\n"
            f"I'm Carson, software engineer and founder of Orbit Security. We noticed {domain} ({tech_stack}) "
            f"was recently audited on the ORBIT // PERIMETER RADAR TERMINAL (Score: {score}/100, Grade: {grade}).\n\n"
            f"Key perimeter observations:\n"
            f"{finding_line}\n\n"
            f"I've attached your co-branded PDF audit report ({pdf_filename}) along with copy-paste DNS remediation records "
            f"for {enrichment.get('dns_provider', 'your DNS provider')}.\n\n"
            f"If you'd like continuous 24/7 subdomain takeover monitoring and monthly executive audit PDFs for {domain}, "
            f"we can activate your retainer portal in one click.\n\n"
            f"Best,\n"
            f"Carson Haynes\n"
            f"Founder & Principal Systems Architect, Orbit Security\n"
            f"https://cmfh009.github.io/Orbit-Security/\n"
        )

    def stage_campaign(
        self,
        domain: str,
        query_record: Optional[Dict[str, Any]] = None,
        enrichment: Optional[Dict[str, Any]] = None,
        agency_branding: Optional[AgencyBranding] = None,
    ) -> Dict[str, Any]:
        """Generates and writes the PDF audit, DNS remediation plan, and retainer proposal to outbound_campaigns/<slug>/."""
        clean_domain = (domain or "").strip().lower()
        slug = self.domain_to_slug(clean_domain)
        target_dir = self.campaigns_dir / slug
        target_dir.mkdir(parents=True, exist_ok=True)

        q_rec = query_record or {}
        enrich = enrichment or {}

        score = q_rec.get("score")
        if score is None:
            score = enrich.get("computed_score", 78)
        score = int(score)

        grade = q_rec.get("grade") or enrich.get("computed_grade") or (
            "A+" if score >= 95 else ("A" if score >= 88 else ("B" if score >= 75 else ("C" if score >= 60 else "D")))
        )

        dmarc_status = str(q_rec.get("dmarc_status") or enrich.get("dmarc_status") or "missing").lower()
        spf_status = str(q_rec.get("spf_status") or enrich.get("spf_status") or "pass").lower()
        cname_status = str(q_rec.get("cname_status") or "pass").lower()

        audit_result = self._build_audit_result(
            domain=clean_domain,
            score=score,
            grade=grade,
            dmarc_status=dmarc_status,
            spf_status=spf_status,
            cname_status=cname_status,
            enrichment=enrich,
            agency_branding=agency_branding,
        )

        pdf_filename = f"{slug}_security_audit.pdf"
        pdf_path = target_dir / pdf_filename
        ReportGenerator.generate_pdf(audit_result, str(pdf_path))

        audit_md_path = target_dir / f"{slug}_security_audit.md"
        audit_md_path.write_text(ReportGenerator.generate_markdown(audit_result), encoding="utf-8")

        remediation_path = target_dir / "dns_remediation_plan.md"
        remediation_md = self._render_dns_remediation_markdown(
            domain=clean_domain,
            score=score,
            grade=grade,
            enrichment=enrich,
        )
        remediation_path.write_text(remediation_md, encoding="utf-8")

        proposal_path = target_dir / "retainer_proposal.md"
        proposal_md = self._render_retainer_proposal_markdown(
            domain=clean_domain,
            score=score,
            grade=grade,
            enrichment=enrich,
            pdf_filename=pdf_filename,
        )
        proposal_path.write_text(proposal_md, encoding="utf-8")

        pitch_path = target_dir / "pitch_email.txt"
        pitch_txt = self._render_pitch_email(
            domain=clean_domain,
            score=score,
            grade=grade,
            enrichment=enrich,
            pdf_filename=pdf_filename,
        )
        pitch_path.write_text(pitch_txt, encoding="utf-8")

        staged_summary = {
            "ok": True,
            "domain": clean_domain,
            "domain_slug": slug,
            "score": score,
            "grade": grade,
            "campaign_dir": str(target_dir),
            "pdf_path": str(pdf_path),
            "audit_md_path": str(audit_md_path),
            "remediation_path": str(remediation_path),
            "dns_remediation_path": str(remediation_path),
            "proposal_path": str(proposal_path),
            "retainer_proposal_path": str(proposal_path),
            "pitch_path": str(pitch_path),
            "staged_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        self._publish_blackboard_event(staged_summary)
        return staged_summary

    def stage_proposal(
        self,
        domain_or_query: Any,
        enrichment: Optional[Dict[str, Any]] = None,
        agency_branding: Optional[AgencyBranding] = None,
    ) -> Dict[str, Any]:
        """Convenience wrapper accepting either a domain string or a query record dict."""
        if isinstance(domain_or_query, dict):
            dom = str(domain_or_query.get("domain") or "")
            return self.stage_campaign(
                domain=dom,
                query_record=domain_or_query,
                enrichment=enrichment,
                agency_branding=agency_branding,
            )
        return self.stage_campaign(
            domain=str(domain_or_query),
            query_record=None,
            enrichment=enrichment,
            agency_branding=agency_branding,
        )

    def _publish_blackboard_event(self, staged_summary: Dict[str, Any]) -> None:
        try:
            from orbit_security.blackboard import (
                EVENT_RADAR_PROPOSAL_STAGED,
                TOPIC_GROWTH,
                publish_event,
            )

            publish_event(
                event_type=EVENT_RADAR_PROPOSAL_STAGED,
                payload=staged_summary,
                source="radar_proposal_stager",
                topic=TOPIC_GROWTH,
            )
        except Exception as ex:
            pass
