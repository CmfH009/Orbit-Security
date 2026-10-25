import html
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
    Image as RLImage
)

from orbit_security.models import DomainAuditResult, Severity


class ReportGenerator:
    @staticmethod
    def generate_markdown(audit: DomainAuditResult) -> str:
        b = audit.agency_branding
        lines = [
            f"# 🛡️ Client Security & Domain Health Audit",
            f"**Audited Target:** `{audit.domain}`  ",
            f"**Prepared By:** {b.agency_name} ({b.agency_tagline})  ",
            f"**Audit Date:** {audit.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Executive Grade:** **{audit.grade}** (Score: {audit.score}/100)",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"This perimeter hygiene audit analyzed domain records, transport security, email authentication, and publicly exposed server paths for **{audit.domain}**.",
            "",
            f"- **Security Score:** `{audit.score} / 100`",
            f"- **Overall Assessment:** `{audit.grade}`",
            f"- **Total Findings:** `{len(audit.findings)}`",
            f"- **Subdomains Probed:** `{len(audit.subdomains_scanned)}`",
            "",
            "---",
            "",
            "## 2. Findings & Recommended Actions",
            "",
        ]

        if not audit.findings:
            lines.append("✅ **No critical perimetral vulnerabilities or security regressions detected.**")
        else:
            for i, f in enumerate(audit.findings, start=1):
                badge = {
                    Severity.CRITICAL: "🔴 **CRITICAL**",
                    Severity.HIGH: "🟠 **HIGH**",
                    Severity.MEDIUM: "🟡 **MEDIUM**",
                    Severity.LOW: "🔵 **LOW**",
                    Severity.INFO: "⚪ **INFO**",
                }.get(f.severity, f.severity.value)

                lines.append(f"### {i}. {f.title} ({badge})")
                lines.append(f"- **Category:** {f.category}")
                lines.append(f"- **Target / Endpoint:** `{f.target}`")
                lines.append(f"- **Risk Description:** {f.description}")
                if f.evidence:
                    lines.append(f"- **Evidence Detected:** `{f.evidence}`")
                lines.append(f"- **Recommended Remediation:** {f.remediation}")
                lines.append("")

        # Section 3: Passive OSINT Intelligence
        osint = audit.osint_intel or {}
        if osint.get("bridge_available"):
            lines.extend([
                "---",
                "",
                "## 3. Passive OSINT Intelligence",
                f"This audit cross-referenced the target against the public-apis catalog "
                f"({osint.get('total_catalog_apis', 0)} indexed APIs) for security and OSINT-relevant "
                f"endpoints ({osint.get('security_osint_count', 0)} in security categories).",
                "",
            ])
            matches = osint.get("domain_matches", [])
            if matches:
                lines.append(f"### Domain-Relevant OSINT Endpoints ({len(matches)})")
                lines.append("")
                for m in matches[:10]:
                    lines.append(
                        f"- **{m.get('name', '')}** ({m.get('category', '')}) — {m.get('link', '')}"
                    )
                lines.append("")
            pivot = osint.get("pivot_domains", [])
            if pivot:
                lines.append(f"### Pivot Domains ({len(pivot)})")
                lines.append("")
                lines.append(", ".join(f"`{d}`" for d in pivot[:20]))
                lines.append("")

        # Section 4: Agency Care Plan Value Breakdown
        lines.extend([
            "---",
            "",
            "## 3. Retainer & Infrastructure Care Plan Recommendations",
            f"As part of your managed web operations with **{b.agency_name}**, we recommend the following ongoing safeguards:",
            "- **Continuous Subdomain Sentinel:** Automated monitoring against dangling DNS takeovers as SaaS trials (Unbounce, Webflow, Shopify, Azure) expire.",
            "- **Google & Yahoo Bulk Sender Protection:** Active enforcement of DMARC (`p=quarantine`/`p=reject`), SPF, and MTA-STS TLS encryption to preserve 100% primary inbox deliverability.",
            "- **BIMI Verified Brand Logo:** Publishing BIMI (RFC 8617) to display authenticated client logos in Gmail and Apple Mail.",
            "- **Zero-Exposure Secret Hygiene:** Automated surveillance preventing accidental public exposure of `.env`, `.git`, or database backups.",
            "",
            "---",
            "",
            f"### Managed Service Contact",
            f"For automated remediation or questions regarding this audit, please contact **{b.agency_name}** at [{b.support_email}](mailto:{b.support_email}) or visit [{b.website}]({b.website}).",
        ])

        return "\n".join(lines)

    @staticmethod
    def generate_pdf(audit: DomainAuditResult, output_path: str):
        b = audit.agency_branding
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        primary_hex = b.primary_color if b.primary_color.startswith("#") else f"#{b.primary_color}"
        accent_hex = b.accent_color if b.accent_color.startswith("#") else f"#{b.accent_color}"
        primary_col = colors.HexColor(primary_hex)
        accent_col = colors.HexColor(accent_hex)

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=primary_col,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),
            fontName="Helvetica",
        )
        h2_style = ParagraphStyle(
            "H2Style",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=primary_col,
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica",
        )
        finding_title_style = ParagraphStyle(
            "FindingTitle",
            parent=styles["Heading3"],
            fontSize=11,
            leading=14,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0F172A"),
        )
        remed_style = ParagraphStyle(
            "Remediation",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#0F766E"),
            fontName="Helvetica-Oblique",
        )

        story = []

        # Header Block with Astro-Cat Sentinel Brand Badge
        logo_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "landing", "assets", "orbit_cats_square.jpg"
        )
        logo_cell = ""
        if os.path.exists(logo_path):
            logo_cell = RLImage(logo_path, width=38, height=38)

        header_data = [
            [
                logo_cell if logo_cell else "",
                Paragraph(f"<b>{b.agency_name}</b><br/>{b.agency_tagline}", subtitle_style),
                Paragraph("<b>MONTHLY DOMAIN & SECURITY AUDIT</b>", ParagraphStyle(
                    "RightAlign", parent=subtitle_style, alignment=2, textColor=accent_col
                )),
            ]
        ]
        t_header = Table(header_data, colWidths=[46, 264, 230] if logo_cell else [300, 240])
        t_header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_header)
        story.append(HRFlowable(width="100%", thickness=1.5, color=primary_col, spaceBefore=6, spaceAfter=14))

        # Title & Target Box
        story.append(Paragraph(f"Perimeter Health Audit: {audit.domain}", title_style))
        story.append(Paragraph(f"Generated on {audit.timestamp.strftime('%B %d, %Y at %H:%M UTC')} | Confidential Client Report", subtitle_style))
        story.append(Spacer(1, 12))

        # Scorecard Banner
        grade_bg = colors.HexColor("#10B981") if audit.score >= 88 else (
            colors.HexColor("#F59E0B") if audit.score >= 70 else colors.HexColor("#EF4444")
        )
        
        score_data = [
            [
                Paragraph(f"<font size=28 color='white'><b>{audit.grade}</b></font><br/><font size=8 color='white'>OVERALL GRADE</font>", ParagraphStyle("GradeCell", alignment=1)),
                Paragraph(f"<b>Security Hygiene Score:</b> {audit.score} / 100<br/>"
                          f"<b>Monitored Apex:</b> {audit.domain}<br/>"
                          f"<b>Subdomains Scanned:</b> {len(audit.subdomains_scanned)} endpoints<br/>"
                          f"<b>Identified Vulnerabilities:</b> {len(audit.findings)} items", body_style),
                Paragraph(f"<b>Retainer Status:</b> Active Protection<br/>"
                          f"<b>Next Audit:</b> 1st of Next Month<br/>"
                          f"<b>Support:</b> {b.support_email}<br/>"
                          f"<b>Web:</b> {b.website}", body_style)
            ]
        ]
        t_score = Table(score_data, colWidths=[100, 240, 200])
        t_score.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), grade_bg),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, 0), 1, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t_score)
        story.append(Spacer(1, 14))

        # Section: Findings
        story.append(Paragraph("Perimeter Findings & Remediation Items", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

        if not audit.findings:
            story.append(Paragraph("<b>No critical vulnerabilities or regressions detected during this billing cycle.</b>", body_style))
        else:
            for idx, f in enumerate(audit.findings, 1):
                sev_color = {
                    Severity.CRITICAL: colors.HexColor("#DC2626"),
                    Severity.HIGH: colors.HexColor("#EA580C"),
                    Severity.MEDIUM: colors.HexColor("#D97706"),
                    Severity.LOW: colors.HexColor("#2563EB"),
                    Severity.INFO: colors.HexColor("#64748B"),
                }.get(f.severity, colors.black)

                safe_title = html.escape(str(f.title))
                safe_category = html.escape(str(f.category))
                safe_target = html.escape(str(f.target))
                safe_desc = html.escape(str(f.description))
                safe_evidence = html.escape(str(f.evidence)) if f.evidence else ""
                safe_remediation = html.escape(str(f.remediation))

                item_table_data = [
                    [
                        Paragraph(f"<font color='white'><b>{f.severity.value}</b></font>", ParagraphStyle("SevBadge", alignment=1, fontSize=8)),
                        Paragraph(f"<b>{idx}. {safe_title}</b> — <font color='#64748B'>[{safe_category}]</font>", finding_title_style),
                    ],
                    [
                        Paragraph("", body_style),
                        Paragraph(f"<b>Target:</b> <font face='Courier'>{safe_target}</font><br/>"
                                  f"<b>Details:</b> {safe_desc}<br/>"
                                  f"{f'<b>Evidence:</b> <font face=\"Courier\">{safe_evidence}</font><br/>' if safe_evidence else ''}"
                                  f"<b>Remediation:</b> {safe_remediation}", body_style)
                    ]
                ]

                t_finding = Table(item_table_data, colWidths=[70, 470])
                t_finding.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0), sev_color),
                    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]))

                story.append(KeepTogether([t_finding, Spacer(1, 8)]))

        # PDF Section: Passive OSINT Intelligence
        osint = audit.osint_intel or {}
        if osint.get("bridge_available"):
            story.append(Spacer(1, 4))
            story.append(Paragraph("Passive OSINT Intelligence (public-apis catalog)", h2_style))
            story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

            osint_summary = (
                f"This audit cross-referenced the target against the public-apis catalog "
                f"({osint.get('total_catalog_apis', 0)} indexed APIs) for security and OSINT-relevant "
                f"endpoints ({osint.get('security_osint_count', 0)} in security categories)."
            )
            story.append(Paragraph(osint_summary, body_style))
            story.append(Spacer(1, 6))

            matches = osint.get("domain_matches", [])
            if matches:
                story.append(Paragraph(f"Domain-Relevant OSINT Endpoints ({len(matches)})", ParagraphStyle(
                    "OsintSubH", parent=styles["Heading3"], fontSize=11, leading=14,
                    fontName="Helvetica-Bold", textColor=colors.HexColor("#0F172A"), spaceBefore=6, spaceAfter=4
                )))
                match_rows = [[Paragraph("API", ParagraphStyle("OsintH", fontName="Helvetica-Bold", fontSize=8.5)),
                               Paragraph("Category", ParagraphStyle("OsintH", fontName="Helvetica-Bold", fontSize=8.5)),
                               Paragraph("Link", ParagraphStyle("OsintH", fontName="Helvetica-Bold", fontSize=8.5))]]
                for m in matches[:10]:
                    match_rows.append([
                        Paragraph(m.get("name", ""), body_style),
                        Paragraph(m.get("category", ""), body_style),
                        Paragraph(m.get("link", ""), body_style),
                    ])
                t_osint = Table(match_rows, colWidths=[140, 120, 280])
                t_osint.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(t_osint)
                story.append(Spacer(1, 6))

            pivot = osint.get("pivot_domains", [])
            if pivot:
                pivot_text = ", ".join(f"<font face='Courier'>{d}</font>" for d in pivot[:20])
                story.append(Paragraph(f"Pivot Domains ({len(pivot)})", ParagraphStyle(
                    "OsintSubH2", parent=styles["Heading3"], fontSize=11, leading=14,
                    fontName="Helvetica-Bold", textColor=colors.HexColor("#0F172A"), spaceBefore=6, spaceAfter=4
                )))
                story.append(Paragraph(pivot_text, body_style))

        # Retainer & Infrastructure Care Plan Recommendations
        story.append(Spacer(1, 10))
        story.append(Paragraph("Retainer & Infrastructure Care Plan Recommendations", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

        care_plan_intro = Paragraph(
            f"As part of managed web operations with <b>{b.agency_name}</b>, we recommend enrolling in the "
            "Continuous Security & Infrastructure Care Plan ($1,500/mo retainer) covering:",
            body_style
        )
        story.append(care_plan_intro)
        story.append(Spacer(1, 6))

        care_plan_items = [
            ("Continuous Subdomain Sentinel", "Automated monitoring preventing dangling DNS takeovers as SaaS trials (Unbounce, Webflow, Shopify, Azure) expire."),
            ("Google & Yahoo Bulk Sender Protection", "Active enforcement of DMARC (escalating p=none to p=quarantine/p=reject), SPF alignment, and MTA-STS TLS encryption to preserve 100% primary inbox deliverability."),
            ("Third-Party Supply-Chain & CDN Surveillance", "Real-time auditing of external script dependencies to block compromised CDN assets (e.g., polyfill.io, bootcdn.net) and eliminate insecure mixed content."),
            ("JavaScript Bundle Secret Harvesting Protection", "Continuous passive inspection of client-side assets to catch leaked API keys, tokens (Stripe, AWS, SendGrid, GitHub PAT, Slack), and sensitive endpoints prior to public exploitation."),
            ("BIMI & Brand Trust Verification", "Publishing BIMI (RFC 8617) to display verified brand logos directly in Gmail, Yahoo, and Apple Mail client inboxes.")
        ]

        care_rows = []
        for c_title, c_desc in care_plan_items:
            care_rows.append([
                Paragraph(f"<b>• {c_title}</b>", ParagraphStyle("CareH", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=primary_col)),
                Paragraph(c_desc, body_style)
            ])

        t_care = Table(care_rows, colWidths=[180, 360])
        t_care.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(KeepTogether([t_care]))

        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=8, spaceAfter=8))
        story.append(Paragraph(f"Confidential Report compiled by {b.agency_name} for client records. Powered by Orbit Security Labs. Questions? Contact {b.support_email}.", subtitle_style))

        doc.build(story)
        return output_path

    @staticmethod
    def generate_white_label_fleet_pdf(
        agency: object,
        output_path: str,
        kev_epss_highlights: list | None = None,
    ) -> str:
        """Generates a multi-domain White-Label Executive Fleet Posture PDF for an AgencyRetainer (Project #4)."""
        import datetime as _dt

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        raw_primary = getattr(agency, "primary_color", "#0B132B") or "#0B132B"
        raw_accent = getattr(agency, "accent_color", "#48CAE4") or "#48CAE4"
        primary_hex = raw_primary if raw_primary.startswith("#") else f"#{raw_primary}"
        accent_hex = raw_accent if raw_accent.startswith("#") else f"#{raw_accent}"
        primary_col = colors.HexColor(primary_hex)
        accent_col = colors.HexColor(accent_hex)

        agency_name = html.escape(str(getattr(agency, "agency_name", "Agency Partner")))
        agency_tagline = html.escape(str(getattr(agency, "agency_tagline", "Managed Web & Security Operations")))
        support_email = html.escape(str(getattr(agency, "support_email", "security@agency.example.com")))
        website = html.escape(str(getattr(agency, "website", "https://agency.example.com")))
        tier_obj = getattr(agency, "tier", "Scale")
        tier_label = html.escape(str(getattr(tier_obj, "value", tier_obj)))
        sla_guarantee = html.escape(str(getattr(agency, "sla_guarantee", "99.9% Perimeter Uptime & <15-Min Takeover Alert Guarantee")))

        title_style = ParagraphStyle(
            "FleetTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=primary_col,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "FleetSubTitle",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#64748B"),
            fontName="Helvetica",
        )
        h2_style = ParagraphStyle(
            "FleetH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=primary_col,
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "FleetBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica",
        )
        th_style = ParagraphStyle(
            "FleetTH",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )

        story = []

        logo_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "landing", "assets", "orbit_cats_square.jpg"
        )
        logo_cell = RLImage(logo_path, width=36, height=36) if os.path.exists(logo_path) else ""

        header_data = [
            [
                logo_cell if logo_cell else "",
                Paragraph(f"<b>{agency_name}</b><br/>{agency_tagline}", subtitle_style),
                Paragraph(
                    f"<b>WHITE-LABEL FLEET POSTURE BRIEF</b><br/><font size=8>{tier_label} Retainer Tier</font>",
                    ParagraphStyle("FleetRight", parent=subtitle_style, alignment=2, textColor=accent_col),
                ),
            ]
        ]
        t_header = Table(header_data, colWidths=[46, 264, 230] if logo_cell else [300, 240])
        t_header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_header)
        story.append(HRFlowable(width="100%", thickness=1.5, color=primary_col, spaceBefore=6, spaceAfter=12))

        now_str = _dt.datetime.now(_dt.timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
        story.append(Paragraph(f"Executive Multi-Domain Security Posture: {agency_name}", title_style))
        story.append(Paragraph(f"Compiled {now_str} | SLA: {sla_guarantee}", subtitle_style))
        story.append(Spacer(1, 10))

        client_domains = list(getattr(agency, "client_domains", []) or [])
        total_domains = len(client_domains)
        avg_score = int(sum(getattr(d, "last_score", 100) for d in client_domains) / total_domains) if total_domains else 100
        fleet_grade = "A+" if avg_score >= 95 else ("A" if avg_score >= 88 else ("B" if avg_score >= 75 else ("C" if avg_score >= 60 else "D")))
        crit_total = sum(int(getattr(d, "critical_findings", 0)) for d in client_domains)
        high_total = sum(int(getattr(d, "high_findings", 0)) for d in client_domains)

        grade_bg = colors.HexColor("#10B981") if avg_score >= 88 else (
            colors.HexColor("#F59E0B") if avg_score >= 70 else colors.HexColor("#EF4444")
        )
        summary_data = [
            [
                Paragraph(
                    f"<font size=26 color='white'><b>{fleet_grade}</b></font><br/><font size=8 color='white'>FLEET GRADE</font>",
                    ParagraphStyle("FleetGradeCell", alignment=1),
                ),
                Paragraph(
                    f"<b>Portfolio Average Score:</b> {avg_score} / 100<br/>"
                    f"<b>Enrolled Client Perimeters:</b> {total_domains} domains<br/>"
                    f"<b>Critical / High Findings:</b> {crit_total} Critical, {high_total} High<br/>"
                    f"<b>Scoring Model:</b> R1-R5 Exploitability-Aware Engine",
                    body_style,
                ),
                Paragraph(
                    f"<b>Managed By:</b> {agency_name}<br/>"
                    f"<b>Operations Desk:</b> {support_email}<br/>"
                    f"<b>Portal Web:</b> {website}<br/>"
                    f"<b>Billing Cycle:</b> Active Retainer",
                    body_style,
                ),
            ]
        ]
        t_summary = Table(summary_data, colWidths=[100, 240, 200])
        t_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), grade_bg),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, 0), 1, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 14))

        # Section 1: Enrolled Client Domain Matrix
        story.append(Paragraph("1. Enrolled Client Domain Posture & Trend Telemetry", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

        rows = [[
            Paragraph("Client & Domain", th_style),
            Paragraph("Score / Grade", th_style),
            Paragraph("Delta Trend", th_style),
            Paragraph("Crit / High", th_style),
            Paragraph("Status", th_style),
        ]]
        for site in client_domains:
            c_name = html.escape(str(getattr(site, "client_name", "")))
            c_dom = html.escape(str(getattr(site, "domain", "")))
            s_val = int(getattr(site, "last_score", 100))
            g_val = html.escape(str(getattr(site, "last_grade", "A+")))
            crit_v = int(getattr(site, "critical_findings", 0))
            high_v = int(getattr(site, "high_findings", 0))
            trend = site.get_score_trend() if hasattr(site, "get_score_trend") else "baseline"
            delta_val = getattr(site, "score_delta", None)
            if trend == "baseline" or delta_val is None:
                trend_str = "Baseline"
            elif delta_val > 0:
                trend_str = f"Improved (+{delta_val})"
            elif delta_val < 0:
                trend_str = f"Declined ({delta_val})"
            else:
                trend_str = "Stable (0)"

            status_label = "SECURE" if s_val >= 88 and crit_v == 0 else ("WARNING" if s_val >= 70 and crit_v == 0 else "AT RISK")
            rows.append([
                Paragraph(f"<b>{c_name}</b><br/><font face='Courier' size=8>{c_dom}</font>", body_style),
                Paragraph(f"<b>{s_val}/100</b> ({g_val})", body_style),
                Paragraph(trend_str, body_style),
                Paragraph(f"{crit_v} Crit / {high_v} High", body_style),
                Paragraph(f"<b>{status_label}</b>", body_style),
            ])

        t_fleet = Table(rows, colWidths=[180, 90, 95, 95, 80])
        t_fleet.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), primary_col),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t_fleet)
        story.append(Spacer(1, 14))

        # Section 2: CISA KEV + EPSS Threat Intelligence Highlights
        if kev_epss_highlights:
            story.append(Paragraph("2. Active CISA KEV & 30-Day EPSS Threat Radar Watchlist", h2_style))
            story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))
            kev_rows = [[
                Paragraph("CVE Advisory", th_style),
                Paragraph("Vendor / Product", th_style),
                Paragraph("30-Day EPSS", th_style),
                Paragraph("Classification", th_style),
            ]]
            for item in kev_epss_highlights[:8]:
                cve_id = html.escape(str(item.get("cve", "CVE-UNKNOWN")))
                vendor = html.escape(str(item.get("vendor", "Vendor")))
                product = html.escape(str(item.get("product", "Product")))
                epss_pct = f"{float(item.get('epss', 0.0)) * 100:.1f}%"
                cls_tag = "CISA KEV (Active Exploit)" if item.get("is_cisa_kev") else "High-Velocity EPSS"
                kev_rows.append([
                    Paragraph(f"<font face='Courier'><b>{cve_id}</b></font>", body_style),
                    Paragraph(f"{vendor} — {product}", body_style),
                    Paragraph(f"<b>{epss_pct}</b>", body_style),
                    Paragraph(cls_tag, body_style),
                ])
            t_kev = Table(kev_rows, colWidths=[120, 180, 90, 150])
            t_kev.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), primary_col),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(t_kev)
            story.append(Spacer(1, 12))

        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=6, spaceAfter=6))
        story.append(Paragraph(
            f"Confidential White-Label Executive Deliverable compiled by {agency_name} ({support_email}).",
            subtitle_style,
        ))

        doc.build(story)
        return output_path
