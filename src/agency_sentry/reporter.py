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
    KeepTogether
)

from agency_sentry.models import DomainAuditResult, Severity


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

        lines.extend([
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

        # Header Block
        header_data = [
            [
                Paragraph(f"<b>{b.agency_name}</b><br/>{b.agency_tagline}", subtitle_style),
                Paragraph("<b>MONTHLY DOMAIN & SECURITY AUDIT</b>", ParagraphStyle(
                    "RightAlign", parent=subtitle_style, alignment=2, textColor=accent_col
                )),
            ]
        ]
        t_header = Table(header_data, colWidths=[300, 240])
        t_header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t_header)
        story.append(HRFlowable(width="100%", thickness=1.5, color=primary_col, spaceBefore=4, spaceAfter=14))

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

                item_table_data = [
                    [
                        Paragraph(f"<font color='white'><b>{f.severity.value}</b></font>", ParagraphStyle("SevBadge", alignment=1, fontSize=8)),
                        Paragraph(f"<b>{idx}. {f.title}</b> — <font color='#64748B'>[{f.category}]</font>", finding_title_style),
                    ],
                    [
                        Paragraph("", body_style),
                        Paragraph(f"<b>Target:</b> <font face='Courier'>{f.target}</font><br/>"
                                  f"<b>Details:</b> {f.description}<br/>"
                                  f"{f'<b>Evidence:</b> <font face=\"Courier\">{f.evidence}</font><br/>' if f.evidence else ''}"
                                  f"<b>Remediation:</b> {f.remediation}", body_style)
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

        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=8, spaceAfter=8))
        story.append(Paragraph(f"Confidential Report compiled by {b.agency_name} for client records. Questions? Contact {b.support_email}.", subtitle_style))

        doc.build(story)
        return output_path
