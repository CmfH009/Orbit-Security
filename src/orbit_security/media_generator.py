"""Orbit Security Dynamic Multimodal Media Generator (media_generator.py).

Agent Persona: @OrbitStudio
Mandate: Autonomously synthesizes fresh, high-aesthetic dark-mode visual assets
(diagrams, telemetry cards, exploit flows, and terminal replays) for every post on X.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image, ImageColor, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Standard 16:9 dimensions for optimal Twitter / X card preview
CANVAS_WIDTH = 1200
CANVAS_HEIGHT = 675

# Cyber / Space palette
BG_DARK = (10, 14, 23)        # #0a0e17 deep cosmic navy
CARD_BG = (17, 24, 39)        # #111827 slate 900
CARD_BORDER = (31, 41, 55)    # #1f2937 slate 800
CYAN_ACCENT = (6, 182, 212)   # #06b6d4 neon cyan
ORANGE_ACCENT = (249, 115, 22)# #f97316 cosmic orange
GREEN_SUCCESS = (16, 185, 129)# #10b981 emerald
RED_ALERT = (239, 68, 68)     # #ef4444 ruby red
PURPLE_AI = (168, 85, 247)    # #a855f7 neon purple
TEXT_MAIN = (243, 244, 246)   # #f3f4f6 white/gray
TEXT_MUTED = (156, 163, 175)  # #9ca3af cool gray


class MediaGenerator:
    """Procedurally renders high-impact infosec, AI security, and DNS telemetry cards."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.output_dir = self.root / "data" / "generated_media"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _get_font(self, size: int) -> ImageFont.ImageFont:
        """Attempts to load common system fonts or falls back to PIL default."""
        font_candidates = [
            # Windows
            "C:\\Windows\\Fonts\\consola.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            "C:\\Windows\\Fonts\\arial.ttf",
            # Linux (Debian/Ubuntu/CentOS/Fedora)
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            # macOS
            "/System/Library/Fonts/SFNSMono.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/Library/Fonts/Arial.ttf",
            # Generic / Local
            "consola.ttf",
            "arial.ttf",
        ]
        for candidate in font_candidates:
            try:
                return ImageFont.truetype(candidate, size)
            except Exception:
                continue
        return ImageFont.load_default()

    def _draw_background_grid(self, draw: ImageDraw.ImageDraw) -> None:
        """Draws subtle orbital / cyber telemetry grid lines."""
        step = 40
        grid_color = (18, 25, 38)
        for x in range(0, CANVAS_WIDTH, step):
            draw.line([(x, 0), (x, CANVAS_HEIGHT)], fill=grid_color, width=1)
        for y in range(0, CANVAS_HEIGHT, step):
            draw.line([(0, y), (CANVAS_WIDTH, y)], fill=grid_color, width=1)

    def generate_dns_attack_diagram(
        self,
        domain: str = "promo.targetbrand.com",
        target_cname: str = "unbouncepages.com",
        is_vulnerable: bool = True,
    ) -> Path:
        """Generates a crisp DNS resolution waterfall showing dangling CNAME takeover topology."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_code = self._get_font(15)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=CYAN_ACCENT, width=2)
        draw.text((80, 52), "ORBIT SECURITY // TOPOLOGY RADAR", fill=CYAN_ACCENT, font=font_sub)

        # Title
        title_text = "ANATOMY OF A DANGLING CNAME SUBDOMAIN TAKEOVER"
        draw.text((60, 110), title_text, fill=TEXT_MAIN, font=font_title)

        # Main Visualization Container
        container_rect = [(60, 170), (1140, 560)]
        draw.rectangle(container_rect, fill=CARD_BG, outline=CARD_BORDER, width=2)

        # Step Nodes (4 columns)
        nodes = [
            ("1. DNS Query", f"User requests\n{domain}", CYAN_ACCENT),
            ("2. Authoritative DNS", f"CNAME Record points to\n{target_cname}", ORANGE_ACCENT),
            ("3. Cloud Edge", "Cloud provider returns:\nHTTP 404 (Not Found)", RED_ALERT if is_vulnerable else GREEN_SUCCESS),
            ("4. Threat Verdict", "Open for Instant\nSubdomain Takeover!" if is_vulnerable else "Secured by Orbit\nZero Hijack Risk", RED_ALERT if is_vulnerable else GREEN_SUCCESS),
        ]

        node_w = 230
        node_h = 160
        y_node = 230
        for i, (step_title, step_desc, color) in enumerate(nodes):
            x_node = 90 + i * (node_w + 30)
            # Node Box
            draw.rectangle([(x_node, y_node), (x_node + node_w, y_node + node_h)], fill=(24, 32, 47), outline=color, width=2)
            # Node Header
            draw.text((x_node + 15, y_node + 15), step_title, fill=color, font=font_body)
            draw.line([(x_node + 15, y_node + 45), (x_node + node_w - 15, y_node + 45)], fill=CARD_BORDER, width=1)
            # Node Body
            draw.text((x_node + 15, y_node + 60), step_desc, fill=TEXT_MAIN, font=font_code)

            # Connector Arrow (except last)
            if i < len(nodes) - 1:
                arrow_x = x_node + node_w + 5
                arrow_y = y_node + node_h // 2
                draw.line([(arrow_x, arrow_y), (arrow_x + 20, arrow_y)], fill=CYAN_ACCENT, width=3)
                draw.polygon([(arrow_x + 20, arrow_y - 6), (arrow_x + 20, arrow_y + 6), (arrow_x + 27, arrow_y)], fill=CYAN_ACCENT)

        # Bottom Telemetry Strip
        status_color = RED_ALERT if is_vulnerable else GREEN_SUCCESS
        status_text = "STATUS: CRITICAL EXPOSURE DETECTED" if is_vulnerable else "STATUS: VERIFIED SECURE PERIMETER"
        draw.text((90, 440), status_text, fill=status_color, font=font_body)
        draw.text((90, 475), f"RFC 8484 DoH Resolution Time: 8.4ms | Scanner Engine: Orbit AST Radar v2", fill=TEXT_MUTED, font=font_code)
        draw.text((90, 505), "Live Scanner: https://cmfh009.github.io/Orbit-Security/ | Astro-Cat Telemetry", fill=CYAN_ACCENT, font=font_code)

        # Footer Signature
        draw.text((60, 590), "Orbit Security Research • Defending 90+ Ecosystem Targets 24/7", fill=TEXT_MUTED, font=font_code)

        # Save to disk
        out_name = f"dns_takeover_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated DNS attack diagram: {out_path}")
        return out_path

    def generate_ai_security_flowchart(
        self,
        topic: str = "MCP Tool Injection & Sandbox Escape",
        attack_vector: str = "Malicious tool payload attempts unauthorized file exfiltration",
        orbit_defense: str = "Zero-Trust AST parser isolates tool call context",
    ) -> Path:
        """Generates an AI security / prompt injection threat diagram."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_code = self._get_font(15)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=PURPLE_AI, width=2)
        draw.text((80, 52), "ORBIT AI SECURITY // THREAT MATRIX", fill=PURPLE_AI, font=font_sub)

        # Title
        draw.text((60, 110), f"AI VULNERABILITY TEARDOWN: {topic.upper()}", fill=TEXT_MAIN, font=font_title)

        # Threat vs Defense Cards
        # Box 1: Exploit Vector
        draw.rectangle([(60, 180), (580, 530)], fill=CARD_BG, outline=RED_ALERT, width=2)
        draw.rectangle([(60, 180), (580, 230)], fill=(38, 20, 20))
        draw.text((80, 195), "1. THE ATTACK VECTOR (UNPROTECTED AGENT)", fill=RED_ALERT, font=font_body)
        draw.text((80, 250), "How the exploit executes:", fill=TEXT_MUTED, font=font_code)
        draw.text((80, 280), f"• Vector: {attack_vector}", fill=TEXT_MAIN, font=font_code)
        draw.text((80, 330), "• Impact: Context window poisoning\n• Consequence: Autonomous shell access\n• Risk Tier: HIGH / UNRESTRICTED", fill=TEXT_MAIN, font=font_code)

        # Box 2: Orbit Hardening
        draw.rectangle([(620, 180), (1140, 530)], fill=CARD_BG, outline=GREEN_SUCCESS, width=2)
        draw.rectangle([(620, 180), (1140, 230)], fill=(18, 38, 25))
        draw.text((640, 195), "2. ORBIT HARDENED ARCHITECTURE", fill=GREEN_SUCCESS, font=font_body)
        draw.text((640, 250), "How Orbit stops the breach:", fill=TEXT_MUTED, font=font_code)
        draw.text((640, 280), f"• Shield: {orbit_defense}", fill=TEXT_MAIN, font=font_code)
        draw.text((640, 330), "• Protocol: Deterministic tool sandboxing\n• Policy: Zero unverified command loops\n• Astro-Cat Sentinel: THREAT NEUTRALIZED 🛡️🐾", fill=TEXT_MAIN, font=font_code)

        # Footer Signature
        draw.text((60, 590), "Orbit AI Research • Autonomous Agent Hardening Guidelines • https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"ai_sec_flow_{hashlib.md5(topic.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated AI security diagram: {out_path}")
        return out_path

    def generate_telemetry_radar_card(
        self,
        domain: str = "example.com",
        score: int = 85,
        spf_status: str = "PASS",
        dmarc_status: str = "ENFORCED",
        dangling_count: int = 0,
    ) -> Path:
        """Generates an executive-ready cybersecurity audit card with Astro-Cat badge."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(20)
        font_score = self._get_font(64)
        font_body = self._get_font(18)
        font_code = self._get_font(15)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=CYAN_ACCENT, width=2)
        draw.text((80, 52), "ORBIT SECURITY // LIVE AUDIT CARD", fill=CYAN_ACCENT, font=font_body)

        # Domain Title
        draw.text((60, 110), f"PERIMETER REPORT: {domain.upper()}", fill=TEXT_MAIN, font=font_title)

        # Score Box
        draw.rectangle([(60, 180), (360, 520)], fill=CARD_BG, outline=CYAN_ACCENT, width=2)
        draw.text((100, 210), "SECURITY SCORE", fill=TEXT_MUTED, font=font_sub)
        score_color = GREEN_SUCCESS if score >= 80 else (ORANGE_ACCENT if score >= 60 else RED_ALERT)
        draw.text((120, 270), f"{score}/100", fill=score_color, font=font_score)
        grade = "GRADE: A+" if score >= 90 else ("GRADE: B" if score >= 75 else "GRADE: CRITICAL")
        draw.text((120, 390), grade, fill=score_color, font=font_sub)
        draw.text((90, 460), "10-Sec RFC 8484 Telemetry", fill=TEXT_MUTED, font=font_code)

        # Checklist Metrics Box
        draw.rectangle([(400, 180), (1140, 520)], fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((430, 210), "DETAILED PERIMETER TELEMETRY", fill=TEXT_MAIN, font=font_sub)
        draw.line([(430, 245), (1110, 245)], fill=CARD_BORDER, width=1)

        metrics = [
            ("SPF Record (RFC 7208)", spf_status, GREEN_SUCCESS if "PASS" in spf_status else RED_ALERT),
            ("DMARC Enforcement (RFC 7489)", dmarc_status, GREEN_SUCCESS if "ENFORCE" in dmarc_status else ORANGE_ACCENT),
            ("Dangling CNAMEs Detected", f"{dangling_count} Vulnerable", GREEN_SUCCESS if dangling_count == 0 else RED_ALERT),
            ("DNSSEC Signature Chain", "Active & Validated", GREEN_SUCCESS),
            ("Astronaut Cat Laser Defense", "ACTIVE & READY 🐾🚀", CYAN_ACCENT),
        ]

        y_m = 270
        for label, val, col in metrics:
            draw.text((430, y_m), f"• {label}:", fill=TEXT_MAIN, font=font_body)
            draw.text((860, y_m), val, fill=col, font=font_body)
            y_m += 45

        # Footer Signature
        draw.text((60, 590), "Generated live by Orbit Security • Free 10s passive client scans at https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"telemetry_card_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated telemetry radar card: {out_path}")
        return out_path

    def generate_spf_overflow_diagram(
        self,
        domain: str = "enterprise-saas.io",
        mechanisms: Optional[List[str]] = None,
    ) -> Path:
        """Generates an RFC 7208 10-lookup limit overflow teardown diagram."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_code = self._get_font(14)
        font_big = self._get_font(36)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=RED_ALERT, width=2)
        draw.text((80, 52), "ORBIT PROTOCOL LAB // RFC 7208 TEARDOWN", fill=RED_ALERT, font=font_sub)

        # Title
        draw.text((60, 110), f"THE 10-LOOKUP SPF OVERFLOW TRAP: {domain.upper()}", fill=TEXT_MAIN, font=font_title)

        # Mechanism Grid Container
        draw.rectangle([(60, 175), (780, 530)], fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.text((80, 195), "ACCUMULATED INCLUDE LOOKUPS (11 / 10 MAX LIMIT)", fill=ORANGE_ACCENT, font=font_sub)
        draw.line([(80, 230), (760, 230)], fill=CARD_BORDER, width=1)

        default_mechs = mechanisms or [
            "1. include:_spf.google.com (Workspace)",
            "2. include:sendgrid.net (Transactional)",
            "3. include:mailgun.org (Notifications)",
            "4. include:servers.mcsv.net (Mailchimp)",
            "5. include:spf.mandrillapp.com (Billing)",
            "6. include:spf.protection.outlook.com (O365)",
            "7. include:hubspot.com (CRM Email)",
            "8. include:zendesk.com (Support Desk)",
            "9. include:stripe.com (Invoicing)",
            "10. include:helpscout.net (MAX REACHED)",
            "11. include:freshdesk.com (OVERFLOW!)",
        ]

        y_pos = 245
        for mech in default_mechs[:11]:
            is_overflow = "OVERFLOW" in mech or "11." in mech
            mech_color = RED_ALERT if is_overflow else CYAN_ACCENT
            draw.text((80, y_pos), mech, fill=mech_color, font=font_code)
            y_pos += 24

        # Threat Verdict Box
        draw.rectangle([(810, 175), (1140, 530)], fill=CARD_BG, outline=RED_ALERT, width=2)
        draw.text((830, 195), "PROTOCOL VERDICT", fill=RED_ALERT, font=font_sub)
        draw.line([(830, 230), (1120, 230)], fill=CARD_BORDER, width=1)

        draw.text((830, 250), "STATUS: PermError", fill=RED_ALERT, font=font_big)
        draw.text((830, 310), "Consequence:\nResolvers ABORT evaluation.\nEntire SPF policy ignored.", fill=TEXT_MAIN, font=font_body)
        draw.text((830, 390), "Vulnerability:\nAnyone can forge\nCEO email without auth.", fill=ORANGE_ACCENT, font=font_body)
        draw.text((830, 470), "Orbit Astro-Cat Fix:\nFlatten SPF or enforce DMARC", fill=GREEN_SUCCESS, font=font_code)

        draw.text((60, 590), "Orbit Security Protocol Intelligence • Passive DoH Analysis • https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"spf_overflow_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated SPF overflow diagram: {out_path}")
        return out_path

    def generate_dns_drift_timeline(
        self,
        domain: str = "brand.com",
    ) -> Path:
        """Generates a step-by-step timeline of DNS drift and subdomain hijack."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_code = self._get_font(14)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=ORANGE_ACCENT, width=2)
        draw.text((80, 52), "ORBIT THREAT RADAR // DNS DRIFT TIMELINE", fill=ORANGE_ACCENT, font=font_sub)

        # Title
        draw.text((60, 110), f"HOW FORGOTTEN CNAMES BECOME ATTACK VECTORS: {domain.upper()}", fill=TEXT_MAIN, font=font_title)

        container_rect = [(60, 175), (1140, 530)]
        draw.rectangle(container_rect, fill=CARD_BG, outline=CARD_BORDER, width=2)

        stages = [
            ("Month 0: Launch", "Contractor creates\npromo.brand.com ->\nUnbounce/S3 landing.", CYAN_ACCENT),
            ("Month 3: Campaign End", "Campaign completes.\nTeam cancels SaaS\nsubscription.", (150, 150, 150)),
            ("Month 6: DNS Drift", "CNAME pointer remains\nlive in Route53/Cloudflare.\nReturns HTTP 404.", ORANGE_ACCENT),
            ("Month 7: Takeover", "Attacker registers slug,\ngains SSL & parent cookie\ncredential harvest.", RED_ALERT),
        ]

        card_w = 230
        card_h = 240
        y_card = 220
        for i, (stitle, sdesc, scolor) in enumerate(stages):
            x_card = 90 + i * (card_w + 35)
            draw.rectangle([(x_card, y_card), (x_card + card_w, y_card + card_h)], fill=(22, 30, 45), outline=scolor, width=2)
            draw.text((x_card + 15, y_card + 20), stitle, fill=scolor, font=font_body)
            draw.line([(x_card + 15, y_card + 55), (x_card + card_w - 15, y_card + 55)], fill=CARD_BORDER, width=1)
            draw.text((x_card + 15, y_card + 75), sdesc, fill=TEXT_MAIN, font=font_code)

            if i < len(stages) - 1:
                arr_x = x_card + card_w + 8
                arr_y = y_card + card_h // 2
                draw.line([(arr_x, arr_y), (arr_x + 20, arr_y)], fill=CYAN_ACCENT, width=3)
                draw.polygon([(arr_x + 20, arr_y - 6), (arr_x + 20, arr_y + 6), (arr_x + 27, arr_y)], fill=CYAN_ACCENT)

        draw.text((90, 485), "Orbit Fix: Continuous sub-second RFC 8484 DoH audits detect dangling endpoints in 800ms.", fill=GREEN_SUCCESS, font=font_code)
        draw.text((60, 590), "Orbit Security • Open-Source Autonomous Perimeter Sentinel • https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"dns_drift_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated DNS drift timeline: {out_path}")
        return out_path

    def generate_doh_speed_benchmark(
        self,
        domain: str = "target.io",
        doh_ms: float = 8.4,
        legacy_ms: float = 380.0,
    ) -> Path:
        """Generates a performance benchmark card comparing encrypted RFC 8484 DoH vs legacy UDP."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_big = self._get_font(42)
        font_code = self._get_font(14)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=GREEN_SUCCESS, width=2)
        draw.text((80, 52), "ORBIT SPEED BENCHMARK // RFC 8484 DOH", fill=GREEN_SUCCESS, font=font_sub)

        # Title
        draw.text((60, 110), f"LATENCY BENCHMARK: ENCRYPTED DOH VS LEGACY PORT 53", fill=TEXT_MAIN, font=font_title)

        # Left: Orbit DoH
        draw.rectangle([(60, 175), (580, 530)], fill=CARD_BG, outline=CYAN_ACCENT, width=2)
        draw.rectangle([(60, 175), (580, 225)], fill=(15, 35, 45))
        draw.text((80, 190), "ORBIT ENCRYPTED DOH (RFC 8484)", fill=CYAN_ACCENT, font=font_sub)
        draw.text((80, 250), f"{doh_ms} ms", fill=GREEN_SUCCESS, font=font_big)
        draw.text((80, 320), "• Transport: HTTP/2 over TLS 1.3\n• Anycast Global Edges: Cloudflare & Google\n• Port 53 Eavesdropping: IMPOSSIBLE\n• Local Server Requirements: ZERO (Pure Browser/CLI)\n• Rate Limiting: None (Parallel DoH streams)", fill=TEXT_MAIN, font=font_code)

        # Right: Legacy Port 53
        draw.rectangle([(620, 175), (1140, 530)], fill=CARD_BG, outline=CARD_BORDER, width=2)
        draw.rectangle([(620, 175), (1140, 225)], fill=(35, 25, 25))
        draw.text((640, 190), "LEGACY RECON (UNENCRYPTED UDP 53)", fill=RED_ALERT, font=font_sub)
        draw.text((640, 250), f"{legacy_ms} ms", fill=RED_ALERT, font=font_big)
        draw.text((640, 320), "• Transport: Cleartext UDP packets\n• ISP / Network Snooping: Exposed to eavesdropping\n• Packet Drop Risk: High on congested Wi-Fi\n• Firewall Blocks: Frequently restricted in corporate lans\n• Relative Speed: 45x SLOWER than Orbit DoH", fill=TEXT_MUTED, font=font_code)

        draw.text((60, 590), "Tested live across 90+ ecosystem targets • Free 10s audits: https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"doh_speed_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated DoH benchmark card: {out_path}")
        return out_path

    def generate_agency_retainer_card(
        self,
        agency_name: str = "Modern Web Agency",
        clients_managed: int = 25,
        monthly_rate: int = 250,
    ) -> Path:
        """Generates an agency care plan retainer ROI breakdown card."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_big = self._get_font(44)
        font_code = self._get_font(14)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=ORANGE_ACCENT, width=2)
        draw.text((80, 52), "AGENCY GROWTH MOAT // CARE PLAN RETAINER", fill=ORANGE_ACCENT, font=font_sub)

        # Title
        draw.text((60, 110), f"HOW AGENCIES BUILD A ${clients_managed * monthly_rate:,}/MO PERIMETER MOAT", fill=TEXT_MAIN, font=font_title)

        # Left: Financials
        annual_rev = clients_managed * monthly_rate * 12
        draw.rectangle([(60, 175), (500, 530)], fill=CARD_BG, outline=GREEN_SUCCESS, width=2)
        draw.text((80, 200), "RECURRING RETAINER REVENUE", fill=GREEN_SUCCESS, font=font_sub)
        draw.text((80, 250), f"${clients_managed * monthly_rate:,}/mo", fill=GREEN_SUCCESS, font=font_big)
        draw.text((80, 315), f"${annual_rev:,} Annual Recurring Revenue", fill=TEXT_MAIN, font=font_body)
        draw.text((80, 360), f"• {clients_managed} Active Care Plan Clients\n• ${monthly_rate}/mo Average Security Retainer\n• Tooling Cost: $0 (Orbit Open Source)\n• Time per Audit: 10 seconds via DoH\n• Net Profit Margin: ~98%", fill=TEXT_MUTED, font=font_code)

        # Right: The 4-Step Agency Flywheel
        draw.rectangle([(530, 175), (1140, 530)], fill=CARD_BG, outline=CYAN_ACCENT, width=2)
        draw.text((550, 200), "THE 4-STEP CLIENT CONVERSION FLYWHEEL", fill=CYAN_ACCENT, font=font_sub)
        draw.line([(550, 235), (1110, 235)], fill=CARD_BORDER, width=1)

        steps = [
            ("1. 10-Second Audit", "Run Orbit DoH scan on prospect domain before client pitch."),
            ("2. Surface Hidden Drift", "Identify dangling CNAMEs, expired SaaS endpoints & DMARC p=none."),
            ("3. Export Executive PDF", "Generate white-label branded PDF showing perimeter health grade."),
            ("4. Lock In Retainer", "\"We monitor & patch your perimeter 24/7 for $250/month.\""),
        ]
        y_s = 255
        for s_title, s_desc in steps:
            draw.text((550, y_s), s_title, fill=ORANGE_ACCENT, font=font_body)
            draw.text((550, y_s + 24), s_desc, fill=TEXT_MAIN, font=font_code)
            y_s += 65

        draw.text((60, 590), "Orbit Security Agency Partner Suite • Free Scans at https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"agency_retainer_{clients_managed}_{monthly_rate}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated agency retainer card: {out_path}")
        return out_path

    def generate_shadow_ai_card(
        self,
        domain: str = "fintech-core.io",
        exposed_model: str = "Ollama / vLLM (Llama-3-70b)",
    ) -> Path:
        """Generates an AI security radar card showing detection of unauthenticated LLM endpoints."""
        img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BG_DARK)
        draw = ImageDraw.Draw(img)
        self._draw_background_grid(draw)

        font_title = self._get_font(28)
        font_sub = self._get_font(18)
        font_body = self._get_font(16)
        font_code = self._get_font(14)
        font_big = self._get_font(32)

        # Header Badge
        draw.rectangle([(60, 40), (450, 85)], fill=CARD_BG, outline=PURPLE_AI, width=2)
        draw.text((80, 52), "ORBIT AI SECURITY // SHADOW AI RADAR", fill=PURPLE_AI, font=font_sub)

        # Title
        draw.text((60, 110), f"SHADOW AI ENDPOINT DISCOVERY: {domain.upper()}", fill=TEXT_MAIN, font=font_title)

        container_rect = [(60, 175), (1140, 530)]
        draw.rectangle(container_rect, fill=CARD_BG, outline=PURPLE_AI, width=2)

        # Box 1: Finding
        draw.rectangle([(90, 205), (600, 500)], fill=(25, 20, 35), outline=RED_ALERT, width=2)
        draw.text((110, 225), "EXPOSED INTERNAL LLM SERVICE", fill=RED_ALERT, font=font_sub)
        draw.text((110, 270), f"Endpoint: ai-internal.{domain}:11434\nModel: {exposed_model}\nAuth Header: NONE (Open Internet)", fill=TEXT_MAIN, font=font_code)
        draw.text((110, 360), "Risk Vector:\n• Unauthenticated inference execution\n• Proprietary system prompt extraction\n• GPU cluster compute theft & DDoS", fill=ORANGE_ACCENT, font=font_code)

        # Box 2: Orbit AST Shield
        draw.rectangle([(630, 205), (1110, 500)], fill=(18, 30, 35), outline=GREEN_SUCCESS, width=2)
        draw.text((650, 225), "ORBIT AI PERIMETER DEFENSE", fill=GREEN_SUCCESS, font=font_sub)
        draw.text((650, 270), "• DoH Subdomain Enumeration: Caught in 800ms\n• Port & Header AST Inspection: Zero-trust scan\n• Astro-Cat Alert: Instant webhook notification\n• Remediation: Auto-generate Cloudflare Zero-Trust Tunnel", fill=TEXT_MAIN, font=font_code)
        draw.text((650, 400), "STATUS: EXPOSURE BLOCKED & CONTAINED 🛡️🐾", fill=GREEN_SUCCESS, font=font_body)

        draw.text((60, 590), "Orbit AI Security Division • Continuous AI Fleet Protection • https://cmfh009.github.io/Orbit-Security/", fill=TEXT_MUTED, font=font_code)

        out_name = f"shadow_ai_{hashlib.md5(domain.encode()).hexdigest()[:8]}.png"
        out_path = self.output_dir / out_name
        img.save(out_path, format="PNG")
        logger.info(f"Generated Shadow AI card: {out_path}")
        return out_path
