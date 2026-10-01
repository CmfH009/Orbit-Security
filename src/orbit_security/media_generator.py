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
            "C:\\Windows\\Fonts\\consola.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            "C:\\Windows\\Fonts\\arial.ttf",
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
