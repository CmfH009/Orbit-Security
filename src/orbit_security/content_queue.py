"""Orbit Security Staged Content Queue & Rotation Engine (content_queue.py).

Coordinates sequential hourly publication across:
1. 3-Part Viral Video Trilogy (Astro-Cat, Animation Montage, Retainer Exploit)
2. 7-Part Technical Dangling CNAME Master Thread
3. High-Signal Evergreen Infosec & DNS Hygiene Breakdowns

Integrates with SocialStateManager for persistent SQLite deduplication so each
piece of content is published exactly in order, with zero amnesia and zero double-posting.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ContentQueue:
    """Manages the prioritized sequence of staged social posts for Orbit Security."""

    ARCADE_URL = "https://cmfh009.github.io/Orbit-Security/"

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.items: List[Dict[str, Any]] = []
        self._load_staged_content()

    def _load_staged_content(self):
        """Loads and normalizes all staged content sources into a linear priority queue."""
        self.items = []

        # -------------------------------------------------------------
        # Vector A: 3-Part Viral Video Trilogy
        # -------------------------------------------------------------
        trilogy_file = self.root / "marketing" / "campaigns" / "x_video_trilogy_staged.json"
        if trilogy_file.exists():
            try:
                with open(trilogy_file, "r", encoding="utf-8") as f:
                    trilogy_data = json.load(f)
                for idx, t in enumerate(trilogy_data, start=1):
                    vid_path = t.get("video_path")
                    # Validate local existence of video
                    media = vid_path if (vid_path and Path(vid_path).exists()) else None
                    self.items.append({
                        "id": f"video_trilogy_{idx}",
                        "title": t.get("title", f"Video Trilogy Part {idx}"),
                        "text": t.get("tweet_text", "").strip(),
                        "media_path": media,
                        "category": "video_trilogy",
                    })
            except Exception as e:
                logger.error(f"Error loading video trilogy staged content: {e}")

        # -------------------------------------------------------------
        # Vector B: 7-Part Technical Dangling CNAME Master Thread
        # -------------------------------------------------------------
        default_img = self.root / "landing" / "assets" / "orbit_cats_pounce.jpg"
        fleet_preview = self.root / "docs" / "assets" / "fleet_arena_preview.png"
        header_media = str(fleet_preview) if fleet_preview.exists() else (str(default_img) if default_img.exists() else None)

        thread_tweets = [
            {
                "id": "cname_thread_1",
                "title": "Master Thread 1: The Hook",
                "media_path": header_media,
                "text": (
                    "How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:\n\n"
                    "The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance "
                    "catches them in 800ms. \ud83e\uddf5\ud83d\udc47"
                ),
            },
            {
                "id": "cname_thread_2",
                "title": "Master Thread 2: The Setup",
                "media_path": None,
                "text": (
                    "Web & Shopify agencies launch dozens of promo subdomains every year:\n"
                    "\u2022 promo.brand.com \u2794 Unbounce\n"
                    "\u2022 store.brand.com \u2794 Shopify\n"
                    "\u2022 docs.brand.com \u2794 AWS S3 / GitHub Pages\n\n"
                    "The seasonal campaign ends. The agency cancels the SaaS plan.\n\n"
                    "But nobody touches the DNS manager."
                ),
            },
            {
                "id": "cname_thread_3",
                "title": "Master Thread 3: The Vulnerability",
                "media_path": None,
                "text": (
                    "The DNS record still points:\n"
                    "`promo.brand.com CNAME unbouncepages.com`\n\n"
                    "When anyone visits the URL, Unbounce’s edge returns:\n"
                    "\"The requested URL was not found on this server.\"\n\n"
                    "To an attacker running automated reconnaissance, that 404 is an open invitation."
                ),
            },
            {
                "id": "cname_thread_4",
                "title": "Master Thread 4: The Exploit",
                "media_path": None,
                "text": (
                    "A malicious actor registers a $15 trial on the vendor and claims promo.brand.com.\n\n"
                    "Suddenly, they gain:\n"
                    "1. Complete HTTPS delivery under brand.com\n"
                    "2. Cookie access across parent domain scopes\n"
                    "3. Valid Let's Encrypt SSL certificates\n"
                    "4. Flawless credential harvesting legitimacy"
                ),
            },
            {
                "id": "cname_thread_5",
                "title": "Master Thread 5: The Solution & Automation",
                "media_path": None,
                "text": (
                    "You don't need a $20k enterprise audit to stop this.\n\n"
                    "Orbit packages detection heuristics into an open-source CLI:\n\n"
                    "`pip install orbit-security`\n"
                    "`orbit-recon clientbrand.com --remediate`\n\n"
                    "Resolves DNS pointers, audits RFC 7489 DMARC, and checks 30+ SaaS takeover signatures."
                ),
            },
            {
                "id": "cname_thread_6",
                "title": "Master Thread 6: The Agency Retainer Moat",
                "media_path": None,
                "text": (
                    "For web & eCommerce agencies:\n\n"
                    "Running this audit monthly turns a hidden liability into a high-margin $250/mo \"Care Plan Retainer\".\n\n"
                    "Orbit generates automated white-label client PDF audits with your agency logo—giving clients tangible proof of proactive perimeter hygiene."
                ),
            },
            {
                "id": "cname_thread_7",
                "title": "Master Thread 7: The Call to Action",
                "media_path": None,
                "text": (
                    "Want to see your perimeter hygiene score?\n\n"
                    "1. Test our zero-server DoH terminal in your browser (16-bit cyber arcade & Simple Cat decoder):\n"
                    "https://cmfh009.github.io/Orbit-Security/\n\n"
                    "2. Or drop your domain below for an instant audit.\n\n"
                    "GitHub: https://github.com/CmfH009/Orbit-Security"
                ),
            },
        ]
        for t in thread_tweets:
            t["category"] = "master_thread"
            self.items.append(t)

        # -------------------------------------------------------------
        # Vector C: High-Signal Evergreen Infosec Breakdowns
        # -------------------------------------------------------------
        evergreen_posts = [
            {
                "id": "evergreen_dmarc_decay",
                "title": "DMARC Enforcement Decay",
                "media_path": str(default_img) if default_img.exists() else None,
                "text": (
                    "Over 65% of digital agencies have client domains stuck in DMARC `p=none` (monitoring mode).\n\n"
                    "Monitoring mode provides ZERO protection against spoofed executive invoices or lookalike phishing.\n\n"
                    "Audit your clients' DMARC alignment in 800ms with Orbit:\n"
                    f"{self.ARCADE_URL}"
                ),
            },
            {
                "id": "evergreen_dns_drift",
                "title": "The Danger of DNS Drift",
                "media_path": None,
                "text": (
                    "DNS drift is the silent killer of web perimeters.\n\n"
                    "A contractor builds a landing page on Unbounce, Instapage, or S3. Two quarters later, the bill lapses.\n\n"
                    "The CNAME record remains live. Within 48 hours, automated bots claim the subdomain.\n\n"
                    "Check your edge with our open-source scanner:\n"
                    f"{self.ARCADE_URL}"
                ),
            },
            {
                "id": "evergreen_doh_speed",
                "title": "RFC 8484 DNS-over-HTTPS Radar",
                "media_path": None,
                "text": (
                    "Legacy DNS reconnaissance floods port 53 with unencrypted UDP packets that get rate-limited and logged.\n\n"
                    "Orbit Security uses encrypted RFC 8484 DNS-over-HTTPS with asynchronous multiplexing across Google, Cloudflare, and Quad9.\n\n"
                    "Sub-second audits with zero server overhead:\n"
                    f"{self.ARCADE_URL}"
                ),
            },
            {
                "id": "evergreen_agency_retainers",
                "title": "Care Plan Retainers for Web Agencies",
                "media_path": None,
                "text": (
                    "How modern web agencies defend $250/mo care plans:\n\n"
                    "\u2022 Continuous DNS drift telemetry\n"
                    "\u2022 Proactive dangling CNAME takeover alerts\n"
                    "\u2022 White-label executive security audits\n"
                    "\u2022 Zero-server client arcade demonstration\n\n"
                    "Run an instant perimeter audit:\n"
                    f"{self.ARCADE_URL}"
                ),
            },
        ]
        for ep in evergreen_posts:
            ep["category"] = "evergreen"
            self.items.append(ep)

    def get_next_queued_post(self, state_manager: Any) -> Optional[Dict[str, Any]]:
        """Returns the next unposted staged content item.

        Checks SQLite via state_manager.is_interacted(post_id, 'POST').
        If all base items have been published, rotates through evergreen items
        with an incrementing epoch suffix to maintain continuous hourly publishing.
        """
        # First pass: find the first item that has never been posted
        for item in self.items:
            if not state_manager.is_interacted(item["id"], "POST"):
                logger.info(f"ContentQueue: Next staged post selected: [{item['id']}] {item['title']}")
                return item

        # Second pass: all items posted once. Rotate evergreen posts with epoch suffix
        evergreen = [it for it in self.items if it.get("category") == "evergreen"]
        if not evergreen:
            evergreen = self.items

        # Find which rotation iteration we are on
        for round_num in range(1, 100):
            for item in evergreen:
                rotation_id = f"{item['id']}_r{round_num}"
                if not state_manager.is_interacted(rotation_id, "POST"):
                    clone = dict(item)
                    clone["id"] = rotation_id
                    logger.info(f"ContentQueue: Rotating evergreen post: [{rotation_id}] {clone['title']}")
                    return clone

        return None
