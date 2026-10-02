"""Orbit Security Staged Content Queue & Rotation Engine (content_queue.py).

Coordinates sequential hourly publication across:
1. 3-Part Viral Video Trilogy (Astro-Cat, Animation Montage, Retainer Exploit)
2. 7-Part Technical Dangling CNAME Master Thread (Strict Image <-> Video Alternation)
3. High-Signal Evergreen Infosec & DNS Hygiene Breakdowns (Strict Image <-> Video Alternation)

Integrates with SocialStateManager for persistent SQLite deduplication so each
piece of content is published exactly in order, strictly alternating between images and videos,
and dynamically generating brand new assets on the fly whenever duplicates or repeats are detected.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Set

from orbit_security.creative_engine import CreativeEngine

logger = logging.getLogger(__name__)


class ContentQueue:
    """Manages the prioritized sequence of staged social posts for Orbit Security."""

    ARCADE_URL = "https://cmfh009.github.io/Orbit-Security/"

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.items: List[Dict[str, Any]] = []
        self.creative_engine = CreativeEngine(project_root=self.root)
        self._load_staged_content()

    def _resolve_media(self, filename: Optional[str]) -> Optional[Path]:
        """Resolves a media filename from known project directories."""
        if not filename:
            return None
        candidates = [
            self.root / "landing" / "assets" / filename,
            self.root / "data" / "generated_media" / filename,
            self.root / "data" / "generated_videos" / filename,
            Path.home() / "Downloads" / filename,
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def _load_staged_content(self):
        """Loads and normalizes all staged content sources into a linear priority queue."""
        self.items = []

        # -------------------------------------------------------------
        # Vector A: 3-Part Viral Video Trilogy
        # -------------------------------------------------------------
        trilogy_videos = [
            ("video_trilogy_1", "Astro-Cat Gameplay Showcase", "orbit_astro_cat_gameplay_x.mp4", (
                "Most cybersecurity landing pages are boring corporate templates with stock photos of padlocks.\n\n"
                "We built an interactive zero-gravity astronaut cat with orbital thrusters and laser cannons instead. 🛡️🐾\n\n"
                "Play with him live & run a free client DNS audit:\n"
                "https://cmfh009.github.io/Orbit-Security/"
            )),
            ("video_trilogy_2", "Full Feature & Animation Montage", "orbit_montage_master.mp4", (
                "We ditched the corporate playbook for Orbit Security.\n\n"
                "Here's the full command deck:\n"
                "• Sub-second RFC 8484 DNS radar\n"
                "• Dangling CNAME takeover diagnostics\n"
                "• Passive fleet portfolio telemetry\n"
                "• Zero-G Astro-Cat with laser cannons 🚀🐱\n\n"
                "Audit your edge:\n"
                "https://cmfh009.github.io/Orbit-Security/"
            )),
            ("video_trilogy_3", "The $250/mo Retainer Exploit", "orbit_teardown_master.mp4", (
                "How web agencies justify $250/mo retainers without writing code:\n\n"
                "1. Scan client domain (10s passive DoH)\n"
                "2. Spot dangling CNAMEs & spoofable DNS\n"
                "3. Astro-Cat zaps the threat 👾💥\n"
                "4. Export white-label executive audit PDF\n\n"
                "Run a free scan:\n"
                "https://cmfh009.github.io/Orbit-Security/"
            )),
        ]
        for v_id, v_title, v_file, v_text in trilogy_videos:
            resolved = self._resolve_media(v_file)
            self.items.append({
                "id": v_id,
                "title": v_title,
                "text": v_text,
                "media_path": str(resolved) if resolved else None,
                "media_type": "video",
                "category": "video_trilogy",
            })

        # -------------------------------------------------------------
        # Vector B: 7-Part Technical Dangling CNAME Master Thread (Alternating Image <-> Video)
        # -------------------------------------------------------------
        thread_definitions = [
            (
                "cname_thread_1",
                "Master Thread 1: The Hook",
                "orbit_cname_blackhole.jpg",
                "image",
                (
                    "How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:\n\n"
                    "The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance "
                    "catches them in 800ms. 🧵👇\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_2",
                "Master Thread 2: The Setup",
                "orbit_astro_cat_gameplay_x.mp4",
                "video",
                (
                    "Web & Shopify agencies launch dozens of promo subdomains every year:\n"
                    "• promo.brand.com ➔ Unbounce\n"
                    "• store.brand.com ➔ Shopify\n"
                    "• docs.brand.com ➔ AWS S3 / GitHub Pages\n\n"
                    "The seasonal campaign ends. The agency cancels the SaaS plan.\n\n"
                    "But nobody touches the DNS manager.\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_3",
                "Master Thread 3: The Vulnerability",
                "orbit_cyber_command_deck.jpg",
                "image",
                (
                    "The DNS record still points:\n"
                    "`promo.brand.com CNAME unbouncepages.com`\n\n"
                    "When anyone visits the URL, Unbounce’s edge returns:\n"
                    "\"The requested URL was not found on this server.\"\n\n"
                    "To an attacker running automated reconnaissance, that 404 is an open invitation.\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_4",
                "Master Thread 4: The Exploit",
                "orbit_montage_master.mp4",
                "video",
                (
                    "A malicious actor registers a $15 trial on the vendor and claims promo.brand.com.\n\n"
                    "Suddenly, they gain:\n"
                    "1. Complete HTTPS delivery under brand.com\n"
                    "2. Cookie access across parent domain scopes\n"
                    "3. Valid Let's Encrypt SSL certificates\n"
                    "4. Flawless credential harvesting legitimacy\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_5",
                "Master Thread 5: The Solution & Automation",
                "orbit_astrocat_laser_sentinel.jpg",
                "image",
                (
                    "You don't need a $20k enterprise audit to stop this.\n\n"
                    "Orbit packages detection heuristics into an open-source CLI:\n\n"
                    "`pip install orbit-security`\n"
                    "`orbit-recon clientbrand.com --remediate`\n\n"
                    "Resolves DNS pointers, audits RFC 7489 DMARC, and checks 30+ SaaS takeover signatures.\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_6",
                "Master Thread 6: The Agency Retainer Moat",
                "orbit_teardown_master.mp4",
                "video",
                (
                    "For web & eCommerce agencies:\n\n"
                    "Running this audit monthly turns a hidden liability into a high-margin $250/mo \"Care Plan Retainer\".\n\n"
                    "Orbit generates automated white-label client PDF audits with your agency logo—giving clients tangible proof of proactive perimeter hygiene.\n"
                    "https://cmfh009.github.io/Orbit-Security/"
                ),
            ),
            (
                "cname_thread_7",
                "Master Thread 7: The Call to Action",
                "orbit_agency_retainer_vault.jpg",
                "image",
                (
                    "Want to see your perimeter hygiene score?\n\n"
                    "1. Test our zero-server DoH terminal in your browser (16-bit cyber arcade & Simple Cat decoder):\n"
                    "https://cmfh009.github.io/Orbit-Security/\n\n"
                    "2. Or drop your domain below for an instant audit.\n\n"
                    "GitHub: https://github.com/CmfH009/Orbit-Security"
                ),
            ),
        ]
        for t_id, t_title, t_media, t_type, t_text in thread_definitions:
            resolved = self._resolve_media(t_media)
            self.items.append({
                "id": t_id,
                "title": t_title,
                "text": t_text,
                "media_path": str(resolved) if resolved else None,
                "media_type": t_type,
                "category": "master_thread",
            })

        # -------------------------------------------------------------
        # Vector C: High-Signal Evergreen Infosec Breakdowns (Alternating Image <-> Video)
        # -------------------------------------------------------------
        evergreen_definitions = [
            (
                "evergreen_dmarc_decay",
                "DMARC Enforcement Decay",
                "orbit_doh_encrypted_shield.jpg",
                "image",
                (
                    "Over 65% of digital agencies have client domains stuck in DMARC `p=none` (monitoring mode).\n\n"
                    "Monitoring mode provides ZERO protection against spoofed executive invoices or lookalike phishing.\n\n"
                    "Audit your clients' DMARC alignment in 800ms with Orbit:\n"
                    f"{self.ARCADE_URL}"
                ),
            ),
            (
                "evergreen_dns_drift",
                "The Danger of DNS Drift",
                "orbit_cat_ad_final.mp4",
                "video",
                (
                    "DNS drift is the silent killer of web perimeters.\n\n"
                    "A contractor builds a landing page on Unbounce or S3. Months later, the campaign ends.\n\n"
                    "The CNAME lives on until bots hijack it.\n\n"
                    "Audit your edge with our open-source scanner:\n"
                    f"{self.ARCADE_URL}"
                ),
            ),
            (
                "evergreen_doh_speed",
                "RFC 8484 DNS-over-HTTPS Radar",
                "orbit_mcp_agent_sandbox.jpg",
                "image",
                (
                    "Legacy DNS recon floods port 53 with unencrypted UDP packets that get rate-limited and logged.\n\n"
                    "Orbit Security uses encrypted RFC 8484 DNS-over-HTTPS across Cloudflare and Google.\n\n"
                    "Sub-second audits with zero server overhead:\n"
                    f"{self.ARCADE_URL}"
                ),
            ),
            (
                "evergreen_agency_retainers",
                "Care Plan Retainers for Web Agencies",
                "orbit_cat_humor_ad.mp4",
                "video",
                (
                    "How modern web agencies defend $250/mo care plans:\n\n"
                    "• Continuous DNS drift telemetry\n"
                    "• Proactive dangling CNAME takeover alerts\n"
                    "• White-label executive security audits\n"
                    "• Zero-server client arcade demonstration\n\n"
                    "Run an instant perimeter audit:\n"
                    f"{self.ARCADE_URL}"
                ),
            ),
        ]
        for e_id, e_title, e_media, e_type, e_text in evergreen_definitions:
            resolved = self._resolve_media(e_media)
            self.items.append({
                "id": e_id,
                "title": e_title,
                "text": e_text,
                "media_path": str(resolved) if resolved else None,
                "media_type": e_type,
                "category": "evergreen",
            })

    def _ensure_fresh_media_for_item(
        self,
        item: Dict[str, Any],
        required_type: str,
        recent_media_names: Set[str],
    ) -> Dict[str, Any]:
        """Validates that the post has non-repeating media of the required type.

        If media is missing, wrong type, or duplicate:
        Synthesizes a brand new media asset on-the-fly before returning.
        """
        curr_path = item.get("media_path")
        curr_type = item.get("media_type")
        needs_new_media = False

        if not curr_path or not Path(curr_path).exists():
            needs_new_media = True
        elif curr_type != required_type:
            needs_new_media = True
        elif Path(curr_path).name in recent_media_names:
            needs_new_media = True

        if not needs_new_media:
            return item

        logger.info(
            f"ContentQueue: Detected duplicate, missing, or mismatched media for [{item['id']}]. "
            f"Autonomously generating fresh {required_type} before posting."
        )

        fresh_path = None
        if required_type == "video":
            try:
                card = self.creative_engine.media_gen.generate_telemetry_radar_card(
                    domain=f"radar-{random.randint(100, 999)}.io",
                    score=random.randint(75, 98),
                )
                vid = self.creative_engine.video_gen.generate_video_short(
                    script_text=item.get("text", "Orbit Security radar online. Perimeter validated.")[:120],
                    image_path=card,
                    title=f"auto_{item['id']}",
                )
                fresh_path = str(vid)
            except Exception as e:
                logger.error(f"Error synthesizing dynamic video: {e}")
                for vid_candidate in [
                    "orbit_astro_cat_gameplay_x.mp4",
                    "orbit_montage_master.mp4",
                    "orbit_teardown_master.mp4",
                    "orbit_cat_ad_final.mp4",
                ]:
                    resolved = self._resolve_media(vid_candidate)
                    if resolved and resolved.name not in recent_media_names:
                        fresh_path = str(resolved)
                        break
        else:
            try:
                gen_func = random.choice([
                    self.creative_engine.media_gen.generate_dns_attack_diagram,
                    self.creative_engine.media_gen.generate_spf_overflow_diagram,
                    self.creative_engine.media_gen.generate_dns_drift_timeline,
                    self.creative_engine.media_gen.generate_doh_speed_benchmark,
                    self.creative_engine.media_gen.generate_agency_retainer_card,
                    self.creative_engine.media_gen.generate_shadow_ai_card,
                    self.creative_engine.media_gen.generate_telemetry_radar_card,
                ])
                card = gen_func()
                fresh_path = str(card)
            except Exception as e:
                logger.error(f"Error generating fresh procedural image: {e}")
                for img_candidate in [
                    "orbit_astrocat_laser_sentinel.jpg",
                    "orbit_cyber_command_deck.jpg",
                    "orbit_doh_encrypted_shield.jpg",
                    "orbit_cname_blackhole.jpg",
                    "orbit_mcp_agent_sandbox.jpg",
                    "orbit_agency_retainer_vault.jpg",
                ]:
                    resolved = self._resolve_media(img_candidate)
                    if resolved and resolved.name not in recent_media_names:
                        fresh_path = str(resolved)
                        break

        item_copy = dict(item)
        item_copy["media_path"] = fresh_path
        item_copy["media_type"] = required_type
        return item_copy

    def get_next_queued_post(
        self, state_manager: Any, allow_generative: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Returns the next unposted staged content item adhering to strict media alternation.

        1. Checks last post media type from SQLite ('image' vs 'video').
        2. Sets required_media_type to alternate ('video' if last was 'image', else 'image').
        3. Retrieves recent media paths to prevent repetition.
        4. If candidate media would repeat or is mismatched: generates something fresh before posting.
        """
        last_info = None
        if hasattr(state_manager, "get_last_post_media_info"):
            last_info = state_manager.get_last_post_media_info()

        last_type = last_info.get("media_type") if last_info else None
        # When a prior media type is known, strictly alternate!
        required_media_type = None
        if last_type:
            required_media_type = "video" if last_type == "image" else "image"

        recent_media: List[str] = []
        if hasattr(state_manager, "get_recent_media_paths"):
            recent_media = state_manager.get_recent_media_paths(limit=15)
        recent_media_names = {Path(p).name for p in recent_media}

        logger.info(
            f"ContentQueue: Next post requirement -> MediaType: [{str(required_media_type).upper()}] "
            f"(Previous was: {last_type or 'None'}). Recent media items: {len(recent_media_names)}"
        )

        # First pass: find staged items matching required_media_type (or first unposted if none required)
        for item in self.items:
            if not state_manager.is_interacted(item["id"], "POST"):
                eff_type = required_media_type or item.get("media_type", "image")
                if required_media_type is None or item.get("media_type") == required_media_type:
                    fresh_item = self._ensure_fresh_media_for_item(
                        item, eff_type, recent_media_names
                    )
                    logger.info(
                        f"ContentQueue: Next staged post selected: [{fresh_item['id']}] {fresh_item['title']} "
                        f"({fresh_item.get('media_type')} -> {Path(fresh_item.get('media_path') or '').name})"
                    )
                    return fresh_item

        # Second pass: if no matching unposted item with exact type, check ANY unposted item and adapt its media
        for item in self.items:
            if not state_manager.is_interacted(item["id"], "POST"):
                eff_type = required_media_type or item.get("media_type", "image")
                fresh_item = self._ensure_fresh_media_for_item(
                    item, eff_type, recent_media_names
                )
                logger.info(
                    f"ContentQueue: Adapted staged post: [{fresh_item['id']}] {fresh_item['title']} "
                    f"({fresh_item.get('media_type')} -> {Path(fresh_item.get('media_path') or '').name})"
                )
                return fresh_item

        # Third pass: dynamic creative generation via CreativeEngine
        if allow_generative and self.creative_engine:
            try:
                recent_ids = []
                if hasattr(state_manager, "get_recent_actions"):
                    recent_actions = state_manager.get_recent_actions(limit=50)
                    recent_ids = [a.get("tweet_id") for a in recent_actions if a.get("tweet_id")]

                eff_type = required_media_type or "image"
                dynamic_post = self.creative_engine.generate_next_post(
                    recent_post_ids=recent_ids,
                    target_media_type=eff_type,
                    recent_media_paths=recent_media,
                )
                if not state_manager.is_interacted(dynamic_post.id, "POST"):
                    logger.info(
                        f"ContentQueue: Synthesized fresh multimodal post: [{dynamic_post.id}] {dynamic_post.title} "
                        f"({dynamic_post.media_type} -> {Path(dynamic_post.media_path or '').name})"
                    )
                    return {
                        "id": dynamic_post.id,
                        "title": dynamic_post.title,
                        "text": dynamic_post.text,
                        "media_path": dynamic_post.media_path,
                        "media_type": dynamic_post.media_type,
                        "category": dynamic_post.pillar.value,
                    }
            except Exception as e:
                logger.error(f"Error synthesizing dynamic post from CreativeEngine: {e}")

        # Fourth pass: fallback evergreen rotation with adapted fresh media
        evergreen = [it for it in self.items if it.get("category") == "evergreen"] or self.items
        for round_num in range(1, 100):
            for item in evergreen:
                rotation_id = f"{item['id']}_r{round_num}"
                if not state_manager.is_interacted(rotation_id, "POST"):
                    clone = dict(item)
                    clone["id"] = rotation_id
                    eff_type = required_media_type or clone.get("media_type", "image")
                    fresh_clone = self._ensure_fresh_media_for_item(
                        clone, eff_type, recent_media_names
                    )
                    logger.info(
                        f"ContentQueue: Rotating evergreen post: [{rotation_id}] {fresh_clone['title']} "
                        f"({fresh_clone.get('media_type')} -> {Path(fresh_clone.get('media_path') or '').name})"
                    )
                    return fresh_clone

        return None
