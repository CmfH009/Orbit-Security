"""Orbit Security High-IQ Witty Infosec & AI Copy Engine (creative_engine.py).

Agent Personas:
- @OrbitSatirist: Razor-sharp dry wit, zero corporate fluff, Carson the Astronaut Cat persona
- @OrbitThreatRadar: Deep DNS, DoH (RFC 8484), Dangling CNAME, and perimeter threat authority
- @OrbitAISec: AI safety, MCP prompt injection, context window defense, and agentic sandboxing

Synthesizes intelligent, funny, and technically rigorous social posts on X,
automatically pairing each piece of copy with a freshly generated multimodal asset.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import json
import logging
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple

from orbit_security.marketing_strategy import ContentPillar, MarketingStrategyEngine
from orbit_security.media_generator import MediaGenerator
from orbit_security.video_generator import VideoGenerator

logger = logging.getLogger(__name__)


@dataclass
class GeneratedPost:
    """A complete, publish-ready social post with paired multimodal asset."""

    id: str
    text: str
    media_path: Optional[str]
    media_type: str  # "image" or "video"
    pillar: ContentPillar
    title: str
    hook_score: float
    created_at_utc: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["pillar"] = self.pillar.value
        return d


# Dynamic theme catalogs curated by the 9-Agent Persona Council
POST_BLUEPRINTS: List[Dict[str, Any]] = [
    # -------------------------------------------------------------
    # Pillar: BREAK_AND_FIX (DNS & Protocol Teardowns - IMAGES)
    # -------------------------------------------------------------
    {
        "id": "cname_unbounce_takeover",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "image",
        "title": "The $50M Shopify Brand Dangling CNAME",
        "generator_type": "dns_attack",
        "domain": "promo.nordicwear.com",
        "target_cname": "unbouncepages.com",
        "text": (
            "A $50M ecommerce brand cancelled Unbounce 6mo ago.\n"
            "Nobody deleted the DNS CNAME: promo -> unbouncepages.com.\n\n"
            "When the tenant vanished, it became dangling. An attacker claims the slug and steals customer cookies.\n\n"
            "Catch dangling CNAMEs in 800ms:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️🐾"
        ),
    },
    {
        "id": "spf_10_lookup_limit",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "image",
        "title": "The 10-DNS-Lookup SPF Trap",
        "generator_type": "spf_overflow",
        "domain": "enterprise-saas.io",
        "text": (
            "RFC 7208 hard rule: SPF evaluation aborts after 10 DNS lookups.\n\n"
            "Adding HubSpot, SendGrid, Zendesk, Stripe & Google to one TXT record triggers PermError.\n"
            "Resolvers discard the policy—anyone can spoof your domain.\n\n"
            "Run a 10s DoH audit:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🚀"
        ),
    },
    {
        "id": "dns_drift_timeline_breakdown",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "image",
        "title": "How Forgotten CNAMEs Become Attack Vectors",
        "generator_type": "dns_drift",
        "domain": "launch-promo.brand.com",
        "text": (
            "The silent killer of modern perimeters isn't zero-days.\n"
            "It's DNS drift.\n\n"
            "Campaigns end, SaaS tools get cancelled, but DNS pointers live on until an adversary claims the slug.\n\n"
            "Audit your attack surface in 800ms with Orbit DoH Radar:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🔍🛰️"
        ),
    },
    {
        "id": "doh_speed_vs_legacy",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "image",
        "title": "RFC 8484 Encrypted DoH vs Cleartext UDP 53",
        "generator_type": "doh_speed",
        "domain": "target-recon.io",
        "text": (
            "Legacy DNS recon floods port 53 with unencrypted UDP packets.\n\n"
            "Orbit runs encrypted RFC 8484 DNS-over-HTTPS across Cloudflare and Google edges.\n"
            "8.4ms resolution with zero port 53 leakage:\n\n"
            "Audit your perimeter:\n"
            "https://cmfh009.github.io/Orbit-Security/ ⚡🐾"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: HIGH_IQ_WIT (Sysadmin & Astro-Cat Satire - IMAGES)
    # -------------------------------------------------------------
    {
        "id": "soc2_vs_dangling_subdomain",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "image",
        "title": "The $250k SOC2 vs One Abandoned Subdomain",
        "asset_image": "orbit_cname_blackhole.jpg",
        "text": (
            "Companies spend $250k on SOC2 audits while leaving staging-2022 pointing to a deleted S3 bucket.\n\n"
            "Perimeters aren't secured by PDF compliance binders. They're secured by cleaning up your DNS garbage.\n\n"
            "Astro-Cat demands clean zone files:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🐾⚡"
        ),
    },
    {
        "id": "cat_dns_laser_defense",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "image",
        "title": "Astro-Cat Orbital Laser Sentinel",
        "asset_image": "orbit_astrocat_laser_sentinel.jpg",
        "text": (
            "Senior systems engineering rule #1:\n"
            "If a DNS record exists and nobody remembers what it does, don't ignore it.\n"
            "That's how dangling CNAME takeovers happen.\n\n"
            "Knock abandoned subdomains off the counter like a glass of water.\n\n"
            "Sub-second DNS radar:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛰️🐱"
        ),
    },
    {
        "id": "cyber_command_deck_view",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "image",
        "title": "Orbit Cyber Command Deck",
        "asset_image": "orbit_cyber_command_deck.jpg",
        "text": (
            "Most cybersecurity dashboards are sterile corporate spreadsheets.\n\n"
            "Orbit provides an orbital command deck: 16-bit cyber arcade, real-time RFC 8484 DoH telemetry, and Astro-Cat guarding your apex.\n\n"
            "Real perimeter defense:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🚀🐾"
        ),
    },
    {
        "id": "doh_shield_protection",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "image",
        "title": "The Encrypted DoH Crystalline Shield",
        "asset_image": "orbit_doh_encrypted_shield.jpg",
        "text": (
            "Cleartext DNS is 1983 technology in a modern threat landscape.\n\n"
            "Spoofed responses and unauthenticated NXDOMAIN hijacks disappear when you enforce RFC 8484 DoH resolution with DNSSEC validation.\n\n"
            "Shield your client fleet:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️✨"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: MULTIMODAL_VISUAL & AI SECURITY - IMAGES
    # -------------------------------------------------------------
    {
        "id": "mcp_tool_injection_teardown",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "media_type": "image",
        "title": "Model Context Protocol (MCP) Prompt Injection Anatomy",
        "generator_type": "ai_sec_flow",
        "topic": "MCP Tool Output Poisoning & Sandbox Escape",
        "attack_vector": "Untrusted web content injects malicious JSON tool call parameters",
        "orbit_defense": "Deterministic AST parser isolates agent execution boundaries",
        "text": (
            "Giving an AI agent shell access without tool-output sandboxing is remote code execution with polite syntax.\n\n"
            "Anatomy of MCP injection:\n"
            "1. Untrusted page scrape\n"
            "2. Hidden markdown payload\n"
            "3. Arbitrary CLI execution\n\n"
            "Enforce zero-trust:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️🤖"
        ),
    },
    {
        "id": "mcp_agent_sandbox_chamber",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "media_type": "image",
        "title": "Zero-Trust Agentic Sandboxing",
        "asset_image": "orbit_mcp_agent_sandbox.jpg",
        "text": (
            "How do you stop an autonomous coding agent from executing rm -rf when an attacker poisons context?\n\n"
            "Don't rely on model alignment prompts.\n"
            "Enforce hard deterministic AST parsing & isolated containers.\n\n"
            "Agentic DevSecOps architecture:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🧪🐾"
        ),
    },
    {
        "id": "shadow_ai_dns_exfiltration",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "media_type": "image",
        "title": "Shadow AI & Rogue DNS Endpoints",
        "generator_type": "shadow_ai",
        "domain": "internal-ai.dev",
        "text": (
            "Engineers spin up private Ollama / vLLM endpoints on AWS, map them to ai-test.company.com, and skip auth.\n\n"
            "One sub-second DNS scan catches them all before external attackers do.\n\n"
            "Audit before your embeddings leak:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️⚡"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: AGENCY_GROWTH - IMAGES
    # -------------------------------------------------------------
    {
        "id": "agency_retainer_conversion_formula",
        "pillar": ContentPillar.AGENCY_GROWTH,
        "media_type": "image",
        "title": "How Agencies Turn a 10s Scan into a $250/mo Retainer",
        "generator_type": "agency_retainer",
        "text": (
            "How web agencies pitch $250-$500/mo security retainers without code:\n\n"
            "1. Run Orbit's 10s DoH audit on prospect\n"
            "2. Discover abandoned CNAMEs & spoofable SPF\n"
            "3. Export white-label client PDF\n"
            "4. Close retainer to patch perimeters\n\n"
            "Free client radar:\n"
            "https://cmfh009.github.io/Orbit-Security/ 💼🐾"
        ),
    },
    {
        "id": "agency_careplan_vault_roi",
        "pillar": ContentPillar.AGENCY_GROWTH,
        "media_type": "image",
        "title": "The High-Margin Agency Care Plan Vault",
        "asset_image": "orbit_agency_retainer_vault.jpg",
        "text": (
            "Stop competing on hourly rates for WordPress & Shopify maintenance.\n\n"
            "Package perimeter security & DNS drift protection into a $250/mo retainer with Orbit's automated white-label client PDF cards.\n\n"
            "Build recurring revenue:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🏰📈"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: VIDEO_BROADCAST (Cinematic Shorts & Montages - VIDEOS)
    # -------------------------------------------------------------
    {
        "id": "video_astro_cat_gameplay",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "video",
        "title": "Astro-Cat Zero-G Gameplay Showcase",
        "asset_video": "orbit_astro_cat_gameplay_x.mp4",
        "text": (
            "Most cybersecurity landing pages are boring corporate templates with stock photos of padlocks.\n\n"
            "We built an interactive zero-gravity astronaut cat with orbital thrusters and laser cannons instead. 🛡️🐾\n\n"
            "Play with him live & run a free client DNS audit:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        ),
    },
    {
        "id": "video_full_montage",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "media_type": "video",
        "title": "Full Feature & Animation Showcase Montage",
        "asset_video": "orbit_montage_master.mp4",
        "text": (
            "We ditched the corporate playbook for Orbit Security.\n\n"
            "Here's the full command deck:\n"
            "• Sub-second RFC 8484 DNS radar\n"
            "• Dangling CNAME takeover diagnostics\n"
            "• Passive fleet portfolio telemetry\n"
            "• Zero-G Astro-Cat with laser cannons 🚀🐱\n\n"
            "Audit your edge:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        ),
    },
    {
        "id": "video_retainer_exploit_teardown",
        "pillar": ContentPillar.AGENCY_GROWTH,
        "media_type": "video",
        "title": "The $250/mo Agency Retainer Exploit",
        "asset_video": "orbit_teardown_master.mp4",
        "text": (
            "How web agencies justify $250/mo retainers without writing code:\n\n"
            "1. Scan client domain (10s passive DoH)\n"
            "2. Spot dangling CNAMEs & spoofable DNS\n"
            "3. Astro-Cat zaps the threat 👾💥\n"
            "4. Export white-label executive audit PDF\n\n"
            "Run a free scan:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        ),
    },
    {
        "id": "video_cat_humor_short",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "media_type": "video",
        "title": "Astro-Cat Humor Ad Short",
        "asset_video": "orbit_cat_humor_ad.mp4",
        "text": (
            "Why do cats make the best cybersecurity engineers?\n\n"
            "Because they knock abandoned DNS records off the table before attackers can pounce on them. 🐾🚀\n\n"
            "Zero-fluff perimeter defense:\n"
            "https://cmfh009.github.io/Orbit-Security/"
        ),
    },
    {
        "id": "video_security_tour_web",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "video",
        "title": "Orbit Security Full Architecture Tour",
        "asset_video": "orbit_security_ad_video_web.mp4",
        "text": (
            "A fast walkthrough of Orbit Security's zero-server architecture:\n\n"
            "Encrypted RFC 8484 DNS-over-HTTPS, 30+ SaaS takeover heuristics, and client PDF generation all in the browser.\n\n"
            "Try it live:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️"
        ),
    },
    {
        "id": "video_dynamic_doh_brief",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "media_type": "video",
        "title": "Dynamic Audio-Visual DoH Intel Brief",
        "is_dynamic_video": True,
        "script": "Orbit Security telemetry radar confirmed. DNS over HTTPS query resolved in eight milliseconds. Zero dangling CNAME records found.",
        "text": (
            "Encrypted RFC 8484 DNS-over-HTTPS intelligence brief:\n\n"
            "Sub-10ms resolution across Cloudflare and Google edges prevents port 53 eavesdropping and DNS spoofing.\n\n"
            "Check your score:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛰️🎧"
        ),
    },
]


class CreativeEngine:
    """Orchestrates high-IQ copywriting, prompt generation, and multimodal visual pairing."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.marketing = MarketingStrategyEngine(project_root=self.root)
        self.media_gen = MediaGenerator(project_root=self.root)
        self.video_gen = VideoGenerator(project_root=self.root)

    def _resolve_asset_path(self, filename: str) -> Optional[Path]:
        """Looks for an asset file in landing/assets or data/generated_*."""
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

    def generate_next_post(
        self,
        recent_post_ids: Optional[List[str]] = None,
        target_pillar: Optional[ContentPillar] = None,
        target_media_type: Optional[str] = None,
        recent_media_paths: Optional[List[str]] = None,
    ) -> GeneratedPost:
        """Selects or synthesizes the next high-impact post and generates or binds its fresh multimodal asset.

        Args:
            recent_post_ids: IDs of recent posts to prevent blueprint reuse.
            target_pillar: Optional pillar filter.
            target_media_type: Strict media type filter ("image" or "video").
            recent_media_paths: List of recent media paths or basenames to guarantee no media reuse.
        """
        recent_ids = recent_post_ids or []
        recent_media = [Path(p).name for p in (recent_media_paths or [])]

        eligible = [bp for bp in POST_BLUEPRINTS if bp["id"] not in recent_ids]
        if not eligible:
            eligible = POST_BLUEPRINTS

        # Filter by media type if requested
        if target_media_type:
            media_filtered = [bp for bp in eligible if bp.get("media_type") == target_media_type]
            if media_filtered:
                eligible = media_filtered

        # Filter by pillar if specified
        if target_pillar:
            pillar_eligible = [bp for bp in eligible if bp["pillar"] == target_pillar]
            if pillar_eligible:
                eligible = pillar_eligible

        # Filter out blueprints whose static asset is in recent_media
        fresh_eligible = []
        for bp in eligible:
            asset_name = bp.get("asset_image") or bp.get("asset_video")
            if asset_name and asset_name in recent_media:
                continue
            fresh_eligible.append(bp)

        chosen = random.choice(fresh_eligible) if fresh_eligible else random.choice(eligible)
        media_type = chosen.get("media_type", "image")
        media_path: Optional[str] = None

        # 1. Video Resolution & Synthesis
        if media_type == "video":
            if chosen.get("is_dynamic_video"):
                try:
                    dyn_card = self.media_gen.generate_doh_speed_benchmark()
                    vid = self.video_gen.generate_video_short(
                        script_text=chosen.get("script", chosen["text"][:100]),
                        image_path=dyn_card,
                        title=chosen["id"],
                    )
                    media_path = str(vid)
                except Exception as e:
                    logger.error(f"Error synthesizing dynamic video for {chosen['id']}: {e}")
            elif chosen.get("asset_video"):
                resolved = self._resolve_asset_path(chosen["asset_video"])
                if resolved and resolved.name not in recent_media:
                    media_path = str(resolved)
                else:
                    # Synthesize on the fly if video missing or repeated
                    try:
                        dyn_card = self.media_gen.generate_telemetry_radar_card()
                        vid = self.video_gen.generate_video_short(
                            script_text="Orbit Security automated radar. Threat perimeter verified secure.",
                            image_path=dyn_card,
                            title=f"auto_{chosen['id']}",
                        )
                        media_path = str(vid)
                    except Exception as e:
                        logger.error(f"Error generating fallback video: {e}")

        # 2. Image Resolution & Synthesis
        else:
            gen_type = chosen.get("generator_type")
            asset_img = chosen.get("asset_image")

            if asset_img:
                resolved = self._resolve_asset_path(asset_img)
                if resolved and resolved.name not in recent_media:
                    media_path = str(resolved)

            if not media_path and gen_type:
                try:
                    if gen_type == "dns_attack":
                        media_path = str(
                            self.media_gen.generate_dns_attack_diagram(
                                domain=chosen.get("domain", f"promo-{random.randint(10,99)}.brand.com"),
                                target_cname=chosen.get("target_cname", "unbouncepages.com"),
                            )
                        )
                    elif gen_type == "spf_overflow":
                        media_path = str(
                            self.media_gen.generate_spf_overflow_diagram(
                                domain=chosen.get("domain", f"saas-{random.randint(10,99)}.io")
                            )
                        )
                    elif gen_type == "dns_drift":
                        media_path = str(
                            self.media_gen.generate_dns_drift_timeline(
                                domain=chosen.get("domain", f"brand-{random.randint(10,99)}.com")
                            )
                        )
                    elif gen_type == "doh_speed":
                        media_path = str(
                            self.media_gen.generate_doh_speed_benchmark(
                                domain=chosen.get("domain", "target-edge.org")
                            )
                        )
                    elif gen_type == "agency_retainer":
                        media_path = str(
                            self.media_gen.generate_agency_retainer_card(
                                clients_managed=random.randint(20, 40),
                                monthly_rate=250,
                            )
                        )
                    elif gen_type == "shadow_ai":
                        media_path = str(
                            self.media_gen.generate_shadow_ai_card(
                                domain=chosen.get("domain", f"core-ai-{random.randint(10,99)}.io")
                            )
                        )
                    elif gen_type == "ai_sec_flow":
                        media_path = str(
                            self.media_gen.generate_ai_security_flowchart(
                                topic=chosen.get("topic", "MCP Tool Injection"),
                                attack_vector=chosen.get("attack_vector", "Untrusted tool payload"),
                                orbit_defense=chosen.get("orbit_defense", "Deterministic AST containment"),
                            )
                        )
                    elif gen_type == "telemetry_card":
                        media_path = str(
                            self.media_gen.generate_telemetry_radar_card(
                                domain=chosen.get("domain", f"client-{random.randint(10,99)}.com"),
                                score=chosen.get("score", random.randint(70, 95)),
                            )
                        )
                except Exception as e:
                    logger.error(f"Error generating procedural image for {chosen['id']}: {e}")

            # Fallback if image still not assigned or duplicate: generate fresh telemetry card
            if not media_path:
                try:
                    media_path = str(self.media_gen.generate_telemetry_radar_card(domain=f"orbit-radar-{random.randint(100,999)}.io"))
                except Exception:
                    media_path = None

        # Evaluate opening hook
        hook_eval = self.marketing.evaluate_hook(chosen["text"])

        return GeneratedPost(
            id=chosen["id"],
            text=chosen["text"],
            media_path=media_path,
            media_type=media_type,
            pillar=chosen["pillar"],
            title=chosen["title"],
            hook_score=hook_eval.score,
        )

