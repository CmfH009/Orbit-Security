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

logger = logging.getLogger(__name__)


@dataclass
class GeneratedPost:
    """A complete, publish-ready social post with paired multimodal asset."""

    id: str
    text: str
    media_path: Optional[str]
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
    # Pillar: BREAK_AND_FIX (DNS & Protocol Teardowns)
    # -------------------------------------------------------------
    {
        "id": "cname_unbounce_takeover",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "title": "The $50M Shopify Brand Dangling CNAME",
        "generator_type": "dns_attack",
        "domain": "promo.nordicwear.com",
        "target_cname": "unbouncepages.com",
        "text": (
            "A $50M ecommerce brand cancelled their Unbounce subscription 6 months ago.\n\n"
            "Nobody deleted the DNS CNAME record: `promo -> unbouncepages.com`.\n"
            "When Unbounce deleted the tenant, that record didn't disappear—it became a dangling pointer.\n\n"
            "An attacker claims the slug on Unbounce for $15, serves malicious checkout malware, "
            "and steals customer cookies on your apex domain.\n\n"
            "We catch dangling CNAMEs in 800ms via passive DoH (RFC 8484):\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️🐾"
        ),
    },
    {
        "id": "spf_10_lookup_limit",
        "pillar": ContentPillar.BREAK_AND_FIX,
        "title": "The 10-DNS-Lookup SPF Trap",
        "generator_type": "telemetry_card",
        "domain": "enterprise-saas.io",
        "score": 52,
        "spf_status": "PERMERROR (>10 lookups)",
        "dmarc_status": "NONE (Spoofable)",
        "dangling_count": 1,
        "text": (
            "RFC 7208 has a hard rule: SPF evaluation stops after 10 DNS lookups.\n\n"
            "Your team added HubSpot, SendGrid, Zendesk, Stripe, and Google Workspace to one TXT record.\n"
            "Result? `PermError`. Resolvers discard the entire policy.\n\n"
            "Congratulations: Anyone on earth can now spoof your CEO's email address and pass DMARC.\n\n"
            "Run a 10-second DoH audit before your next phishing simulation does it for you:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🚀"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: HIGH_IQ_WIT (Sysadmin & Astro-Cat Satire)
    # -------------------------------------------------------------
    {
        "id": "soc2_vs_dangling_subdomain",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "title": "The $250k SOC2 vs One Abandoned Subdomain",
        "generator_type": "dns_attack",
        "domain": "dev-staging-legacy.fintech.com",
        "target_cname": "s3-website-us-east-1.amazonaws.com",
        "text": (
            "Companies will spend $250,000 on a SOC2 Type II audit to prove their laptops have screensavers,\n"
            "while leaving `staging-2022.company.com` pointing to a deleted S3 bucket.\n\n"
            "Your perimeter isn't secured by PDF compliance binders.\n"
            "It's secured by cleaning up your DNS garbage before someone else claims your CNAMEs.\n\n"
            "Astro-Cat does not accept SOC2 excuses. Only clean zone files.\n"
            "https://cmfh009.github.io/Orbit-Security/ 🐾⚡"
        ),
    },
    {
        "id": "cat_dns_philosophy",
        "pillar": ContentPillar.HIGH_IQ_WIT,
        "title": "Astro-Cat DNS Engineering Principles",
        "generator_type": "telemetry_card",
        "domain": "acmecloud.dev",
        "score": 88,
        "spf_status": "PASS (Strict -all)",
        "dmarc_status": "REJECT (Enforced)",
        "dangling_count": 0,
        "text": (
            "Senior systems engineering rule #1:\n"
            "If a DNS record exists and nobody remembers what it does, do not delete it.\n"
            "Wait—no, that's how dangling CNAME takeovers happen.\n\n"
            "Delete the abandoned subdomain. Knock it off the counter like a glass of water.\n\n"
            "Sub-second DNS radar with zero bloat:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛰️🐱"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: MULTIMODAL_VISUAL & AI SECURITY
    # -------------------------------------------------------------
    {
        "id": "mcp_tool_injection_teardown",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "title": "Model Context Protocol (MCP) Prompt Injection Anatomy",
        "generator_type": "ai_sec_flow",
        "topic": "MCP Tool Output Poisoning & Sandbox Escape",
        "attack_vector": "Untrusted web content injects malicious JSON tool call parameters",
        "orbit_defense": "Deterministic AST parser isolates agent execution boundaries",
        "text": (
            "Giving an autonomous AI agent shell access without tool-output sandboxing is just "
            "remote code execution with polite English syntax.\n\n"
            "Anatomy of an MCP tool injection:\n"
            "1. Agent scrapes untrusted external page\n"
            "2. Hidden markdown payload overrides system prompt\n"
            "3. Agent executes arbitrary CLI commands\n\n"
            "Here is how we architect zero-trust boundaries around AI agent loops:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️🤖👇"
        ),
    },
    {
        "id": "shadow_ai_dns_exfiltration",
        "pillar": ContentPillar.MULTIMODAL_VISUAL,
        "title": "Shadow AI & Rogue DNS Endpoints",
        "generator_type": "ai_sec_flow",
        "topic": "Shadow AI API Exposure & DNS Tunneling",
        "attack_vector": "Unsanctioned internal LLM test servers exposed on public CNAMEs",
        "orbit_defense": "Continuous DoH fleet radar catches unauthenticated endpoints",
        "text": (
            "Every startup currently has 3 engineers who spun up private Ollama / vLLM endpoints on AWS,\n"
            "mapped them to `ai-test.company.com`, and forgot to configure authentication.\n\n"
            "One sub-second DNS scan catches them all before external attackers do.\n\n"
            "Audit your perimeter before your proprietary embeddings end up on Pastebin:\n"
            "https://cmfh009.github.io/Orbit-Security/ 🛡️⚡"
        ),
    },
    # -------------------------------------------------------------
    # Pillar: AGENCY_GROWTH (Retainer Conversion Playbook)
    # -------------------------------------------------------------
    {
        "id": "agency_retainer_conversion_formula",
        "pillar": ContentPillar.AGENCY_GROWTH,
        "title": "How Agencies Turn a 10s Scan into a $250/mo Retainer",
        "generator_type": "telemetry_card",
        "domain": "clientbrand.com",
        "score": 64,
        "spf_status": "SOFTFAIL (~all)",
        "dmarc_status": "NONE (High Risk)",
        "dangling_count": 2,
        "text": (
            "How web agencies pitch $250–$500/mo security retainers without writing code:\n\n"
            "1. Run Orbit's 10-second DoH audit on prospect domain\n"
            "2. Discover their abandoned CNAMEs & spoofable SPF\n"
            "3. Export white-label executive audit PDF\n"
            "4. \"We found 2 critical perimeter vulnerabilities in your DNS. Let's patch them this week.\"\n\n"
            "Free client scanning radar:\n"
            "https://cmfh009.github.io/Orbit-Security/ 💼🐾"
        ),
    },
]


class CreativeEngine:
    """Orchestrates high-IQ copywriting, prompt generation, and multimodal visual pairing."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.marketing = MarketingStrategyEngine(project_root=self.root)
        self.media_gen = MediaGenerator(project_root=self.root)

    def generate_next_post(
        self,
        recent_post_ids: Optional[List[str]] = None,
        target_pillar: Optional[ContentPillar] = None,
    ) -> GeneratedPost:
        """Selects or synthesizes the next high-impact post and generates its multimodal asset."""
        recent_ids = recent_post_ids or []

        # Find eligible blueprints not recently posted
        eligible = [bp for bp in POST_BLUEPRINTS if bp["id"] not in recent_ids]
        if not eligible:
            # All posted; reset pool
            eligible = POST_BLUEPRINTS

        # Filter by pillar if specified
        if target_pillar:
            pillar_eligible = [bp for bp in eligible if bp["pillar"] == target_pillar]
            if pillar_eligible:
                eligible = pillar_eligible

        chosen = random.choice(eligible)

        # Generate fresh multimodal asset tailored to the blueprint
        gen_type = chosen.get("generator_type")
        media_path = None
        try:
            if gen_type == "dns_attack":
                media_path = str(
                    self.media_gen.generate_dns_attack_diagram(
                        domain=chosen.get("domain", "promo.brand.com"),
                        target_cname=chosen.get("target_cname", "unbouncepages.com"),
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
                        domain=chosen.get("domain", "clientdomain.com"),
                        score=chosen.get("score", 75),
                        spf_status=chosen.get("spf_status", "PASS"),
                        dmarc_status=chosen.get("dmarc_status", "ENFORCED"),
                        dangling_count=chosen.get("dangling_count", 0),
                    )
                )
        except Exception as e:
            logger.error(f"Error generating multimodal visual for {chosen['id']}: {e}")
            media_path = None

        # Evaluate opening hook
        hook_eval = self.marketing.evaluate_hook(chosen["text"])

        return GeneratedPost(
            id=chosen["id"],
            text=chosen["text"],
            media_path=media_path,
            pillar=chosen["pillar"],
            title=chosen["title"],
            hook_score=hook_eval.score,
        )
