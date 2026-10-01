"""Orbit Security Conversation & Intelligent Reply Diplomat (conversation_diplomat.py).

Agent Persona: @OrbitDiplomat
Mandate: Contextually analyzes inbound mentions and viral infosec/AI discussions,
synthesizing high-IQ, helpful, and technically authoritative replies that build
domain credibility without promotional spam.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DiscussionContext:
    """Parsed metadata of an external thread or inbound mention."""

    tweet_id: str
    author_handle: str
    text: str
    reply_count: int = 0
    like_count: int = 0
    is_direct_mention: bool = False
    detected_topic: str = "general_infosec"


@dataclass
class DiplomaticReply:
    """A generated high-signal response to a technical thread."""

    target_tweet_id: str
    target_handle: str
    reply_text: str
    topic: str
    confidence_score: float
    includes_remediation_hint: bool = True


# Topic signature patterns
TOPIC_PATTERNS: Dict[str, List[str]] = {
    "dangling_cname": [
        "cname",
        "subdomain",
        "404",
        "subdomain takeover",
        "abandoned subdomain",
        "unbounce",
        "s3 bucket takeover",
    ],
    "email_auth": [
        "dmarc",
        "spf",
        "dkim",
        "emails going to spam",
        "permerror",
        "email spoofing",
        "deliverability",
    ],
    "dns_performance": [
        "dns-over-https",
        "doh",
        "rfc 8484",
        "port 53",
        "ttl propagation",
        "slow dns",
        "resolver latency",
    ],
    "ai_security": [
        "prompt injection",
        "mcp tool",
        "model context protocol",
        "agent loop",
        "sandbox escape",
        "context window leak",
    ],
}


class ConversationDiplomat:
    """Synthesizes high-IQ technical responses to community discussions."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent

    def detect_topic(self, text: str) -> Tuple[str, float]:
        """Detects the primary technical dilemma in the source tweet."""
        text_lower = text.lower()
        topic_scores: Dict[str, float] = {}

        for topic, keywords in TOPIC_PATTERNS.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                topic_scores[topic] = len(matches) * 0.35

        if not topic_scores:
            return "general_infosec", 0.50

        best_topic = max(topic_scores.items(), key=lambda kv: kv[1])
        return best_topic[0], min(best_topic[1] + 0.40, 0.98)

    def generate_reply(self, discussion: DiscussionContext) -> DiplomaticReply:
        """Formulates an authoritative, conversational response tailored to the problem."""
        topic, confidence = self.detect_topic(discussion.text)
        handle = discussion.author_handle.lstrip("@")

        if topic == "dangling_cname":
            reply = (
                f"@{handle} Classic dangling pointer trap. If the SaaS tenant was deleted "
                f"before the DNS zone record was pruned, edge resolvers will return 404 until claimed.\n\n"
                f"Quick check: `dig +nocmd +noall +answer {handle}.com CNAME`.\n"
                f"Passive RFC 8484 telemetry catches these before scanning bots do 🛡️🐾"
            )
        elif topic == "email_auth":
            reply = (
                f"@{handle} Worth checking if your SPF record hit the RFC 7208 10-lookup limit.\n"
                f"Once you chain HubSpot + SendGrid + Google Workspace, resolvers return PermError "
                f"and DMARC silently fails open.\n\n"
                f"Flattening your includes or checking alignment usually resolves it in minutes."
            )
        elif topic == "ai_security":
            reply = (
                f"@{handle} The core failure mode in agentic MCP loops is treating tool outputs "
                f"as trusted tokens in the next turn.\n"
                f"Without an AST validation boundary isolating tool returns from system instructions, "
                f"any parsed webpage can hijack execution flow 🤖🛡️"
            )
        elif topic == "dns_performance":
            reply = (
                f"@{handle} RFC 8484 DNS-over-HTTPS multiplexing over HTTP/2 handles this with "
                f"sub-10ms latency across Cloudflare & Google resolvers while bypassing local UDP throttling."
            )
        else:
            reply = (
                f"@{handle} Interesting angle. The perimeter edge is usually where the drift starts—"
                f"especially when teams rotate infrastructure without cleaning up legacy DNS zone pointers."
            )

        return DiplomaticReply(
            target_tweet_id=discussion.tweet_id,
            target_handle=handle,
            reply_text=reply,
            topic=topic,
            confidence_score=confidence,
        )
