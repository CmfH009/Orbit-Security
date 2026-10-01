"""Orbit Security Marketing Strategy & Growth Intelligence Engine (marketing_strategy.py).

Agent Persona: @OrbitStrategist
Mandate: Implements the 4-Pillar Content Matrix, viral hook scoring,
algorithmic posting cadence, and trend-alignment for Orbit Security on X.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
from enum import Enum
import json
import logging
from pathlib import Path
import random
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ContentPillar(str, Enum):
    BREAK_AND_FIX = "break_and_fix"          # 40% target: Technical DNS & Infosec teardowns
    HIGH_IQ_WIT = "high_iq_wit"              # 25% target: Dev/Sysadmin satire & cat founder humor
    MULTIMODAL_VISUAL = "multimodal_visual"  # 20% target: Network diagrams, animations, telemetry
    AGENCY_GROWTH = "agency_growth"          # 15% target: $250/mo security retainer conversions


@dataclass
class HookEvaluation:
    """Quantitative scoring of a tweet opening hook."""

    text: str
    score: float
    is_strong: bool
    feedback: List[str] = field(default_factory=list)
    banned_words_found: List[str] = field(default_factory=list)


BANNED_BUZZWORDS: List[str] = [
    "in today's fast-paced",
    "dive deep",
    "game-changer",
    "game changer",
    "unlock the power",
    "revolutionize",
    "vital importance",
    "it's crucial to",
    "look no further",
    "buckle up",
    "let's unpack",
    "supercharge",
    "seamlessly integrate",
]

TECHNICAL_CREDIBILITY_TRIGGERS: List[str] = [
    "rfc",
    "dns",
    "cname",
    "doh",
    "dmarc",
    "spf",
    "dkim",
    "zone file",
    "subdomain",
    "mcp",
    "injection",
    "sandbox",
    "cve",
    "takeover",
    "resolver",
    "ttl",
    "tls",
]


class MarketingStrategyEngine:
    """Evaluates content cadence, audience timing, and viral mechanics."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.pillar_weights: Dict[ContentPillar, float] = {
            ContentPillar.BREAK_AND_FIX: 0.40,
            ContentPillar.HIGH_IQ_WIT: 0.25,
            ContentPillar.MULTIMODAL_VISUAL: 0.20,
            ContentPillar.AGENCY_GROWTH: 0.15,
        }

    def evaluate_hook(self, text: str) -> HookEvaluation:
        """Scores the first 1-2 lines of copy for viral intrigue and authority."""
        first_paragraph = text.strip().split("\n\n")[0].strip()
        first_lower = first_paragraph.lower()
        score = 0.50
        feedback = []
        banned_found = []

        # 1. Banned buzzword penalty
        for buzz in BANNED_BUZZWORDS:
            if buzz in first_lower:
                banned_found.append(buzz)
                score -= 0.25
                feedback.append(f"Contains AI cliché buzzword: '{buzz}'")

        # 2. Technical credibility triggers
        tech_matches = [trig for trig in TECHNICAL_CREDIBILITY_TRIGGERS if trig in first_lower]
        if tech_matches:
            boost = min(len(tech_matches) * 0.10, 0.30)
            score += boost
            feedback.append(f"Strong technical anchors: {tech_matches[:3]}")

        # 3. Conciseness check (first hook should be snappy, ideally <= 140 chars)
        hook_len = len(first_paragraph)
        if 40 <= hook_len <= 150:
            score += 0.15
            feedback.append(f"Ideal hook length ({hook_len} chars)")
        elif hook_len > 220:
            score -= 0.10
            feedback.append(f"Hook too verbose ({hook_len} chars); consider breaking earlier")

        # 4. Curiosity/Contrarian marker (questions, colons, numbers)
        if any(c in first_paragraph for c in [":", "?", "$", "%"]):
            score += 0.10
            feedback.append("Contains high-engagement structural anchors (colon, metric, or question)")

        final_score = round(min(max(score, 0.0), 1.0), 2)
        return HookEvaluation(
            text=first_paragraph,
            score=final_score,
            is_strong=final_score >= 0.70 and len(banned_found) == 0,
            feedback=feedback,
            banned_words_found=banned_found,
        )

    def select_next_content_pillar(self, recent_categories: List[str]) -> ContentPillar:
        """Selects the next optimal pillar using weighted distribution balanced against recent history."""
        counts = {p: 0 for p in ContentPillar}
        for cat in recent_categories:
            for p in ContentPillar:
                if p.value == cat or p.name.lower() == cat.lower():
                    counts[p] += 1

        total = sum(counts.values()) or 1
        # Calculate current deficit compared to target weights
        deficits: Dict[ContentPillar, float] = {}
        for pillar, target_weight in self.pillar_weights.items():
            actual_weight = counts[pillar] / total
            deficits[pillar] = target_weight - actual_weight

        # Sort pillars by highest deficit (most under-represented)
        sorted_pillars = sorted(deficits.items(), key=lambda kv: kv[1], reverse=True)
        return sorted_pillars[0][0]

    def get_audience_engagement_band(self, target_time: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Calculates current time-of-day window and algorithmic reach multiplier."""
        dt = target_time or datetime.datetime.now(datetime.timezone.utc)
        hour_utc = dt.hour

        # Peak hours map approximately to US Eastern 08:00 - 17:00 (12:00 - 21:00 UTC)
        if 12 <= hour_utc <= 15:
            band = "MORNING_PRIME"
            multiplier = 1.3
            recommended_pillar = ContentPillar.BREAK_AND_FIX
        elif 16 <= hour_utc <= 20:
            band = "AFTERNOON_PEAK"
            multiplier = 1.2
            recommended_pillar = ContentPillar.MULTIMODAL_VISUAL
        elif 21 <= hour_utc <= 23:
            band = "EVENING_CASUAL"
            multiplier = 1.0
            recommended_pillar = ContentPillar.HIGH_IQ_WIT
        else:
            band = "NIGHT_OFF_PEAK"
            multiplier = 0.7
            recommended_pillar = ContentPillar.AGENCY_GROWTH

        return {
            "hour_utc": hour_utc,
            "band": band,
            "reach_multiplier": multiplier,
            "recommended_pillar": recommended_pillar.value,
        }
