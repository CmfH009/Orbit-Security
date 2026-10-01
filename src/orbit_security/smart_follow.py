"""Orbit Security Smart Follower & Network Graph Discovery Engine (smart_follow.py).

Agent Persona: @OrbitScout
Mandate: Autonomously curates and expands Orbit Security's network graph on X.
Targets high-signal cybersecurity researchers, CISOs, AI safety specialists,
and SaaS/agency founders while enforcing strict anti-bot quota governors.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
from pathlib import Path
import random
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# High-signal seed accounts across Infosec, AI Safety, and SaaS Agency domains
DEFAULT_SEED_ACCOUNTS: List[Dict[str, Any]] = [
    {
        "handle": "troyhunt",
        "name": "Troy Hunt",
        "category": "infosec",
        "topics": ["haveibeenpwned", "passwords", "dns", "web-security"],
        "authority_weight": 0.95,
    },
    {
        "handle": "SwiftOnSecurity",
        "name": "SwiftOnSecurity",
        "category": "infosec",
        "topics": ["sysadmin", "defense", "dns", "infosec-humor"],
        "authority_weight": 0.95,
    },
    {
        "handle": "briankrebs",
        "name": "Brian Krebs",
        "category": "infosec",
        "topics": ["investigative", "cve", "breaches", "cybercrime"],
        "authority_weight": 0.92,
    },
    {
        "handle": "danielmiessler",
        "name": "Daniel Miessler",
        "category": "infosec_ai",
        "topics": ["fabric", "unsupervised-learning", "recon", "ai-security"],
        "authority_weight": 0.93,
    },
    {
        "handle": "simonw",
        "name": "Simon Willison",
        "category": "ai_security",
        "topics": ["prompt-injection", "llm-security", "datasette", "python"],
        "authority_weight": 0.96,
    },
    {
        "handle": "karpathy",
        "name": "Andrej Karpathy",
        "category": "ai",
        "topics": ["deep-learning", "llms", "ai-architecture", "neural-nets"],
        "authority_weight": 0.98,
    },
    {
        "handle": "yoheinakajima",
        "name": "Yohei Nakajima",
        "category": "ai_agents",
        "topics": ["autonomous-agents", "babyagi", "startups"],
        "authority_weight": 0.88,
    },
    {
        "handle": "BleepinComputer",
        "name": "BleepingComputer",
        "category": "threat_intel",
        "topics": ["ransomware", "zero-days", "vulnerabilities"],
        "authority_weight": 0.94,
    },
    {
        "handle": "SchneierBlog",
        "name": "Bruce Schneier",
        "category": "cryptography",
        "topics": ["crypto", "privacy", "security-philosophy"],
        "authority_weight": 0.95,
    },
    {
        "handle": "levelsio",
        "name": "Pieter Levels",
        "category": "agency_saas",
        "topics": ["indie-hackers", "solopreneur", "automation"],
        "authority_weight": 0.90,
    },
    {
        "handle": "rauchg",
        "name": "Guillermo Rauch",
        "category": "infrastructure",
        "topics": ["vercel", "dns", "edge-computing", "web-performance"],
        "authority_weight": 0.92,
    },
    {
        "handle": "moxie",
        "name": "Moxie Marlinspike",
        "category": "cryptography",
        "topics": ["signal", "encryption", "privacy-systems"],
        "authority_weight": 0.93,
    },
]

# Keywords indicating technical alignment for prospective follows
POSITIVE_BIO_KEYWORDS: Set[str] = {
    "ciso",
    "infosec",
    "cybersecurity",
    "security",
    "devsecops",
    "dns",
    "red team",
    "blue team",
    "pentester",
    "bug bounty",
    "ai safety",
    "prompt injection",
    "llm security",
    "vulnerability",
    "sysadmin",
    "cloud architect",
    "founder",
    "cto",
    "security engineer",
    "zero trust",
}

# Negative keywords for immediate rejection (crypto shilling, engagement bait, bots)
NEGATIVE_BIO_KEYWORDS: Set[str] = {
    "crypto airdrop",
    "pump and dump",
    "memecoin",
    "follow back 100%",
    "f4f",
    "dm for promo",
    "telegram signal",
    "forex trader",
}


@dataclass
class AccountProfile:
    """Represents candidate metadata for follow evaluation."""

    handle: str
    name: str = ""
    bio: str = ""
    followers_count: int = 0
    following_count: int = 0
    posts_count: int = 0
    is_verified: bool = False
    pinned_tweet: str = ""
    discovered_via: str = "seed"


@dataclass
class FollowEvaluation:
    """Result of an account quality and relevance evaluation."""

    handle: str
    should_follow: bool
    score: float
    reasons: List[str] = field(default_factory=list)
    category: str = "general_tech"


class SmartFollowEngine:
    """Intelligent network graph builder and follow governor."""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        daily_follow_cap: int = 10,
        unfollow_grace_days: int = 30,
    ):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.state_file = self.root / "data" / "smart_follow_state.json"
        self.daily_follow_cap = daily_follow_cap
        self.unfollow_grace_days = unfollow_grace_days
        self._load_state()

    def _load_state(self) -> None:
        """Loads persistent follow history and daily tracking."""
        self.followed_accounts: Dict[str, Dict[str, Any]] = {}
        self.daily_history: Dict[str, int] = {}
        self.ignored_accounts: Set[str] = set()

        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.followed_accounts = data.get("followed_accounts", {})
                    self.daily_history = data.get("daily_history", {})
                    self.ignored_accounts = set(data.get("ignored_accounts", []))
            except Exception as e:
                logger.error(f"Error loading smart_follow_state.json: {e}")

    def _save_state(self) -> None:
        """Persists follow history and daily tracking to disk."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            payload = {
                "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "daily_history": self.daily_history,
                "followed_accounts": self.followed_accounts,
                "ignored_accounts": list(self.ignored_accounts),
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving smart_follow_state.json: {e}")

    def get_today_follow_count(self) -> int:
        """Returns the number of follows executed on the current UTC date."""
        today_key = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        return self.daily_history.get(today_key, 0)

    def can_follow_today(self) -> bool:
        """Checks if today's follow quota allows additional follows."""
        return self.get_today_follow_count() < self.daily_follow_cap

    def evaluate_account(self, profile: AccountProfile) -> FollowEvaluation:
        """Heuristically evaluates an account profile for follow worthiness."""
        handle_lower = profile.handle.lower().lstrip("@")
        bio_lower = profile.bio.lower()

        # Reject if already followed or intentionally ignored
        if handle_lower in self.followed_accounts:
            return FollowEvaluation(
                handle=handle_lower,
                should_follow=False,
                score=0.0,
                reasons=["Already followed"],
            )

        if handle_lower in self.ignored_accounts:
            return FollowEvaluation(
                handle=handle_lower,
                should_follow=False,
                score=0.0,
                reasons=["Previously marked ignored/irrelevant"],
            )

        # 1. Filter negative keywords
        for neg in NEGATIVE_BIO_KEYWORDS:
            if neg in bio_lower:
                return FollowEvaluation(
                    handle=handle_lower,
                    should_follow=False,
                    score=0.0,
                    reasons=[f"Contains negative bio keyword: '{neg}'"],
                )

        score = 0.50
        reasons = []

        # 2. Check positive keyword matches
        matched_keywords = [kw for kw in POSITIVE_BIO_KEYWORDS if kw in bio_lower]
        if matched_keywords:
            keyword_boost = min(len(matched_keywords) * 0.12, 0.35)
            score += keyword_boost
            reasons.append(f"Matched positive keywords: {matched_keywords[:4]}")

        # 3. Follower ratio analysis (must not be an extreme follower spammer)
        if profile.following_count > 0:
            ratio = profile.followers_count / profile.following_count
            if ratio < 0.2 and profile.following_count > 1000:
                score -= 0.3
                reasons.append(f"Low follower-to-following ratio ({ratio:.2f})")
            elif ratio >= 1.0:
                score += 0.1
                reasons.append(f"Healthy follower ratio ({ratio:.2f})")

        # 4. Activity check
        if profile.posts_count > 50:
            score += 0.05
            reasons.append("Active posting history (>50 posts)")

        # 5. Verified / Authority boost
        if profile.is_verified:
            score += 0.05
            reasons.append("Verified account")

        score = min(max(score, 0.0), 1.0)
        should_follow = score >= 0.65 and len(matched_keywords) > 0

        # Determine primary category
        category = "infosec"
        if any(k in bio_lower for k in ["ai safety", "prompt injection", "llm", "neural"]):
            category = "ai_security"
        elif any(k in bio_lower for k in ["founder", "cto", "agency"]):
            category = "saas_founder"

        return FollowEvaluation(
            handle=handle_lower,
            should_follow=should_follow,
            score=round(score, 3),
            reasons=reasons,
            category=category,
        )

    def select_seed_target(self) -> Optional[Dict[str, Any]]:
        """Selects an unfollowed high-authority seed target from the curated roster."""
        unfollowed_seeds = [
            seed for seed in DEFAULT_SEED_ACCOUNTS
            if seed["handle"].lower() not in self.followed_accounts
            and seed["handle"].lower() not in self.ignored_accounts
        ]
        if not unfollowed_seeds:
            return None

        # Sort by authority weight descending with slight random jitter
        unfollowed_seeds.sort(
            key=lambda s: s.get("authority_weight", 0.5) + random.uniform(-0.05, 0.05),
            reverse=True,
        )
        return unfollowed_seeds[0]

    def record_follow_success(
        self,
        handle: str,
        category: str = "infosec",
        notes: str = "",
        discovered_via: str = "seed",
    ) -> None:
        """Records a successful follow action, updating daily quotas and persistence."""
        handle_clean = handle.lower().lstrip("@")
        today_key = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        self.followed_accounts[handle_clean] = {
            "followed_at_utc": now_iso,
            "category": category,
            "notes": notes,
            "discovered_via": discovered_via,
            "has_followed_back": False,
            "status": "FOLLOWING",
        }

        self.daily_history[today_key] = self.daily_history.get(today_key, 0) + 1
        self._save_state()
        logger.info(
            f"Successfully logged follow for @{handle_clean} (Today: {self.daily_history[today_key]}/{self.daily_follow_cap})"
        )

    def identify_stale_follows(self) -> List[str]:
        """Identifies accounts followed past the grace period that did not follow back."""
        stale = []
        now = datetime.datetime.now(datetime.timezone.utc)
        for handle, data in self.followed_accounts.items():
            if data.get("status") == "FOLLOWING" and not data.get("has_followed_back", False):
                followed_at_str = data.get("followed_at_utc")
                if followed_at_str:
                    try:
                        followed_at = datetime.datetime.fromisoformat(followed_at_str)
                        days_elapsed = (now - followed_at).days
                        if days_elapsed >= self.unfollow_grace_days:
                            stale.append(handle)
                    except Exception:
                        pass
        return stale
