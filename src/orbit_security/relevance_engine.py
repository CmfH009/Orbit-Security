"""Orbit Security — Relevance Intelligence & Social Action Engine (relevance_engine.py).

Autonomous discovery, multi-tier keyword filtering, spam/noise suppression,
composite relevance scoring (0-100), domain extraction, and automated action
classification (LIKE vs REPOST vs REPLY vs POST) for the Project ORBIT social agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
from enum import Enum
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field as PydanticField

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 1. CURATED KNOWLEDGE & REGISTRIES
# -----------------------------------------------------------------------------

# Curated X List: "Infosec & Zero-Day Watch" (List ID: 2103939027368051079)
CURATED_INFOSEC_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    # Tier 1: Industry Broadcasters & Journalists
    "briankrebs": {"tier": 1, "role": "Investigative Journalist", "weight": 25},
    "krebsonsecurity": {"tier": 1, "role": "Investigative News Wire", "weight": 25},
    "thehackersnews": {"tier": 1, "role": "Global Breaking News", "weight": 25},
    "bleepincomputer": {"tier": 1, "role": "Ransomware & Threat Wire", "weight": 25},
    "darkreading": {"tier": 1, "role": "Enterprise Cyber Defense", "weight": 25},

    # Tier 2: Technical Researchers & Thought Leaders
    "troyhunt": {"tier": 2, "role": "Web App Security & HIBP Creator", "weight": 25},
    "danielmiessler": {"tier": 2, "role": "Security Architect & AI/Recon", "weight": 25},
    "gossithedog": {"tier": 2, "role": "Threat Intelligence Specialist", "weight": 25},
    "cyb3rops": {"tier": 2, "role": "Threat Hunter & SIGMA Creator", "weight": 25},
    "swiftonsecurity": {"tier": 2, "role": "Systems Architecture & Defensive Culture", "weight": 25},

    # Tier 3: Practical Red Team & Security Educators
    "_johnhammond": {"tier": 3, "role": "Malware Analyst & Educator", "weight": 25},
    "hackingdave": {"tier": 3, "role": "TrustedSec Founder & Red Team Lead", "weight": 25},
    "malwarejake": {"tier": 3, "role": "SANS Principal Instructor", "weight": 25},
    "racheltobac": {"tier": 3, "role": "Social Engineering & Defensive Sec", "weight": 25},
    "k8em0": {"tier": 3, "role": "Vulnerability Disclosure & Bug Bounty Pioneer", "weight": 25},
    "hacks4pancakes": {"tier": 3, "role": "Incident Response & ICS Defense", "weight": 25},

    # Supplementary Watchdogs completing the 19 list members
    "campuscodi": {"tier": 1, "role": "Threat Intel & Cybercrime Reporter", "weight": 25},
    "vxunderground": {"tier": 2, "role": "Malware Research Library", "weight": 25},
    "malwrhunterteam": {"tier": 2, "role": "Threat & Ransomware Hunter", "weight": 25},
}

# Live Keyword Search Vector Queries
LIVE_SEARCH_QUERIES: List[Dict[str, Any]] = [
    {
        "query_id": "takeover_dns",
        "category": "Core Subdomain Hygiene",
        "query": '("dangling CNAME" OR "subdomain takeover" OR "dangling DNS") -airdrop -giveaway',
        "priority": "HIGH",
        "cadence_hours": 1,
    },
    {
        "query_id": "email_auth_drift",
        "category": "Email Spoofing & RFC 7489",
        "query": '("DMARC p=none" OR "SPF fail" OR "RFC 7489" OR "email spoofing") -airdrop',
        "priority": "HIGH",
        "cadence_hours": 1,
    },
    {
        "query_id": "agency_retainers",
        "category": "Care Plans & Retainer Defense",
        "query": '("website maintenance retainer" OR "WordPress maintenance care plan" OR "maintenance care plan" OR "agency retainer churn") -crypto',
        "priority": "HIGH",
        "cadence_hours": 2,
    },
    {
        "query_id": "shopify_dns",
        "category": "Shopify Plus Infrastructure",
        "query": '("Shopify Plus DNS" OR "Shopify CNAME" OR "headless Shopify DNS")',
        "priority": "MEDIUM",
        "cadence_hours": 2,
    },
    {
        "query_id": "ssl_expirations",
        "category": "TLS Certificate Drift",
        "query": '("expired SSL certificate" OR "SSL cert expired" OR "cert expired production") -giveaway',
        "priority": "MEDIUM",
        "cadence_hours": 2,
    },
    {
        "query_id": "inbound_roast_mentions",
        "category": "Inbound Roast & Tool Mentions",
        "query": '(@_arsoncode OR "Orbit Security" OR "orbit-recon" OR "roast my site" OR "audit my domain")',
        "priority": "URGENT",
        "cadence_hours": 1,
    },
]

# Denied Domains and False Positives for Domain Extraction
DENIED_DOMAINS_SET: Set[str] = {
    # Platforms & Social
    "x.com", "twitter.com", "t.co", "github.com", "github.io", "gitlab.com",
    "youtube.com", "youtu.be", "linkedin.com", "facebook.com", "instagram.com",
    "medium.com", "reddit.com", "discord.gg", "discord.com", "slack.com",
    "threads.net", "tiktok.com", "twitch.tv", "substack.com", "wikipedia.org",
    # URL Shorteners
    "bit.ly", "tinyurl.com", "ow.ly", "buff.ly", "is.gd", "goo.gl", "ft.com",
    # Code extensions / common technical names
    "node.js", "react.js", "vue.js", "next.js", "angular.js", "express.js",
    "schema.org", "w3.org", "rfc-editor.org", "package.json", "index.html",
    "orbit-security.com", "cmfh009.github.io",
}

# Negative Spam Triggers (Hard Instant Drop)
SPAM_HARD_TRIGGERS: List[re.Pattern] = [
    re.compile(r"\b(airdrop|airdropping|minting|presale|whitelist|claim\s+airdrop)\b", re.I),
    re.compile(r"\b(pump\.fun|dexscreener|memecoin|moonshot|\$sol|\$btc|\$eth|\$usdt)\b", re.I),
    re.compile(r"\b(ca:\s*0x[a-f0-9]{30,}|solana\s+contract)\b", re.I),
    re.compile(r"\b(f4f|follow\s*for\s*follow|gain\s*followers|follow\s*train)\b", re.I),
    re.compile(r"\b(t\.me\/|wa\.me\/|telegram\s+channel|whatsapp\s+recovery)\b", re.I),
    re.compile(r"\b(dm\s+to\s+recover|hacked\s+account\s+recovery|recover\s+crypto)\b", re.I),
]

# Negative Soft Noise Triggers (Penalty Deductions)
SPAM_SOFT_TRIGGERS: List[Tuple[re.Pattern, int]] = [
    (re.compile(r"\b(grow\s+your\s+b2b\s+saas\s+fast|automated\s+lead\s+gen)\b", re.I), 25),
    (re.compile(r"\b(cve-\d{4}-\d{4,}\s+vulnerability\s+published)\b", re.I), 20),  # Raw CVE bot feed without insight
    (re.compile(r"\b(link\s+in\s+bio|check\s+bio)\b", re.I), 15),
]


# -----------------------------------------------------------------------------
# 2. DATA MODELS & SCHEMAS
# -----------------------------------------------------------------------------

class DiscoveryVector(str, Enum):
    CURATED_LIST = "CURATED_LIST"
    TARGET_AGENCY = "TARGET_AGENCY"
    KEYWORD_SEARCH = "KEYWORD_SEARCH"
    INBOUND_MENTION = "INBOUND_MENTION"


class ActionType(str, Enum):
    LIKE = "LIKE"
    REPOST = "REPOST"
    QUOTE = "QUOTE"
    REPLY = "REPLY"
    POST_ORIGINAL = "POST"
    DROP = "DROP"


class DiscoveredPost(BaseModel):
    tweet_id: str
    author_handle: str
    text: str
    author_followers: int = 0
    is_verified: bool = False
    created_at_utc: datetime.datetime = PydanticField(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    like_count: int = 0
    retweet_count: int = 0
    reply_count: int = 0
    discovery_vector: DiscoveryVector = DiscoveryVector.KEYWORD_SEARCH
    query_id: Optional[str] = None
    detected_domains: List[str] = PydanticField(default_factory=list)


class RelevanceScore(BaseModel):
    total_score: int
    keyword_score: int
    author_score: int
    domain_score: int
    engagement_score: int
    noise_penalty: int
    is_hard_dropped: bool = False
    drop_reason: Optional[str] = None
    matched_keywords: List[str] = PydanticField(default_factory=list)


class ActionDecision(BaseModel):
    post_id: str
    author_handle: str
    action: ActionType
    score: int
    reasoning: str
    target_domain: Optional[str] = None
    roast_tweet_copy: Optional[str] = None
    scan_recommended: bool = False


# -----------------------------------------------------------------------------
# 3. RELEVANCE & SCORING INTELLIGENCE ENGINE
# -----------------------------------------------------------------------------

class RelevanceEngine:
    """Core discovery, evaluation, and decision engine for Orbit Security's social agent."""

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path(__file__).resolve().parent.parent.parent
        self.data_dir = self.project_root / "data"

        # Cached lookups
        self.agency_handles: Dict[str, Dict[str, Any]] = {}
        self.portfolio_domains: Dict[str, str] = {}  # domain -> agency_name
        self.agency_domains: Dict[str, str] = {}     # agency_domain -> agency_name

        self._load_registries()

    def _load_registries(self):
        """Loads and indexes agency profiles and portfolio targets."""
        # 1. Load data/agency_x_profiles.json
        agency_profiles_path = self.data_dir / "agency_x_profiles.json"
        if agency_profiles_path.exists():
            try:
                with open(agency_profiles_path, "r", encoding="utf-8") as f:
                    profiles = json.load(f)
                for p in profiles:
                    handle = p.get("x_handle", "").replace("@", "").lower().strip()
                    if handle:
                        self.agency_handles[handle] = p
                    # Index agency domain
                    ag_dom = p.get("agency_domain", "").lower().strip()
                    if ag_dom:
                        self.agency_domains[ag_dom] = p.get("agency_name", "")
                    # Index client domain
                    cl_dom = p.get("target_client_domain", "").lower().strip()
                    if cl_dom:
                        self.portfolio_domains[cl_dom] = p.get("agency_name", "")
            except Exception as e:
                logger.error(f"Error loading agency_x_profiles.json: {e}")

        # 2. Load data/prospects.json
        prospects_path = self.data_dir / "prospects.json"
        if prospects_path.exists():
            try:
                with open(prospects_path, "r", encoding="utf-8") as f:
                    prospects = json.load(f)
                for pr in prospects:
                    ag_name = pr.get("agency_name", "")
                    ag_dom = pr.get("agency_domain", "").lower().strip()
                    if ag_dom:
                        self.agency_domains[ag_dom] = ag_name
                    for port_dom in pr.get("portfolio_domains", []):
                        clean_p = port_dom.lower().strip()
                        if clean_p:
                            self.portfolio_domains[clean_p] = ag_name
            except Exception as e:
                logger.error(f"Error loading prospects.json: {e}")

    # -------------------------------------------------------------------------
    # DOMAIN EXTRACTION
    # -------------------------------------------------------------------------

    def extract_domains(self, text: str) -> List[str]:
        """Extracts and sanitizes valid fully qualified domain names from post text."""
        # Regex to locate standard hostnames
        domain_pattern = re.compile(
            r"\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,24})\b",
            re.IGNORECASE,
        )

        candidates = set()
        for match in domain_pattern.finditer(text):
            raw = match.group(0).lower().strip()
            # Clean protocol, port, path, query
            if raw.startswith("http://") or raw.startswith("https://"):
                try:
                    parsed = urlparse(raw)
                    raw = parsed.netloc or parsed.path
                except Exception:
                    pass

            raw = raw.split("/")[0].split(":")[0].strip(".,!?:;\"'()[]{}<>")
            if raw.startswith("www."):
                raw = raw[4:]

            # Basic validations
            if "." not in raw or len(raw) < 4:
                continue

            parts = raw.split(".")
            tld = parts[-1]
            # Exclude digits-only TLDs or common file types
            if tld.isdigit() or tld in {"png", "jpg", "jpeg", "gif", "svg", "pdf", "txt", "zip", "tar", "gz"}:
                continue

            if raw in DENIED_DOMAINS_SET:
                continue

            candidates.add(raw)

        # Prioritize portfolio domains first, then others
        def domain_sorter(d: str) -> int:
            if d in self.portfolio_domains:
                return 0
            if d in self.agency_domains:
                return 1
            return 2

        sorted_domains = sorted(list(candidates), key=domain_sorter)
        return sorted_domains

    # -------------------------------------------------------------------------
    # SPAM & NOISE SUPPRESSION
    # -------------------------------------------------------------------------

    def check_noise_and_spam(self, text: str, author_handle: str) -> Tuple[bool, Optional[str], int]:
        """Evaluates post for crypto spam, follow trains, tag floods, and soft noise.
        Returns: (is_hard_drop, drop_reason, penalty_points)
        """
        clean_handle = author_handle.lower().strip().replace("@", "")

        # Target agency or Curated list accounts get noise immunity against soft triggers
        is_curated = clean_handle in CURATED_INFOSEC_ACCOUNTS
        is_agency = clean_handle in self.agency_handles

        # 1. Hard Trigger Check (Crypto, Airdrops, Recovery Scams, Follow Trains)
        for pattern in SPAM_HARD_TRIGGERS:
            if pattern.search(text):
                return True, f"Spam Hard Filter Matched: {pattern.pattern}", 100

        # 2. Tag Flooding Check (5+ @mentions)
        mentions = re.findall(r"@([a-zA-Z0-9_]{1,30})", text)
        if len(mentions) >= 5:
            return True, "Tag flood detected (>= 5 mentions)", 100

        # 3. Soft Noise Penalty Evaluation
        soft_penalty = 0
        if not (is_curated or is_agency):
            for pattern, penalty in SPAM_SOFT_TRIGGERS:
                if pattern.search(text):
                    soft_penalty += penalty

        return False, None, soft_penalty

    # -------------------------------------------------------------------------
    # RELEVANCE SCORING ALGORITHM (0-100)
    # -------------------------------------------------------------------------

    def calculate_score(self, post: DiscoveredPost) -> RelevanceScore:
        """Computes multi-tier composite relevance score strictly in range [0, 100]."""
        text = post.text
        text_lower = text.lower()
        clean_handle = post.author_handle.lower().strip().replace("@", "")

        # 1. Spam & Noise Check
        is_hard_drop, drop_reason, noise_penalty = self.check_noise_and_spam(text, post.author_handle)
        if is_hard_drop:
            return RelevanceScore(
                total_score=0,
                keyword_score=0,
                author_score=0,
                domain_score=0,
                engagement_score=0,
                noise_penalty=100,
                is_hard_dropped=True,
                drop_reason=drop_reason,
            )

        matched_keywords = []

        # 2. Keyword Weighting (W_keyword: Max 35 pts)
        w_keyword = 0
        # Tier A: Core Subdomain & Takeover / DMARC Direct Hits (+35)
        tier_a_kw = [
            "dangling cname", "subdomain takeover", "cname takeover",
            "dmarc p=none", "dangling dns", "takeover signature",
        ]
        for kw in tier_a_kw:
            if kw in text_lower:
                w_keyword = max(w_keyword, 35)
                matched_keywords.append(kw)

        # Tier B: Agency Care Plans & Retainers (+30)
        tier_b_kw = [
            "website maintenance retainer", "wordpress maintenance care plan",
            "maintenance care plan", "care plan retainer", "retainer churn",
            "shopify plus dns", "maintenance retainer",
        ]
        for kw in tier_b_kw:
            if kw in text_lower:
                w_keyword = max(w_keyword, 30)
                matched_keywords.append(kw)

        # Tier C: Perimeter Hygiene & Email Auth (+22)
        tier_c_kw = [
            "spf fail", "expired ssl certificate", "mta-sts", "bimi record",
            "dkim alignment", "rfc 7489", "ssl cert expired",
        ]
        for kw in tier_c_kw:
            if kw in text_lower:
                w_keyword = max(w_keyword, 22)
                matched_keywords.append(kw)

        # Tier D: Secondary Infrastructure Signals (+15)
        tier_d_kw = [
            "dns drift", "unbounce 404", "s3 bucket takeover", "dns misconfiguration",
            "email spoofing", "bec fraud", "doh audit",
        ]
        for kw in tier_d_kw:
            if kw in text_lower:
                w_keyword = max(w_keyword, 15)
                matched_keywords.append(kw)

        # Tier E: General Infosec Terms (+8)
        tier_e_kw = ["zero-day", "breach", "cve", "vulnerability", "phishing attack"]
        for kw in tier_e_kw:
            if kw in text_lower and w_keyword == 0:
                w_keyword = max(w_keyword, 8)
                matched_keywords.append(kw)

        # Baseline hygiene relevance: genuine discussions of Tier A/B/C keywords qualify for engagement (LIKE threshold >= 50)
        if w_keyword >= 22:
            w_keyword = max(w_keyword, 45)

        # 3. Author Authority & Alignment (W_author: Max 35 pts)
        w_author = 5  # baseline
        if clean_handle in self.agency_handles:
            w_author = 30  # Verified target agency
        elif clean_handle in CURATED_INFOSEC_ACCOUNTS:
            w_author = CURATED_INFOSEC_ACCOUNTS[clean_handle]["weight"]  # 25 pts
        elif "_arsoncode" in text_lower or "orbit security" in text_lower or "orbit-recon" in text_lower:
            w_author = 25  # Inbound user addressing Orbit / Carson
        elif post.author_followers > 10000 or post.is_verified:
            w_author = 15

        # 4. Domain Detection & Audit Potential (W_domain: Max 25 pts)
        w_domain = 0
        detected = post.detected_domains or self.extract_domains(text)
        has_inbound_roast_request = any(
            req in text_lower
            for req in ["roast my", "check my", "audit my", "scan my", "what's my score", "hygiene score"]
        )

        if has_inbound_roast_request:
            w_keyword = max(w_keyword, 25)
            matched_keywords.append("inbound roast request")

        if detected:
            first_domain = detected[0]
            if first_domain in self.portfolio_domains:
                w_domain = 25  # Matches real agency client target
            elif has_inbound_roast_request:
                w_domain = 25  # Explicit user audit request
            elif first_domain in self.agency_domains:
                w_domain = 22  # Direct agency site
            else:
                w_domain = 18  # Valid FQDN routable domain
        elif has_inbound_roast_request:
            w_domain = 15  # Asked for roast but omitted domain

        # 5. Engagement Momentum & Actionability (W_engagement: Max 15 pts)
        w_engagement = 0
        # Author asks explicit question
        if "?" in text or any(q in text_lower for q in ["thoughts?", "anyone seen", "how do you handle", "help with"]):
            w_engagement += 8

        # Viral momentum
        velocity = post.like_count + (post.retweet_count * 2)
        if velocity >= 50:
            w_engagement += 7
        elif velocity >= 15:
            w_engagement += 4

        w_engagement = min(15, w_engagement)

        # 6. Composite Sum & Clamping
        gross_score = w_keyword + w_author + w_domain + w_engagement
        composite = max(0, min(100, gross_score - noise_penalty))

        return RelevanceScore(
            total_score=composite,
            keyword_score=w_keyword,
            author_score=w_author,
            domain_score=w_domain,
            engagement_score=w_engagement,
            noise_penalty=noise_penalty,
            is_hard_dropped=False,
            matched_keywords=matched_keywords,
        )

    # -------------------------------------------------------------------------
    # ACTION CLASSIFICATION & DECISION MATRIX
    # -------------------------------------------------------------------------

    def classify_action(self, post: DiscoveredPost, score: RelevanceScore) -> ActionDecision:
        """Classifies recommended action (LIKE, REPOST, QUOTE, REPLY, POST, DROP)."""
        clean_handle = post.author_handle.lower().strip().replace("@", "")
        text = post.text
        text_lower = text.lower()
        detected_domains = post.detected_domains or self.extract_domains(text)
        primary_domain = detected_domains[0] if detected_domains else None

        # Hard Drops or Sub-threshold
        if score.is_hard_dropped:
            return ActionDecision(
                post_id=post.tweet_id,
                author_handle=post.author_handle,
                action=ActionType.DROP,
                score=0,
                reasoning=f"Hard filter dropped: {score.drop_reason}",
            )

        if score.total_score < 50:
            return ActionDecision(
                post_id=post.tweet_id,
                author_handle=post.author_handle,
                action=ActionType.DROP,
                score=score.total_score,
                reasoning="Relevance score < 50 threshold for autonomous interaction.",
            )

        # Score 50 - 74: Standard Alignment -> LIKE
        if 50 <= score.total_score < 75:
            return ActionDecision(
                post_id=post.tweet_id,
                author_handle=post.author_handle,
                action=ActionType.LIKE,
                score=score.total_score,
                reasoning="Moderate alignment (50-74). Ideal for like/appreciation touchpoint.",
                target_domain=primary_domain,
            )

        # Score >= 75: High-Impact -> Evaluate REPLY vs REPOST/QUOTE vs LIKE

        # A. Inbound Roast Request or Mentions
        has_roast_request = any(
            hook in text_lower
            for hook in ["roast my", "check my", "audit my", "scan my", "what's my score", "hygiene score"]
        )
        if primary_domain and (has_roast_request or "_arsoncode" in text_lower or "orbit" in text_lower):
            return ActionDecision(
                post_id=post.tweet_id,
                author_handle=post.author_handle,
                action=ActionType.REPLY,
                score=score.total_score,
                reasoning="Inbound roast request with extracted domain. Trigger automated passive scan.",
                target_domain=primary_domain,
                scan_recommended=True,
            )

        # B. Direct Agency Engagement (Target Agency discussing clients or retainers)
        if clean_handle in self.agency_handles:
            # Agency discussing maintenance or launching build
            if any(term in text_lower for term in ["retainer", "maintenance", "care plan", "launch", "client"]):
                return ActionDecision(
                    post_id=post.tweet_id,
                    author_handle=post.author_handle,
                    action=ActionType.REPLY,
                    score=score.total_score,
                    reasoning="Target agency discussing care plans, retainers, or launches. High-priority reply.",
                    target_domain=primary_domain,
                    scan_recommended=bool(primary_domain),
                )
            else:
                return ActionDecision(
                    post_id=post.tweet_id,
                    author_handle=post.author_handle,
                    action=ActionType.LIKE,
                    score=score.total_score,
                    reasoning="Target agency general update. Affirmative like.",
                )

        # C. Question on DNS / DMARC / Subdomain Takeover
        has_question = "?" in text or any(q in text_lower for q in ["how to", "why does", "anyone know", "fix"])
        has_core_vuln = any(kw in text_lower for kw in ["takeover", "dmarc", "spf", "cname", "dns drift", "expired ssl"])
        if has_question and has_core_vuln:
            return ActionDecision(
                post_id=post.tweet_id,
                author_handle=post.author_handle,
                action=ActionType.REPLY,
                score=score.total_score,
                reasoning="Technical question regarding DNS/DMARC/takeovers. Educational reply candidate.",
                target_domain=primary_domain,
                scan_recommended=bool(primary_domain),
            )

        # D. Curated Heavyweight News & Research -> REPOST or QUOTE
        if clean_handle in CURATED_INFOSEC_ACCOUNTS:
            tier = CURATED_INFOSEC_ACCOUNTS[clean_handle]["tier"]
            # Tier 1 Broadcasters -> Repost breaking breaches / zero-days
            if tier == 1 and any(kw in text_lower for kw in ["zero-day", "breach", "compromise", "vulnerability", "dns"]):
                return ActionDecision(
                    post_id=post.tweet_id,
                    author_handle=post.author_handle,
                    action=ActionType.REPOST,
                    score=score.total_score,
                    reasoning="Tier 1 Broadcaster breaking news relevant to web perimeters. Repost for signal.",
                )
            # Tier 2/3 Researchers & Educators -> Quote-tweet with agency retainer lens
            elif tier in (2, 3) and any(kw in text_lower for kw in ["dmarc", "spoof", "dns", "subdomain", "retainer"]):
                return ActionDecision(
                    post_id=post.tweet_id,
                    author_handle=post.author_handle,
                    action=ActionType.QUOTE,
                    score=score.total_score,
                    reasoning="Tier 2/3 Technical insight. Quote-tweet with agency perspective.",
                )

        # Fallback for high score: LIKE
        return ActionDecision(
            post_id=post.tweet_id,
            author_handle=post.author_handle,
            action=ActionType.LIKE,
            score=score.total_score,
            reasoning="High relevance infosec content. Standard value like.",
        )
