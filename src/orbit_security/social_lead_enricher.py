"""Orbit Security Social Lead Enricher & Bio Scraper (social_lead_enricher.py).

Implements Act II Inbound Automation:
1. Extracts author profiles and bio URLs from incoming X interactions (likes, retweets, replies).
2. Parses apex and target domains from bios and website links.
3. Dispatches a rapid 5-second passive DNS/security scan via OrbitSecurityScanner.
4. If critical vulnerabilities are identified (dangling CNAME takeover or DMARC p=none/missing):
   - Qualifies the prospect as a high-value lead.
   - Drafts a personalized direct message (DM) from Carson Haynes (@_arsoncode).
   - Records and deduplicates the lead in data/social_leads.json.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import urllib.parse
import uuid

from orbit_security.models import DomainAuditResult, Finding, Severity
from orbit_security.scanner import OrbitSecurityScanner

logger = logging.getLogger("orbit_security.social_lead_enricher")

DEFAULT_LEADS_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "social_leads.json"
ARCADE_URL = "https://cmfh009.github.io/Orbit-Security/"

# Domains to ignore when extracting company/brand website
IGNORED_DOMAINS = {
    "twitter.com",
    "x.com",
    "t.co",
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "github.com",
    "youtube.com",
    "youtu.be",
    "linktr.ee",
    "bio.link",
    "beacons.ai",
    "tiktok.com",
    "threads.net",
    "discord.gg",
    "twitch.tv",
    "medium.com",
    "substack.com",
}


class BioUrlExtractor:
    """Extracts valid target domains from user bio text and profile website URLs."""

    DOMAIN_REGEX = re.compile(
        r"(?:https?://)?(?:www\.)?((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})",
        re.IGNORECASE,
    )

    @classmethod
    def clean_domain(cls, raw_url_or_domain: str) -> Optional[str]:
        if not raw_url_or_domain:
            return None
        text = raw_url_or_domain.strip().lower()
        # Strip trailing sentence punctuation
        text = text.rstrip(".,;!?:)'\"")

        # Add protocol if missing so urlparse handles netloc properly
        if not text.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse("http://" + text)
        else:
            parsed = urllib.parse.urlparse(text)

        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Strip port and username if any
        netloc = netloc.split(":")[0].split("@")[-1]

        # Strip leading www. and trailing dots
        if netloc.startswith("www."):
            netloc = netloc[4:]
        netloc = netloc.rstrip(".")

        # Validate domain structure
        if "." not in netloc or len(netloc) < 4:
            return None

        # Check ignored domains
        if netloc in IGNORED_DOMAINS or any(netloc.endswith("." + ign) for ign in IGNORED_DOMAINS):
            return None

        return netloc

    @classmethod
    def extract(cls, bio_text: str = "", bio_url: Optional[str] = None) -> Optional[str]:
        # 1. First priority: explicit bio website link
        if bio_url:
            candidate = cls.clean_domain(bio_url)
            if candidate:
                return candidate

        # 2. Second priority: regex search within bio text
        if bio_text:
            matches = cls.DOMAIN_REGEX.findall(bio_text)
            for m in matches:
                cand = cls.clean_domain(m)
                if cand:
                    return cand

        return None


def extract_domain_from_bio(bio_text: str = "", bio_url: Optional[str] = None) -> Optional[str]:
    """Helper functional wrapper for BioUrlExtractor."""
    return BioUrlExtractor.extract(bio_text=bio_text, bio_url=bio_url)


@dataclass
class UserProfile:
    """Represents an interacting X user's profile."""

    handle: str
    name: str = ""
    bio: str = ""
    bio_url: Optional[str] = None
    interaction_type: str = "like"  # "like", "retweet", "reply", "quote", "mention"
    source_tweet_id: Optional[str] = None
    source_post_url: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class SocialLead:
    """Qualified inbound lead from X interaction."""

    lead_id: str
    handle: str
    name: str
    target_domain: str
    interaction_type: str
    score: int
    grade: str
    has_critical_takeover: bool
    has_dmarc_vulnerability: bool
    findings_summary: List[str]
    drafted_dm: str
    status: str = "NEW"  # NEW, CONTACTED, CONVERTED, DROPPED
    source_tweet_id: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def draft_dm_pitch(
    handle: str,
    name: str,
    domain: str,
    findings: List[str],
    has_takeover: bool,
    has_dmarc_vulnerability: bool,
) -> str:
    """Drafts a personalized, value-first direct message from Carson Haynes (@_arsoncode)."""
    first_name = name.split()[0] if name else handle

    if has_takeover:
        takeover_detail = findings[0] if findings else "unclaimed third-party DNS pointer"
        pitch = (
            f"Hey {first_name} — noticed your interaction on Orbit! Quick heads up: our passive scan "
            f"flagged a potential dangling CNAME takeover on {domain} ({takeover_detail[:55]}). "
            f"Anyone could register that SaaS host and spoof your brand. "
            f"You can verify the DNS audit live in our 16-bit arcade: {ARCADE_URL} "
            f"— Carson (@_arsoncode)"
        )
    elif has_dmarc_vulnerability:
        pitch = (
            f"Hey {first_name} — thanks for connecting on Orbit! Ran a passive hygiene check on {domain} "
            f"and saw your DMARC policy is currently in monitoring mode (p=none) or missing. "
            f"This leaves your brand domain vulnerable to direct CEO/invoice email spoofing. "
            f"Check your breakdown in our arcade: {ARCADE_URL} "
            f"— Carson (@_arsoncode)"
        )
    else:
        pitch = (
            f"Hey {first_name} — appreciated your engagement on Orbit! Ran a quick passive security audit "
            f"on {domain} (Score: 78/100). Found a few header and DNS drift items worth patching. "
            f"Full report is available here: {ARCADE_URL} "
            f"— Carson (@_arsoncode)"
        )

    # Hard cap to ensure Twitter DM compliance
    return pitch[:490]


class SocialLeadEnricher:
    """Coordinates profile extraction, passive scanning, lead qualification, and persistence."""

    def __init__(
        self,
        leads_file: Optional[Path] = None,
        scanner_timeout: float = 5.0,
    ):
        self.leads_file = Path(leads_file) if leads_file else DEFAULT_LEADS_FILE
        self.scanner_timeout = scanner_timeout

    def _run_passive_scan(self, domain: str) -> Optional[DomainAuditResult]:
        """Runs an async passive scan with a 5-second timeout."""
        try:
            scanner = OrbitSecurityScanner(timeout=self.scanner_timeout)
            return asyncio.run(scanner.scan_domain(domain, use_crtsh=False))
        except Exception as e:
            logger.error(f"Passive scan error for {domain}: {e}")
            return None

    def load_leads(self) -> List[Dict[str, Any]]:
        """Loads existing leads from disk."""
        if not self.leads_file.exists():
            return []
        try:
            with open(self.leads_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.warning(f"Error loading leads from {self.leads_file}: {e}")
            return []

    def save_lead(self, lead: SocialLead):
        """Appends or updates a qualified lead with deduplication on handle + target_domain."""
        self.leads_file.parent.mkdir(parents=True, exist_ok=True)
        leads = self.load_leads()

        # Update existing record if same handle and domain
        updated = False
        for idx, item in enumerate(leads):
            if item.get("handle") == lead.handle and item.get("target_domain") == lead.target_domain:
                leads[idx] = lead.to_dict()
                updated = True
                break

        if not updated:
            leads.append(lead.to_dict())

        # Atomic file write
        tmp = self.leads_file.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(leads, f, indent=2)
            tmp.replace(self.leads_file)
            logger.info(f"Saved qualified lead @{lead.handle} ({lead.target_domain}) to {self.leads_file.name}")
        except Exception as e:
            if tmp.exists():
                tmp.unlink()
            logger.error(f"Failed to save lead: {e}")

    async def enrich_profile(self, profile: UserProfile) -> Optional[SocialLead]:
        """Processes an interacting profile, extracts domain, audits, and generates lead."""
        target_domain = BioUrlExtractor.extract(bio_text=profile.bio, bio_url=profile.bio_url)
        if not target_domain:
            logger.debug(f"No qualifying domain extracted from profile @{profile.handle}")
            return None

        logger.info(f"Discovered domain '{target_domain}' for @{profile.handle}. Dispatching 5s passive scan...")
        audit = self._run_passive_scan(target_domain)
        if not audit:
            logger.warning(f"Passive audit yielded no result for {target_domain}")
            return None

        # Analyze findings
        has_takeover = False
        has_dmarc_vuln = False
        findings_summary = []

        for f in audit.findings:
            title_lower = f.title.lower()
            category_lower = f.category.lower()
            if (
                f.severity in (Severity.CRITICAL, Severity.HIGH)
                and ("takeover" in title_lower or "expired" in title_lower or category_lower == "takeover")
            ):
                has_takeover = True
                findings_summary.append(f.title)

            if "dmarc" in title_lower and ("p=none" in title_lower or "missing" in title_lower or "none" in title_lower):
                has_dmarc_vuln = True
                findings_summary.append(f.title)

        # Qualification Gate: Only leads with critical takeover or un-enforced DMARC qualify
        if not has_takeover and not has_dmarc_vuln:
            logger.info(f"Target {target_domain} passed security checks (Score: {audit.score}/100). Not qualified as critical lead.")
            return None

        # Draft personalized DM
        dm_text = draft_dm_pitch(
            handle=profile.handle,
            name=profile.name,
            domain=target_domain,
            findings=findings_summary,
            has_takeover=has_takeover,
            has_dmarc_vulnerability=has_dmarc_vuln,
        )

        lead = SocialLead(
            lead_id=f"lead_{uuid.uuid4().hex[:8]}",
            handle=profile.handle,
            name=profile.name,
            target_domain=target_domain,
            interaction_type=profile.interaction_type,
            score=audit.score,
            grade=audit.grade,
            has_critical_takeover=has_takeover,
            has_dmarc_vulnerability=has_dmarc_vuln,
            findings_summary=findings_summary,
            drafted_dm=dm_text,
            source_tweet_id=profile.source_tweet_id,
        )

        self.save_lead(lead)
        return lead

    async def scan_interactions(self, interactions: List[Dict[str, Any]]) -> List[SocialLead]:
        """Batches enrichment across a list of harvested interaction dictionaries."""
        leads = []
        for inter in interactions:
            profile = UserProfile(
                handle=inter.get("handle", ""),
                name=inter.get("name", ""),
                bio=inter.get("bio", ""),
                bio_url=inter.get("bio_url"),
                interaction_type=inter.get("interaction_type", "like"),
                source_tweet_id=inter.get("tweet_id"),
                source_post_url=inter.get("post_url"),
            )
            lead = await self.enrich_profile(profile)
            if lead:
                leads.append(lead)
        return leads
