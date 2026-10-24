"""Structured JSON fetching and parser for X posts, threads, and author metrics.

Implements the ADHX API specification (https://adhx.com/api/share/tweet/{username}/{statusId})
for zero-scraping, headless retrieval of X/Twitter content, engagement statistics,
and long-form X Articles with built-in Cyber Threat Intelligence (CTI) IOC extraction.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ADHXError(Exception):
    """Base exception for ADHX client errors."""
    pass


class InvalidTweetURLError(ADHXError):
    """Raised when an X/Twitter URL cannot be parsed."""
    pass


class TweetNotFoundError(ADHXError):
    """Raised when the specified post cannot be found or retrieved."""
    pass


@dataclass
class AuthorInfo:
    name: str = ""
    username: str = ""
    avatar_url: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthorInfo:
        return cls(
            name=data.get("name", ""),
            username=data.get("username", ""),
            avatar_url=data.get("avatarUrl", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "username": self.username,
            "avatarUrl": self.avatar_url,
        }


@dataclass
class EngagementMetrics:
    replies: int = 0
    retweets: int = 0
    likes: int = 0
    views: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EngagementMetrics:
        return cls(
            replies=int(data.get("replies", 0)),
            retweets=int(data.get("retweets", 0)),
            likes=int(data.get("likes", 0)),
            views=int(data.get("views", 0)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "replies": self.replies,
            "retweets": self.retweets,
            "likes": self.likes,
            "views": self.views,
        }


@dataclass
class ArticleInfo:
    title: str = ""
    preview_text: str = ""
    cover_image_url: str = ""
    content: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ArticleInfo:
        return cls(
            title=data.get("title", ""),
            preview_text=data.get("previewText", ""),
            cover_image_url=data.get("coverImageUrl", ""),
            content=data.get("content", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "previewText": self.preview_text,
            "coverImageUrl": self.cover_image_url,
            "content": self.content,
        }


@dataclass
class ThreatIntelExtraction:
    cves: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    security_tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cves": self.cves,
            "mitre_attack": self.mitre_attack,
            "ips": self.ips,
            "domains": self.domains,
            "hashes": self.hashes,
            "security_tags": self.security_tags,
        }


@dataclass
class TweetData:
    id: str
    url: str
    text: str
    author: AuthorInfo
    created_at: str
    engagement: EngagementMetrics
    article: Optional[ArticleInfo] = None
    intel: Optional[ThreatIntelExtraction] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TweetData:
        author_data = data.get("author", {})
        eng_data = data.get("engagement", {})
        art_data = data.get("article")

        return cls(
            id=str(data.get("id", "")),
            url=data.get("url", ""),
            text=data.get("text", ""),
            author=AuthorInfo.from_dict(author_data) if isinstance(author_data, dict) else AuthorInfo(),
            created_at=data.get("createdAt", ""),
            engagement=EngagementMetrics.from_dict(eng_data) if isinstance(eng_data, dict) else EngagementMetrics(),
            article=ArticleInfo.from_dict(art_data) if isinstance(art_data, dict) and art_data else None,
            raw_data=data,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "text": self.text,
            "author": self.author.to_dict(),
            "createdAt": self.created_at,
            "engagement": self.engagement.to_dict(),
            "article": self.article.to_dict() if self.article else None,
            "intel": self.intel.to_dict() if self.intel else None,
        }


class ADHXClient:
    """Client for retrieving structured X post telemetry via the ADHX API."""

    API_BASE = "https://adhx.com/api/share/tweet"
    URL_REGEX = re.compile(
        r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com|adhx\.com)/(?:(?:api/)?share/tweet/)?([A-Za-z0-9_]+)/(?:status(?:es)?/)?(\d+)",
        re.IGNORECASE,
    )

    CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    MITRE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    HASH_REGEX = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

    SECURITY_KEYWORDS = [
        "0day", "exploit", "poc", "rce", "sqli", "xss", "ssrf", "bounty", "vulnerability",
        "bypass", "advisory", "malware", "ransomware", "takeover", "leak", "breach"
    ]

    def __init__(self, base_url: str = API_BASE, timeout_sec: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec

    @classmethod
    def parse_tweet_url(cls, url: str) -> Tuple[str, str]:
        """Extract username and status ID from an X/Twitter or ADHX URL.

        Args:
            url: URL string (e.g. https://x.com/dgt10011/status/2020167690560647464 or https://adhx.com/dgt10011/2020167690560647464)

        Returns:
            Tuple of (username, status_id)
        """
        match = cls.URL_REGEX.search(url.strip())
        if not match:
            # Check if user passed just status_id and username
            clean = url.strip().strip("/")
            parts = clean.split("/")
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0], parts[1]
            raise InvalidTweetURLError(f"Could not parse username and status ID from URL: {url}")
        return match.group(1), match.group(2)

    def extract_threat_intel(self, tweet: TweetData) -> ThreatIntelExtraction:
        """Scan tweet text and long-form article content for IOCs and security intel."""
        combined_text = f"{tweet.text}\n{tweet.article.content if tweet.article else ''}\n{tweet.article.title if tweet.article else ''}"

        cves = sorted(list(set(m.upper() for m in self.CVE_REGEX.findall(combined_text))))
        mitre = sorted(list(set(m.upper() for m in self.MITRE_REGEX.findall(combined_text))))

        # Hashes: filter out pure numbers (like status IDs or snowflake IDs)
        raw_hashes = self.HASH_REGEX.findall(combined_text)
        hashes = sorted(list(set(h.lower() for h in raw_hashes if not h.isdigit())))

        # Validate IPs excluding loopback, private, broadcast, or invalid octets
        raw_ips = self.IP_REGEX.findall(combined_text)
        valid_ips = []
        for raw_ip in raw_ips:
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                if not (ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved):
                    valid_ips.append(str(ip_obj))
            except ValueError:
                continue
        ips = sorted(list(set(valid_ips)))

        # Find domains mentioned (simple regex)
        domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", combined_text)
        excluded_domains = {"x.com", "twitter.com", "adhx.com", "t.co", "github.com", "google.com", "example.com"}
        domains = sorted(list(set(d.lower() for d in domain_matches if d.lower() not in excluded_domains)))[:15]

        # Security tags
        lower_text = combined_text.lower()
        tags = [kw for kw in self.SECURITY_KEYWORDS if kw in lower_text]

        return ThreatIntelExtraction(
            cves=cves,
            mitre_attack=mitre,
            ips=ips,
            domains=domains,
            hashes=hashes,
            security_tags=tags,
        )

        # Find domains mentioned (simple regex)
        domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", combined_text)
        excluded_domains = {"x.com", "twitter.com", "adhx.com", "t.co", "github.com", "google.com", "example.com"}
        domains = sorted(list(set(d.lower() for d in domain_matches if d.lower() not in excluded_domains)))[:15]

        # Security tags
        lower_text = combined_text.lower()
        tags = [kw for kw in self.SECURITY_KEYWORDS if kw in lower_text]

        return ThreatIntelExtraction(
            cves=cves,
            mitre_attack=mitre,
            ips=ips,
            domains=domains,
            hashes=hashes,
            security_tags=tags,
        )

    def fetch_tweet(
        self,
        url_or_id: str,
        username: Optional[str] = None,
        extract_intel: bool = True,
    ) -> TweetData:
        """Fetch tweet JSON from ADHX API and parse into structured TweetData.

        Args:
            url_or_id: Full URL or status ID.
            username: Optional username if status ID is supplied directly.
            extract_intel: If True, automatically extract IOCs and CVEs.

        Returns:
            Structured TweetData instance.
        """
        if username and url_or_id.isdigit():
            user, status_id = username, url_or_id
        else:
            user, status_id = self.parse_tweet_url(url_or_id)

        target_endpoint = f"{self.base_url}/{user}/{status_id}"

        data = self._http_get_json(target_endpoint)
        if not data:
            raise TweetNotFoundError(f"Post {user}/{status_id} not found or empty response from ADHX.")

        # Ensure ID and URL fallback if missing in API response
        if "id" not in data or not data["id"]:
            data["id"] = status_id
        if "url" not in data or not data["url"]:
            data["url"] = f"https://x.com/{user}/status/{status_id}"

        tweet = TweetData.from_dict(data)

        if extract_intel:
            tweet.intel = self.extract_threat_intel(tweet)

        return tweet

    async def async_fetch_tweet(
        self,
        url_or_id: str,
        username: Optional[str] = None,
        extract_intel: bool = True,
    ) -> TweetData:
        """Asynchronously fetch tweet data."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.fetch_tweet(url_or_id, username=username, extract_intel=extract_intel)
        )

    def _http_get_json(self, url: str) -> Dict[str, Any]:
        """Perform HTTP GET request and parse JSON."""
        try:
            import httpx
            try:
                with httpx.Client(timeout=self.timeout_sec, follow_redirects=True) as client:
                    headers = {"User-Agent": "OrbitSecurity-ADHX/1.0", "Accept": "application/json"}
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 404:
                        raise TweetNotFoundError(f"Post returned 404 at {url}")
                    resp.raise_for_status()
                    return resp.json()
            except TweetNotFoundError:
                raise
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    raise TweetNotFoundError(f"Post returned 404 at {url}") from e
                raise ADHXError(f"HTTP status {e.response.status_code} fetching {url}: {e}") from e
            except Exception as e:
                raise ADHXError(f"Failed to fetch {url} via httpx: {e}") from e
        except ImportError:
            # Fallback to urllib.request
            import urllib.request
            import urllib.error
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OrbitSecurity-ADHX/1.0", "Accept": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_sec) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise TweetNotFoundError(f"Post returned 404 at {url}") from e
                raise ADHXError(f"HTTP error {e.code} fetching {url}: {e.reason}") from e
            except Exception as e:
                raise ADHXError(f"Failed to fetch {url}: {e}") from e


# Convenience functions
default_client = ADHXClient()


def get_x_post(url_or_id: str, username: Optional[str] = None) -> TweetData:
    """Fetch structured X post data using default ADHXClient."""
    return default_client.fetch_tweet(url_or_id, username=username)
