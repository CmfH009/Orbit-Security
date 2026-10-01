#!/usr/bin/env python3
"""
Orbit Security — Feed Harvester & Discovery Engine
=================================================
Automates discovery across:
1. Curated X List: "Infosec & Zero-Day Watch" (List ID: 2103939027368051079)
2. Inbound Mentions & Tags: (@_arsoncode, Orbit Security, orbit-recon)
3. Live Boolean Search Queries: CNAME takeovers, DMARC p=none, agency maintenance retainers
"""

from __future__ import annotations

import datetime
import logging
import random
from typing import Any, Dict, List, Optional

from orbit_security.relevance_engine import (
    CURATED_INFOSEC_ACCOUNTS,
    LIVE_SEARCH_QUERIES,
    DiscoveredPost,
    DiscoveryVector,
)

logger = logging.getLogger("orbit_security.feed_harvester")


class FeedHarvester:
    """Coordinates multi-vector post discovery across lists, notifications, and live searches."""

    CURATED_LIST_URL = "https://x.com/i/lists/2103939027368051079"
    NOTIFICATIONS_URL = "https://x.com/notifications"
    SEARCH_BASE_URL = "https://x.com/search?q={query}&f=live"

    def __init__(self, driver: Optional[Any] = None, dry_run: bool = False):
        self.driver = driver
        self.dry_run = dry_run

    def harvest_curated_list(self, limit: int = 15) -> List[DiscoveredPost]:
        """Harvests recent tweets from the 19 curated infosec heavyweight accounts list."""
        logger.info(f"Harvesting curated infosec list: {self.CURATED_LIST_URL}")
        if self.dry_run or not self.driver or not getattr(self.driver, "is_authenticated", False):
            return self._generate_mock_curated_posts(limit)

        try:
            raw_tweets = self.driver.harvest_feed(feed_url=self.CURATED_LIST_URL, limit=limit)
            return [
                DiscoveredPost(
                    tweet_id=t.tweet_id,
                    author_handle=t.handle.replace("@", ""),
                    text=t.text,
                    discovery_vector=DiscoveryVector.CURATED_LIST,
                )
                for t in raw_tweets
            ]
        except Exception as e:
            logger.error(f"Error harvesting curated list: {e}")
            return []

    def harvest_inbound_mentions(self, limit: int = 10) -> List[DiscoveredPost]:
        """Harvests recent inbound mentions from notifications."""
        logger.info("Harvesting inbound mentions and tags.")
        if self.dry_run or not self.driver or not getattr(self.driver, "is_authenticated", False):
            return self._generate_mock_inbound_mentions(limit)

        try:
            raw_tweets = self.driver.harvest_feed(feed_url=self.NOTIFICATIONS_URL, limit=limit)
            return [
                DiscoveredPost(
                    tweet_id=t.tweet_id,
                    author_handle=t.handle.replace("@", ""),
                    text=t.text,
                    discovery_vector=DiscoveryVector.INBOUND_MENTION,
                )
                for t in raw_tweets
            ]
        except Exception as e:
            logger.error(f"Error harvesting inbound mentions: {e}")
            return []

    def harvest_search_query(self, query_item: Dict[str, Any], limit: int = 10) -> List[DiscoveredPost]:
        """Harvests live search results for a configured query."""
        q_id = query_item.get("query_id") or query_item.get("id") or "query"
        q_text = query_item.get("query", "")
        import urllib.parse
        encoded_q = urllib.parse.quote(q_text)
        url = self.SEARCH_BASE_URL.format(query=encoded_q)

        logger.info(f"Harvesting live query [{q_id}]: {q_text}")
        if self.dry_run or not self.driver or not getattr(self.driver, "is_authenticated", False):
            return self._generate_mock_query_posts(query_item, limit)

        try:
            raw_tweets = self.driver.harvest_feed(feed_url=url, limit=limit)
            return [
                DiscoveredPost(
                    tweet_id=t.tweet_id,
                    author_handle=t.handle.replace("@", ""),
                    text=t.text,
                    discovery_vector=DiscoveryVector.KEYWORD_SEARCH,
                    query_id=q_id,
                )
                for t in raw_tweets
            ]
        except Exception as e:
            logger.error(f"Error harvesting search query {q_id}: {e}")
            return []

    def harvest_hourly_candidates(self, max_candidates: int = 25) -> List[DiscoveredPost]:
        """
        Executes a balanced hourly discovery sweep:
        1. Inbound tags (priority)
        2. Curated infosec list
        3. 2 randomized live search queries from LIVE_SEARCH_QUERIES
        """
        candidates: List[DiscoveredPost] = []
        seen_ids = set()

        # 1. Inbound mentions
        inbound = self.harvest_inbound_mentions(limit=5)
        for post in inbound:
            if post.tweet_id not in seen_ids:
                seen_ids.add(post.tweet_id)
                candidates.append(post)

        # 2. Curated list
        curated = self.harvest_curated_list(limit=10)
        for post in curated:
            if post.tweet_id not in seen_ids:
                seen_ids.add(post.tweet_id)
                candidates.append(post)

        # 3. Pick 2 search queries
        sampled_queries = random.sample(LIVE_SEARCH_QUERIES, min(2, len(LIVE_SEARCH_QUERIES)))
        for q in sampled_queries:
            query_posts = self.harvest_search_query(q, limit=6)
            for post in query_posts:
                if post.tweet_id not in seen_ids:
                    seen_ids.add(post.tweet_id)
                    candidates.append(post)

        # 4. Fallback / supplement from authenticated home feed
        if len(candidates) < 5:
            home_posts = self.harvest_home_feed(limit=10)
            for post in home_posts:
                if post.tweet_id not in seen_ids:
                    seen_ids.add(post.tweet_id)
                    candidates.append(post)

        logger.info(f"Total hourly candidates harvested: {len(candidates)} (deduped)")
        return candidates[:max_candidates]

    def harvest_home_feed(self, limit: int = 10) -> List[DiscoveredPost]:
        """Harvests recent tweets from authenticated home feed."""
        logger.info("Harvesting home feed timeline.")
        if self.dry_run or not self.driver or not getattr(self.driver, "is_authenticated", False):
            return []
        try:
            raw_tweets = self.driver.harvest_feed(feed_url="https://x.com/home", limit=limit)
            return [
                DiscoveredPost(
                    tweet_id=t.tweet_id,
                    author_handle=t.handle.replace("@", ""),
                    text=t.text,
                    discovery_vector=DiscoveryVector.CURATED_LIST,
                )
                for t in raw_tweets
            ]
        except Exception as e:
            logger.error(f"Error harvesting home feed: {e}")
            return []

    # -------------------------------------------------------------------------
    # Deterministic Mock Generators (For Dry-Run, Offline, and Unit Tests)
    # -------------------------------------------------------------------------

    def _generate_mock_curated_posts(self, limit: int) -> List[DiscoveredPost]:
        mock_data = [
            DiscoveredPost(
                tweet_id="cur_001",
                author_handle="BleepinComputer",
                text="Critical zero-day vulnerability in DNS edge routing allows remote subdomain takeover.",
                like_count=145,
                retweet_count=52,
                discovery_vector=DiscoveryVector.CURATED_LIST,
            ),
            DiscoveredPost(
                tweet_id="cur_002",
                author_handle="troyhunt",
                text="Fascinating how many enterprises still run DMARC p=none and think they're safe from spoofing.",
                like_count=98,
                retweet_count=23,
                discovery_vector=DiscoveryVector.CURATED_LIST,
            ),
            DiscoveredPost(
                tweet_id="cur_003",
                author_handle="TheHackersNews",
                text="Attackers weaponize abandoned SaaS subdomains pointing to stale CNAME records in supply chain wave.",
                like_count=210,
                retweet_count=88,
                discovery_vector=DiscoveryVector.CURATED_LIST,
            ),
        ]
        return mock_data[:limit]

    def _generate_mock_inbound_mentions(self, limit: int) -> List[DiscoveredPost]:
        mock_data = [
            DiscoveredPost(
                tweet_id="inb_001",
                author_handle="coolfounder",
                text="Hey @_arsoncode, roast my domain please! acmebrand.com",
                like_count=3,
                discovery_vector=DiscoveryVector.INBOUND_MENTION,
            ),
        ]
        return mock_data[:limit]

    def _generate_mock_query_posts(self, query_item: Dict[str, Any], limit: int) -> List[DiscoveredPost]:
        q_id = query_item.get("query_id") or query_item.get("id") or "query"
        q_name = query_item.get("name") or query_item.get("category") or "hygiene"
        mock_data = [
            DiscoveredPost(
                tweet_id=f"qry_{q_id}_01",
                author_handle="web_dev_daily",
                text=f"Always make sure to check your {q_name.lower()} warnings before rolling out to production.",
                like_count=6,
                discovery_vector=DiscoveryVector.KEYWORD_SEARCH,
                query_id=q_id,
            ),
            DiscoveredPost(
                tweet_id=f"qry_{q_id}_02",
                author_handle="charleagency",
                text="Managing our monthly website maintenance retainer for candykittens.co.uk — DNS hygiene is critical.",
                like_count=18,
                discovery_vector=DiscoveryVector.KEYWORD_SEARCH,
                query_id=q_id,
            ),
        ]
        return mock_data[:limit]
