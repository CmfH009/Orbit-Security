#!/usr/bin/env python3
"""Tests for FeedHarvester multi-vector post discovery."""

import pytest
from orbit_security.feed_harvester import FeedHarvester
from orbit_security.relevance_engine import DiscoveryVector


@pytest.fixture
def harvester():
    return FeedHarvester(driver=None, dry_run=True)


def test_harvest_curated_list(harvester):
    posts = harvester.harvest_curated_list(limit=3)
    assert len(posts) == 3
    for p in posts:
        assert p.discovery_vector == DiscoveryVector.CURATED_LIST
        assert p.author_handle in ["BleepinComputer", "troyhunt", "TheHackersNews"]


def test_harvest_inbound_mentions(harvester):
    posts = harvester.harvest_inbound_mentions(limit=2)
    assert len(posts) >= 1
    assert posts[0].discovery_vector == DiscoveryVector.INBOUND_MENTION
    assert "roast my domain" in posts[0].text.lower()


def test_harvest_search_query(harvester):
    query_item = {"id": "cname_takeovers", "name": "Dangling CNAMEs", "query": "dangling CNAME"}
    posts = harvester.harvest_search_query(query_item, limit=2)
    assert len(posts) == 2
    for p in posts:
        assert p.discovery_vector == DiscoveryVector.KEYWORD_SEARCH
        assert p.query_id == "cname_takeovers"


def test_harvest_hourly_candidates_deduped(harvester):
    candidates = harvester.harvest_hourly_candidates(max_candidates=10)
    assert len(candidates) >= 4
    tweet_ids = [c.tweet_id for c in candidates]
    # Invariant: No duplicate tweet IDs
    assert len(tweet_ids) == len(set(tweet_ids))
