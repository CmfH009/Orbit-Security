"""Unit tests for Marketing Strategy Engine (marketing_strategy.py)."""

import datetime
from pathlib import Path
import tempfile
import pytest

from orbit_security.marketing_strategy import (
    ContentPillar,
    HookEvaluation,
    MarketingStrategyEngine,
)


def test_hook_evaluation_strong():
    engine = MarketingStrategyEngine()
    hook = (
        "How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:\n\n"
        "The hidden anatomy of Dangling CNAME Subdomain Takeovers."
    )
    res = engine.evaluate_hook(hook)
    assert res.is_strong is True
    assert res.score >= 0.70
    assert len(res.banned_words_found) == 0


def test_hook_evaluation_banned_buzzwords():
    engine = MarketingStrategyEngine()
    hook = (
        "In today's fast-paced digital world, it's crucial to dive deep and revolutionize "
        "your cybersecurity game-changer approach."
    )
    res = engine.evaluate_hook(hook)
    assert res.is_strong is False
    assert len(res.banned_words_found) > 0
    assert res.score < 0.50


def test_select_next_content_pillar_distribution():
    engine = MarketingStrategyEngine()
    # If recent posts were all high_iq_wit, next recommended should be break_and_fix (highest weight)
    recent = ["high_iq_wit", "high_iq_wit", "high_iq_wit"]
    pillar = engine.select_next_content_pillar(recent)
    assert pillar == ContentPillar.BREAK_AND_FIX


def test_audience_engagement_band():
    engine = MarketingStrategyEngine()
    morning_utc = datetime.datetime(2026, 9, 30, 14, 0, tzinfo=datetime.timezone.utc)
    res = engine.get_audience_engagement_band(morning_utc)
    assert res["band"] == "MORNING_PRIME"
    assert res["reach_multiplier"] >= 1.2
