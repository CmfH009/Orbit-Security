"""Unit tests for Orbit Security Smart Follow Engine (smart_follow.py)."""

import datetime
from pathlib import Path
import tempfile
import pytest

from orbit_security.smart_follow import (
    AccountProfile,
    FollowEvaluation,
    SmartFollowEngine,
    DEFAULT_SEED_ACCOUNTS,
)


def test_seed_accounts_configured():
    assert len(DEFAULT_SEED_ACCOUNTS) >= 10
    handles = [s["handle"] for s in DEFAULT_SEED_ACCOUNTS]
    assert "troyhunt" in handles
    assert "SwiftOnSecurity" in handles
    assert "simonw" in handles


def test_evaluate_account_infosec_match():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SmartFollowEngine(project_root=Path(tmpdir))
        profile = AccountProfile(
            handle="test_ciso",
            name="Alice CISO",
            bio="CISO & DevSecOps advocate. Researching DNS hygiene, RFC standards, and zero trust.",
            followers_count=5000,
            following_count=1200,
            posts_count=200,
            is_verified=True,
        )
        res = engine.evaluate_account(profile)
        assert res.should_follow is True
        assert res.score >= 0.65
        assert res.category in ("infosec", "ai_security", "saas_founder")


def test_evaluate_account_negative_filter():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SmartFollowEngine(project_root=Path(tmpdir))
        profile = AccountProfile(
            handle="spam_crypto",
            bio="Crypto airdrop hunter! Follow back 100% f4f DM for promo",
            followers_count=100,
            following_count=8000,
        )
        res = engine.evaluate_account(profile)
        assert res.should_follow is False
        assert res.score == 0.0


def test_daily_follow_quota_and_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SmartFollowEngine(project_root=Path(tmpdir), daily_follow_cap=2)
        assert engine.can_follow_today() is True
        assert engine.get_today_follow_count() == 0

        engine.record_follow_success("troyhunt", category="infosec")
        assert engine.get_today_follow_count() == 1
        assert engine.can_follow_today() is True

        engine.record_follow_success("simonw", category="ai_security")
        assert engine.get_today_follow_count() == 2
        assert engine.can_follow_today() is False

        # Reload engine from disk to verify persistence
        engine2 = SmartFollowEngine(project_root=Path(tmpdir), daily_follow_cap=2)
        assert engine2.get_today_follow_count() == 2
        assert "troyhunt" in engine2.followed_accounts
        assert "simonw" in engine2.followed_accounts
