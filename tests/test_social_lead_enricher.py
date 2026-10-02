"""Unit and integration tests for Social Lead Enricher & Bio Scraper (Act II).

Verifies:
1. Bio domain extraction:
   - Direct bio URLs (https://agency.com, https://company.co.uk/team)
   - In-bio text mentions ("Founder at techbrand.io", "visit store.app")
   - Exclusions for social platforms (twitter.com, instagram.com, etc.)
2. Personalized DM drafting:
   - Carson Haynes persona (@_arsoncode)
   - Direct, actionable vulnerability disclosure (Dangling CNAME / DMARC p=none)
   - Professional tone and arcade verification link
3. 5-Second passive scan qualification:
   - Qualifies leads with critical dangling CNAME or DMARC p=none
   - Drops/defers targets with pristine security posture
4. Deduplication & storage in data/social_leads.json
5. DesktopAutomationDriver bridge methods:
   - scrape_user_profile
   - harvest_inbound_interactions
   - send_direct_message
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orbit_security.desktop_x_bridge import DesktopAutomationDriver, DesktopDriverConfig
from orbit_security.models import DomainAuditResult, Finding, Severity
from orbit_security.social_lead_enricher import (
    BioUrlExtractor,
    SocialLead,
    SocialLeadEnricher,
    UserProfile,
    draft_dm_pitch,
    extract_domain_from_bio,
)


# ============================================================================
# 1. Bio Domain Extraction Tests
# ============================================================================


def test_extract_domain_from_direct_url():
    """Extracts apex/registered domain from explicit bio URL."""
    assert extract_domain_from_bio("", "https://www.eastsideco.com") == "eastsideco.com"
    assert extract_domain_from_bio("", "https://charle.co.uk/services") == "charle.co.uk"
    assert extract_domain_from_bio("", "http://apexapparel.io?ref=twitter") == "apexapparel.io"


def test_extract_domain_from_bio_text():
    """Extracts domain when mentioned directly within the user's bio copy."""
    bio_text = "Building the future of DTC commerce @ velvetcraft.com | Angel investor & tech advisor"
    assert extract_domain_from_bio(bio_text) == "velvetcraft.com"

    bio_text_sub = "Co-founder of https://dev.cloudsentinel.co.uk. Cloud infrastructure engineer."
    assert extract_domain_from_bio(bio_text_sub) == "dev.cloudsentinel.co.uk"


def test_extract_domain_ignores_social_and_linktree():
    """Ignores generic social networks and falls back to bio text or None."""
    # When bio_url is a linktree or github, it should look in bio text or return None
    bio_text = "Coffee enthusiast. Tweets are my own."
    assert extract_domain_from_bio(bio_text, "https://github.com/myuser") is None
    assert extract_domain_from_bio(bio_text, "https://twitter.com/myuser") is None

    # If bio has real domain but bio_url is twitter, extract from bio
    bio_text_with_domain = "Founder of modernagency.studio. Follow my journey!"
    assert extract_domain_from_bio(bio_text_with_domain, "https://twitter.com/someuser") == "modernagency.studio"


# ============================================================================
# 2. Personalized DM Drafting Tests
# ============================================================================


def test_draft_dm_pitch_cname_takeover():
    """Verifies DM draft when a critical dangling CNAME takeover is detected."""
    dm = draft_dm_pitch(
        handle="alex_founder",
        name="Alex River",
        domain="velvetcraft.com",
        findings=["Dangling CNAME points to unclaimed AWS S3 bucket: cdn.velvetcraft.com"],
        has_takeover=True,
        has_dmarc_vulnerability=False,
    )
    assert "@alex_founder" not in dm  # Direct messages do not need @-handle prefix in body
    assert "velvetcraft.com" in dm
    assert "dangling CNAME" in dm or "takeover" in dm
    assert "Carson" in dm or "@_arsoncode" in dm
    assert len(dm) <= 500  # Twitter DM length guidance


def test_draft_dm_pitch_dmarc_p_none():
    """Verifies DM draft when DMARC is un-enforced (p=none or missing)."""
    dm = draft_dm_pitch(
        handle="sarah_cto",
        name="Sarah Chen",
        domain="chencapital.co",
        findings=["DMARC record policy is p=none (Monitoring mode)"],
        has_takeover=False,
        has_dmarc_vulnerability=True,
    )
    assert "chencapital.co" in dm
    assert "DMARC" in dm or "spoofing" in dm
    assert "Carson" in dm or "@_arsoncode" in dm
    assert len(dm) <= 500


# ============================================================================
# 3. Lead Qualification & 5-Second Passive Scan Tests
# ============================================================================


@pytest.mark.asyncio
async def test_enrich_profile_with_critical_takeover():
    """Enriches profile and flags lead when dangling takeover is discovered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        leads_file = Path(tmpdir) / "social_leads.json"
        enricher = SocialLeadEnricher(leads_file=leads_file)

        mock_audit = DomainAuditResult(
            domain="velvetcraft.com",
            score=45,
            grade="F",
            findings=[
                Finding(
                    category="TAKEOVER",
                    severity=Severity.CRITICAL,
                    title="Dangling CNAME takeover on cdn.velvetcraft.com",
                    description="Points to unclaimed S3 bucket.",
                    remediation="Remove or claim CNAME record.",
                    target="cdn.velvetcraft.com",
                )
            ],
            subdomains_checked=["cdn.velvetcraft.com"],
            scan_time_seconds=1.2,
        )

        with patch.object(enricher, "_run_passive_scan", return_value=mock_audit):
            profile = UserProfile(
                handle="alex_founder",
                name="Alex River",
                bio="Building @ velvetcraft.com",
                bio_url="https://velvetcraft.com",
                interaction_type="like",
                source_tweet_id="1841234567890",
            )
            lead = await enricher.enrich_profile(profile)

            assert lead is not None
            assert lead.handle == "alex_founder"
            assert lead.target_domain == "velvetcraft.com"
            assert lead.has_critical_takeover is True
            assert lead.score == 45
            assert "velvetcraft.com" in lead.drafted_dm

            # Check persistence
            saved = enricher.load_leads()
            assert len(saved) == 1
            assert saved[0]["handle"] == "alex_founder"
            assert saved[0]["has_critical_takeover"] is True


@pytest.mark.asyncio
async def test_enrich_profile_ignores_pristine_targets():
    """Does not draft outbound DM if domain has zero critical vulnerabilities."""
    with tempfile.TemporaryDirectory() as tmpdir:
        leads_file = Path(tmpdir) / "social_leads.json"
        enricher = SocialLeadEnricher(leads_file=leads_file)

        clean_audit = DomainAuditResult(
            domain="pristinesec.com",
            score=98,
            grade="A+",
            findings=[],
            subdomains_checked=["pristinesec.com"],
            scan_time_seconds=0.8,
        )

        with patch.object(enricher, "_run_passive_scan", return_value=clean_audit):
            profile = UserProfile(
                handle="clean_user",
                name="Clean User",
                bio="Secure by default",
                bio_url="https://pristinesec.com",
                interaction_type="retweet",
            )
            lead = await enricher.enrich_profile(profile)
            assert lead is None

            saved = enricher.load_leads()
            assert len(saved) == 0


@pytest.mark.asyncio
async def test_lead_deduplication():
    """Prevents duplicate lead records for the same handle and domain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        leads_file = Path(tmpdir) / "social_leads.json"
        enricher = SocialLeadEnricher(leads_file=leads_file)

        mock_audit = DomainAuditResult(
            domain="vulnsite.org",
            score=50,
            grade="D",
            findings=[
                Finding(
                    category="EMAIL_SECURITY",
                    severity=Severity.HIGH,
                    title="DMARC record missing or p=none",
                    description="Mail domain is vulnerable to direct spoofing.",
                    remediation="Configure p=quarantine or p=reject.",
                    target="vulnsite.org",
                )
            ],
            subdomains_checked=["vulnsite.org"],
            scan_time_seconds=1.0,
        )

        with patch.object(enricher, "_run_passive_scan", return_value=mock_audit):
            profile = UserProfile(
                handle="mark_dev",
                name="Mark Developer",
                bio="Engineer @ vulnsite.org",
                bio_url="https://vulnsite.org",
                interaction_type="reply",
            )
            # First interaction
            lead1 = await enricher.enrich_profile(profile)
            assert lead1 is not None

            # Second interaction (like on another tweet)
            profile2 = UserProfile(
                handle="mark_dev",
                name="Mark Developer",
                bio="Engineer @ vulnsite.org",
                bio_url="https://vulnsite.org",
                interaction_type="like",
            )
            lead2 = await enricher.enrich_profile(profile2)
            assert lead2 is not None

            # Ensure file only has 1 record updated
            saved = enricher.load_leads()
            assert len(saved) == 1
            assert saved[0]["handle"] == "mark_dev"


# ============================================================================
# 4. Desktop Automation Driver Integration Tests
# ============================================================================


def test_desktop_driver_scrape_user_profile_mock():
    """Verifies scrape_user_profile method on DesktopAutomationDriver in mock mode."""
    driver = DesktopAutomationDriver(mock_mode=True)
    prof = driver.scrape_user_profile("alex_founder")
    assert prof is not None
    assert prof["handle"] == "alex_founder"
    assert "bio" in prof
    assert len(driver.action_history) > 0


def test_desktop_driver_harvest_interactions_mock():
    """Verifies harvest_inbound_interactions method on DesktopAutomationDriver."""
    driver = DesktopAutomationDriver(mock_mode=True)
    interactions = driver.harvest_inbound_interactions(limit=5)
    assert isinstance(interactions, list)
    assert len(interactions) > 0
    assert "handle" in interactions[0]
    assert "interaction_type" in interactions[0]


def test_desktop_driver_send_direct_message_mock():
    """Verifies send_direct_message method on DesktopAutomationDriver."""
    driver = DesktopAutomationDriver(mock_mode=True)
    res = driver.send_direct_message("alex_founder", "Hey Alex, noticed a DNS drift issue.")
    assert res is True
    actions = [a["action"] for a in driver.action_history]
    assert "send_direct_message" in actions
