"""Unit and integration tests for ReportCriticVerifier and Anti-Hallucination Pipeline (Track 3).

Verifies:
1. Grounded pitches mentioning target domain and verified flaw keywords pass with confidence 1.0.
2. Pitches missing the target domain are rejected for lack of grounding.
3. Pitches with hallucinated vulnerabilities (e.g., claiming SQL Injection on SPF PermError) are rejected.
4. Pitches using alarmist, hallucinated terms ("critical 0-day", "ransomware payload") are rejected.
5. AgencyTeardownPublisher rejects ungrounded LLM copy and falls back to verified deterministic copy.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.agency_teardown_publisher import AgencyTeardownCampaign, AgencyTeardownPublisher
from orbit_security.report_verifier import (
    CriticVerificationResult,
    EmpiricalEvidenceArtifact,
    ReportCriticVerifier,
    compute_evidence_digest,
    extract_cited_endpoints,
)


def test_critic_verifier_passes_grounded_pitch():
    pitch = (
        "During recent perimeter audits of 10up Inc. (10up.com), our scanner identified "
        "RFC 7208 SPF PermError (12 DNS lookups exceeding limit). This misconfiguration "
        "can lead to mail delivery issues. A 1-click DNS fixpack is available."
    )
    res = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="10up.com",
        core_finding="RFC 7208 SPF PermError (12 DNS lookups)",
        audit_score=68.5,
    )
    assert res.passed is True
    assert res.confidence_score == 1.0
    assert len(res.reasons) == 0


def test_critic_verifier_rejects_missing_target_domain():
    pitch = (
        "During our recent audits of your infrastructure, our scanner identified "
        "RFC 7208 SPF PermError. Contact us to fix it."
    )
    res = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="RFC 7208 SPF PermError",
    )
    assert res.passed is False
    assert any("DOMAIN_GROUNDING_FAILED" in r for r in res.reasons)


def test_critic_verifier_rejects_hallucinated_finding():
    pitch = (
        "We scanned targetcorp.com and discovered an open SQL injection endpoint in your login portal. "
        "Please address this immediately."
    )
    res = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="RFC 7208 SPF PermError (13 DNS lookups)",
    )
    assert res.passed is False
    assert any("FINDING_MISALIGNMENT" in r for r in res.reasons)


def test_critic_verifier_rejects_alarmist_terms():
    pitch = (
        "Perimeter audit on targetcorp.com uncovered a critical 0-day and an active ransomware payload "
        "in your SPF records."
    )
    res = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="RFC 7208 SPF PermError",
        audit_score=72.0,
    )
    assert res.passed is False
    assert any("ALARMIST_CLAIM_DETECTED" in r for r in res.reasons)
    assert "critical 0-day" in res.flagged_terms


def test_publisher_falls_back_when_llm_hallucinates(tmp_path: Path):
    pub = AgencyTeardownPublisher(staged_dir=tmp_path)

    # Mock _generate_copy_via_llm to simulate an ungrounded hallucinating model
    hallucinated_copy = "We found compromised credit cards on completely-unrelated.com!"
    pub._generate_copy_via_llm = MagicMock(return_value=hallucinated_copy)

    camp = pub.stage_teardown(
        agency_slug="hallucinating_lead",
        agency_name="Test Agency",
        target_domain="testagency.com",
        audit_score=75.0,
        audit_grade="C+",
        core_finding="RFC 7208 SPF PermError (11 DNS lookups)",
    )

    # Critic must have rejected the hallucinated copy and reverted to deterministic fallback
    assert "compromised credit cards" not in camp.briefing_pitch
    assert "testagency.com" in camp.briefing_pitch
    assert "SPF PermError" in camp.briefing_pitch
    assert camp.critic_verified is True
    assert camp.critic_verdict["passed"] is True

    # Check file saved
    staged_file = tmp_path / "hallucinating_lead_campaign.json"
    assert staged_file.exists()
    data = json.loads(staged_file.read_text(encoding="utf-8"))
    assert data["critic_verified"] is True
