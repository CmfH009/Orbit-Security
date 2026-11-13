"""tests/test_critic_artifact_grounding.py: Unit and integration tests for Cryptographic Artifact-Hash Evidence Grounding."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from orbit_security.agency_teardown_publisher import AgencyTeardownPublisher
from orbit_security.report_verifier import (
    CriticVerificationResult,
    EmpiricalEvidenceArtifact,
    ReportCriticVerifier,
    compute_evidence_digest,
    extract_cited_endpoints,
    extract_cited_status_codes,
    extract_empirical_artifacts_from_blackboard,
)


class MockBlackboard:
    """Mock blackboard store capturing events and providing get_recent."""

    def __init__(self, events: list[dict] | None = None) -> None:
        self.events: list[dict] = events or []

    def get_recent(self, limit: int = 50) -> list[dict]:
        return self.events[:limit]

    def publish(self, event_type: str, payload: dict, **kwargs) -> None:
        self.events.insert(0, {"event_type": event_type, "payload": payload, "source": "test_scanner"})


def test_evidence_digest_computation_deterministic() -> None:
    digest1 = compute_evidence_digest(
        target="https://api.targetcorp.com/v1/auth",
        status_code=200,
        flaw_type="CORS Misconfiguration",
        evidence_snippet="Access-Control-Allow-Origin: *",
        provider="bounty_active_prober",
    )
    digest2 = compute_evidence_digest(
        target="https://api.targetcorp.com/v1/auth",
        status_code=200,
        flaw_type="CORS Misconfiguration",
        evidence_snippet="Access-Control-Allow-Origin: *",
        provider="bounty_active_prober",
    )
    assert digest1.startswith("ev_")
    assert len(digest1) == 15  # "ev_" + 12 hex chars
    assert digest1 == digest2

    # Different status code produces distinct hash
    digest3 = compute_evidence_digest(
        target="https://api.targetcorp.com/v1/auth",
        status_code=403,
        flaw_type="CORS Misconfiguration",
        evidence_snippet="Access-Control-Allow-Origin: *",
        provider="bounty_active_prober",
    )
    assert digest1 != digest3


def test_claim_extraction_helpers() -> None:
    text = (
        "We detected an exposed directory at /admin and backup file at /.env on targetcorp.com. "
        "The server returned 200 OK and status 403 on https://targetcorp.com/api/v2/keys."
    )
    endpoints = extract_cited_endpoints(text)
    assert "/admin" in endpoints
    assert "/.env" in endpoints
    assert "/api/v2/keys" in endpoints

    statuses = extract_cited_status_codes(text)
    assert 200 in statuses
    assert 403 in statuses


def test_report_accepted_when_claims_match_blackboard_artifact_hashes() -> None:
    bb = MockBlackboard(
        events=[
            {
                "event_type": "PROBE_VULN_VERIFIED",
                "source": "bounty_active_prober",
                "payload": {
                    "target_domain": "targetcorp.com",
                    "target_url": "https://targetcorp.com/api/v1/auth",
                    "status_code": 200,
                    "flaw_type": "CORS Misconfiguration",
                    "evidence_snippet": "Access-Control-Allow-Origin: *",
                    "endpoint": "/api/v1/auth",
                },
            }
        ]
    )

    pitch = (
        "During perimeter audits of targetcorp.com, our scanner identified CORS misconfiguration "
        "on /api/v1/auth returning 200 OK with wildcard origin headers."
    )

    result = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="CORS Misconfiguration",
        audit_score=65.0,
        blackboard=bb,
        require_artifact_grounding=True,
    )

    assert result.passed is True
    assert result.confidence_score == 1.0
    assert len(result.reasons) == 0
    assert len(result.ungrounded_claims) == 0
    assert len(result.verified_artifact_ids) >= 1
    assert result.verified_artifact_ids[0].startswith("ev_")


def test_report_rejected_when_llm_invents_unseen_endpoint() -> None:
    # Blackboard only has evidence for /api/v1/status
    bb = MockBlackboard(
        events=[
            {
                "event_type": "PROBE_VULN_VERIFIED",
                "source": "bounty_active_prober",
                "payload": {
                    "target_domain": "targetcorp.com",
                    "target_url": "https://targetcorp.com/api/v1/status",
                    "status_code": 200,
                    "flaw_type": "CORS Misconfiguration",
                    "evidence_snippet": "Access-Control-Allow-Origin: *",
                },
            }
        ]
    )

    # LLM hallucinates an unprobed /admin panel
    pitch = (
        "During perimeter audits of targetcorp.com, our scanner identified CORS misconfiguration "
        "and an exposed admin portal at /admin returning 200 OK."
    )

    result = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="CORS Misconfiguration",
        audit_score=65.0,
        blackboard=bb,
        require_artifact_grounding=True,
    )

    assert result.passed is False
    assert any("UNGROUNDED_CLAIM_ENDPOINT" in r for r in result.reasons)
    assert any(c.get("claim") == "/admin" for c in result.ungrounded_claims)


def test_report_rejected_when_llm_invents_unseen_status_code() -> None:
    bb = MockBlackboard(
        events=[
            {
                "event_type": "PROBE_VULN_VERIFIED",
                "source": "bounty_active_prober",
                "payload": {
                    "target_domain": "targetcorp.com",
                    "target_url": "https://targetcorp.com/api/v1/auth",
                    "status_code": 403,
                    "flaw_type": "CORS Misconfiguration",
                    "evidence_snippet": "Forbidden access",
                },
            }
        ]
    )

    # LLM claims 200 OK when probe was 403 Forbidden
    pitch = (
        "During perimeter audits of targetcorp.com, our scanner identified CORS misconfiguration "
        "on /api/v1/auth returning 200 OK."
    )

    result = ReportCriticVerifier.verify_briefing_pitch(
        pitch_text=pitch,
        target_domain="targetcorp.com",
        core_finding="CORS Misconfiguration",
        audit_score=65.0,
        blackboard=bb,
        require_artifact_grounding=True,
    )

    assert result.passed is False
    assert any("UNGROUNDED_CLAIM_STATUS" in r for r in result.reasons)
    assert any(c.get("claim") == 200 for c in result.ungrounded_claims)


def test_agency_teardown_publisher_falls_back_when_llm_fails_artifact_grounding(tmp_path: Path) -> None:
    bb = MockBlackboard(
        events=[
            {
                "event_type": "DNS_AUDIT_COMPLETED",
                "source": "dns_sentinel",
                "payload": {
                    "target_domain": "groundingtest.com",
                    "flaw_type": "RFC 7208 SPF PermError",
                    "evidence_snippet": "12 DNS lookups exceeding limit",
                },
            }
        ]
    )

    publisher = AgencyTeardownPublisher(
        staged_dir=tmp_path,
        blackboard=bb,
    )

    # Simulate LLM generating copy with fabricated endpoints and status codes
    hallucinated_llm_copy = (
        "During audits of groundingtest.com, we found an exposed /admin panel returning HTTP 200 "
        "linked to your RFC 7208 SPF PermError."
    )
    publisher._generate_copy_via_llm = MagicMock(return_value=hallucinated_llm_copy)

    campaign = publisher.stage_teardown(
        agency_slug="grounding_lead",
        agency_name="Grounding Test Inc",
        target_domain="groundingtest.com",
        audit_score=68.0,
        audit_grade="C",
        core_finding="RFC 7208 SPF PermError (12 DNS lookups)",
    )

    # Fabricated /admin and HTTP 200 must be rejected; publisher must have fallen back to verified deterministic copy
    assert "/admin" not in campaign.briefing_pitch
    assert "HTTP 200" not in campaign.briefing_pitch
    assert "remediation bundle" in campaign.briefing_pitch
    assert campaign.critic_verified is True
    assert campaign.critic_verdict.get("passed") is True

    # Check staged file exists on disk and is valid JSON
    staged_file = tmp_path / "grounding_lead_campaign.json"
    assert staged_file.exists()
    data = json.loads(staged_file.read_text(encoding="utf-8"))
    assert data["agency_slug"] == "grounding_lead"
    assert "/admin" not in data["briefing_pitch"]
