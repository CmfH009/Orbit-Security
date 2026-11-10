"""Unit tests for AgencyTeardownPublisher (Pathway 2)."""

from __future__ import annotations

import json
from pathlib import Path
from orbit_security.agency_teardown_publisher import AgencyTeardownPublisher, AgencyTeardownCampaign


def test_stage_teardown_deterministic_fallback(tmp_path: Path):
    # Pass bad URL to force deterministic fallback
    pub = AgencyTeardownPublisher(staged_dir=tmp_path, ollama_url="http://127.0.0.1:99999")
    camp = pub.stage_teardown(
        agency_slug="10up",
        agency_name="10up Inc.",
        target_domain="10up.com",
        audit_score=68.5,
        audit_grade="C+",
        core_finding="RFC 7208 SPF PermError (12 DNS lookups exceeding limit)",
    )

    assert camp.agency_slug == "10up"
    assert camp.target_domain == "10up.com"
    assert "10up Inc." in camp.briefing_pitch
    assert "SPF PermError" in camp.briefing_pitch
    assert camp.requires_operator_approval is True
    assert camp.operator_approved is False
    assert len(camp.sha256_hash) == 64

    # Verify file saved on disk
    saved_file = tmp_path / "10up_campaign.json"
    assert saved_file.exists()
    data = json.loads(saved_file.read_text(encoding="utf-8"))
    assert data["agency_slug"] == "10up"
    assert data["audit_score"] == 68.5


def test_campaign_to_dict_roundtrip():
    camp = AgencyTeardownCampaign(
        agency_slug="alley",
        agency_name="Alley Interactive",
        target_domain="alley.com",
        recipient_role="CTO",
        audit_score=85.0,
        audit_grade="B",
        core_finding="Missing DMARC reject/quarantine policy",
        briefing_pitch="Custom pitch test.",
        sha256_hash="abc123",
        deliverability_score=99.0,
    )
    d = camp.to_dict()
    assert d["agency_slug"] == "alley"
    assert d["audit_grade"] == "B"
    assert d["recipient_role"] == "CTO"
