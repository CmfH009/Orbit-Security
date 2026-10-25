"""Unit tests for orbit_security.triage_agent (TDD).

Validates:
1. Schema-constrained triage output conforming to TriageRemediationSpec.
2. Formatting and options passed to Ollama (format=schema, temperature=0.1, keep_alive=0).
3. Deterministic offline fallback when Ollama is unreachable.
4. Publication of TRIAGE_COMPLETED events into SQLite WAL Blackboard.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.blackboard import Blackboard
from orbit_security.triage_agent import LocalTriageAgent, TriageRemediationSpec


def test_triage_remediation_spec_validation():
    spec = TriageRemediationSpec(
        cve_id="CVE-2024-21887",
        threat_level="CRITICAL",
        cvss_score=9.8,
        attack_vector="NETWORK",
        remediation_patch="Apply Ivanti security mitigation patch immediately.",
        executive_summary="Critical command injection actively exploited in the wild.",
    )
    assert spec.cvss_score == 9.8
    assert spec.threat_level == "CRITICAL"
    data = spec.model_dump()
    assert data["cve_id"] == "CVE-2024-21887"

    # Out of range CVSS score rejected by Pydantic
    with pytest.raises(Exception):
        TriageRemediationSpec(
            cve_id="CVE-TEST",
            threat_level="LOW",
            cvss_score=11.5,
            attack_vector="NETWORK",
            remediation_patch="Patch",
            executive_summary="Summary",
        )


def test_local_triage_agent_offline_fallback(tmp_path):
    db_path = tmp_path / "triage_bb.db"
    bb = Blackboard(db_path=db_path)

    agent = LocalTriageAgent(
        ollama_url="http://127.0.0.1:99999/api/chat",  # Unreachable port
        blackboard=bb,
    )

    payload = {
        "domain": "vpn.example.com",
        "cve_id": "CVE-2024-21887",
        "product": "Connect Secure",
    }

    # Should fall back gracefully and return validated spec
    spec = agent.triage_vulnerability("CISA_KEV_MATCH_DETECTED", payload)
    assert isinstance(spec, TriageRemediationSpec)
    assert spec.cve_id == "CVE-2024-21887"
    assert spec.threat_level == "CRITICAL"
    assert spec.cvss_score == 9.8

    # Verify event published into Blackboard WAL
    recent = bb.get_recent(limit=10, event_type="TRIAGE_COMPLETED")
    assert len(recent) == 1
    assert recent[0]["payload"]["cve_id"] == "CVE-2024-21887"
    assert recent[0]["payload"]["target"] == "vpn.example.com"


def test_local_triage_agent_ollama_mock_inference(tmp_path):
    db_path = tmp_path / "triage_mock_bb.db"
    bb = Blackboard(db_path=db_path)

    agent = LocalTriageAgent(blackboard=bb)

    mock_ollama_response = {
        "message": {
            "content": json.dumps({
                "cve_id": "CVE-2021-41773",
                "threat_level": "CRITICAL",
                "cvss_score": 7.5,
                "attack_vector": "NETWORK",
                "remediation_patch": "Update Apache to 2.4.50 or higher.",
                "executive_summary": "Path traversal flaw in Apache HTTP Server mapped.",
            })
        }
    }

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(mock_ollama_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch.object(agent, "is_ollama_available", return_value=True):
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            spec = agent.triage_vulnerability(
                event_type="CISA_KEV_MATCH_DETECTED",
                payload={"target": "web.example.com", "cve_id": "CVE-2021-41773"},
                unload_after=True,
            )

            assert spec.cve_id == "CVE-2021-41773"
            assert spec.cvss_score == 7.5

            # Verify request payload contained format schema and keep_alive="0"
            mock_urlopen.assert_called_once()
            req = mock_urlopen.call_args[0][0]
            sent_data = json.loads(req.data.decode("utf-8"))
            assert sent_data["keep_alive"] == "0"
            assert sent_data["options"]["temperature"] == 0.1
            assert "properties" in sent_data["format"]
