import json
import pytest
from unittest.mock import MagicMock, patch
from orbit_security.inbox_triage_bridge import (
    InboxTriageBridge,
    InboundTriageDecision,
    TriageAction,
)

def test_pydantic_schema_validation():
    decision = InboundTriageDecision(
        sender="lead@agency.com",
        subject="Re: Pricing",
        intent="INQUIRY_PRICING",
        confidence=0.95,
        reasoning="Agency asked for monitoring price.",
        recommended_action=TriageAction.AUTONOMOUS_REPLY,
        suggested_tier="monitoring",
        draft_reply_subject="Re: Pricing",
        draft_reply_body="Hi there,\n\nOur monitoring plan is $499/mo.\n\nBest,\nCarson Haynes",
        provider_resolved="GEMINI_CLI",
    )
    assert decision.intent == "INQUIRY_PRICING"
    assert decision.recommended_action == TriageAction.AUTONOMOUS_REPLY

def test_bridge_uses_gemini_cli_when_healthy():
    mock_cli = MagicMock()
    mock_decision_dict = {
        "sender": "prospect@dev.com",
        "subject": "Re: Orbit Audit",
        "intent": "INQUIRY_PRICING",
        "confidence": 0.9,
        "reasoning": "Pricing inquiry",
        "recommended_action": "AUTONOMOUS_REPLY",
        "suggested_tier": "monitoring",
        "portal_link_requested": True,
        "draft_reply_subject": "Re: Orbit Audit",
        "draft_reply_body": "Our monitoring retainer is $499/mo.\n\nBest,\nCarson Haynes",
        "provider_resolved": "GEMINI_CLI"
    }
    mock_cli.execute_json.return_value = MagicMock(
        exit_code=0,
        success=True,
        data=mock_decision_dict
    )

    bridge = InboxTriageBridge(gemini_bridge=mock_cli)
    decision = bridge.triage_inbound_message("prospect@dev.com", "Re: Orbit Audit", "How much does monitoring cost?")
    assert decision.provider_resolved == "GEMINI_CLI"
    assert decision.suggested_tier == "monitoring"
    assert "$499/mo" in decision.draft_reply_body

def test_bridge_falls_back_to_ollama_when_cli_fails():
    mock_cli = MagicMock()
    mock_cli.execute_json.side_effect = Exception("CLI binary timeout")

    bridge = InboxTriageBridge(gemini_bridge=mock_cli)
    
    with patch.object(bridge, "_call_local_ollama") as mock_ollama:
        mock_ollama.return_value = InboundTriageDecision(
            sender="prospect@dev.com",
            subject="Re: Orbit Audit",
            intent="INQUIRY_PRICING",
            confidence=0.85,
            reasoning="Ollama parsed pricing question",
            recommended_action=TriageAction.AUTONOMOUS_REPLY,
            suggested_tier="monitoring",
            draft_reply_body="Monitoring is $499/mo.\n\nBest,\nCarson Haynes",
            provider_resolved="OLLAMA_LOCAL"
        )
        decision = bridge.triage_inbound_message("prospect@dev.com", "Re: Orbit Audit", "What is the fee?")
        assert decision.provider_resolved == "OLLAMA_LOCAL"

def test_bridge_falls_back_to_deterministic_when_all_llms_offline():
    mock_cli = MagicMock()
    mock_cli.execute_json.side_effect = Exception("CLI offline")

    bridge = InboxTriageBridge(gemini_bridge=mock_cli)
    with patch.object(bridge, "_call_local_ollama", side_effect=Exception("Ollama down")):
        decision = bridge.triage_inbound_message("prospect@dev.com", "Re: Urgent Issue", "Can you fix our DNS?")
        assert decision.provider_resolved == "DETERMINISTIC_FALLBACK"
        assert decision.recommended_action == TriageAction.ESCALATE_TO_CARSON
