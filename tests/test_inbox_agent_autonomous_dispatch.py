import os
import json
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from orbit_security.inbox_agent import InboxAgent
from orbit_security.inbox_triage_bridge import InboundTriageDecision, TriageAction
from orbit_security.inbox_guardrail import AutonomousReplyGuardrail, GuardrailStatus


@pytest.fixture(autouse=True)
def cleanup_portals():
    yield
    for name in ["agency123.html", "acme.html", "enterprise.html"]:
        for parent in ["docs/portals", "landing/portals"]:
            p = os.path.join(parent, name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


@pytest.fixture
def temp_state_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        f.write(json.dumps({"leads": {}, "unsubscribes": []}).encode("utf-8"))
        f_path = f.name
    yield f_path
    if os.path.exists(f_path):
        os.remove(f_path)


def test_inbound_lead_autonomous_dispatch_happy_path(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="cto@agency123.com",
        subject="Pricing inquiry",
        intent="INQUIRY_PRICING",
        confidence=0.92,
        reasoning="Agency asked for rates",
        recommended_action=TriageAction.AUTONOMOUS_REPLY,
        suggested_tier="monitoring",
        draft_reply_subject="Re: Pricing inquiry",
        draft_reply_body="Monitoring is $499/mo.\n\nBest,\nCarson Haynes\nFounder, Orbit Security",
        provider_resolved="GEMINI_CLI"
    )
    agent.triage_bridge = mock_bridge
    agent.dispatcher = MagicMock()
    agent.dispatcher.send_email.return_value = True

    with patch("orbit_security.blackboard.publish_event") as mock_bb:
        result = agent.process_inbound_lead(
            lead_data_or_sender={"sender": "cto@agency123.com", "subject": "Pricing inquiry", "body": "What are your rates?"}
        )

        assert result["status"] == "AUTONOMOUS_REPLY_SENT"
        agent.dispatcher.send_email.assert_called_once()
        assert mock_bb.call_count >= 1

        # Verify atomic write updated state
        with open(temp_state_file, "r") as sf:
            state = json.load(sf)
            assert state["leads"]["cto@agency123.com"]["auto_replies_count"] == 1


def test_inbound_lead_blocked_when_guardrail_fails(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    # Seed state with existing auto-reply
    agent.state["leads"]["spammer@acme.com"] = {"auto_replies_count": 1}
    agent._save_state()

    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="spammer@acme.com",
        subject="Re: Loop",
        intent="INQUIRY_PRICING",
        confidence=0.9,
        reasoning="Follow up",
        recommended_action=TriageAction.AUTONOMOUS_REPLY,
        draft_reply_subject="Re: Loop",
        draft_reply_body="Price is $499/mo.\n\nBest,\nCarson Haynes",
    )
    agent.triage_bridge = mock_bridge
    agent.dispatcher = MagicMock()

    result = agent.process_inbound_lead(
        lead_data_or_sender={"sender": "spammer@acme.com", "subject": "Re: Loop", "body": "Tell me more"}
    )
    assert result["status"] == "HELD_FOR_REVIEW"
    assert result["violation_code"] == "ANTI_LOOP_DETECTED"
    agent.dispatcher.send_email.assert_not_called()


def test_inbox_agent_init_with_custom_dependencies(temp_state_file):
    custom_guard = AutonomousReplyGuardrail(max_global_per_hour=5)
    custom_bridge = MagicMock()
    agent = InboxAgent(
        state_file=temp_state_file,
        guardrail=custom_guard,
        triage_bridge=custom_bridge
    )
    assert agent.guardrail is custom_guard
    assert agent.triage_bridge is custom_bridge
    assert "leads" in agent.state


def test_atomic_state_write():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = os.path.join(tmp_dir, "leads_state.json")
        agent = InboxAgent(state_file=state_file)
        agent.state["test_key"] = "test_value"
        agent._save_state()

        with open(state_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["test_key"] == "test_value"

        # Verify no dangling .tmp files in state directory
        tmp_files = [f for f in os.listdir(tmp_dir) if f.endswith(".tmp")]
        assert len(tmp_files) == 0


def test_inbound_lead_escalates_to_carson(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="partner@enterprise.com",
        subject="Partnership inquiry",
        intent="REQUEST_HUMAN",
        confidence=0.95,
        reasoning="Custom enterprise contract requested",
        recommended_action=TriageAction.ESCALATE_TO_CARSON,
        draft_reply_subject="Re: Partnership inquiry",
        draft_reply_body="Thanks for contacting us.",
        provider_resolved="GEMINI_CLI"
    )
    agent.triage_bridge = mock_bridge
    agent.dispatcher = MagicMock()

    result = agent.process_inbound_lead(
        lead_data_or_sender={"sender": "partner@enterprise.com", "subject": "Partnership inquiry", "body": "Let's talk"}
    )
    assert result["status"] == "ESCALATE_TO_CARSON"
    agent.dispatcher.send_email.assert_not_called()
    assert agent.state["leads"]["partner@enterprise.com"]["status"] == "ESCALATE_TO_CARSON"
