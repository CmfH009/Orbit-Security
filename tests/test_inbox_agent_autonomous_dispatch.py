import os
import json
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from orbit_security.inbox_agent import InboxAgent
from orbit_security.inbox_triage_bridge import InboundTriageDecision, TriageAction
from orbit_security.inbox_guardrail import AutonomousReplyGuardrail, GuardrailStatus, GuardrailEvaluationResult


@pytest.fixture(autouse=True)
def cleanup_portals():
    yield
    for name in ["agency123.html", "acme.html", "enterprise.html", "charleagency.html"]:
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


def test_process_inbound_lead_fail_safe_error_handling(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.side_effect = RuntimeError("Bridge subprocess connection refused")
    agent.triage_bridge = mock_bridge

    result = agent.process_inbound_lead(
        lead_data_or_sender={"sender": "cto@agency123.com", "subject": "Pricing inquiry", "body": "What are your rates?"}
    )
    assert result["status"] == "HELD_FOR_REVIEW"
    assert "Bridge subprocess connection refused" in result["error"]
    assert "INTERNAL_ERROR" in result["reason"]

    # Verify state was atomically persisted with internal error
    with open(temp_state_file, "r") as sf:
        state = json.load(sf)
        assert state["leads"]["cto@agency123.com"]["status"] == "HELD_FOR_REVIEW"
        assert "INTERNAL_ERROR" in state["leads"]["cto@agency123.com"]["reason"]


def test_poll_inbox_does_not_bypass_guardrail_on_held_for_review(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    agent.dispatcher = MagicMock()
    agent.dispatcher.is_configured.return_value = True

    # Seed spammer with auto-reply count 1
    agent.state["leads"]["spammer@charleagency.com"] = {"auto_replies_count": 1}
    agent._save_state()

    raw_msg = (
        b"From: cto@charleagency.com\r\n"
        b"To: carsonmail009@gmail.com\r\n"
        b"Subject: Re: Security notice regarding charleagency.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"What are your rates for client retainers?\r\n"
    )

    mock_mail = MagicMock()
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="cto@charleagency.com",
        subject="Re: Security notice regarding charleagency.com",
        intent="INQUIRY_PRICING",
        confidence=0.9,
        reasoning="Inquiry about rates",
        recommended_action=TriageAction.AUTONOMOUS_REPLY,
        draft_reply_subject="Re: Security notice",
        draft_reply_body="Price is $499/mo.\n\nBest,\nCarson Haynes",
    )
    agent.triage_bridge = mock_bridge

    # Mock guardrail to return BLOCKED (e.g. rate limit / anti-loop)
    agent.guardrail = MagicMock()
    agent.guardrail.evaluate.return_value = GuardrailEvaluationResult(
        status=GuardrailStatus.BLOCKED,
        violation_layer="LAYER_1_ANTI_LOOP",
        violation_code="ANTI_LOOP_DETECTED",
        reason="Thread limit exceeded",
    )

    with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
        with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
            processed = agent.poll_inbox()

    # Verify prospect NEVER received an email
    for call in agent.dispatcher.send_email.call_args_list:
        assert call.kwargs.get("recipient_email") != "cto@charleagency.com"

    # Verify operator was alerted
    operator_calls = [
        call for call in agent.dispatcher.send_email.call_args_list
        if call.kwargs.get("recipient_email") == "carsonmail009@gmail.com"
    ]
    assert len(operator_calls) >= 1
    assert "GUARDRAIL HELD FOR REVIEW" in operator_calls[0].kwargs.get("subject")

    # Verify intent in state matches resolved intent
    state_entry = next((v for k, v in agent.state.items() if isinstance(v, dict) and v.get("sender") == "cto@charleagency.com"), None)
    assert state_entry is not None
    assert state_entry["intent"] == "INQUIRY_PRICING"
    assert state_entry["escalated"] is True


def test_poll_inbox_passes_inbound_headers_to_process_lead(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    agent.dispatcher = MagicMock()
    agent.dispatcher.is_configured.return_value = True

    raw_msg = (
        b"From: rep@charleagency.com\r\n"
        b"To: carsonmail009@gmail.com\r\n"
        b"Subject: Re: Security notice regarding charleagency.com\r\n"
        b"Auto-Submitted: auto-replied\r\n"
        b"X-Autoreply: yes\r\n"
        b"Precedence: bulk\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"I am out of the office.\r\n"
    )

    mock_mail = MagicMock()
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

    captured_headers = {}
    orig_process = agent.process_inbound_lead

    def mock_process(*args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers", {})
        return orig_process(*args, **kwargs)

    agent.process_inbound_lead = mock_process

    with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
        with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
            agent.poll_inbox()

    assert captured_headers.get("Auto-Submitted") == "auto-replied"
    assert captured_headers.get("X-Autoreply") == "yes"
    assert captured_headers.get("Precedence") == "bulk"


def test_poll_inbox_escalate_to_carson_does_not_send_reply_to_prospect(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    agent.dispatcher = MagicMock()
    agent.dispatcher.is_configured.return_value = True

    raw_msg = (
        b"From: partner@charleagency.com\r\n"
        b"To: carsonmail009@gmail.com\r\n"
        b"Subject: Re: Security notice regarding charleagency.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Can Carson jump on a call?\r\n"
    )

    mock_mail = MagicMock()
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="partner@charleagency.com",
        subject="Re: Security notice regarding charleagency.com",
        intent="REQUEST_HUMAN",
        confidence=0.98,
        reasoning="Requested phone call with founder",
        recommended_action=TriageAction.ESCALATE_TO_CARSON,
        draft_reply_subject="Re: Security notice",
        draft_reply_body="Thanks for contacting us.",
        provider_resolved="GEMINI_CLI"
    )
    agent.triage_bridge = mock_bridge

    with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
        with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
            agent.poll_inbox()

    # Verify prospect NEVER received an email
    for call in agent.dispatcher.send_email.call_args_list:
        assert call.kwargs.get("recipient_email") != "partner@charleagency.com"

    # Verify operator received alert
    operator_calls = [
        call for call in agent.dispatcher.send_email.call_args_list
        if call.kwargs.get("recipient_email") == "carsonmail009@gmail.com"
    ]
    assert len(operator_calls) >= 1
    assert "TRIAGE ESCALATION" in operator_calls[0].kwargs.get("subject")


def test_poll_inbox_archive_no_action_suppresses_canned_replies(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    agent.dispatcher = MagicMock()
    agent.dispatcher.is_configured.return_value = True

    raw_msg = (
        b"From: marketing@charleagency.com\r\n"
        b"To: carsonmail009@gmail.com\r\n"
        b"Subject: Re: Security notice regarding charleagency.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"This is an automated digest with no response needed.\r\n"
    )

    mock_mail = MagicMock()
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="marketing@charleagency.com",
        subject="Re: Security notice regarding charleagency.com",
        intent="UNCLEAR",
        confidence=0.99,
        reasoning="Automated marketing digest, no action needed",
        recommended_action=TriageAction.ARCHIVE_NO_ACTION,
        draft_reply_subject=None,
        draft_reply_body=None,
        provider_resolved="GEMINI_CLI"
    )
    agent.triage_bridge = mock_bridge

    with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
        with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
            processed = agent.poll_inbox()

    # Zero emails should be dispatched (neither to prospect nor operator)
    assert agent.dispatcher.send_email.call_count == 0
    assert len(processed) == 1
    assert processed[0]["needs_escalation"] is False


def test_poll_inbox_suppress_unsubscribe_suppresses_canned_replies(temp_state_file):
    agent = InboxAgent(state_file=temp_state_file)
    agent.dispatcher = MagicMock()
    agent.dispatcher.is_configured.return_value = True

    raw_msg = (
        b"From: optout@charleagency.com\r\n"
        b"To: carsonmail009@gmail.com\r\n"
        b"Subject: Re: Security notice regarding charleagency.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please remove us from your mailing list.\r\n"
    )

    mock_mail = MagicMock()
    mock_mail.search.return_value = ("OK", [b"1"])
    mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

    mock_bridge = MagicMock()
    mock_bridge.triage_inbound_message.return_value = InboundTriageDecision(
        sender="optout@charleagency.com",
        subject="Re: Security notice regarding charleagency.com",
        intent="UNCLEAR",
        confidence=0.97,
        reasoning="Prospect requested unsubscription, suppress automated responses",
        recommended_action=TriageAction.SUPPRESS_UNSUBSCRIBE,
        draft_reply_subject=None,
        draft_reply_body=None,
        provider_resolved="GEMINI_CLI"
    )
    agent.triage_bridge = mock_bridge

    with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
        with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
            processed = agent.poll_inbox()

    # Zero emails should be dispatched (neither canned reply to prospect nor alert to operator)
    assert agent.dispatcher.send_email.call_count == 0
    assert len(processed) == 1
    assert processed[0]["needs_escalation"] is False


