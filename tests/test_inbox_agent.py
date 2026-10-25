import json
import os
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.inbox_agent import InboxAgent, LeadIntent


def test_classify_intent_ready_to_buy():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "Sounds great, can you send over the payment link or invoice?",
        "We'd love to try this for 20 client sites. How do we sign up?",
        "Please send the stripe checkout link so we can get started.",
        "Yes, we want to buy the Growth plan. Send details to pay.",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.READY_TO_BUY


def test_classify_intent_pricing():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "What are your prices for this?",
        "How much does it cost per month for 30 domains?",
        "Can you send over your pricing tiers and care plan options?",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.INQUIRY_PRICING


def test_classify_intent_technical():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "How did you detect the DMARC record? Is this automated?",
        "Does your scanner do port scanning or is it purely DNS based?",
        "Can we customize the PDF with our agency's logo and branding?",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.INQUIRY_TECHNICAL


def test_classify_intent_not_interested():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "Please unsubscribe us from this list.",
        "Not interested, do not email again.",
        "We already have an in-house security team, thanks.",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.NOT_INTERESTED


def test_classify_intent_request_human():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "Can I speak to a human about our agency's needs?",
        "Is there a phone number where I can talk to Carson?",
        "Are you an AI? I'd like to jump on a quick Zoom call with a real person.",
        "Can we schedule a call to discuss custom terms?",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.REQUEST_HUMAN


def test_generate_reply_and_human_escalation():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)
        mock_dispatcher = MagicMock()
        agent.dispatcher = mock_dispatcher

        reply_text, needs_escalation = agent.handle_message(
            sender_email="cto@agencypartners.com",
            subject="Re: Questions regarding retainers",
            message_body="Can we schedule a call with Carson? We want to talk to a human before deciding."
        )

        assert needs_escalation is True
        assert "Carson here" in reply_text
        assert "direct, personal access to me" in reply_text
        mock_dispatcher.send_email.assert_called_once()
        kwargs = mock_dispatcher.send_email.call_args.kwargs
        assert "carsonmail009@gmail.com" in kwargs["recipient_email"]
        assert "URGENT HUMAN ESCALATION" in kwargs["subject"]
        assert "cto@agencypartners.com" in kwargs["subject"]
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_generate_reply_and_escalation():

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)
        
        # Test Ready to buy triggers escalation email to Carson
        mock_dispatcher = MagicMock()
        agent.dispatcher = mock_dispatcher

        reply_text, needs_escalation = agent.handle_message(
            sender_email="founder@testagency.com",
            subject="Re: Security notice",
            message_body="We want to sign up, please send the stripe payment link."
        )

        assert needs_escalation is True
        assert "Carson is preparing your agency workspace" in reply_text
        mock_dispatcher.send_email.assert_called_once()
        kwargs = agent.dispatcher.send_email.call_args.kwargs
        assert "carsonmail009@gmail.com" in kwargs["recipient_email"]
        assert "ACTION REQUIRED" in kwargs["subject"]

    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_check_stripe_payments():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)
        mock_dispatcher = MagicMock()
        agent.dispatcher = mock_dispatcher

        # Mock Stripe API response
        mock_sessions_response = MagicMock()
        mock_sessions_response.status_code = 200
        mock_sessions_response.json.return_value = {
            "data": [
                {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "customer_details": {"email": "paying_agency@example.com", "name": "Paying Agency"},
                    "amount_total": 5900,
                    "currency": "usd"
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_sessions_response):
            # The Stripe poller short-circuits when no API key is configured, so
            # the test must supply one. Without this the test silently depends on
            # a developer's local .env and fails in CI.
            with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_hermetic"}):
                new_payments = agent.check_stripe_payments()
            assert len(new_payments) == 1
            assert new_payments[0]["id"] == "cs_test_123"
            mock_dispatcher.send_email.assert_called_once()
            call_kwargs = mock_dispatcher.send_email.call_args.kwargs
            assert "PAYMENT RECEIVED" in call_kwargs["subject"]
            assert "paying_agency@example.com" in call_kwargs["body_text"]
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_is_system_or_vendor_email():
    agent = InboxAgent(state_file=tempfile.mktemp())
    # System / vendor emails should be identified
    assert agent.is_system_or_vendor_email("notifications@github.com", "[CmfH009/Orbit-Security] Run failed: Orbit Security Perimeter Sentinel")
    assert agent.is_system_or_vendor_email("hello@ollama.com", "Pay as you go pricing for Ollama cloud")
    assert agent.is_system_or_vendor_email("no.reply@connect.razer.com", "Meet the all new Kiyo")
    assert agent.is_system_or_vendor_email("googleplay-noreply@google.com", "Payment declined for Google Play Pass")
    assert agent.is_system_or_vendor_email("hello@newsletter.life360.com", "Next up: add your four-legged family")
    assert agent.is_system_or_vendor_email("no-reply@accounts.google.com", "Security alert")

    # Legitimate agency emails must NOT be classified as system/vendor
    assert not agent.is_system_or_vendor_email("andre@charle.co.uk", "Re: Security notice regarding candykittens.co.uk")
    assert not agent.is_system_or_vendor_email("support@cleancanvas.co.uk", "Re: candykittens perimeter check")
    assert not agent.is_system_or_vendor_email("cto@commandc.com", "Question regarding agency retainers")


def test_handle_message_ignores_system_bots():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)
        mock_dispatcher = MagicMock()
        agent.dispatcher = mock_dispatcher

        reply_text, needs_escalation = agent.handle_message(
            sender_email="notifications@github.com",
            subject="[CmfH009/Orbit-Security] Run failed: Orbit Security Perimeter Sentinel - main (9c08745)",
            message_body="Run failed for workflow Orbit Security Perimeter Sentinel. Check logs at https://github.com/..."
        )

        assert reply_text == ""
        assert needs_escalation is False
        mock_dispatcher.send_email.assert_not_called()
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_detect_bounce_notification_records_state_without_name_error():
    """Verify that IMAP bounce processing extracts recipient and writes timestamp without NameError."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)

        raw_msg = (
            b"From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>\r\n"
            b"To: carsonmail009@gmail.com\r\n"
            b"Subject: Delivery Status Notification (Failure)\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"The following message to <hello@avexdesigns.com> was undeliverable.\r\n"
            b"Technical details of permanent failure:\r\n"
            b"550 5.1.1 The email account that you tried to reach does not exist.\r\n"
        )

        mock_mail = MagicMock()
        mock_mail.search.return_value = ("OK", [b"1"])
        mock_mail.fetch.return_value = ("OK", [(b"1", raw_msg)])

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            with patch.dict(os.environ, {"IMAP_SERVER": "imap.test.local", "IMAP_USER": "test@test.local", "IMAP_PASSWORD": "secret"}):
                agent.poll_inbox()

        state_entry = next((v for k, v in agent.state.items() if v.get("intent") == "BOUNCE"), None)
        assert state_entry is not None, "Expected bounce entry in agent state"
        assert state_entry["bounced_target"] == "hello@avexdesigns.com"
        assert state_entry["verdict"] == "HARD_BOUNCE_PRUNED"
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_classify_intent_auto_reply_or_ticket():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "Your support request received: Ticket #99281 has been opened.",
        "Automatic reply: I am currently out of the office and away until next Monday.",
        "Thank you for contacting the reception team. We will review your query-1049.",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.AUTO_REPLY_OR_TICKET


def test_classify_intent_unclear():
    agent = InboxAgent(state_file=tempfile.mktemp())
    text_samples = [
        "We have received the transmission regarding company infrastructure. Considering various alternatives.",
        "Our digital ecosystem is undergoing a transition phase at this time.",
    ]
    for sample in text_samples:
        intent = agent.classify_intent(sample)
        assert intent == LeadIntent.UNCLEAR


def test_process_inbound_lead_provisions_portal_and_blackboard():
    portal_created = None
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        state_file = f.name
    try:
        agent = InboxAgent(state_file=state_file)
        lead_input = {
            "sender": "austin@alley.com",
            "subject": "Re: White-label security audits for Alley Interactive's client portfolio",
            "body": "Hi Carson, we want to buy the Scale remediation retainer for 15 domains. Send payment link.",
            "agency_name": "Alley Interactive Test"
        }
        res = agent.process_inbound_lead(lead_input)
        assert res["ok"] is True
        assert res["intent"] == "READY_TO_BUY"
        assert res["tier"] == "remediation"
        assert "alley_interactive_test.html" in res["portal_path"]
        assert "https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800" in res["checkout_url"]
        assert os.path.exists(res["portal_path"])
        portal_created = res["portal_path"]
    finally:
        if portal_created and os.path.exists(portal_created):
            try:
                os.remove(portal_created)
                landing_copy = Path(portal_created).resolve().parents[2] / "landing" / "portals" / Path(portal_created).name
                if landing_copy.exists():
                    landing_copy.unlink()
            except Exception:
                pass
        if os.path.exists(state_file):
            os.remove(state_file)



