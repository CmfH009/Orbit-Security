import json
import os
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

