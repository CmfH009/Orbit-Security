"""Unit tests for Conversation Diplomat (conversation_diplomat.py)."""

from pathlib import Path
import tempfile
import pytest

from orbit_security.conversation_diplomat import (
    ConversationDiplomat,
    DiscussionContext,
)


def test_detect_topic_dangling_cname():
    diplomat = ConversationDiplomat()
    topic, conf = diplomat.detect_topic(
        "Our marketing agency just shut down our Unbounce campaign and now our subdomain gives a 404!"
    )
    assert topic == "dangling_cname"
    assert conf >= 0.70


def test_detect_topic_ai_security():
    diplomat = ConversationDiplomat()
    topic, conf = diplomat.detect_topic(
        "Is anyone worried about prompt injection via malicious MCP tools in agentic coding loops?"
    )
    assert topic == "ai_security"
    assert conf >= 0.70


def test_generate_reply_dangling_cname():
    diplomat = ConversationDiplomat()
    ctx = DiscussionContext(
        tweet_id="12345",
        author_handle="dev_lead",
        text="Why does our old subdomain show a 404 error? We deleted the SaaS account last week.",
    )
    reply = diplomat.generate_reply(ctx)
    assert reply.target_tweet_id == "12345"
    assert reply.target_handle == "dev_lead"
    assert "dangling" in reply.reply_text.lower()
    assert "dig" in reply.reply_text.lower()
