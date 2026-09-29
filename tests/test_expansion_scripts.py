import json
import os
import sys
import tempfile
from unittest.mock import patch, mock_open
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.daily_briefing import query_daemon_health, query_inbox_pipeline, dispatch_email_briefing, generate_briefing
from scripts.setup_custom_domain import configure_domain


def test_query_daemon_health():
    mock_data = json.dumps({
        "supervisor_pid": 12345,
        "running": True,
        "services": {
            "orbit_security": {
                "pid": 54321,
                "active": True,
                "restart_count": 0
            }
        }
    })

    with patch("scripts.daily_briefing.os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=mock_data)):
            res = query_daemon_health()
            assert res["supervisor_active"] is True
            assert res["supervisor_pid"] == 12345
            assert res["sentinel_running"] is True
            assert res["sentinel_pid"] == 54321
            assert res["sentinel_restarts"] == 0


def test_query_inbox_pipeline():
    mock_data = json.dumps({
        "lead1": {"intent": "READY_TO_BUY", "escalated": True},
        "lead2": {"intent": "INQUIRY_PRICING", "escalated": False},
        "lead3": {"intent": "NOT_INTERESTED", "escalated": False}
    })

    with patch("scripts.daily_briefing.os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=mock_data)):
            res = query_inbox_pipeline()
            assert res["total_threads"] == 3
            assert res["escalations"] == 1
            assert res["inquiries"] == 1


def test_configure_domain():
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_cname = os.path.join(tmpdir, "CNAME")
        with patch("scripts.setup_custom_domain.os.path.join", return_value=fake_cname):
            with patch("scripts.setup_custom_domain.os.getenv", return_value=None):
                configure_domain("testorbit.io", verify_dns=False)

        assert os.path.exists(fake_cname)
        with open(fake_cname, "r", encoding="utf-8") as f:
            content = f.read().strip()
            assert content == "testorbit.io"


def test_dispatch_email_briefing_success():
    with patch("orbit_security.mailer.EmailDispatcher.is_configured", return_value=True):
        with patch("orbit_security.mailer.EmailDispatcher.send_email", return_value=True) as mock_send:
            res = dispatch_email_briefing("# Test Report", recipient="test@example.com")
            assert res is True
            mock_send.assert_called_once()
            args, kwargs = mock_send.call_args
            assert kwargs.get("recipient_email") == "test@example.com"
            assert kwargs.get("body_text") == "# Test Report"


def test_dispatch_email_briefing_unconfigured():
    with patch("orbit_security.mailer.EmailDispatcher.is_configured", return_value=False):
        res = dispatch_email_briefing("# Test Report")
        assert res is False
