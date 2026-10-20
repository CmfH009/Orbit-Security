import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure system scripts directory is in sys.path
SYSTEM_SCRIPTS = Path("A:/system/scripts") if Path("A:/system/scripts").exists() else Path(r"C:\AgyHut\system\scripts")
if str(SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SYSTEM_SCRIPTS))

from nova_email_daemon import (
    NovaEmailDaemon,
    EmailCategory,
    EmailMessage,
)


@pytest.fixture
def temp_daemon_env(tmp_path):
    """Provides an isolated environment for NovaEmailDaemon."""
    state_file = tmp_path / "nova_email_state.json"
    queue_dir = tmp_path / "queue"
    inbox_pending = tmp_path / "inbox" / "pending"
    queue_dir.mkdir(parents=True)
    inbox_pending.mkdir(parents=True)

    daemon = NovaEmailDaemon(
        account="ravenova9@gmail.com",
        operator_email="carsonmail009@gmail.com",
        state_file=str(state_file),
        queue_dir=str(queue_dir),
        pending_inbox_dir=str(inbox_pending),
        health_port=0,  # disable auto-starting server on fixed port during unit tests
    )
    return daemon, state_file, queue_dir, inbox_pending


def test_classify_task_directive_from_operator(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env
    msg = EmailMessage(
        sender="carsonmail009@gmail.com",
        subject="[TASK] Audit Orbit Security DNS records",
        body="Hey Nova, please run a full DNS scan on our portfolio and generate client reports.",
        message_id="msg-101",
    )

    category, dispatch_result = daemon.process_message(msg)
    assert category == EmailCategory.TASK_DIRECTIVE
    assert dispatch_result is not None
    assert "task_id" in dispatch_result

    # Verify task file was created in inbox/pending
    pending_files = list(inbox_pending.glob("*.json"))
    assert len(pending_files) == 1
    with open(pending_files[0], "r", encoding="utf-8") as f:
        task_data = json.load(f)
    assert task_data["source"] == "email_directive"
    assert "Audit Orbit Security DNS records" in task_data["title"]
    assert task_data["sender"] == "carsonmail009@gmail.com"


def test_classify_ai_service_alert(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env
    msg = EmailMessage(
        sender="google-cloud-noreply@google.com",
        subject="Your Google AI Pro Subscription Confirmation",
        body="Thank you for subscribing to Google AI Pro for ravenova9@gmail.com. Your 3-month access is now active.",
        message_id="msg-102",
    )

    category, dispatch_result = daemon.process_message(msg)
    assert category == EmailCategory.AI_SERVICE_ALERT
    assert len(list(inbox_pending.glob("*.json"))) == 0

    # Verify state recorded alert
    assert len(daemon.state["ai_service_alerts"]) == 1
    assert daemon.state["ai_service_alerts"][0]["subject"] == msg.subject


def test_classify_security_orbit_update(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env
    msg = EmailMessage(
        sender="stripe-alerts@orbit-security.com",
        subject="[Orbit Security] New Agency Retainer Stripe Checkout",
        body="Customer from wholegraindigital.com activated Growth tier ($59/mo).",
        message_id="msg-103",
    )

    category, dispatch_result = daemon.process_message(msg)
    assert category == EmailCategory.SECURITY_ORBIT_UPDATE
    assert len(daemon.state["security_updates"]) == 1


def test_offline_queue_processing(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env

    # Inject message into offline queue
    queue_file = queue_dir / "test_incoming.json"
    queue_file.write_text(
        json.dumps({
            "sender": "carsonmail009@gmail.com",
            "subject": "Deploy latest landing portal changes",
            "body": "Nova, push the latest client portals to production.",
            "message_id": "queue-001"
        }),
        encoding="utf-8"
    )

    processed = daemon.poll_offline_queue()
    assert len(processed) == 1
    assert processed[0]["category"] == EmailCategory.TASK_DIRECTIVE.value

    # Queue file should be archived or removed
    assert not queue_file.exists()


def test_graceful_missing_credentials(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env

    with patch.dict(os.environ, {}, clear=True):
        # Should return empty list and not crash when IMAP creds are absent
        res = daemon.poll_imap()
        assert res == []


def test_status_report(temp_daemon_env):
    daemon, state_file, queue_dir, inbox_pending = temp_daemon_env
    status = daemon.get_status()

    assert status["account"] == "ravenova9@gmail.com"
    assert status["status"] == "active"
    assert "tasks_dispatched" in status
    assert "total_processed" in status
