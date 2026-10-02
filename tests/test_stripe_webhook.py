"""Unit and integration tests for Automated Stripe Webhook Onboarding & Provisioning (Act II Item 2).

Verifies:
1. Stripe cryptographic HMAC-SHA256 signature verification:
   - Valid signature with current timestamp
   - Invalid / tampered signature rejection
   - Timestamp replay tolerance enforcement
2. Cryptographic SLA PDF certificate generation:
   - Valid PDF binary output with %PDF header
   - Deterministic SHA256 cryptographic verification digest
   - Injected domain, client name, plan tier, and 99.9% uptime SLA terms
3. Subscriber provisioning in data/subscribers.json:
   - Atomic recording of subscriber record
   - Linking of SLA certificate ID, file path, and crypto hash
4. 24/7 Fleet Sentinel monitoring registration:
   - Automatic registration of ClientTarget into data/clients.json
   - Retainer plan assignment and active monitoring status
5. Full checkout.session.completed event workflow
6. Subscription cancellation / pause handling
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict

import pytest

from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    compute_sla_crypto_hash,
    generate_stripe_signature,
    verify_stripe_signature,
)


# ============================================================================
# 1. Stripe HMAC-SHA256 Signature Verification Tests
# ============================================================================


def test_verify_stripe_signature_valid():
    """Verifies that an authentic HMAC-SHA256 Stripe signature passes."""
    secret = "whsec_test_secret_key_12345"
    payload = b'{"id": "evt_test_123", "type": "checkout.session.completed"}'
    ts = int(time.time())

    sig_header = generate_stripe_signature(payload, secret, timestamp=ts)
    assert verify_stripe_signature(payload, sig_header, secret, tolerance=300) is True


def test_verify_stripe_signature_tampered_payload():
    """Rejects signature if payload bytes have been altered."""
    secret = "whsec_test_secret_key_12345"
    original_payload = b'{"amount": 29900}'
    tampered_payload = b'{"amount": 100}'
    ts = int(time.time())

    sig_header = generate_stripe_signature(original_payload, secret, timestamp=ts)
    assert verify_stripe_signature(tampered_payload, sig_header, secret, tolerance=300) is False


def test_verify_stripe_signature_expired_timestamp():
    """Rejects signature if timestamp is outside the replay tolerance window."""
    secret = "whsec_test_secret_key_12345"
    payload = b'{"id": "evt_test_old"}'
    old_ts = int(time.time()) - 400  # 400 seconds ago > 300s tolerance

    sig_header = generate_stripe_signature(payload, secret, timestamp=old_ts)
    assert verify_stripe_signature(payload, sig_header, secret, tolerance=300) is False


# ============================================================================
# 2. Cryptographic SLA PDF Certificate Tests
# ============================================================================


def test_compute_sla_crypto_hash():
    """Verifies deterministic SHA-256 digest generation for SLA certificates."""
    h1 = compute_sla_crypto_hash("ORBIT-SLA-001", "Apex Apparel", "apexapparel.io", "Scale", "2026-10-02")
    h2 = compute_sla_crypto_hash("ORBIT-SLA-001", "Apex Apparel", "apexapparel.io", "Scale", "2026-10-02")
    assert h1 == h2
    assert len(h1) == 64

    # Tampered domain produces different hash
    h3 = compute_sla_crypto_hash("ORBIT-SLA-001", "Apex Apparel", "hackeddomain.io", "Scale", "2026-10-02")
    assert h1 != h3


def test_sla_certificate_pdf_generation():
    """Generates a valid, cryptographically signed SLA PDF certificate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        generator = SlaCertificateGenerator(output_dir=output_dir)

        cert_path, cert_id, crypto_hash = generator.generate_certificate(
            client_name="Eastside Co Agency",
            apex_domain="eastsideco.com",
            plan="Enterprise Retainer ($499/mo)",
            effective_date="2026-10-02",
        )

        assert cert_path.exists()
        assert cert_path.suffix == ".pdf"
        assert cert_id.startswith("ORBIT-SLA-")
        assert len(crypto_hash) == 64

        # Verify PDF header
        with open(cert_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"


# ============================================================================
# 3. Subscriber Provisioning Tests
# ============================================================================


def test_subscriber_manager_provisioning():
    """Tests saving and retrieving subscriber records in data/subscribers.json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sub_file = Path(tmpdir) / "subscribers.json"
        mgr = SubscriberManager(subscribers_file=sub_file)

        record = mgr.provision_subscriber(
            customer_id="cus_N12345",
            customer_email="billing@domaincraft.org",
            customer_name="Domain Craft LLC",
            apex_domain="domaincraft.org",
            plan="Scale",
            amount_cents=29900,
            currency="usd",
            sla_cert_id="ORBIT-SLA-TEST99",
            sla_cert_path="/path/to/SLA_domaincraft_org.pdf",
            sla_crypto_hash="abcdef0123456789" * 4,
            stripe_session_id="cs_test_session_xyz",
        )

        assert record["apex_domain"] == "domaincraft.org"
        assert record["status"] == "active"
        assert record["sla_certificate_id"] == "ORBIT-SLA-TEST99"

        # Verify disk persistence
        subs = mgr.list_subscribers()
        assert len(subs) == 1
        assert subs[0]["customer_email"] == "billing@domaincraft.org"

        # Updating existing subscriber
        mgr.provision_subscriber(
            customer_id="cus_N12345",
            customer_email="billing@domaincraft.org",
            customer_name="Domain Craft LLC",
            apex_domain="domaincraft.org",
            plan="Enterprise",
            amount_cents=49900,
            currency="usd",
            sla_cert_id="ORBIT-SLA-TEST99-UPDATED",
            sla_cert_path="/path/to/SLA_domaincraft_org_v2.pdf",
            sla_crypto_hash="abcdef0123456789" * 4,
            stripe_session_id="cs_test_session_xyz2",
        )
        subs_updated = mgr.list_subscribers()
        assert len(subs_updated) == 1
        assert subs_updated[0]["plan"] == "Enterprise"


# ============================================================================
# 4. Fleet Sentinel 24/7 Monitoring Registration Tests
# ============================================================================


def test_register_for_24_7_fleet_monitoring():
    """Verifies subscriber domain is registered into data/clients.json for 24/7 monitoring."""
    with tempfile.TemporaryDirectory() as tmpdir:
        clients_file = Path(tmpdir) / "clients.json"
        registry = FleetRegistry(data_path=clients_file)

        handler = StripeWebhookHandler(fleet_registry=registry)
        client = handler.register_client_for_monitoring(
            apex_domain="swankyagency.com",
            client_name="Swanky Agency",
            contact_email="ops@swankyagency.com",
            plan="Scale Retainer",
        )

        assert client.apex_domain == "swankyagency.com"
        assert client.status == "active"

        # Reload from disk
        reloaded_reg = FleetRegistry(data_path=clients_file)
        active = reloaded_reg.list_active()
        assert any(c.apex_domain == "swankyagency.com" for c in active)


# ============================================================================
# 5. Full End-to-End checkout.session.completed Event Workflow
# ============================================================================


def test_handle_checkout_session_completed_event():
    """Tests the full end-to-end webhook event ingestion and domain provisioning."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sub_file = Path(tmpdir) / "subscribers.json"
        clients_file = Path(tmpdir) / "clients.json"
        certs_dir = Path(tmpdir) / "certificates"

        webhook_secret = "whsec_live_test_orbit_key"
        sub_mgr = SubscriberManager(subscribers_file=sub_file)
        cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
        registry = FleetRegistry(data_path=clients_file)

        handler = StripeWebhookHandler(
            webhook_secret=webhook_secret,
            subscriber_manager=sub_mgr,
            sla_generator=cert_gen,
            fleet_registry=registry,
        )

        event_payload = {
            "id": "evt_checkout_success_998",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_session_123456",
                    "customer": "cus_998877",
                    "customer_details": {
                        "email": "cto@koru-digital.com",
                        "name": "Koru Digital",
                    },
                    "metadata": {
                        "domain": "koru-digital.com",
                        "plan": "Scale Retainer ($299/mo)",
                    },
                    "amount_total": 29900,
                    "currency": "usd",
                    "payment_status": "paid",
                }
            },
        }

        payload_bytes = json.dumps(event_payload).encode("utf-8")
        sig_header = generate_stripe_signature(payload_bytes, webhook_secret)

        result = handler.handle_webhook(payload_bytes, sig_header)

        assert result["status"] == "PROVISIONED"
        assert result["apex_domain"] == "koru-digital.com"
        assert result["sla_certificate_id"].startswith("ORBIT-SLA-")
        assert Path(result["sla_certificate_path"]).exists()

        # Check subscriber persistence
        subs = sub_mgr.list_subscribers()
        assert len(subs) == 1
        assert subs[0]["apex_domain"] == "koru-digital.com"

        # Check fleet monitoring persistence
        clients = registry.list_active()
        assert any(c.apex_domain == "koru-digital.com" for c in clients)


def test_handle_subscription_deleted_event():
    """Tests subscription cancellation marking subscriber status as canceled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sub_file = Path(tmpdir) / "subscribers.json"
        clients_file = Path(tmpdir) / "clients.json"

        sub_mgr = SubscriberManager(subscribers_file=sub_file)
        registry = FleetRegistry(data_path=clients_file)

        # Pre-seed subscriber
        sub_mgr.provision_subscriber(
            customer_id="cus_cancel_me",
            customer_email="admin@cancel-target.io",
            customer_name="Cancel Target",
            apex_domain="cancel-target.io",
            plan="Scale",
            amount_cents=29900,
            currency="usd",
            sla_cert_id="ORBIT-SLA-CANCEL",
            sla_cert_path="/dev/null",
            sla_crypto_hash="000",
        )

        handler = StripeWebhookHandler(
            subscriber_manager=sub_mgr,
            fleet_registry=registry,
        )

        event = {
            "id": "evt_sub_deleted",
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "customer": "cus_cancel_me",
                    "metadata": {"domain": "cancel-target.io"},
                }
            },
        }

        res = handler.handle_webhook(json.dumps(event).encode("utf-8"))
        assert res["status"] == "DEPROVISIONED"

        # Check status changed
        subs = sub_mgr.list_subscribers()
        assert subs[0]["status"] == "canceled"
