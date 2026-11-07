"""Empirical Challenger 2 Adversarial Stress Suite for Milestone M2 Iteration 2.

Author: Challenger 2 (teamwork_challenger_m2_iter2_2)
Verifies:
1. Malicious domain normalization and path traversal immunity.
2. Hard containment of SLA certificates inside output_dir across hostile inputs.
3. StripeWebhookHandler resilience against malformed signatures, non-UTF8 payloads,
   corrupted JSON, and hostile metadata.
4. Client bundle provisioning containment inside data/client_bundles/<agency_slug>/
   without directory traversal escapes or unhandled exceptions.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List
import zipfile

import pytest

from orbit_security.deal_desk import RetainerDealDeskConcierge
from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    generate_stripe_signature,
    normalize_apex_domain,
    verify_stripe_signature,
)


@pytest.fixture
def temp_workspace():
    """Provides an isolated clean workspace per test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ============================================================================
# 1. Hostile Domain Normalization & Path Traversal Immunity
# ============================================================================


@pytest.mark.parametrize(
    "hostile_input,expected_domain",
    [
        ("../../evil/escape.com", "escape.com"),
        ("..\\..\\windows\\escape.com", "escape.com"),
        ("/absolute/root/domain.com", "domain.com"),
        ("https://user:pass@domain.com:8443/nested/path?query=1#hash", "domain.com"),
        ("http://sub.deep.example.co.uk:8080/index.html", "sub.deep.example.co.uk"),
        ("ftp://ftp.files.org/pub/file.tar.gz", "ftp.files.org"),
        ("scheme://evil.com?param=../../etc/passwd", "evil.com"),
        ("....//....//....//escape.com", "escape.com"),
        ("C:\\Windows\\System32\\domain.com", "domain.com"),
        ("\\\\remote-share\\folder\\target.io", "target.io"),
        ("   leading-trailing-spaces.com   ", "leading-trailing-spaces.com"),
        ("http://[::1]:8080/local.com", "local.com"),
        ("https://target.com/../../secret", "target.com"),
        ("https://user:pass@nested.domain.org/", "nested.domain.org"),
    ],
)
def test_normalize_apex_domain_hostile_inputs(hostile_input: str, expected_domain: str):
    """Verifies that normalize_apex_domain strips dangerous path separators and schemes."""
    res = normalize_apex_domain(hostile_input)
    assert "/" not in res
    assert "\\" not in res
    assert ".." not in res
    assert res == expected_domain


@pytest.mark.parametrize(
    "corrupt_input",
    [
        "",
        "   ",
        None,
        "....",
        "////",
        "\\\\\\",
        "../../..",
        "http://",
        "https://",
    ],
)
def test_normalize_apex_domain_degenerate_inputs(corrupt_input: Any):
    """Verifies degenerate or traversal-only inputs safely return empty string without error."""
    res = normalize_apex_domain(corrupt_input)
    assert res == ""
    assert "/" not in res
    assert "\\" not in res


# ============================================================================
# 2. SLA Certificate Containment & Defense-in-Depth
# ============================================================================


@pytest.mark.parametrize(
    "hostile_domain",
    [
        "../../evil/escape.com",
        "..\\..\\windows\\system32\\calc.exe",
        "/etc/passwd",
        "C:\\Windows\\System32\\hosts",
        "\\\\remote-host\\share\\exploit.pdf",
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "LPT1",
        "a" * 150 + ".com",
        "<script>alert(1)</script>.com",
        "domain with spaces.com",
        "domain;rm -rf /;.com",
        "emoji_test.com",
    ],
)
def test_sla_certificate_strict_containment(temp_workspace: Path, hostile_domain: str):
    """Verifies that SlaCertificateGenerator NEVER writes outside output_dir under hostile payloads."""
    certs_dir = temp_workspace / "certificates"
    certs_dir.mkdir(parents=True, exist_ok=True)
    generator = SlaCertificateGenerator(output_dir=certs_dir)

    cert_path, cert_id, crypto_hash = generator.generate_certificate(
        client_name="Adversarial Test Client",
        apex_domain=hostile_domain,
        plan="Enterprise",
    )
    assert cert_path.exists()
    # Verify strict filesystem containment inside certs_dir
    assert certs_dir.resolve() in cert_path.resolve().parents
    assert cert_path.is_file()
    assert cert_path.stat().st_size > 0
    assert cert_id.startswith("ORBIT-SLA-")
    assert len(crypto_hash) == 64


def test_sla_certificate_special_typography_resilience(temp_workspace: Path):
    """Verifies that ReportLab typography generation handles special characters and names."""
    certs_dir = temp_workspace / "certificates"
    generator = SlaCertificateGenerator(output_dir=certs_dir)

    hostile_clients = [
        "ACME & Sons",
        "Tom & Jerry Inc.",
        "Smith <John>",
        "A < B Security",
        "Special chars !@#$%^*()_+=-`~[]{}|;':,./?",
        "Multi-line\nCompany\r\nName",
        "Unicode \u2620\ufe0f Danger Corp \u4e2d\u6587",
    ]

    for client in hostile_clients:
        cert_path, cert_id, crypto_hash = generator.generate_certificate(
            client_name=client,
            apex_domain="typography-test.com",
            plan="Scale Retainer",
        )
        assert cert_path.exists()
        assert certs_dir.resolve() in cert_path.resolve().parents
        assert cert_path.stat().st_size > 1000


# ============================================================================
# 3. Stripe Webhook Signature & Corrupted Payload Resilience
# ============================================================================


def test_stripe_webhook_invalid_signatures(temp_workspace: Path):
    """Verifies StripeWebhookHandler rejects forged, expired, or malformed signatures."""
    webhook_secret = "whsec_adversarial_sig_test"
    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=SubscriberManager(subscribers_file=temp_workspace / "subscribers.json"),
        sla_generator=SlaCertificateGenerator(output_dir=temp_workspace / "certificates"),
        fleet_registry=FleetRegistry(data_path=temp_workspace / "clients.json"),
    )

    valid_payload = json.dumps({"type": "checkout.session.completed", "data": {"object": {}}}).encode("utf-8")

    # 1. Missing header
    res1 = handler.handle_webhook(valid_payload, None)
    assert res1["status"] == "ERROR"

    # 2. Forged signature
    res2 = handler.handle_webhook(valid_payload, "t=1234567,v1=bad_hex_signature")
    assert res2["status"] == "ERROR"

    # 3. Expired timestamp (> 600s tolerance)
    old_ts = int(time.time()) - 1000
    expired_sig = generate_stripe_signature(valid_payload, webhook_secret, timestamp=old_ts)
    res3 = handler.handle_webhook(valid_payload, expired_sig)
    assert res3["status"] == "ERROR"

    # 4. Future timestamp (> 600s tolerance)
    future_ts = int(time.time()) + 1000
    future_sig = generate_stripe_signature(valid_payload, webhook_secret, timestamp=future_ts)
    res4 = handler.handle_webhook(valid_payload, future_sig)
    assert res4["status"] == "ERROR"

    # 5. Wrong secret
    wrong_sig = generate_stripe_signature(valid_payload, "whsec_wrong_secret")
    res5 = handler.handle_webhook(valid_payload, wrong_sig)
    assert res5["status"] == "ERROR"


def test_stripe_webhook_corrupted_payload_bytes(temp_workspace: Path):
    """Verifies that non-JSON, non-UTF8, or truncated payloads return clean error without crashing."""
    handler = StripeWebhookHandler(
        webhook_secret=None,  # skip signature verification to stress json parser
        subscriber_manager=SubscriberManager(subscribers_file=temp_workspace / "subscribers.json"),
        sla_generator=SlaCertificateGenerator(output_dir=temp_workspace / "certificates"),
        fleet_registry=FleetRegistry(data_path=temp_workspace / "clients.json"),
    )

    bad_payloads = [
        b"",
        b"{invalid json",
        b"\x80\x81\xfe\xff",
        b"<html><body>502 Bad Gateway</body></html>",
    ]

    for p in bad_payloads:
        res = handler.handle_webhook(p, None)
        assert res.get("status") == "ERROR"
        assert "Invalid JSON" in res.get("message", "")


# ============================================================================
# 4. Hostile Checkout Traversal & Bundle Containment
# ============================================================================


def test_stripe_webhook_hostile_checkout_traversal(temp_workspace: Path):
    """Stress tests checkout.session.completed with multi-level directory traversal
    in domain, agency_id, and customer name simultaneously.
    """
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"
    bundles_dir = temp_workspace / "client_bundles"

    webhook_secret = "whsec_deep_traversal"
    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)
    deal_desk = RetainerDealDeskConcierge(
        workspace_root=temp_workspace,
        portals_dir=temp_workspace / "portals",
        bundles_dir=bundles_dir,
    )

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
        deal_desk=deal_desk,
    )

    payload = {
        "id": "evt_traversal_deep",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_deep_traversal_999",
                "customer": "cus_hostile_root",
                "customer_details": {
                    "email": "hacker@escape.com",
                    "name": "Hostile Agency Name",
                },
                "metadata": {
                    "domain": "https://user:pass@../../evil/escape.com:8443/deep/path?a=1#fragment",
                    "agency_id": "../../../root_escape_agency",
                    "tier": "Enterprise",
                },
                "amount_total": 99900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_stripe_signature(payload_bytes, webhook_secret)

    res = handler.handle_webhook(payload_bytes, sig)

    assert res["status"] == "PROVISIONED"
    assert res["apex_domain"] == "escape.com"

    # 1. Certificate file containment
    cert_path = Path(res["sla_certificate_path"])
    assert cert_path.exists()
    assert certs_dir.resolve() in cert_path.resolve().parents

    # 2. Bundle file containment
    bundle_path = Path(res["bundle_path"])
    assert bundle_path.exists()
    assert bundles_dir.resolve() in bundle_path.resolve().parents
    assert zipfile.is_zipfile(bundle_path)

    # 3. Verify ZIP members inside bundle
    with zipfile.ZipFile(bundle_path, "r") as archive:
        namelist = set(archive.namelist())
        expected_members = {
            "reports/executive_summary.html",
            "reports/executive_summary.md",
            "remediation/remediation.tf",
            "remediation/remediation.cfn.yaml",
            "remediation/remediation.zone",
            ".orbit.yml",
            "bundle_manifest.json",
        }
        for member in expected_members:
            assert member in namelist, f"Missing member: {member}"

    # 4. Subscriber record integrity
    subs = sub_mgr.list_subscribers()
    assert len(subs) == 1
    sub = subs[0]
    assert sub["stripe_customer_id"] == "cus_hostile_root"
    assert sub["apex_domain"] == "escape.com"
    assert sub["sla_certificate_id"] == res["sla_certificate_id"]
    assert sub["status"] == "active"
    assert sub["amount_cents"] == 99900


# ============================================================================
# 5. Full Lifecycle State Machine (Webhook De-provisioning & Recovery)
# ============================================================================


def test_stripe_webhook_lifecycle_state_machine(temp_workspace: Path):
    """Verifies full subscription lifecycle transitions:
    checkout.session.completed -> customer.subscription.updated (past_due) ->
    invoice.payment_failed -> invoice.payment_succeeded -> customer.subscription.deleted.
    """
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"

    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)

    handler = StripeWebhookHandler(
        webhook_secret=None,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
    )

    # 1. Onboarding
    checkout_payload = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_life_1",
                "customer": "cus_life_1",
                "subscription": "sub_life_1",
                "customer_details": {"email": "admin@lifecycle.io", "name": "Lifecycle Agency"},
                "metadata": {"domain": "lifecycle.io", "agency_id": "lifecycle-agency"},
            }
        },
    }
    res_onboard = handler.handle_webhook(json.dumps(checkout_payload).encode("utf-8"))
    assert res_onboard["status"] == "PROVISIONED"
    assert sub_mgr.list_subscribers()[0]["status"] == "active"

    # 2. Subscription past_due
    update_payload = {
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_life_1",
                "customer": "cus_life_1",
                "status": "past_due",
            }
        },
    }
    res_update = handler.handle_webhook(json.dumps(update_payload).encode("utf-8"))
    assert res_update["status"] == "UPDATED"
    assert res_update["billing_status"] == "past_due"
    assert sub_mgr.list_subscribers()[0]["status"] == "past_due"

    # 3. Invoice payment failure
    fail_payload = {
        "type": "invoice.payment_failed",
        "data": {
            "object": {
                "subscription": "sub_life_1",
                "customer": "cus_life_1",
            }
        },
    }
    res_fail = handler.handle_webhook(json.dumps(fail_payload).encode("utf-8"))
    assert res_fail["status"] == "PAYMENT_FAILED"
    assert sub_mgr.list_subscribers()[0]["status"] == "past_due"

    # 4. Invoice payment succeeded (Recovery)
    success_payload = {
        "type": "invoice.payment_succeeded",
        "data": {
            "object": {
                "subscription": "sub_life_1",
                "customer": "cus_life_1",
            }
        },
    }
    res_success = handler.handle_webhook(json.dumps(success_payload).encode("utf-8"))
    assert res_success["status"] == "PAYMENT_SUCCEEDED"
    assert sub_mgr.list_subscribers()[0]["status"] == "active"

    # 5. Cancellation / Deprovisioning
    delete_payload = {
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_life_1",
                "customer": "cus_life_1",
                "metadata": {"domain": "lifecycle.io"},
            }
        },
    }
    res_delete = handler.handle_webhook(json.dumps(delete_payload).encode("utf-8"))
    assert res_delete["status"] == "DEPROVISIONED"
    assert sub_mgr.list_subscribers()[0]["status"] == "canceled"
    assert sub_mgr.list_subscribers()[0]["monitoring_enabled"] is False
