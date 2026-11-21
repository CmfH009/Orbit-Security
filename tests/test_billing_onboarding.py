"""Deep-interface tests for BillingOnboarding (signup -> webhook -> provisioning -> lifecycle -> cancellation).

Exercises the single deepened Billing & Agency Onboarding module configured by
a ``tmp_path`` workspace_root and an injected ``InMemoryStripeTransport`` fake
adapter, with zero live network calls, zero live data/* mutations, and zero
global blackboard or os.environ monkeypatching.
"""

from __future__ import annotations

import hashlib
from http.client import HTTPConnection
from http.server import HTTPServer
import json
from pathlib import Path
import threading
import time
import urllib.parse
import zipfile

import pytest

from orbit_security import deal_desk, stripe_checkout, stripe_webhook
from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
from orbit_security.billing_onboarding import (
    DEFAULT_PRICE_IDS,
    BillingOnboarding,
    InMemoryStripeTransport,
    generate_stripe_signature,
    get_price_id,
    resolve_deal_desk_tier_key,
    resolve_retainer_tier,
)
from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_checkout import make_checkout_request_handler
from orbit_security.stripe_webhook import make_webhook_request_handler


def test_full_signup_webhook_provisioning_upgrade_and_cancellation_lifecycle(tmp_path: Path):
    """End-to-end lifecycle through the single deepened BillingOnboarding interface."""
    transport = InMemoryStripeTransport()
    webhook_secret = "whsec_deep_interface_test"
    billing = BillingOnboarding(
        workspace_root=tmp_path,
        stripe_transport=transport,
        stripe_secret_key="sk_test_deep_interface_001",
        webhook_secret=webhook_secret,
        price_ids={
            RetainerTier.STARTER: "price_starter_test",
            RetainerTier.SCALE: "price_scale_test",
            RetainerTier.ENTERPRISE: "price_enterprise_test",
        },
    )

    # 1. Signup -> Checkout Session creation with UI tier alias ("Growth" -> Scale)
    checkout = billing.create_checkout_session(
        agency_id="Northwind Security",
        agency_name="Northwind Security",
        tier="Growth",
        contact_email="ops@northwind-sec.example",
        website="https://northwind-sec.example",
        support_email="support@northwind-sec.example",
        domain="northwind-sec.example",
        custom_domain="portal.northwind-sec.example",
        primary_color="#0B132B",
        accent_color="#10B981",
        tagline="Autonomous Perimeter Guard",
        client_reference_id="northwind-security-a1b2c3d4",
    )
    assert checkout["id"].startswith("cs_test_inmem_")
    assert checkout["url"].startswith("https://checkout.stripe.com/c/pay/")

    req = transport.requests[-1]
    assert req["method"] == "POST"
    assert req["endpoint"] == "checkout/sessions"
    assert req["fields"]["mode"] == "subscription"
    assert req["fields"]["line_items[0][price]"] == "price_scale_test"
    assert req["fields"]["metadata[agency_id]"] == "northwind-security"
    assert req["fields"]["metadata[tier]"] == "Scale"
    assert req["fields"]["metadata[domain]"] == "northwind-sec.example"
    assert req["fields"]["client_reference_id"] == "northwind-security-a1b2c3d4"

    session_state = transport.sessions[checkout["id"]]
    customer_id = session_state["customer"]
    subscription_id = session_state["subscription"]

    # 2. Signed checkout.session.completed webhook -> Multi-store provisioning
    completed_event = {
        "id": "evt_deep_completed_001",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": checkout["id"],
                "customer": customer_id,
                "subscription": subscription_id,
                "client_reference_id": "northwind-security-a1b2c3d4",
                "customer_details": {
                    "email": "ops@northwind-sec.example",
                    "name": "Northwind Security",
                },
                "metadata": session_state["metadata"],
                "amount_total": 49900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }
    payload_bytes = json.dumps(completed_event).encode("utf-8")
    sig = generate_stripe_signature(payload_bytes, webhook_secret)
    prov = billing.handle_webhook(payload_bytes, sig)

    assert prov["status"] == "PROVISIONED"
    assert prov["apex_domain"] == "northwind-sec.example"
    assert prov["agency_id"] == "northwind-security"
    assert prov["stripe_customer_id"] == customer_id
    assert prov["stripe_subscription_id"] == subscription_id
    assert prov["billing_status"] == "active"

    # All artifacts live strictly under tmp_path
    sla_path = Path(prov["sla_certificate_path"])
    portal_path = Path(prov["portal_path"])
    bundle_path = Path(prov["bundle_path"])
    for artifact in (
        billing.subscribers_file,
        billing.clients_file,
        billing.retainers_file,
        sla_path,
        portal_path,
        bundle_path,
    ):
        assert artifact.is_file()
        assert artifact.resolve().is_relative_to(tmp_path.resolve())

    assert sla_path.read_bytes().startswith(b"%PDF-")
    assert hashlib.sha256(bundle_path.read_bytes()).hexdigest() == prov["bundle_sha256"]
    with zipfile.ZipFile(bundle_path, "r") as zf:
        assert zf.testzip() is None
        assert "bundle_manifest.json" in zf.namelist()

    assert "Northwind Security" in portal_path.read_text(encoding="utf-8")
    assert billing.resolve_portal_path("northwind-security") == portal_path.resolve()
    assert prov["dns_fixpack"]["domain"] == "northwind-sec.example"

    # Local event log captured deal-desk events without touching global blackboard
    event_types = [e["event_type"] for e in billing.published_events]
    assert "PORTAL_GENERATED" in event_types
    assert "CLIENT_BUNDLE_GENERATED" in event_types

    # Verify multi-store persistence on reload
    subs = billing.list_subscribers()
    assert len(subs) == 1
    assert subs[0]["status"] == "active"
    assert subs[0]["monitoring_enabled"] is True

    reloaded_fleet = FleetRegistry(data_path=billing.clients_file)
    fleet_client = reloaded_fleet.get_client("client-northwind-sec-example")
    assert fleet_client is not None
    assert fleet_client.status == "active"
    assert fleet_client.agency_id == "northwind-security"

    reloaded_retainer = AgencyRetainerManager(data_path=billing.retainers_file).get_agency("northwind-security")
    assert reloaded_retainer is not None
    assert reloaded_retainer.tier == RetainerTier.SCALE
    assert reloaded_retainer.stripe_subscription_id == subscription_id
    assert reloaded_retainer.billing_status == "active"

    # 3. Subscription lookup & tier upgrade via canonical alias ("pro" -> Enterprise)
    fetched = billing.get_subscription(subscription_id)
    assert fetched["id"] == subscription_id
    assert fetched["status"] == "active"

    upgraded = billing.update_subscription(subscription_id, "pro")
    assert upgraded["items"]["data"][0]["price"]["id"] == "price_enterprise_test"

    # 4. Payment failure -> past_due -> recovery -> active
    for ev_type, expected_status, expected_billing in (
        ("invoice.payment_failed", "PAYMENT_FAILED", "past_due"),
        ("invoice.payment_succeeded", "PAYMENT_SUCCEEDED", "active"),
    ):
        inv_bytes = json.dumps(
            {
                "id": f"evt_{ev_type}",
                "type": ev_type,
                "data": {"object": {"subscription": subscription_id, "customer": customer_id}},
            }
        ).encode("utf-8")
        inv_res = billing.handle_webhook(inv_bytes, generate_stripe_signature(inv_bytes, webhook_secret))
        assert inv_res["status"] == expected_status
        assert inv_res["billing_status"] == expected_billing
        assert AgencyRetainerManager(data_path=billing.retainers_file).get_agency(
            "northwind-security"
        ).billing_status == expected_billing

    # 5. Cancellation via Stripe API + customer.subscription.deleted webhook -> deprovisioned
    at_period_end = billing.cancel_subscription(subscription_id, cancel_at_period_end=True)
    assert at_period_end["cancel_at_period_end"] is True
    assert at_period_end["status"] == "active"

    canceled_now = billing.cancel_subscription(subscription_id, cancel_at_period_end=False)
    assert canceled_now["status"] == "canceled"

    deleted_event = {
        "id": "evt_deep_deleted_001",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": subscription_id,
                "customer": customer_id,
                "metadata": {"domain": "northwind-sec.example"},
            }
        },
    }
    del_bytes = json.dumps(deleted_event).encode("utf-8")
    del_res = billing.handle_webhook(del_bytes, generate_stripe_signature(del_bytes, webhook_secret))
    assert del_res["status"] == "DEPROVISIONED"
    assert del_res["target"] == "northwind-sec.example"

    assert billing.list_subscribers()[0]["status"] == "canceled"
    assert billing.list_subscribers()[0]["monitoring_enabled"] is False
    assert FleetRegistry(data_path=billing.clients_file).get_client(
        "client-northwind-sec-example"
    ).status == "canceled"
    assert AgencyRetainerManager(data_path=billing.retainers_file).get_agency(
        "northwind-security"
    ).billing_status == "past_due"


@pytest.mark.parametrize(
    "raw,expected_tier,expected_deal_desk",
    [
        ("starter", RetainerTier.STARTER, "monitoring"),
        ("Starter", RetainerTier.STARTER, "monitoring"),
        ("monitoring", RetainerTier.STARTER, "monitoring"),
        ("scale", RetainerTier.SCALE, "remediation"),
        ("Scale", RetainerTier.SCALE, "remediation"),
        ("growth", RetainerTier.SCALE, "remediation"),
        ("Growth", RetainerTier.SCALE, "remediation"),
        ("remediation", RetainerTier.SCALE, "remediation"),
        ("enterprise", RetainerTier.ENTERPRISE, "enterprise"),
        ("Enterprise", RetainerTier.ENTERPRISE, "enterprise"),
        ("pro", RetainerTier.ENTERPRISE, "enterprise"),
        ("Pro", RetainerTier.ENTERPRISE, "enterprise"),
    ],
)
def test_canonical_tier_alias_resolution_single_source_of_truth(
    raw: str, expected_tier: RetainerTier, expected_deal_desk: str
):
    assert resolve_retainer_tier(raw) == expected_tier
    assert resolve_retainer_tier(raw, strict=True) == expected_tier
    assert resolve_deal_desk_tier_key(raw) == expected_deal_desk
    assert get_price_id(raw, env={}) == DEFAULT_PRICE_IDS[expected_tier]

    # Invalid tier raises under strict=True and defaults to Scale otherwise
    assert resolve_retainer_tier("unknown-tier") == RetainerTier.SCALE
    with pytest.raises(ValueError, match="Invalid tier"):
        resolve_retainer_tier("unknown-tier", strict=True)


def test_no_is_pytest_active_or_duplicate_tier_tables_in_thin_adapters():
    """Guardrail verifying duplicated tier maps and test-runner branching stay deleted."""
    from orbit_security import billing_onboarding

    billing_src = Path(billing_onboarding.__file__).read_text(encoding="utf-8")
    webhook_src = Path(stripe_webhook.__file__).read_text(encoding="utf-8")
    checkout_src = Path(stripe_checkout.__file__).read_text(encoding="utf-8")
    deal_desk_src = Path(deal_desk.__file__).read_text(encoding="utf-8")

    assert "is_pytest_active" not in billing_src
    assert "is_pytest_active" not in webhook_src
    assert "tier_lookup" not in webhook_src
    assert "_TIER_ALIASES" not in checkout_src
    assert "tier_map =" not in deal_desk_src


def test_workspace_scoped_env_isolation_without_pytest_branching(tmp_path: Path, monkeypatch):
    """Workspace .env resolution is strictly scoped to workspace_root with explicit > env > .env precedence."""
    for key in ("STRIPE_WEBHOOK_SECRET", "STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_PRICE_SCALE"):
        monkeypatch.delenv(key, raising=False)

    # 1. Clean tmp_path never leaks live repo .env secrets
    clean_billing = BillingOnboarding(workspace_root=tmp_path, stripe_transport=InMemoryStripeTransport())
    assert clean_billing.webhook_secret is None
    assert clean_billing.get_price_id("growth") == DEFAULT_PRICE_IDS[RetainerTier.SCALE]

    # 2. Writing tmp_path/.env resolves workspace-scoped config
    (tmp_path / ".env").write_text(
        "STRIPE_WEBHOOK_SECRET=whsec_ws_dotenv\n"
        "STRIPE_SECRET_KEY=sk_test_ws_dotenv\n"
        "STRIPE_PRICE_SCALE=price_scale_ws_dotenv\n",
        encoding="utf-8",
    )
    ws_billing = BillingOnboarding(workspace_root=tmp_path, stripe_transport=InMemoryStripeTransport())
    assert ws_billing.webhook_secret == "whsec_ws_dotenv"
    assert ws_billing.get_price_id("growth") == "price_scale_ws_dotenv"

    # 3. os.environ beats workspace .env; explicit constructor args beat both
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_env_override")
    assert BillingOnboarding(workspace_root=tmp_path).webhook_secret == "whsec_env_override"
    assert (
        BillingOnboarding(workspace_root=tmp_path, webhook_secret="whsec_explicit").webhook_secret
        == "whsec_explicit"
    )


def test_webhook_rejects_invalid_and_expired_signatures_without_side_effects(tmp_path: Path):
    billing = BillingOnboarding(
        workspace_root=tmp_path,
        stripe_transport=InMemoryStripeTransport(),
        webhook_secret="whsec_strict_check",
    )
    body = json.dumps({"type": "checkout.session.completed", "data": {"object": {}}}).encode("utf-8")

    assert billing.handle_webhook(body, None)["status"] == "ERROR"
    assert billing.handle_webhook(body, "t=123,v1=forged")["status"] == "ERROR"
    old_sig = generate_stripe_signature(body, "whsec_strict_check", timestamp=int(time.time()) - 1000)
    assert billing.handle_webhook(body, old_sig)["status"] == "ERROR"
    assert billing.list_subscribers() == []


def test_thin_http_adapters_end_to_end_over_single_billing_module(tmp_path: Path):
    """Thin checkout + webhook HTTP handlers share one BillingOnboarding module."""
    transport = InMemoryStripeTransport()
    webhook_secret = "whsec_http_adapter_test"
    billing = BillingOnboarding(
        workspace_root=tmp_path,
        stripe_transport=transport,
        stripe_secret_key="sk_test_http_adapter",
        webhook_secret=webhook_secret,
    )

    checkout_srv = HTTPServer(("127.0.0.1", 0), make_checkout_request_handler(billing))
    webhook_srv = HTTPServer(("127.0.0.1", 0), make_webhook_request_handler(billing))
    t1 = threading.Thread(target=checkout_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=webhook_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()

    try:
        # 1. POST /create-checkout-session -> 302 redirect to Stripe
        c_conn = HTTPConnection("127.0.0.1", checkout_srv.server_port, timeout=5)
        form = urllib.parse.urlencode(
            {
                "agency_id": "harbor-ops",
                "agency_name": "Harbor Ops",
                "tier": "Growth",
                "contact_email": "ops@harbor-ops.example",
                "domain": "harbor-ops.example",
            }
        ).encode("utf-8")
        c_conn.request(
            "POST",
            "/create-checkout-session",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        c_resp = c_conn.getresponse()
        c_resp.read()
        assert c_resp.status == 302
        assert str(c_resp.getheader("Location", "")).startswith("https://checkout.stripe.com/c/pay/")
        c_conn.close()

        session_id = next(iter(transport.sessions))
        sess = transport.sessions[session_id]

        # 2. Deliver signed webhook to HTTP webhook adapter -> 200 PROVISIONED
        wh_payload = json.dumps(
            {
                "id": "evt_http_001",
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "id": session_id,
                        "customer": sess["customer"],
                        "subscription": sess["subscription"],
                        "customer_details": {"email": "ops@harbor-ops.example", "name": "Harbor Ops"},
                        "metadata": sess["metadata"],
                        "amount_total": 49900,
                        "currency": "usd",
                    }
                },
            }
        ).encode("utf-8")
        w_conn = HTTPConnection("127.0.0.1", webhook_srv.server_port, timeout=5)
        w_conn.request(
            "POST",
            "/webhook",
            body=wh_payload,
            headers={
                "Content-Type": "application/json",
                "Stripe-Signature": generate_stripe_signature(wh_payload, webhook_secret),
            },
        )
        w_resp = w_conn.getresponse()
        w_data = json.loads(w_resp.read().decode("utf-8"))
        w_conn.close()
        assert w_resp.status == 200
        assert w_data["status"] == "PROVISIONED"

        # 3. GET /portal/harbor-ops serves newly provisioned portal from tmp_path
        p_conn = HTTPConnection("127.0.0.1", checkout_srv.server_port, timeout=5)
        p_conn.request("GET", "/portal/harbor-ops")
        p_resp = p_conn.getresponse()
        p_html = p_resp.read().decode("utf-8")
        p_conn.close()
        assert p_resp.status == 200
        assert "Harbor Ops" in p_html

        # 4. Subscription lookup, alias upgrade, and cancel via checkout HTTP adapter
        sub_id = sess["subscription"]
        s_conn = HTTPConnection("127.0.0.1", checkout_srv.server_port, timeout=5)
        s_conn.request("GET", f"/subscription/{sub_id}")
        s_resp = s_conn.getresponse()
        assert s_resp.status == 200
        assert json.loads(s_resp.read().decode("utf-8"))["status"] == "active"

        s_conn.request(
            "POST",
            "/update-subscription",
            body=urllib.parse.urlencode({"subscription_id": sub_id, "new_tier": "pro"}).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        u_resp = s_conn.getresponse()
        u_data = json.loads(u_resp.read().decode("utf-8"))
        assert u_resp.status == 200
        assert u_data["status"] == "UPDATED"
        assert u_data["tier"] == "Enterprise"

        s_conn.request(
            "POST",
            "/cancel-subscription",
            body=urllib.parse.urlencode({"subscription_id": sub_id}).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        x_resp = s_conn.getresponse()
        x_data = json.loads(x_resp.read().decode("utf-8"))
        assert x_resp.status == 200
        assert x_data["status"] == "CANCELED"
        assert x_data["status_stripe"] == "canceled"
        s_conn.close()
    finally:
        checkout_srv.shutdown()
        checkout_srv.server_close()
        webhook_srv.shutdown()
        webhook_srv.server_close()
        t1.join(timeout=5)
        t2.join(timeout=5)
