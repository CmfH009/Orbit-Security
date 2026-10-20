"""Tests for the Stripe self-service checkout onboarding flow.

Covers the Act II merchant-facing half (complementing tests/test_stripe_webhook.py):

1. Tier -> Stripe Price ID mapping (env vars + placeholders).
2. Checkout Session payload construction (mode=subscription, line items,
   metadata, success/cancel URLs) with a mocked Stripe API call.
3. checkout.session.completed webhook -> AgencyRetainerManager.register_agency
   wiring: stripe_customer_id, stripe_subscription_id, billing_status="active".
4. customer.subscription.deleted / .updated -> retainer billing_status
   ("past_due" / "paused" / "active").
5. Subscription lifecycle management: get_subscription, update_subscription
   (tier change), cancel_subscription (immediate / at period end).
6. Webhook invoice.payment_succeeded / invoice.payment_failed -> retainer
   billing_status ("active" / "past_due").
7. Subscription HTTP endpoints: GET /subscription/<id>,
   POST /update-subscription, POST /cancel-subscription.
8. Signup HTTP endpoint happy path: form POST creates a Checkout Session and
   302-redirects to Stripe; /health and /signup page served.

All tests are offline: no live Stripe network calls.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.parse
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path

import pytest

from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_checkout import (
    DEFAULT_PRICE_IDS,
    STRIPE_PRICE_ENV,
    StripeCheckoutRequestHandler,
    cancel_subscription,
    create_checkout_session,
    get_price_id,
    get_subscription,
    run_checkout_server,
    update_subscription,
)
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    generate_stripe_signature,
)


class _FakeResponse:
    """urllib-like response stub: .status and .read(), context-manager friendly."""

    def __init__(self, body: bytes, status: int = 200):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


# ---------------------------------------------------------------------------
# 1. Tier -> Price mapping
# ---------------------------------------------------------------------------


def test_tier_price_mapping_uses_env_vars(monkeypatch):
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter_live_299")
    monkeypatch.setenv("STRIPE_PRICE_SCALE", "price_scale_live_499")
    monkeypatch.setenv("STRIPE_PRICE_ENTERPRISE", "price_enterprise_live_999")

    assert get_price_id(RetainerTier.STARTER) == "price_starter_live_299"
    assert get_price_id(RetainerTier.SCALE) == "price_scale_live_499"
    assert get_price_id(RetainerTier.ENTERPRISE) == "price_enterprise_live_999"


def test_tier_price_mapping_falls_back_to_placeholders(monkeypatch):
    for env_var in STRIPE_PRICE_ENV.values():
        monkeypatch.delenv(env_var, raising=False)

    assert get_price_id(RetainerTier.STARTER) == DEFAULT_PRICE_IDS[RetainerTier.STARTER]
    assert get_price_id(RetainerTier.SCALE) == DEFAULT_PRICE_IDS[RetainerTier.SCALE]
    assert get_price_id(RetainerTier.ENTERPRISE) == DEFAULT_PRICE_IDS[RetainerTier.ENTERPRISE]


# ---------------------------------------------------------------------------
# 2. Checkout Session payload construction (mocked Stripe API)
# ---------------------------------------------------------------------------


def test_create_checkout_session_payload_shape(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_open(req, timeout=30):
        captured["method"] = req.method
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = req.data.decode("utf-8") if req.data else ""
        return _FakeResponse(
            b'{"id": "cs_test_123", "url": "https://checkout.stripe.com/pay/cs_test_123"}'
        )

    session = create_checkout_session(
        agency_id="eastside-co",
        agency_name="Eastside Co",
        tier=RetainerTier.SCALE,
        contact_email="ops@eastsideco.com",
        website="https://eastsideco.com",
        support_email="ops@eastsideco.com",
        primary_color="#0B132B",
        accent_color="#48CAE4",
        tagline="Enterprise Shopify Plus Technical Solutions",
        custom_domain="security.eastsideco.com",
        http_open=fake_open,
    )

    assert session == {
        "id": "cs_test_123",
        "url": "https://checkout.stripe.com/pay/cs_test_123",
    }
    assert captured["method"] == "POST"
    assert "https://api.stripe.com/v1/checkout/sessions" in captured["url"]
    headers_lc = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers_lc["authorization"] == "Bearer sk_test_12345"
    assert headers_lc["content-type"] == "application/x-www-form-urlencoded"

    body = urllib.parse.parse_qs(captured["body"])
    assert body["mode"][0] == "subscription"
    assert body["payment_method_types[0]"][0] == "card"
    assert body["line_items[0][price]"][0] == "price_scale_499_monthly"
    assert body["line_items[0][quantity]"][0] == "1"
    assert body["customer_email"][0] == "ops@eastsideco.com"

    meta = body
    assert meta["metadata[agency_id]"][0] == "eastside-co"
    assert meta["metadata[agency_name]"][0] == "Eastside Co"
    assert meta["metadata[tier]"][0] == "Scale"
    assert meta["metadata[contact_email]"][0] == "ops@eastsideco.com"
    assert meta["metadata[support_email]"][0] == "ops@eastsideco.com"
    assert meta["metadata[website]"][0] == "https://eastsideco.com"
    assert meta["metadata[primary_color]"][0] == "#0B132B"
    assert meta["metadata[accent_color]"][0] == "#48CAE4"
    assert meta["metadata[tagline]"][0] == "Enterprise Shopify Plus Technical Solutions"
    assert meta["metadata[custom_domain]"][0] == "security.eastsideco.com"

    assert "/portal/eastside-co?session_id=" in meta["success_url"][0]
    assert "{CHECKOUT_SESSION_ID}" in meta["success_url"][0]
    assert meta["cancel_url"][0] == "http://localhost:8089/canceled"


def test_create_checkout_session_default_success_url(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_open(req, timeout=30):
        captured["body"] = req.data.decode("utf-8")
        return _FakeResponse(b'{"id": "cs_x", "url": "https://checkout.stripe.com/pay/cs_x"}')

    create_checkout_session(
        agency_id="My Agency",
        agency_name="My Agency",
        contact_email="ops@myagency.com",
        http_open=fake_open,
    )
    body = urllib.parse.parse_qs(captured["body"])
    assert body["success_url"][0] == "http://localhost:8089/portal/my-agency?session_id={CHECKOUT_SESSION_ID}"


# ---------------------------------------------------------------------------
# 3. Webhook -> AgencyRetainerManager wiring
# ---------------------------------------------------------------------------


def _build_handler(tmp_path):
    retainers_file = tmp_path / "agency_retainers.json"
    subscribers_file = tmp_path / "subscribers.json"
    clients_file = tmp_path / "clients.json"
    certs_dir = tmp_path / "certificates"

    webhook_secret = "whsec_test_orbit_key"
    sub_mgr = SubscriberManager(subscribers_file=subscribers_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)
    retainer_mgr = AgencyRetainerManager(data_path=retainers_file)

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
        retainer_manager=retainer_mgr,
    )
    return handler, retainer_mgr, retainers_file


def test_webhook_checkout_completed_registers_agency_retainer(tmp_path):
    handler, retainer_mgr, retainers_file = _build_handler(tmp_path)

    event_payload = {
        "id": "evt_checkout_success_001",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_session_001",
                "customer": "cus_test_001",
                "subscription": "sub_test_001",
                "customer_details": {
                    "email": "cto@koru-digital.com",
                    "name": "Koru Digital",
                },
                "metadata": {
                    "agency_id": "koru-digital",
                    "agency_name": "Koru Digital",
                    "tier": "Starter",
                    "contact_email": "cto@koru-digital.com",
                    "support_email": "support@koru-digital.com",
                    "website": "https://koru-digital.com",
                    "primary_color": "#0F172A",
                    "accent_color": "#2563EB",
                    "tagline": "Security for modern teams",
                    "custom_domain": "security.koru-digital.com",
                },
                "amount_total": 29900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }

    payload_bytes = json.dumps(event_payload).encode("utf-8")
    sig_header = generate_stripe_signature(payload_bytes, "whsec_test_orbit_key")

    result = handler.handle_webhook(payload_bytes, sig_header)

    assert result["status"] == "PROVISIONED"
    assert result["agency_id"] == "koru-digital"
    assert result["agency_name"] == "Koru Digital"
    assert result["stripe_customer_id"] == "cus_test_001"
    assert result["stripe_subscription_id"] == "sub_test_001"
    assert result["billing_status"] == "active"

    agency = retainer_mgr.get_agency("koru-digital")
    assert agency is not None
    assert agency.tier == RetainerTier.STARTER
    assert agency.monthly_price == 299
    assert agency.custom_domain == "security.koru-digital.com"
    assert agency.stripe_customer_id == "cus_test_001"
    assert agency.stripe_subscription_id == "sub_test_001"
    assert agency.billing_status == "active"
    assert agency.primary_color == "#0F172A"
    assert agency.accent_color == "#2563EB"
    assert agency.support_email == "support@koru-digital.com"
    assert agency.website == "https://koru-digital.com"
    assert agency.agency_tagline == "Security for modern teams"

    # Persisted to disk and reloadable
    reloaded = AgencyRetainerManager(data_path=retainers_file)
    saved = reloaded.get_agency("koru-digital")
    assert saved is not None
    assert saved.stripe_subscription_id == "sub_test_001"
    assert saved.billing_status == "active"


# ---------------------------------------------------------------------------
# 4. Subscription cancellation / pause -> retainer billing_status
# ---------------------------------------------------------------------------


def test_webhook_subscription_deleted_marks_retainer_past_due(tmp_path):
    retainers_file = tmp_path / "agency_retainers.json"
    manager = AgencyRetainerManager(data_path=retainers_file)
    agency = manager.register_agency(
        agency_id="sunset-studio",
        agency_name="Sunset Studio",
        tier=RetainerTier.SCALE,
    )
    agency.stripe_subscription_id = "sub_sunset_99"
    manager.save()

    handler = StripeWebhookHandler(retainer_manager=manager)

    event = {
        "id": "sub_sunset_99",
        "type": "customer.subscription.deleted",
        "data": {"object": {"id": "sub_sunset_99", "customer": "cus_x"}},
    }
    res = handler.handle_webhook(json.dumps(event).encode("utf-8"))
    assert res["status"] == "DEPROVISIONED"

    reloaded = AgencyRetainerManager(data_path=retainers_file)
    assert reloaded.get_agency("sunset-studio").billing_status == "past_due"


@pytest.mark.parametrize(
    "stripe_status,expected_billing",
    [
        ("active", "active"),
        ("past_due", "past_due"),
        ("paused", "paused"),
        ("canceled", "past_due"),
        ("unpaid", "past_due"),
    ],
)
def test_webhook_subscription_updated_mirrors_billing_status(
    tmp_path, stripe_status, expected_billing
):
    retainers_file = tmp_path / "agency_retainers.json"
    manager = AgencyRetainerManager(data_path=retainers_file)
    agency = manager.register_agency(
        agency_id="loop-labs", agency_name="Loop Labs", tier=RetainerTier.ENTERPRISE
    )
    agency.stripe_subscription_id = "sub_loop_1"
    manager.save()

    handler = StripeWebhookHandler(retainer_manager=manager)

    event = {
        "id": "sub_loop_1",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_loop_1",
                "status": stripe_status,
                "customer": "cus_y",
            }
        },
    }
    res = handler.handle_webhook(json.dumps(event).encode("utf-8"))
    assert res["status"] == "UPDATED"
    assert res["billing_status"] == expected_billing

    reloaded = AgencyRetainerManager(data_path=retainers_file)
    assert reloaded.get_agency("loop-labs").billing_status == expected_billing


# ---------------------------------------------------------------------------
# 6. Subscription lifecycle management (mocked Stripe API)
# ---------------------------------------------------------------------------


def test_get_subscription(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_open(req, timeout=30):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return _FakeResponse(
            b'{"id": "sub_test_123", "status": "active", "customer": "cus_x", '
            b'"current_period_start": 1000, "current_period_end": 2000, '
            b'"cancel_at_period_end": false, "metadata": {}}'
        )

    sub = get_subscription("sub_test_123", http_open=fake_open)

    assert sub["id"] == "sub_test_123"
    assert sub["status"] == "active"
    assert captured["url"] == "https://api.stripe.com/v1/subscriptions/sub_test_123"
    headers_lc = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers_lc["authorization"] == "Bearer sk_test_12345"


def test_update_subscription_changes_price(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")
    monkeypatch.setenv("STRIPE_PRICE_ENTERPRISE", "price_enterprise_live_999")

    captured = {}

    def fake_open(req, timeout=30):
        captured.setdefault("calls", []).append(
            {"url": req.full_url, "method": req.method, "body": req.data}
        )
        # First call: GET subscription -> return an item id
        if "subscriptions/" in req.full_url:
            return _FakeResponse(
                b'{"id": "sub_test_123", "items": {"data": [{"id": "si_123"}]}}'
            )
        # Second call: POST subscription item update -> return updated sub
        return _FakeResponse(b'{"id": "sub_test_123", "status": "active"}')

    result = update_subscription("sub_test_123", RetainerTier.ENTERPRISE, http_open=fake_open)

    assert result["id"] == "sub_test_123"
    assert result["status"] == "active"
    calls = captured["calls"]
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"] == "https://api.stripe.com/v1/subscriptions/sub_test_123"
    assert calls[1]["method"] == "POST"
    assert "subscription_items/si_123" in calls[1]["url"]
    body = urllib.parse.parse_qs(calls[1]["body"].decode("utf-8"))
    assert body["price"][0] == "price_enterprise_live_999"
    assert body["proration_behavior"][0] == "create_prorations"


def test_cancel_subscription_immediate(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_open(req, timeout=30):
        captured["url"] = req.full_url
        captured["body"] = req.data.decode("utf-8") if req.data else ""
        return _FakeResponse(b'{"id": "sub_test_123", "status": "canceled"}')

    result = cancel_subscription("sub_test_123", http_open=fake_open)

    assert result["id"] == "sub_test_123"
    assert result["status"] == "canceled"
    assert captured["url"] == "https://api.stripe.com/v1/subscriptions/sub_test_123/cancel"
    body = urllib.parse.parse_qs(captured["body"])
    assert "cancel_at_period_end" not in body


def test_cancel_subscription_at_period_end(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_open(req, timeout=30):
        captured["body"] = req.data.decode("utf-8") if req.data else ""
        return _FakeResponse(b'{"id": "sub_test_123", "status": "active"}')

    cancel_subscription("sub_test_123", cancel_at_period_end=True, http_open=fake_open)
    body = urllib.parse.parse_qs(captured["body"])
    assert body["cancel_at_period_end"][0] == "true"


# ---------------------------------------------------------------------------
# 7. Webhook invoice payment events -> retainer billing_status
# ---------------------------------------------------------------------------


def test_webhook_invoice_payment_succeeded_marks_retainer_active(tmp_path):
    retainers_file = tmp_path / "agency_retainers.json"
    manager = AgencyRetainerManager(data_path=retainers_file)
    agency = manager.register_agency(
        agency_id="paid-agency", agency_name="Paid Agency", tier=RetainerTier.SCALE
    )
    agency.stripe_subscription_id = "sub_paid_1"
    agency.billing_status = "past_due"
    manager.save()

    handler = StripeWebhookHandler(retainer_manager=manager)

    event = {
        "id": "evt_invoice_paid",
        "type": "invoice.payment_succeeded",
        "data": {
            "object": {
                "subscription": "sub_paid_1",
                "customer": "cus_paid",
            }
        },
    }
    res = handler.handle_webhook(json.dumps(event).encode("utf-8"))
    assert res["status"] == "PAYMENT_SUCCEEDED"
    assert res["billing_status"] == "active"

    reloaded = AgencyRetainerManager(data_path=retainers_file)
    assert reloaded.get_agency("paid-agency").billing_status == "active"


def test_webhook_invoice_payment_failed_marks_retainer_past_due(tmp_path):
    retainers_file = tmp_path / "agency_retainers.json"
    manager = AgencyRetainerManager(data_path=retainers_file)
    agency = manager.register_agency(
        agency_id="unpaid-agency", agency_name="Unpaid Agency", tier=RetainerTier.SCALE
    )
    agency.stripe_subscription_id = "sub_unpaid_1"
    agency.billing_status = "active"
    manager.save()

    handler = StripeWebhookHandler(retainer_manager=manager)

    event = {
        "id": "evt_invoice_failed",
        "type": "invoice.payment_failed",
        "data": {
            "object": {
                "subscription": "sub_unpaid_1",
                "customer": "cus_unpaid",
            }
        },
    }
    res = handler.handle_webhook(json.dumps(event).encode("utf-8"))
    assert res["status"] == "PAYMENT_FAILED"
    assert res["billing_status"] == "past_due"

    reloaded = AgencyRetainerManager(data_path=retainers_file)
    assert reloaded.get_agency("unpaid-agency").billing_status == "past_due"


# ---------------------------------------------------------------------------
# 8. Subscription HTTP endpoints happy path
# ---------------------------------------------------------------------------


def test_subscription_endpoints(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    monkeypatch.setattr(
        "orbit_security.stripe_checkout.get_subscription",
        lambda sid, http_open=None: {
            "id": sid,
            "status": "active",
            "customer": "cus_x",
            "current_period_start": 1000,
            "current_period_end": 2000,
            "cancel_at_period_end": False,
            "metadata": {},
        },
    )
    monkeypatch.setattr(
        "orbit_security.stripe_checkout.update_subscription",
        lambda sid, tier, http_open=None: {"id": sid, "status": "active"},
    )
    monkeypatch.setattr(
        "orbit_security.stripe_checkout.cancel_subscription",
        lambda sid, http_open=None, cancel_at_period_end=False: {
            "id": sid,
            "status": "canceled",
            "cancel_at_period_end": cancel_at_period_end,
        },
    )

    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), StripeCheckoutRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=10)

        # GET /subscription/sub_test_123
        conn.request("GET", "/subscription/sub_test_123")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["id"] == "sub_test_123"
        assert data["status"] == "active"

        # POST /update-subscription
        form = urllib.parse.urlencode(
            {"subscription_id": "sub_test_123", "new_tier": "Enterprise"}
        ).encode("utf-8")
        conn.request(
            "POST",
            "/update-subscription",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "UPDATED"

        # POST /cancel-subscription
        form = urllib.parse.urlencode(
            {"subscription_id": "sub_test_123", "cancel_at_period_end": "true"}
        ).encode("utf-8")
        conn.request(
            "POST",
            "/cancel-subscription",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "CANCELED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _find_free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_signup_endpoint_happy_path(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_12345")

    captured = {}

    def fake_create_checkout_session(**kwargs):
        captured["kwargs"] = kwargs
        return {"id": "cs_endpoint_1", "url": "https://checkout.stripe.com/pay/cs_endpoint_1"}

    monkeypatch.setattr(
        "orbit_security.stripe_checkout.create_checkout_session",
        fake_create_checkout_session,
    )

    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), StripeCheckoutRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # GET / serves the signup page
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        html = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "Orbit Security" in html
        assert 'name="agency_id"' in html
        assert 'name="tier"' in html

        # GET /health
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 200
        assert json.loads(resp.read().decode("utf-8"))["status"] == "healthy"

        # POST /create-checkout-session -> 302 to Stripe
        body = urllib.parse.urlencode(
            {
                "agency_id": "endpoint-agency",
                "agency_name": "Endpoint Agency",
                "tier": "Scale",
                "contact_email": "ops@endpoint.test",
                "website": "https://endpoint.test",
                "support_email": "ops@endpoint.test",
                "primary_color": "#0F172A",
                "accent_color": "#3B82F6",
                "tagline": "Test Tagline",
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        conn.request("POST", "/create-checkout-session", body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 302
        assert resp.getheader("Location") == "https://checkout.stripe.com/pay/cs_endpoint_1"

        # The handler called create_checkout_session with form-mapped args
        assert captured["kwargs"]["agency_id"] == "endpoint-agency"
        assert captured["kwargs"]["agency_name"] == "Endpoint Agency"
        assert captured["kwargs"]["tier"] == RetainerTier.SCALE
        assert captured["kwargs"]["contact_email"] == "ops@endpoint.test"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
