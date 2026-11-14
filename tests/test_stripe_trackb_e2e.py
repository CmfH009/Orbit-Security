"""Hermetic End-to-End Dry-Run Integration Tests for Track B Funnel.

Verifies the complete self-serve Track B funnel without live Stripe charges
and with zero mutations to live data/* or docs/portals/*:

1. Landing/Signup self-serve CTA + Checkout HTTP server (`POST /create-checkout-session`)
   with tier alias resolution (`Growth` -> `RetainerTier.SCALE`) and validation.
2. Signed `checkout.session.completed` webhook event -> isolated subscriber JSON,
   isolated Fleet client registration (`agency_id` preserved), isolated cryptographic
   SLA PDF certificate, active `AgencyRetainer` record, isolated Fixpack ZIP + SHA-256
   verification, and white-label HTML portal artifact generation.
3. Checkout server `/portal/<agency_id>` serving both hyphenated and underscored
   portal filenames (`velvet-craft-e2e` -> `velvet_craft_e2e.html`).
4. `ClientBundleExporter.export_dns_fixpack` producing an isolated DNS Fixpack ZIP
   in `tmp_path` (`is_safe_host` mocked for offline `.test` domain).
5. Default-constructed Track B runtime paths stay hermetic under pytest, and
   `scripts/run_stripe_webhook.py` CLI `--test-event` runs strictly hermetically.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
import urllib.parse
import zipfile
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from orbit_security import stripe_checkout
from orbit_security.agency_retainer import (
    AgencyPortalRenderer,
    AgencyRetainer,
    AgencyRetainerManager,
    RetainerTier,
)
from orbit_security.client_bundle_exporter import ClientBundleExporter
from orbit_security.deal_desk import RetainerDealDeskConcierge
from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_checkout import (
    DEFAULT_PRICE_IDS,
    StripeCheckoutRequestHandler,
)
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    generate_stripe_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class _FakeStripeResponse:
    """Minimal urlopen response stub."""

    def __init__(self, body: Dict[str, Any], status: int = 200):
        self.status = status
        self._raw = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> "_FakeStripeResponse":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


def _snapshot_files(paths: List[Path]) -> Dict[Path, Optional[Tuple[int, bytes]]]:
    """Capture (mtime_ns, raw_bytes) so tests prove zero mutations to live data."""
    snap: Dict[Path, Optional[Tuple[int, bytes]]] = {}
    for p in paths:
        if p.exists():
            snap[p] = (p.stat().st_mtime_ns, p.read_bytes())
        else:
            snap[p] = None
    return snap


def test_trackb_full_self_serve_funnel_hermetic_e2e(tmp_path: Path, monkeypatch):
    live_targets = [
        REPO_ROOT / "data" / "subscribers.json",
        REPO_ROOT / "data" / "clients.json",
        REPO_ROOT / "data" / "agency_retainers.json",
        REPO_ROOT / "docs" / "portals" / "velvet_craft_e2e.html",
        REPO_ROOT / "landing" / "portals" / "velvet_craft_e2e.html",
    ]
    before_live = _snapshot_files(live_targets)

    isolated_portals = tmp_path / "portals"
    isolated_bundles = tmp_path / "client_bundles"
    isolated_portals.mkdir(parents=True, exist_ok=True)
    isolated_bundles.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_trackb_e2e")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_trackb_e2e")
    for env_key in stripe_checkout.STRIPE_PRICE_ENV.values():
        monkeypatch.delenv(env_key, raising=False)
    monkeypatch.setattr(stripe_checkout, "PORTALS_DIR", isolated_portals)

    captured_stripe_calls: List[Dict[str, Any]] = []

    def fake_urlopen(req, timeout=30):  # noqa: ARG001
        raw_data = req.data.decode("utf-8") if req.data else ""
        parsed = urllib.parse.parse_qs(raw_data)
        captured_stripe_calls.append({"url": req.full_url, "fields": parsed})
        return _FakeStripeResponse(
            {
                "id": "cs_test_trackb_e2e",
                "url": "https://checkout.stripe.com/c/pay/cs_test_trackb_e2e",
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    httpd = HTTPServer(("127.0.0.1", 0), StripeCheckoutRequestHandler)
    port = httpd.server_port
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        # 1. Serve signup + safe static assets; block traversal outside landing/docs
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/signup.html")
        signup_resp = conn.getresponse()
        signup_html = signup_resp.read().decode("utf-8")
        assert signup_resp.status == 200
        assert "/create-checkout-session" in signup_html
        conn.close()

        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/assets/styles.min.css")
        css_resp = conn.getresponse()
        css_resp.read()
        assert css_resp.status == 200
        conn.close()

        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/assets/../../ROADMAP.md")
        traversal_resp = conn.getresponse()
        traversal_resp.read()
        assert traversal_resp.status in (400, 403, 404)
        conn.close()

        # 2. Reject missing contact_email on checkout POST
        bad_form = urllib.parse.urlencode(
            {"agency_id": "velvet-craft-e2e", "agency_name": "Velvet Craft E2E"}
        )
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/create-checkout-session",
            body=bad_form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        bad_resp = conn.getresponse()
        bad_body = bad_resp.read().decode("utf-8")
        assert bad_resp.status == 400
        assert "contact_email" in bad_body
        conn.close()

        # 3. Happy-path self-serve checkout submission with UI tier alias "Growth"
        form_body = urllib.parse.urlencode(
            {
                "agency_id": "velvet-craft-e2e",
                "agency_name": "Velvet Craft E2E",
                "contact_email": "security@velvetcraft.test",
                "website": "https://velvetcraft.test",
                "domain": "velvetcraft.test",
                "tier": "Growth",
                "custom_domain": "security.velvetcraft.test",
                "support_email": "security@velvetcraft.test",
                "tagline": "Continuous Perimeter Protection",
                "primary_color": "#0B132B",
                "accent_color": "#10B981",
            }
        )
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/create-checkout-session",
            body=form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        checkout_resp = conn.getresponse()
        checkout_resp.read()
        assert checkout_resp.status == 302
        assert (
            checkout_resp.getheader("Location")
            == "https://checkout.stripe.com/c/pay/cs_test_trackb_e2e"
        )
        conn.close()

        assert len(captured_stripe_calls) == 1
        stripe_fields = captured_stripe_calls[0]["fields"]
        assert stripe_fields["mode"] == ["subscription"]
        assert stripe_fields["line_items[0][price]"] == [
            DEFAULT_PRICE_IDS[RetainerTier.SCALE]
        ]
        assert stripe_fields["client_reference_id"] == ["velvet-craft-e2e"]
        assert stripe_fields["metadata[agency_id]"] == ["velvet-craft-e2e"]
        assert stripe_fields["metadata[tier]"] == ["Scale"]
        assert stripe_fields["metadata[domain]"] == ["velvetcraft.test"]

        # 4. Deliver signed checkout.session.completed webhook to isolated stores
        webhook_event = {
            "id": "evt_trackb_e2e_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_trackb_e2e",
                    "customer": "cus_trackb_e2e",
                    "subscription": "sub_trackb_e2e",
                    "customer_details": {
                        "email": "security@velvetcraft.test",
                        "name": "Velvet Craft E2E",
                    },
                    "metadata": {
                        "agency_id": stripe_fields["metadata[agency_id]"][0],
                        "agency_name": stripe_fields["metadata[agency_name]"][0],
                        "tier": stripe_fields["metadata[tier]"][0],
                        "domain": stripe_fields["metadata[domain]"][0],
                        "website": stripe_fields["metadata[website]"][0],
                        "support_email": stripe_fields["metadata[support_email]"][0],
                        "custom_domain": stripe_fields["metadata[custom_domain]"][0],
                        "tagline": stripe_fields["metadata[tagline]"][0],
                        "primary_color": stripe_fields["metadata[primary_color]"][0],
                        "accent_color": stripe_fields["metadata[accent_color]"][0],
                    },
                    "amount_total": 5900,
                    "currency": "usd",
                    "payment_status": "paid",
                }
            },
        }
        payload_bytes = json.dumps(webhook_event).encode("utf-8")
        sig_header = generate_stripe_signature(payload_bytes, "whsec_test_trackb_e2e")

        subs_file = tmp_path / "subscribers.json"
        certs_dir = tmp_path / "certificates"
        clients_file = tmp_path / "clients.json"
        retainers_file = tmp_path / "agency_retainers.json"

        sub_mgr = SubscriberManager(subscribers_file=subs_file)
        sla_gen = SlaCertificateGenerator(output_dir=certs_dir)
        fleet_reg = FleetRegistry(data_path=clients_file)
        retainer_mgr = AgencyRetainerManager(data_path=retainers_file)
        deal_desk = RetainerDealDeskConcierge(
            workspace_root=tmp_path,
            portals_dir=isolated_portals,
            bundles_dir=isolated_bundles,
        )

        webhook_handler = StripeWebhookHandler(
            webhook_secret="whsec_test_trackb_e2e",
            subscriber_manager=sub_mgr,
            sla_generator=sla_gen,
            fleet_registry=fleet_reg,
            retainer_manager=retainer_mgr,
            deal_desk=deal_desk,
        )
        result = webhook_handler.handle_webhook(payload_bytes, sig_header)

        assert result["status"] == "PROVISIONED"
        assert result["agency_id"] == "velvet-craft-e2e"

        # Isolated subscriber + SLA cert PDF + Fleet client + AgencyRetainer
        subs = json.loads(subs_file.read_text(encoding="utf-8"))
        assert len(subs) == 1
        assert subs[0]["apex_domain"] == "velvetcraft.test"
        assert subs[0]["customer_email"] == "security@velvetcraft.test"
        sla_path = Path(result["sla_certificate_path"])
        assert sla_path.is_relative_to(tmp_path)
        assert sla_path.read_bytes().startswith(b"%PDF")

        reloaded_clients = FleetRegistry(data_path=clients_file).list_active()
        matched_clients = [
            c for c in reloaded_clients if c.apex_domain == "velvetcraft.test"
        ]
        assert len(matched_clients) == 1
        assert matched_clients[0].agency_id == "velvet-craft-e2e"

        reloaded_retainer = AgencyRetainerManager(data_path=retainers_file).get_agency(
            "velvet-craft-e2e"
        )
        assert reloaded_retainer is not None
        assert reloaded_retainer.billing_status == "active"
        assert reloaded_retainer.stripe_subscription_id == "sub_trackb_e2e"

        # Isolated white-label Fixpack ZIP + SHA-256 verification
        bundle_path = Path(result["bundle_path"])
        assert bundle_path.is_relative_to(tmp_path)
        assert bundle_path.exists()
        actual_sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        assert result["bundle_sha256"] == actual_sha256
        with zipfile.ZipFile(bundle_path, "r") as zf:
            members = zf.namelist()
            assert "bundle_manifest.json" in members
            assert any(name.endswith(".tf") for name in members)

        # Isolated Portal HTML artifact + Checkout server `/portal/<slug>` resolution
        portal_path = Path(result["portal_path"])
        assert portal_path.is_relative_to(isolated_portals)
        assert portal_path.name == "velvet_craft_e2e.html"
        portal_html = portal_path.read_text(encoding="utf-8")
        assert "Velvet Craft E2E" in portal_html

        for route in ("/portal/velvet-craft-e2e", "/portal/velvet_craft_e2e"):
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", route)
            p_resp = conn.getresponse()
            p_body = p_resp.read().decode("utf-8")
            conn.close()
            assert p_resp.status == 200
            assert "Velvet Craft E2E" in p_body

        # 5. Direct self-serve DNS Fixpack export in isolated workspace
        monkeypatch.setattr("orbit_security.scanner.is_safe_host", lambda _host: True)
        exporter = ClientBundleExporter(workspace_root=tmp_path)
        fixpack = exporter.export_dns_fixpack(
            domain="velvetcraft.test",
            contact_email="security@velvetcraft.test",
            as_dict=True,
        )
        assert fixpack["ok"] is True
        fixpack_zip = Path(fixpack["fixpack_path"])
        assert fixpack_zip.is_relative_to(tmp_path)
        assert fixpack_zip.exists()
        with zipfile.ZipFile(fixpack_zip, "r") as zf:
            assert "fixpack_manifest.json" in zf.namelist()
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert _snapshot_files(live_targets) == before_live


def test_trackb_pytest_runtime_isolation_for_default_constructors(tmp_path: Path, monkeypatch):
    live_targets = [
        REPO_ROOT / "data" / "subscribers.json",
        REPO_ROOT / "data" / "clients.json",
        REPO_ROOT / "data" / "agency_retainers.json",
        REPO_ROOT / "docs" / "portals" / "iso_check_agency.html",
        REPO_ROOT / "landing" / "portals" / "iso_check_agency.html",
    ]
    before_live = _snapshot_files(live_targets)

    test_root = tmp_path / "isolated_runtime"
    test_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(test_root))

    sub_mgr = SubscriberManager()
    sla_gen = SlaCertificateGenerator()
    exporter = ClientBundleExporter()

    sla_dir = getattr(sla_gen, "output_dir", getattr(sla_gen, "certificates_dir", None))
    assert sla_dir is not None
    assert sub_mgr.subscribers_file.resolve().is_relative_to(test_root.resolve())
    assert Path(sla_dir).resolve().is_relative_to(test_root.resolve())
    assert exporter.bundles_dir.resolve().is_relative_to(test_root.resolve())

    sample_agency = AgencyRetainer(
        agency_id="iso_check_agency",
        agency_name="Iso Check Agency",
        tier=RetainerTier.STARTER,
    )
    saved_portal, landing_portal = AgencyPortalRenderer.save_portal(sample_agency)
    assert saved_portal.resolve().is_relative_to(test_root.resolve())
    assert saved_portal.exists()
    assert landing_portal is None

    # Ensure batch provisioning with no explicit dirs never mutates docs/ or landing/
    batch_mgr = AgencyRetainerManager()
    batch_mgr.agencies["iso_check_agency"] = sample_agency
    prov_summary = AgencyPortalRenderer.provision_all_enrolled_portals(
        manager=batch_mgr,
    )
    assert prov_summary["provisioned_count"] >= 1
    assert "iso_check_agency" in prov_summary["agency_ids"]
    assert Path(prov_summary["docs_dir"]).resolve().is_relative_to(test_root.resolve())
    assert Path(prov_summary["landing_dir"]).resolve().is_relative_to(test_root.resolve())

    assert _snapshot_files(live_targets) == before_live


def test_run_stripe_webhook_cli_test_event_is_hermetic(tmp_path: Path):
    live_targets = [
        REPO_ROOT / "data" / "subscribers.json",
        REPO_ROOT / "data" / "clients.json",
        REPO_ROOT / "data" / "agency_retainers.json",
        REPO_ROOT / "docs" / "portals" / "velvet_craft_apparel.html",
    ]
    before_live = _snapshot_files(live_targets)

    script_path = REPO_ROOT / "scripts" / "run_stripe_webhook.py"
    spec = importlib.util.spec_from_file_location("run_stripe_webhook_mod", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_stripe_webhook_mod"] = mod
    spec.loader.exec_module(mod)

    cli_out = tmp_path / "webhook_cli_dryrun"
    result = mod.dispatch_test_event(output_dir=cli_out, live=False)
    assert result["status"] == "PROVISIONED"
    assert Path(result["portal_path"]).resolve().is_relative_to(cli_out.resolve())
    assert Path(result["bundle_path"]).resolve().is_relative_to(cli_out.resolve())
    assert (cli_out / "subscribers.json").exists()
    assert (cli_out / "clients.json").exists()
    assert (cli_out / "agency_retainers.json").exists()

    assert _snapshot_files(live_targets) == before_live
