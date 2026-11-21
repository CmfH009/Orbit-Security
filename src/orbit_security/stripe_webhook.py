"""Orbit Security Automated Stripe Webhook Onboarding & Provisioning (stripe_webhook.py).

Thin adapter over the deep ``BillingOnboarding`` module
(``orbit_security.billing_onboarding``). Preserves public classes, functions,
HTTP webhook handler, and CLI entrypoints with zero duplicated tier tables
or test-runner runtime branching.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, Optional, Type

from orbit_security.agency_retainer import AgencyRetainerManager
from orbit_security.billing_onboarding import (
    DEFAULT_CERTIFICATES_DIR,
    DEFAULT_CLIENTS_FILE,
    DEFAULT_ENV_FILE,
    DEFAULT_STRIPE_TOLERANCE_SECONDS,
    DEFAULT_SUBSCRIBERS_FILE,
    PROJECT_ROOT,
    BillingOnboarding,
    SlaCertificateGenerator,
    SubscriberManager,
    compute_sla_crypto_hash,
    generate_stripe_signature,
    normalize_apex_domain,
    resolve_webhook_secret,
    verify_stripe_signature,
)
from orbit_security.fleet import ClientTarget, FleetRegistry

logger = logging.getLogger("orbit_security.stripe_webhook")


def _resolve_webhook_secret(
    explicit_secret: Optional[str] = None,
    *,
    env_file: Optional[Path] = None,
) -> Optional[str]:
    """Resolves Stripe webhook secret from explicit arg, env var, or target .env file."""
    target_env = Path(env_file) if env_file is not None else DEFAULT_ENV_FILE
    return resolve_webhook_secret(explicit_secret, env_file=target_env)


class StripeWebhookHandler:
    """Thin adapter delegating Stripe webhook verification and provisioning to BillingOnboarding."""

    def __init__(
        self,
        webhook_secret: Optional[str] = None,
        subscriber_manager: Optional[SubscriberManager] = None,
        sla_generator: Optional[SlaCertificateGenerator] = None,
        fleet_registry: Optional[FleetRegistry] = None,
        retainer_manager: Optional[AgencyRetainerManager] = None,
        signature_tolerance: int = DEFAULT_STRIPE_TOLERANCE_SECONDS,
        onboarding_service: Optional[Any] = None,
        deal_desk: Optional[Any] = None,
        *,
        workspace_root: Optional[Path] = None,
        billing: Optional[BillingOnboarding] = None,
    ) -> None:
        if billing is not None:
            self._billing = billing
        else:
            kwargs: Dict[str, Any] = {
                "workspace_root": workspace_root,
                "webhook_secret": webhook_secret,
                "signature_tolerance": signature_tolerance,
                "subscriber_manager": subscriber_manager,
                "sla_generator": sla_generator,
                "fleet_registry": fleet_registry,
                "retainer_manager": retainer_manager,
                "onboarding_service": onboarding_service,
                "deal_desk": deal_desk,
            }
            # Honor explicit module-level DEFAULT_ENV_FILE overrides (e.g. temp .env in tests)
            if DEFAULT_ENV_FILE != (PROJECT_ROOT / ".env"):
                kwargs["env_file"] = DEFAULT_ENV_FILE
            self._billing = BillingOnboarding(**kwargs)

    @property
    def billing(self) -> BillingOnboarding:
        return self._billing

    @property
    def webhook_secret(self) -> Optional[str]:
        return self._billing.webhook_secret

    @webhook_secret.setter
    def webhook_secret(self, value: Optional[str]) -> None:
        self._billing.webhook_secret = value

    @property
    def subscriber_mgr(self) -> SubscriberManager:
        return self._billing.subscriber_mgr

    @property
    def sla_generator(self) -> SlaCertificateGenerator:
        return self._billing.sla_generator

    @property
    def fleet_registry(self) -> FleetRegistry:
        return self._billing.fleet_registry

    @property
    def retainer_manager(self) -> AgencyRetainerManager:
        return self._billing.retainer_manager

    @property
    def signature_tolerance(self) -> int:
        return self._billing.signature_tolerance

    @property
    def onboarding_service(self) -> Optional[Any]:
        return self._billing.onboarding_service

    @property
    def deal_desk(self) -> Optional[Any]:
        return self._billing.deal_desk

    def register_client_for_monitoring(
        self,
        apex_domain: str,
        client_name: str,
        contact_email: str,
        plan: str,
        agency_id: str = "orbit-core",
    ) -> ClientTarget:
        return self._billing.register_client_for_monitoring(
            apex_domain=apex_domain,
            client_name=client_name,
            contact_email=contact_email,
            plan=plan,
            agency_id=agency_id,
        )

    def handle_webhook(
        self, payload_bytes: bytes, sig_header: Optional[str] = None
    ) -> Dict[str, Any]:
        return self._billing.handle_webhook(payload_bytes, sig_header=sig_header)


class StripeWebhookRequestHandler(BaseHTTPRequestHandler):
    """Thin HTTP Request Handler for receiving real-time Stripe webhooks."""

    handler_instance: Optional[StripeWebhookHandler] = None
    billing: Optional[BillingOnboarding] = None

    def do_POST(self):  # noqa: N802 - http.server override naming
        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)
        sig_header = self.headers.get("Stripe-Signature")

        if self.billing is not None:
            result = self.billing.handle_webhook(payload, sig_header)
        else:
            handler = self.handler_instance or StripeWebhookHandler()
            result = handler.handle_webhook(payload, sig_header)

        status = 400 if result.get("status") == "ERROR" else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def do_GET(self):  # noqa: N802 - http.server override naming
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "status": "HEALTHY",
            "service": "Orbit Stripe Webhook Sentinel",
            "timestamp": time.time(),
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def log_message(self, format, *args):
        pass


def make_webhook_request_handler(
    billing: BillingOnboarding,
) -> Type[StripeWebhookRequestHandler]:
    """Bind a BillingOnboarding instance to a thin StripeWebhookRequestHandler class."""

    class _BoundWebhookHandler(StripeWebhookRequestHandler):
        pass

    _BoundWebhookHandler.billing = billing
    return _BoundWebhookHandler


def run_webhook_server(
    host: str = "127.0.0.1",
    port: int = 8088,
    *,
    billing: Optional[BillingOnboarding] = None,
):
    """Starts the standalone Stripe webhook HTTP server."""
    bound_billing = billing if billing is not None else BillingOnboarding(workspace_root=PROJECT_ROOT)
    handler_cls = make_webhook_request_handler(bound_billing)
    server_address = (host, port)
    httpd = HTTPServer(server_address, handler_cls)
    logger.info("Orbit Stripe Webhook Server listening on %s:%d...", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Stripe Webhook Server...")
        httpd.server_close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Orbit Security Stripe Webhook Server")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
    run_webhook_server(host=args.host, port=args.port)
