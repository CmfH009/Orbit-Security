"""Orbit Security Stripe Self-Service Checkout & Signup Server.

Thin HTTP and function adapter over the deep ``BillingOnboarding`` module
(``orbit_security.billing_onboarding``). Preserves existing public entrypoints,
CLI flags, and stdlib ``http.server`` signup/portal/subscription routes.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
from pathlib import Path
import re
from typing import Any, Callable, Dict, Optional, Type
import urllib.parse

from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
from orbit_security.billing_onboarding import (
    DEFAULT_PRICE_IDS,
    PROJECT_ROOT,
    STRIPE_API_BASE,
    STRIPE_PRICE_ENV,
    BillingOnboarding,
    UrllibStripeTransport,
    get_price_id,
    resolve_retainer_tier,
)

logger = logging.getLogger("orbit_security.stripe_checkout")

SIGNUP_HTML_PATH = PROJECT_ROOT / "landing" / "signup.html"
PORTALS_DIR = PROJECT_ROOT / "docs" / "portals"
LANDING_PORTALS_DIR = PROJECT_ROOT / "landing" / "portals"
LANDING_ASSETS_DIR = PROJECT_ROOT / "landing" / "assets"

# Preserve private alias for any callers importing it directly
_resolve_retainer_tier = resolve_retainer_tier


def _build_default_billing(http_open: Optional[Callable[..., Any]] = None) -> BillingOnboarding:
    """Create a request-scoped BillingOnboarding delegating to process env + urllib."""
    return BillingOnboarding(
        stripe_transport=UrllibStripeTransport(http_open=http_open),
        env_file=None,
    )


def create_checkout_session(
    *,
    agency_id: str,
    agency_name: str,
    tier: RetainerTier = RetainerTier.SCALE,
    contact_email: str,
    website: str = "https://example.com",
    support_email: str = "ops@example.com",
    primary_color: str = "#0F172A",
    accent_color: str = "#3B82F6",
    tagline: str = "Managed Web & Security Operations",
    custom_domain: Optional[str] = None,
    domain: Optional[str] = None,
    client_reference_id: Optional[str] = None,
    success_url: Optional[str] = None,
    cancel_url: Optional[str] = None,
    http_open: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Create a Stripe Checkout Session (mode=subscription) for agency signup."""
    return _build_default_billing(http_open=http_open).create_checkout_session(
        agency_id=agency_id,
        agency_name=agency_name,
        tier=tier,
        contact_email=contact_email,
        website=website,
        support_email=support_email,
        primary_color=primary_color,
        accent_color=accent_color,
        tagline=tagline,
        custom_domain=custom_domain,
        domain=domain,
        client_reference_id=client_reference_id,
        success_url=success_url,
        cancel_url=cancel_url,
    )


def get_subscription(
    subscription_id: str, http_open: Optional[Callable[..., Any]] = None
) -> Dict[str, Any]:
    """Retrieve a Stripe Subscription by id."""
    return _build_default_billing(http_open=http_open).get_subscription(subscription_id)


def update_subscription(
    subscription_id: str,
    new_tier: RetainerTier,
    http_open: Optional[Callable[..., Any]] = None,
    proration_behavior: str = "create_prorations",
) -> Dict[str, Any]:
    """Change a subscription's plan to a new retainer tier."""
    return _build_default_billing(http_open=http_open).update_subscription(
        subscription_id,
        new_tier,
        proration_behavior=proration_behavior,
    )


def cancel_subscription(
    subscription_id: str,
    http_open: Optional[Callable[..., Any]] = None,
    cancel_at_period_end: bool = False,
) -> Dict[str, Any]:
    """Cancel a Stripe Subscription immediately or at period end."""
    return _build_default_billing(http_open=http_open).cancel_subscription(
        subscription_id,
        cancel_at_period_end=cancel_at_period_end,
    )


class StripeCheckoutRequestHandler(BaseHTTPRequestHandler):
    """Thin HTTP adapter serving /signup, /portal/<id>, and subscription endpoints."""

    billing: Optional[BillingOnboarding] = None

    def do_GET(self):  # noqa: N802 - http.server override naming
        path = self.path.split("?", 1)[0]
        if path in ("/", "/signup", "/signup.html"):
            self._serve_signup_page()
        elif path.startswith("/assets/"):
            self._serve_asset(path[len("/assets/") :])
        elif path.startswith("/portal/"):
            agency_id = path[len("/portal/") :]
            self._serve_portal(agency_id)
        elif path == "/canceled":
            self._send_text(
                200,
                "<h1>Checkout cancelled</h1><p>No subscription was created. "
                '<a href="/signup">Try again</a>.</p>',
                "text/html",
            )
        elif path == "/health":
            self._send_json(
                200, {"status": "healthy", "service": "orbit-stripe-checkout"}
            )
        elif path.startswith("/subscription/"):
            subscription_id = path[len("/subscription/") :]
            self._serve_subscription(subscription_id)
        else:
            self._send_text(404, "Not found", "text/plain")

    def do_POST(self):  # noqa: N802 - http.server override naming
        path = self.path.split("?", 1)[0]
        if path == "/create-checkout-session":
            self._handle_create_checkout_session()
        elif path == "/update-subscription":
            self._handle_update_subscription()
        elif path == "/cancel-subscription":
            self._handle_cancel_subscription()
        else:
            self._send_text(404, "Not found", "text/plain")

    def _read_form(self) -> Dict[str, str]:
        """Read and parse a URL-encoded or JSON request body into a dict of str values."""
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        content_type = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in content_type and raw.strip():
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, dict):
                return {str(k): ("" if v is None else str(v)) for k, v in payload.items()}
        form = urllib.parse.parse_qs(raw.decode("utf-8"))
        return {k: (v[0] if v else "") for k, v in form.items()}

    def _handle_create_checkout_session(self):
        try:
            form = self._read_form()

            def get(name: str) -> str:
                return form.get(name, "").strip()

            contact_email = get("contact_email")
            if not contact_email:
                self._send_text(
                    400,
                    "<h1>Missing required field</h1><p>contact_email is required.</p>"
                    "<p><a href='/signup'>Back to Onboarding</a></p>",
                    "text/html",
                )
                return

            agency_id = get("agency_id") or get("agency_name") or "new-agency"
            agency_name = get("agency_name") or agency_id
            tier = resolve_retainer_tier(get("tier"))

            kwargs = dict(
                agency_id=agency_id,
                agency_name=agency_name,
                tier=tier,
                contact_email=contact_email,
                website=get("website") or "https://example.com",
                support_email=get("support_email") or contact_email or "ops@example.com",
                primary_color=get("primary_color") or "#0F172A",
                accent_color=get("accent_color") or "#3B82F6",
                tagline=get("tagline") or "Managed Web & Security Operations",
                custom_domain=get("custom_domain") or None,
                domain=get("domain") or None,
                client_reference_id=get("client_reference_id") or agency_id,
            )
            if self.billing is not None:
                session = self.billing.create_checkout_session(**kwargs)
            else:
                session = create_checkout_session(**kwargs)

            checkout_url = session.get("url")
            if not checkout_url:
                raise RuntimeError("Stripe session missing checkout URL")

            self.send_response(302)
            self.send_header("Location", str(checkout_url))
            self.end_headers()
            logger.info(
                "Redirecting agency %s to Stripe Checkout: %s", agency_id, checkout_url
            )
        except Exception as exc:  # noqa: BLE001 - surface Stripe errors plainly
            logger.exception("Checkout session creation failed: %s", exc)
            self._send_text(
                502,
                "<h1>Checkout temporarily unavailable</h1><p>Unable to initialize Stripe checkout session. Please try again later.</p>"
                "<p><a href='/signup'>Back to Onboarding</a></p>",
                "text/html",
            )

    def _handle_update_subscription(self):
        try:
            form = self._read_form()
            subscription_id = form.get("subscription_id", "").strip()
            new_tier_str = form.get("new_tier", "").strip()
            if not subscription_id:
                raise RuntimeError("subscription_id is required")
            try:
                new_tier = resolve_retainer_tier(new_tier_str, strict=True)
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc

            if self.billing is not None:
                result = self.billing.update_subscription(subscription_id, new_tier)
            else:
                result = update_subscription(subscription_id, new_tier)
            self._send_json(
                200,
                {
                    "status": "UPDATED",
                    "subscription_id": result.get("id"),
                    "status_stripe": result.get("status"),
                    "tier": new_tier.value,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Subscription update failed")
            self._send_json(502, {"status": "ERROR", "message": str(exc)})

    def _handle_cancel_subscription(self):
        try:
            form = self._read_form()
            subscription_id = form.get("subscription_id", "").strip()
            cancel_at_period_end = form.get("cancel_at_period_end", "").lower() in (
                "true",
                "1",
                "yes",
            )
            if not subscription_id:
                raise RuntimeError("subscription_id is required")

            if self.billing is not None:
                result = self.billing.cancel_subscription(
                    subscription_id, cancel_at_period_end=cancel_at_period_end
                )
            else:
                result = cancel_subscription(
                    subscription_id, cancel_at_period_end=cancel_at_period_end
                )
            self._send_json(
                200,
                {
                    "status": "CANCELED",
                    "subscription_id": result.get("id"),
                    "status_stripe": result.get("status"),
                    "cancel_at_period_end": result.get("cancel_at_period_end"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Subscription cancellation failed")
            self._send_json(502, {"status": "ERROR", "message": str(exc)})

    def _serve_subscription(self, subscription_id: str):
        try:
            if self.billing is not None:
                sub = self.billing.get_subscription(subscription_id)
            else:
                sub = get_subscription(subscription_id)
            self._send_json(
                200,
                {
                    "id": sub.get("id"),
                    "status": sub.get("status"),
                    "customer": sub.get("customer"),
                    "current_period_start": sub.get("current_period_start"),
                    "current_period_end": sub.get("current_period_end"),
                    "cancel_at_period_end": sub.get("cancel_at_period_end"),
                    "metadata": sub.get("metadata", {}),
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Subscription lookup failed")
            self._send_json(502, {"status": "ERROR", "message": str(exc)})

    def _serve_signup_page(self):
        signup_path = (
            self.billing.signup_html_path
            if self.billing is not None and self.billing.signup_html_path.is_file()
            else SIGNUP_HTML_PATH
        )
        try:
            html_body = signup_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._send_text(500, "signup.html not found on server", "text/html")
            return
        self._send_text(200, html_body, "text/html")

    def _serve_asset(self, rel_asset: str):
        clean_rel = (rel_asset or "").lstrip("/")
        if not clean_rel or ".." in clean_rel or "\\" in clean_rel:
            self._send_text(400, "Invalid asset path", "text/plain")
            return
        assets_dir = (
            self.billing.landing_assets_dir
            if self.billing is not None and self.billing.landing_assets_dir.is_dir()
            else LANDING_ASSETS_DIR
        )
        asset_path = (assets_dir / clean_rel).resolve()
        try:
            if not asset_path.is_relative_to(assets_dir.resolve()):
                self._send_text(403, "Access denied", "text/plain")
                return
        except (ValueError, AttributeError):
            self._send_text(403, "Access denied", "text/plain")
            return
        if not asset_path.is_file():
            self._send_text(404, "Asset not found", "text/plain")
            return
        ext = asset_path.suffix.lower()
        mime_map = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".woff2": "font/woff2",
            ".json": "application/json",
        }
        data = asset_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_map.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_portal(self, agency_id: str):
        if not re.match(r"^[a-zA-Z0-9_-]+$", agency_id):
            self._send_text(400, "Invalid portal identifier", "text/plain")
            return

        if self.billing is not None:
            portal_path = self.billing.resolve_portal_path(agency_id)
            if portal_path is not None:
                self._send_text(200, portal_path.read_text(encoding="utf-8"), "text/html")
                return
        else:
            slug_candidates = []
            for candidate in (
                f"{agency_id}.html",
                f"{agency_id.replace('-', '_')}.html",
                f"{agency_id.replace('_', '-')}.html",
            ):
                if candidate not in slug_candidates:
                    slug_candidates.append(candidate)

            search_dirs = [PORTALS_DIR]
            default_docs_portals = (PROJECT_ROOT / "docs" / "portals").resolve()
            if PORTALS_DIR.resolve() == default_docs_portals and LANDING_PORTALS_DIR.is_dir():
                search_dirs.append(LANDING_PORTALS_DIR)

            for base_dir in search_dirs:
                resolved_base = base_dir.resolve()
                for filename in slug_candidates:
                    portal_path = (base_dir / filename).resolve()
                    try:
                        if not portal_path.is_relative_to(resolved_base):
                            self._send_text(403, "Access denied", "text/plain")
                            return
                    except (ValueError, AttributeError):
                        self._send_text(403, "Access denied", "text/plain")
                        return
                    if portal_path.exists():
                        self._send_text(200, portal_path.read_text(encoding="utf-8"), "text/html")
                        return

        self._send_text(
            404,
            "<h1>Portal not ready</h1><p>Your white-label portal is being "
            "generated after payment. Refresh shortly or contact support.</p>",
            "text/html",
        )

    def _send_text(self, status: int, body: str, content_type: str):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, status: int, payload: Dict[str, Any]):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


def make_checkout_request_handler(
    billing: BillingOnboarding,
) -> Type[StripeCheckoutRequestHandler]:
    """Bind a BillingOnboarding instance to a thin StripeCheckoutRequestHandler class."""

    class _BoundCheckoutHandler(StripeCheckoutRequestHandler):
        pass

    _BoundCheckoutHandler.billing = billing
    return _BoundCheckoutHandler


def run_checkout_server(
    host: str = "127.0.0.1",
    port: int = 8089,
    *,
    billing: Optional[BillingOnboarding] = None,
):
    """Starts the standalone Stripe checkout signup HTTP server."""
    bound_billing = billing if billing is not None else BillingOnboarding(workspace_root=PROJECT_ROOT)
    handler_cls = make_checkout_request_handler(bound_billing)
    server_address = (host, port)
    httpd = HTTPServer(server_address, handler_cls)
    logger.info("Orbit Stripe Checkout server listening on %s:%d ...", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Orbit Stripe Checkout server...")
        httpd.server_close()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Orbit Stripe Checkout Signup Server"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8089, help="Port to listen on (default: 8089)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [STRIPE-CHECKOUT] %(message)s",
        datefmt="%H:%M:%S",
    )
    run_checkout_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
