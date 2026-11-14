"""Orbit Security Stripe Self-Service Checkout & Signup Server.

Act II Inbound Automation - the merchant-facing half of Stripe onboarding:

- Maps ``RetainerTier`` to Stripe Price IDs (env-configurable).
- Creates Stripe Checkout Sessions (``mode=subscription``) for agency signup.
- Hosts a tiny stdlib ``http.server`` that serves the signup page, accepts
  form POSTs, creates the Checkout Session, and 302-redirects the browser to
  Stripe. Routes ``/portal/<agency_id>`` to the generated white-label portal
  (``docs/portals/<slug>.html``) for the post-payment success redirect.

No external web framework: stdlib ``http.server`` + ``urllib`` only.
"""

from __future__ import annotations

import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
import urllib.error
import urllib.parse
import urllib.request

from dotenv import load_dotenv

from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier

logger = logging.getLogger("orbit_security.stripe_checkout")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")

STRIPE_API_BASE = "https://api.stripe.com/v1"

# Env var -> RetainerTier mapping for monthly Stripe Price IDs.
# Create these prices in Stripe Dashboard (Products > Prices):
#   Starter $299/mo, Scale $499/mo, Enterprise $999/mo.
STRIPE_PRICE_ENV: Dict[RetainerTier, str] = {
    RetainerTier.STARTER: "STRIPE_PRICE_STARTER",
    RetainerTier.SCALE: "STRIPE_PRICE_SCALE",
    RetainerTier.ENTERPRISE: "STRIPE_PRICE_ENTERPRISE",
}

# Fallback placeholder price IDs used when env vars are unset (dev only;
# live checkout requires real Stripe Price IDs).
DEFAULT_PRICE_IDS: Dict[RetainerTier, str] = {
    RetainerTier.STARTER: "price_starter_299_monthly",
    RetainerTier.SCALE: "price_scale_499_monthly",
    RetainerTier.ENTERPRISE: "price_enterprise_999_monthly",
}

# ---------------------------------------------------------------------------
# Tier -> Price mapping
# ---------------------------------------------------------------------------


def get_price_id(tier: RetainerTier) -> str:
    """Resolve the Stripe Price ID for a retainer tier.

    Reads STRIPE_PRICE_STARTER / STRIPE_PRICE_SCALE / STRIPE_PRICE_ENTERPRISE
    from the environment; falls back to a tier-derived placeholder so the
    payload shape can be validated offline without a live Stripe account.
    """
    env_var = STRIPE_PRICE_ENV[tier]
    price_id = os.getenv(env_var)
    if price_id:
        return price_id
    return DEFAULT_PRICE_IDS[tier]


def _stripe_secret_key() -> str:
    api_key = os.getenv("STRIPE_SECRET_KEY") or os.getenv("STRIPE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "STRIPE_SECRET_KEY (or STRIPE_API_KEY) is not set. "
            "Add it to .env (see .env.example)."
        )
    return api_key


# ---------------------------------------------------------------------------
# Checkout Session creation
# ---------------------------------------------------------------------------


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
    http_open: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Create a Stripe Checkout Session (mode=subscription) for agency signup.

    Returns a dict with at least ``{"id", "url"}`` of the checkout session.
    Raises ``RuntimeError`` on Stripe API failure.

    ``http_open`` optionally replaces ``urllib.request.urlopen`` for tests
    (must accept ``(request, timeout=...)`` and return a response-like object
    with ``.status`` and ``.read()``).
    """
    price_id = get_price_id(tier)

    base_url = os.getenv("STRIPE_CHECKOUT_BASE_URL", "http://localhost:8089")
    slug = agency_id.strip().lower().replace(" ", "-")
    if success_url is None:
        success_url = f"{base_url}/portal/{slug}?session_id={{CHECKOUT_SESSION_ID}}"
    if cancel_url is None:
        cancel_url = f"{base_url}/canceled"

    metadata: Dict[str, str] = {
        "agency_id": slug,
        "agency_name": agency_name,
        "tier": tier.value,
        "contact_email": contact_email,
        "support_email": support_email,
        "website": website,
        "primary_color": primary_color,
        "accent_color": accent_color,
        "tagline": tagline,
    }
    if custom_domain:
        metadata["custom_domain"] = custom_domain
    if domain:
        metadata["domain"] = domain
    if client_reference_id:
        metadata["client_reference_id"] = client_reference_id

    body_fields: Dict[str, Any] = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "customer_email": contact_email,
        "success_url": success_url,
        "cancel_url": cancel_url,
    }
    if client_reference_id:
        body_fields["client_reference_id"] = client_reference_id
    for key, value in metadata.items():
        body_fields[f"metadata[{key}]"] = value

    body = urllib.parse.urlencode(body_fields).encode("utf-8")
    req = urllib.request.Request(
        f"{STRIPE_API_BASE}/checkout/sessions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {_stripe_secret_key()}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    opener = http_open or urllib.request.urlopen
    try:
        with opener(req, timeout=30) as resp:
            if getattr(resp, "status", 200) not in (200, 201):
                raise RuntimeError(f"Stripe returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        logger.error("Stripe Checkout Session creation failed: %s %s", e.code, body_text)
        raise RuntimeError(f"Stripe API error {e.code}: {body_text}") from e


# ---------------------------------------------------------------------------
# Subscription lifecycle management (upgrade / downgrade / cancel)
# ---------------------------------------------------------------------------


def _stripe_get(endpoint: str, http_open: Optional[Callable] = None) -> Dict[str, Any]:
    """GET a Stripe API endpoint and return the parsed JSON body."""
    opener = http_open or urllib.request.urlopen
    req = urllib.request.Request(
        f"{STRIPE_API_BASE}/{endpoint}",
        method="GET",
        headers={"Authorization": f"Bearer {_stripe_secret_key()}"},
    )
    try:
        with opener(req, timeout=30) as resp:
            if getattr(resp, "status", 200) not in (200, 201):
                raise RuntimeError(f"Stripe returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        logger.error("Stripe GET %s failed: %s %s", endpoint, e.code, body_text)
        raise RuntimeError(f"Stripe API error {e.code}: {body_text}") from e


def _stripe_post(
    endpoint: str,
    fields: Optional[Dict[str, Any]] = None,
    http_open: Optional[Callable] = None,
) -> Dict[str, Any]:
    """POST form-encoded fields to a Stripe API endpoint and return parsed JSON."""
    opener = http_open or urllib.request.urlopen
    body = urllib.parse.urlencode(fields or {}).encode("utf-8")
    req = urllib.request.Request(
        f"{STRIPE_API_BASE}/{endpoint}",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {_stripe_secret_key()}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with opener(req, timeout=30) as resp:
            if getattr(resp, "status", 200) not in (200, 201):
                raise RuntimeError(f"Stripe returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        logger.error("Stripe POST %s failed: %s %s", endpoint, e.code, body_text)
        raise RuntimeError(f"Stripe API error {e.code}: {body_text}") from e


def get_subscription(
    subscription_id: str, http_open: Optional[Callable] = None
) -> Dict[str, Any]:
    """Retrieve a Stripe Subscription by id."""
    return _stripe_get(f"subscriptions/{subscription_id}", http_open=http_open)


def update_subscription(
    subscription_id: str,
    new_tier: RetainerTier,
    http_open: Optional[Callable] = None,
    proration_behavior: str = "create_prorations",
) -> Dict[str, Any]:
    """Change a subscription's plan to a new retainer tier.

    Updates the subscription's line item to the new tier's Stripe Price ID.
    Returns the updated Subscription object from Stripe.
    """
    price_id = get_price_id(new_tier)

    # Retrieve the subscription to find the subscription item id.
    sub = get_subscription(subscription_id, http_open=http_open)
    items = sub.get("items", {}).get("data", [])
    if not items:
        raise RuntimeError(f"Subscription {subscription_id} has no line items")
    item_id = items[0]["id"]

    return _stripe_post(
        f"subscription_items/{item_id}",
        {
            "price": price_id,
            "proration_behavior": proration_behavior,
        },
        http_open=http_open,
    )


def cancel_subscription(
    subscription_id: str,
    http_open: Optional[Callable] = None,
    cancel_at_period_end: bool = False,
) -> Dict[str, Any]:
    """Cancel a Stripe Subscription.

    If ``cancel_at_period_end`` is True, the subscription runs until the end
    of the current billing period then cancels. Otherwise it cancels
    immediately (prorated).
    """
    fields: Dict[str, Any] = {}
    if cancel_at_period_end:
        fields["cancel_at_period_end"] = "true"
    return _stripe_post(
        f"subscriptions/{subscription_id}/cancel",
        fields,
        http_open=http_open,
    )


# ---------------------------------------------------------------------------
# Lightweight stdlib HTTP signup server
# ---------------------------------------------------------------------------

SIGNUP_HTML_PATH = PROJECT_ROOT / "landing" / "signup.html"
PORTALS_DIR = PROJECT_ROOT / "docs" / "portals"
LANDING_PORTALS_DIR = PROJECT_ROOT / "landing" / "portals"
LANDING_ASSETS_DIR = PROJECT_ROOT / "landing" / "assets"

_TIER_ALIASES: Dict[str, RetainerTier] = {
    "starter": RetainerTier.STARTER,
    "monitoring": RetainerTier.STARTER,
    "scale": RetainerTier.SCALE,
    "growth": RetainerTier.SCALE,
    "remediation": RetainerTier.SCALE,
    "enterprise": RetainerTier.ENTERPRISE,
    "pro": RetainerTier.ENTERPRISE,
}


def _resolve_retainer_tier(raw_tier: str) -> RetainerTier:
    """Resolve user-facing or canonical tier names to RetainerTier."""
    normalized = (raw_tier or "").strip()
    if not normalized:
        return RetainerTier.SCALE
    if normalized.lower() in _TIER_ALIASES:
        return _TIER_ALIASES[normalized.lower()]
    try:
        return RetainerTier(normalized)
    except ValueError:
        return RetainerTier.SCALE


class StripeCheckoutRequestHandler(BaseHTTPRequestHandler):
    """Serves /signup and POST /create-checkout-session for self-service onboarding."""

    def do_GET(self):  # noqa: N802 - http.server override naming
        path = self.path.split("?", 1)[0]
        if path in ("/", "/signup", "/signup.html"):
            self._serve_signup_page()
        elif path.startswith("/assets/"):
            self._serve_asset(path[len("/assets/"):])
        elif path.startswith("/portal/"):
            agency_id = path[len("/portal/"):]
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
            subscription_id = path[len("/subscription/"):]
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
            tier = _resolve_retainer_tier(get("tier"))

            session = create_checkout_session(
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
                client_reference_id=get("client_reference_id") or None,
            )
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
                new_tier = RetainerTier(new_tier_str)
            except ValueError:
                raise RuntimeError(f"Invalid tier: {new_tier_str or '(missing)'}")

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
        try:
            html = SIGNUP_HTML_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._send_text(500, "signup.html not found on server", "text/html")
            return
        self._send_text(200, html, "text/html")

    def _serve_asset(self, rel_asset: str):
        clean_rel = (rel_asset or "").lstrip("/")
        if not clean_rel or ".." in clean_rel or "\\" in clean_rel:
            self._send_text(400, "Invalid asset path", "text/plain")
            return
        asset_path = (LANDING_ASSETS_DIR / clean_rel).resolve()
        try:
            if not asset_path.is_relative_to(LANDING_ASSETS_DIR.resolve()):
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
        # Silence default access logs
        pass


def run_checkout_server(host: str = "127.0.0.1", port: int = 8089):
    """Starts the standalone Stripe checkout signup HTTP server."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, StripeCheckoutRequestHandler)
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
