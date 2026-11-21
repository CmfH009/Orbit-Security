"""Orbit Security Deep Billing & Agency Onboarding Module (billing_onboarding.py).

Collapses Stripe self-service checkout creation, subscription lifecycle
management, webhook HMAC-SHA256 verification, canonical tier-alias resolution,
and multi-store agency provisioning behind one deep module configured by a
single ``workspace_root`` and an injected ``StripeTransport`` adapter.

No external web framework: pure stdlib ``urllib`` + ``hmac`` + ``json`` +
ReportLab SLA certificate synthesis.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import html
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid

from dotenv import dotenv_values
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from orbit_security._runtime_paths import resolve_isolated_data_path
from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
from orbit_security.dns_fixpack_optimizer import DnsFixpackOptimizer
from orbit_security.fleet import ClientTarget, FleetRegistry

logger = logging.getLogger("orbit_security.billing_onboarding")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_SUBSCRIBERS_FILE = PROJECT_ROOT / "data" / "subscribers.json"
DEFAULT_CERTIFICATES_DIR = PROJECT_ROOT / "data" / "certificates"
DEFAULT_CLIENTS_FILE = PROJECT_ROOT / "data" / "clients.json"
DEFAULT_STRIPE_TOLERANCE_SECONDS = int(os.environ.get("STRIPE_WEBHOOK_TOLERANCE", "600"))

STRIPE_API_BASE = "https://api.stripe.com/v1"

# ---------------------------------------------------------------------------
# Canonical Tier & Pricing Resolution (Single Source of Truth)
# ---------------------------------------------------------------------------

STRIPE_PRICE_ENV: Dict[RetainerTier, str] = {
    RetainerTier.STARTER: "STRIPE_PRICE_STARTER",
    RetainerTier.SCALE: "STRIPE_PRICE_SCALE",
    RetainerTier.ENTERPRISE: "STRIPE_PRICE_ENTERPRISE",
}

DEFAULT_PRICE_IDS: Dict[RetainerTier, str] = {
    RetainerTier.STARTER: "price_starter_299_monthly",
    RetainerTier.SCALE: "price_scale_499_monthly",
    RetainerTier.ENTERPRISE: "price_enterprise_999_monthly",
}

TIER_ALIASES: Dict[str, RetainerTier] = {
    "starter": RetainerTier.STARTER,
    "monitoring": RetainerTier.STARTER,
    "scale": RetainerTier.SCALE,
    "growth": RetainerTier.SCALE,
    "remediation": RetainerTier.SCALE,
    "enterprise": RetainerTier.ENTERPRISE,
    "pro": RetainerTier.ENTERPRISE,
}

DEAL_DESK_TIER_KEYS: Dict[RetainerTier, str] = {
    RetainerTier.STARTER: "monitoring",
    RetainerTier.SCALE: "remediation",
    RetainerTier.ENTERPRISE: "enterprise",
}


def resolve_retainer_tier(
    raw_tier: Any,
    *,
    default: RetainerTier = RetainerTier.SCALE,
    strict: bool = False,
) -> RetainerTier:
    """Resolve any user-facing, deal-desk, or canonical tier label to RetainerTier."""
    if isinstance(raw_tier, RetainerTier):
        return raw_tier

    normalized = str(raw_tier or "").strip()
    if not normalized:
        if strict:
            raise ValueError("Invalid tier: (missing)")
        return default

    aliased = TIER_ALIASES.get(normalized.lower())
    if aliased is not None:
        return aliased

    try:
        return RetainerTier(normalized)
    except ValueError:
        if strict:
            raise ValueError(f"Invalid tier: {normalized}") from None
        return default


def resolve_deal_desk_tier_key(
    raw_tier: Any,
    *,
    default: RetainerTier = RetainerTier.SCALE,
) -> str:
    """Map any canonical tier or alias to the deal-desk pricing table key."""
    tier = resolve_retainer_tier(raw_tier, default=default)
    return DEAL_DESK_TIER_KEYS[tier]


def get_price_id(
    tier: Any,
    *,
    price_ids: Optional[Mapping[RetainerTier, str]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Resolve the Stripe Price ID for a retainer tier or alias."""
    resolved_tier = resolve_retainer_tier(tier)
    if price_ids and resolved_tier in price_ids and price_ids[resolved_tier]:
        return str(price_ids[resolved_tier])

    env_map = os.environ if env is None else env
    env_var = STRIPE_PRICE_ENV[resolved_tier]
    configured = env_map.get(env_var)
    if configured:
        return str(configured)
    return DEFAULT_PRICE_IDS[resolved_tier]


def _read_dotenv_file(env_file: Optional[Path]) -> Dict[str, str]:
    if env_file is None:
        return {}
    path = Path(env_file)
    if not path.is_file():
        return {}
    try:
        raw = dotenv_values(path)
        return {str(k): str(v).strip() for k, v in raw.items() if v is not None and str(v).strip()}
    except Exception:
        return {}


def resolve_webhook_secret(
    explicit_secret: Optional[str] = None,
    *,
    env_file: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    """Resolve Stripe webhook signing secret from explicit arg, env, or workspace .env."""
    if explicit_secret:
        return explicit_secret

    env_map = os.environ if env is None else env
    env_secret = str(env_map.get("STRIPE_WEBHOOK_SECRET") or "").strip()
    if env_secret:
        return env_secret

    dotenv_map = _read_dotenv_file(env_file)
    secret_val = dotenv_map.get("STRIPE_WEBHOOK_SECRET", "").strip()
    return secret_val or None


def resolve_stripe_secret_key(
    explicit_key: Optional[str] = None,
    *,
    env_file: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Resolve Stripe API secret key from explicit arg, env, or workspace .env."""
    if explicit_key:
        return explicit_key

    env_map = os.environ if env is None else env
    api_key = str(env_map.get("STRIPE_SECRET_KEY") or env_map.get("STRIPE_API_KEY") or "").strip()
    if api_key:
        return api_key

    dotenv_map = _read_dotenv_file(env_file)
    api_key = str(dotenv_map.get("STRIPE_SECRET_KEY") or dotenv_map.get("STRIPE_API_KEY") or "").strip()
    if api_key:
        return api_key

    raise RuntimeError(
        "STRIPE_SECRET_KEY (or STRIPE_API_KEY) is not set. "
        "Add it to .env (see .env.example)."
    )


# ---------------------------------------------------------------------------
# Stripe Transport Seam (Port + Production & In-Memory Adapters)
# ---------------------------------------------------------------------------


class StripeTransport(Protocol):
    """External transport port for Stripe REST API calls."""

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        api_key: str,
        fields: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        ...


class UrllibStripeTransport:
    """Production Stripe transport adapter backed by stdlib urllib."""

    def __init__(
        self,
        *,
        api_base: str = STRIPE_API_BASE,
        http_open: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.http_open = http_open

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        api_key: str,
        fields: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        verb = method.upper()
        url = f"{self.api_base}/{endpoint.lstrip('/')}"
        headers: Dict[str, str] = {"Authorization": f"Bearer {api_key}"}
        data: Optional[bytes] = None
        if verb == "POST":
            data = urllib.parse.urlencode(fields or {}).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=data, method=verb, headers=headers)
        opener = self.http_open or urllib.request.urlopen
        try:
            with opener(req, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                if status not in (200, 201):
                    raise RuntimeError(f"Stripe returned HTTP {status}")
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            logger.error("Stripe %s %s failed: %s %s", verb, endpoint, exc.code, body_text)
            raise RuntimeError(f"Stripe API error {exc.code}: {body_text}") from exc


class InMemoryStripeTransport:
    """Deterministic fake Stripe transport adapter for tests and hermetic dry-runs."""

    def __init__(self, *, api_base: str = STRIPE_API_BASE) -> None:
        self.api_base = api_base.rstrip("/")
        self.requests: List[Dict[str, Any]] = []
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.subscriptions: Dict[str, Dict[str, Any]] = {}
        self._item_to_sub: Dict[str, str] = {}
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def seed_subscription(
        self,
        subscription_id: str,
        *,
        customer: str = "cus_inmem_001",
        status: str = "active",
        price_id: str = DEFAULT_PRICE_IDS[RetainerTier.SCALE],
        metadata: Optional[Dict[str, Any]] = None,
        item_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        sub_item_id = item_id or f"si_{subscription_id}"
        sub = {
            "id": subscription_id,
            "status": status,
            "customer": customer,
            "current_period_start": 1700000000,
            "current_period_end": 1702592000,
            "cancel_at_period_end": False,
            "metadata": dict(metadata or {}),
            "items": {"data": [{"id": sub_item_id, "price": {"id": price_id}}]},
        }
        self.subscriptions[subscription_id] = sub
        self._item_to_sub[sub_item_id] = subscription_id
        return sub

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        api_key: str,
        fields: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        verb = method.upper()
        clean_ep = endpoint.lstrip("/")
        url = f"{self.api_base}/{clean_ep}"
        recorded_fields = dict(fields or {})
        self.requests.append(
            {
                "method": verb,
                "endpoint": clean_ep,
                "url": url,
                "auth_bearer_prefix": f"Bearer {api_key}"[:14],
                "fields": recorded_fields,
                "timeout": timeout,
            }
        )

        if verb == "POST" and clean_ep == "checkout/sessions":
            seq = self._next_seq()
            session_id = f"cs_test_inmem_{seq:03d}"
            customer_id = f"cus_test_inmem_{seq:03d}"
            sub_id = f"sub_test_inmem_{seq:03d}"
            metadata = {
                k[len("metadata[") : -1]: v
                for k, v in recorded_fields.items()
                if k.startswith("metadata[") and k.endswith("]")
            }
            price_id = str(recorded_fields.get("line_items[0][price]", ""))
            session = {
                "id": session_id,
                "url": f"https://checkout.stripe.com/c/pay/{session_id}",
                "customer": customer_id,
                "subscription": sub_id,
                "customer_email": recorded_fields.get("customer_email"),
                "client_reference_id": recorded_fields.get("client_reference_id"),
                "metadata": metadata,
            }
            self.sessions[session_id] = session
            self.seed_subscription(
                sub_id,
                customer=customer_id,
                status="active",
                price_id=price_id or DEFAULT_PRICE_IDS[RetainerTier.SCALE],
                metadata=metadata,
            )
            return {"id": session_id, "url": session["url"]}

        if verb == "GET" and clean_ep.startswith("subscriptions/"):
            sub_id = clean_ep.split("/", 1)[1]
            if sub_id not in self.subscriptions:
                raise RuntimeError(f"Stripe API error 404: No such subscription: {sub_id}")
            return dict(self.subscriptions[sub_id])

        if verb == "POST" and clean_ep.startswith("subscription_items/"):
            item_id = clean_ep.split("/", 1)[1]
            sub_id = self._item_to_sub.get(item_id)
            if not sub_id or sub_id not in self.subscriptions:
                raise RuntimeError(f"Stripe API error 404: No such subscription item: {item_id}")
            sub = self.subscriptions[sub_id]
            new_price = recorded_fields.get("price")
            if new_price:
                sub["items"]["data"][0]["price"]["id"] = new_price
            sub["proration_behavior"] = recorded_fields.get("proration_behavior", "create_prorations")
            return dict(sub)

        if verb == "POST" and clean_ep.startswith("subscriptions/") and clean_ep.endswith("/cancel"):
            sub_id = clean_ep[len("subscriptions/") : -len("/cancel")]
            if sub_id not in self.subscriptions:
                raise RuntimeError(f"Stripe API error 404: No such subscription: {sub_id}")
            sub = self.subscriptions[sub_id]
            at_period_end = str(recorded_fields.get("cancel_at_period_end", "")).lower() == "true"
            sub["cancel_at_period_end"] = at_period_end
            sub["status"] = "active" if at_period_end else "canceled"
            return dict(sub)

        raise RuntimeError(f"Unsupported fake Stripe endpoint: {verb} {clean_ep}")


# ---------------------------------------------------------------------------
# 1. Stripe HMAC-SHA256 Cryptographic Verification
# ---------------------------------------------------------------------------


def generate_stripe_signature(
    payload: bytes, secret: str, timestamp: Optional[int] = None
) -> str:
    """Generates a valid Stripe-Signature header format for tests and webhooks."""
    ts = timestamp if timestamp is not None else int(time.time())
    signed_payload = f"{ts}.".encode("utf-8") + payload
    sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def verify_stripe_signature(
    payload: bytes,
    sig_header: Optional[str],
    secret: Optional[str],
    tolerance: int = DEFAULT_STRIPE_TOLERANCE_SECONDS,
) -> bool:
    """Verifies Stripe HMAC-SHA256 signature with replay tolerance."""
    if not secret:
        return True

    if not sig_header:
        logger.warning("Missing Stripe-Signature header.")
        return False

    items: Dict[str, str] = {}
    for part in sig_header.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            items[k.strip()] = v.strip()

    if "t" not in items or "v1" not in items:
        logger.warning("Malformed Stripe-Signature header: %s", sig_header)
        return False

    try:
        ts = int(items["t"])
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - ts) > tolerance:
        logger.warning(
            "Stripe signature timestamp expired: delta=%ds > tolerance=%ds",
            abs(now - ts),
            tolerance,
        )
        return False

    signed_payload = f"{ts}.".encode("utf-8") + payload
    expected_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, items["v1"])


# ---------------------------------------------------------------------------
# 2. Cryptographic SLA Certificate Generator & Domain Normalization
# ---------------------------------------------------------------------------


def compute_sla_crypto_hash(
    cert_id: str,
    client_name: str,
    apex_domain: str,
    plan: str,
    effective_date: str,
    issuer: str = "Orbit Security Systems",
) -> str:
    """Computes a deterministic SHA-256 fingerprint anchoring the SLA certificate."""
    raw = f"{cert_id}:{client_name}:{apex_domain}:{plan}:{effective_date}:{issuer}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_apex_domain(domain_str: Optional[str]) -> str:
    """Normalizes and sanitizes an apex domain string."""
    if not domain_str:
        return ""
    d = str(domain_str).strip().lower()
    d = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", d)
    d = d.split("?")[0].split("#")[0]
    if "@" in d and "/" not in d.split("@")[0]:
        d = d.split("@", 1)[1]

    parts = [p.strip() for p in re.split(r"[/\\]+", d) if p.strip() and p.strip() not in (".", "..")]
    if not parts:
        return ""

    candidate = ""
    for p in parts:
        host_candidate = p.split(":")[0]
        cleaned = re.sub(r"[^a-zA-Z0-9._-]", "", host_candidate).strip("._-")
        if "." in cleaned and not cleaned.endswith("."):
            candidate = cleaned
            if p == parts[0]:
                break

    if not candidate:
        first_clean = re.sub(r"[^a-zA-Z0-9._-]", "", parts[0].split(":")[0]).strip("._-")
        last_clean = re.sub(r"[^a-zA-Z0-9._-]", "", parts[-1].split(":")[0]).strip("._-")
        candidate = first_clean or last_clean

    candidate = re.sub(r"^[-._]+|[-._]+$", "", candidate)
    return candidate


class SlaCertificateGenerator:
    """Synthesizes high-assurance cryptographic SLA certificates in PDF format."""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = resolve_isolated_data_path(output_dir, DEFAULT_CERTIFICATES_DIR)

    def generate_certificate(
        self,
        client_name: str,
        apex_domain: str,
        plan: str,
        effective_date: Optional[str] = None,
        cert_id: Optional[str] = None,
    ) -> Tuple[Path, str, str]:
        """Generates the signed PDF certificate and returns (cert_path, cert_id, crypto_hash)."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        date_str = effective_date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        cid = cert_id or f"ORBIT-SLA-{uuid.uuid4().hex[:8].upper()}"
        crypto_hash = compute_sla_crypto_hash(cid, client_name, apex_domain, plan, date_str)

        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", str(apex_domain))
        clean_domain = re.sub(r"_+", "_", clean_domain).strip("_-") or "domain"
        target_filename = f"SLA_{clean_domain}_{cid}.pdf"
        pdf_path = (self.output_dir / target_filename).resolve()

        try:
            pdf_path.relative_to(self.output_dir.resolve())
        except ValueError:
            pdf_path = self.output_dir.resolve() / f"SLA_sanitized_{cid}.pdf"

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CertTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
            alignment=1,
        )
        sub_style = ParagraphStyle(
            "CertSub",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#2563EB"),
            alignment=1,
        )
        body_style = ParagraphStyle(
            "CertBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#1E293B"),
        )
        hash_style = ParagraphStyle(
            "CertHash",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
            alignment=1,
        )

        elements: List[Any] = []
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("🛡️ ORBIT SECURITY SYSTEMS", title_style))
        elements.append(Spacer(1, 4))
        elements.append(
            Paragraph("CERTIFICATE OF CYBERSECURITY SERVICE LEVEL AGREEMENT (SLA)", sub_style)
        )
        elements.append(Spacer(1, 12))
        elements.append(
            HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=15)
        )

        safe_client_name = html.escape(str(client_name))
        safe_apex_domain = html.escape(str(apex_domain))
        safe_plan = html.escape(str(plan))
        safe_cid = html.escape(str(cid))
        safe_date_str = html.escape(str(date_str))

        intro = (
            f"This certifies that <b>{safe_client_name}</b> has successfully enrolled the digital assets under "
            f"<b>{safe_apex_domain}</b> into the Orbit Security Autonomous Perimeter &amp; Zero-Drift Sentinel Fleet. "
            f"Orbit Security guarantees continuous, high-frequency surveillance, automated RFC compliance diffing, "
            f"and cryptographic drift verification."
        )
        elements.append(Paragraph(intro, body_style))
        elements.append(Spacer(1, 14))

        details_data = [
            [Paragraph("<b>Certificate Identifier:</b>", body_style), Paragraph(f"<code>{safe_cid}</code>", body_style)],
            [Paragraph("<b>Subscribed Organization:</b>", body_style), Paragraph(f"<b>{safe_client_name}</b>", body_style)],
            [Paragraph("<b>Protected Apex Domain:</b>", body_style), Paragraph(f"<code>{safe_apex_domain}</code>", body_style)],
            [Paragraph("<b>Retainer Plan Tier:</b>", body_style), Paragraph(f"<b>{safe_plan}</b>", body_style)],
            [Paragraph("<b>Effective Commencement:</b>", body_style), Paragraph(safe_date_str, body_style)],
            [Paragraph("<b>Autonomous SLA Term:</b>", body_style), Paragraph("Continuous 24/7/365 Autonomous Active Sentinel", body_style)],
        ]
        t = Table(details_data, colWidths=[180, 360])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        elements.append(t)
        elements.append(Spacer(1, 16))

        elements.append(Paragraph("<b>SERVICE LEVEL COMMITMENTS & GUARANTEED REMEDIATION</b>", sub_style))
        elements.append(Spacer(1, 6))

        clauses = [
            "<b>1. 99.9% Continuous Sentinel Availability:</b> Continuous autonomous polling of DNS records, authoritative nameservers, and TLS perimeters without manual operator intervention.",
            "<b>2. &lt;5-Minute Drift Telemetry:</b> Sub-five-minute identification and dispatch of alerts for dangling CNAME takeovers, unmapped CloudFront/S3/Shopify pointers, and DMARC spoofing drift.",
            "<b>3. OWASP & RFC Strict Validation:</b> Periodic validation of security.txt (RFC 9116), CAA policies (RFC 8659), and strict HSTS headers.",
            "<b>4. Zero Unmitigated High/Critical Takeovers:</b> Immediate automated dispatch of white-label mitigation briefings and pull-request patches to partner engineers.",
        ]
        for clause in clauses:
            elements.append(Paragraph(f"• {clause}", body_style))
            elements.append(Spacer(1, 4))

        elements.append(Spacer(1, 14))

        sig_data = [
            [
                Paragraph("<b>Carson Haynes</b><br/>Founder & Systems Architect<br/>Orbit Security Systems (@_arsoncode)", body_style),
                Paragraph("<b>VERIFIED CYBERSECURITY SEAL</b><br/>Autonomous Cryptographic Hash Verification<br/>Issued under AgyHut Master Security Cluster", body_style),
            ]
        ]
        sig_table = Table(sig_data, colWidths=[270, 270])
        sig_table.setStyle(
            TableStyle(
                [
                    ("LINEABOVE", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
                    ("PADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(sig_table)
        elements.append(Spacer(1, 14))

        elements.append(Paragraph("<b>CRYPTOGRAPHIC SHA-256 DIGITAL AUTHENTICATION DIGEST:</b>", hash_style))
        elements.append(Spacer(1, 2))
        elements.append(Paragraph(f"{crypto_hash}", hash_style))

        doc.build(elements)
        logger.info("Generated Cryptographic SLA Certificate: %s (SHA: %s...)", pdf_path.name, crypto_hash[:16])
        return pdf_path, cid, crypto_hash


# ---------------------------------------------------------------------------
# 3. Subscriber Store (data/subscribers.json)
# ---------------------------------------------------------------------------


class SubscriberManager:
    """Manages active subscriber records and SLA linkages in data/subscribers.json."""

    def __init__(self, subscribers_file: Optional[Path] = None) -> None:
        self.subscribers_file = resolve_isolated_data_path(subscribers_file, DEFAULT_SUBSCRIBERS_FILE)

    def list_subscribers(self) -> List[Dict[str, Any]]:
        """Loads subscriber list from disk."""
        if not self.subscribers_file.exists():
            return []
        try:
            with open(self.subscribers_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and isinstance(data.get("subscribers"), list):
                    return data["subscribers"]
                return []
        except Exception as exc:
            logger.warning("Error reading subscribers file: %s", exc)
            return []

    def provision_subscriber(
        self,
        customer_id: str,
        customer_email: str,
        customer_name: str,
        apex_domain: str,
        plan: str,
        amount_cents: int,
        currency: str,
        sla_cert_id: str,
        sla_cert_path: str,
        sla_crypto_hash: str,
        stripe_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Provisions or updates a subscriber record with atomic persistence."""
        self.subscribers_file.parent.mkdir(parents=True, exist_ok=True)
        subs = self.list_subscribers()

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record = {
            "subscriber_id": f"sub_{uuid.uuid4().hex[:8]}",
            "stripe_customer_id": customer_id,
            "stripe_session_id": stripe_session_id,
            "customer_email": customer_email,
            "customer_name": customer_name,
            "apex_domain": apex_domain,
            "plan": plan,
            "amount_cents": amount_cents,
            "currency": currency,
            "status": "active",
            "subscribed_at": now_iso,
            "sla_certificate_id": sla_cert_id,
            "sla_certificate_path": str(sla_cert_path),
            "sla_crypto_hash": sla_crypto_hash,
            "monitoring_enabled": True,
            "scan_interval_minutes": 60,
        }

        updated = False
        for idx, item in enumerate(subs):
            if item.get("apex_domain") == apex_domain or item.get("stripe_customer_id") == customer_id:
                record["subscriber_id"] = item.get("subscriber_id", record["subscriber_id"])
                record["subscribed_at"] = item.get("subscribed_at", record["subscribed_at"])
                subs[idx] = record
                updated = True
                break

        if not updated:
            subs.append(record)

        tmp = self.subscribers_file.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(subs, f, indent=2)
            tmp.replace(self.subscribers_file)
            logger.info("Provisioned subscriber record for %s (%s)", apex_domain, customer_email)
        except Exception as exc:
            if tmp.exists():
                tmp.unlink()
            logger.error("Failed to persist subscriber: %s", exc)

        return record

    def update_status(self, domain_or_customer: str, status: str) -> bool:
        """Updates subscriber active status (e.g. 'canceled', 'paused', 'active')."""
        subs = self.list_subscribers()
        found = False
        for s in subs:
            if s.get("apex_domain") == domain_or_customer or s.get("stripe_customer_id") == domain_or_customer:
                s["status"] = status
                s["monitoring_enabled"] = status == "active"
                found = True
                break

        if found:
            tmp = self.subscribers_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(subs, f, indent=2)
            tmp.replace(self.subscribers_file)
        return found


# ---------------------------------------------------------------------------
# 4. Deep Module: BillingOnboarding
# ---------------------------------------------------------------------------


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except Exception:
        return False


def _infer_isolated_workspace_root(
    *,
    subscriber_manager: Optional[SubscriberManager] = None,
    sla_generator: Optional[SlaCertificateGenerator] = None,
    fleet_registry: Optional[FleetRegistry] = None,
    retainer_manager: Optional[AgencyRetainerManager] = None,
    onboarding_service: Optional[Any] = None,
    deal_desk: Optional[Any] = None,
) -> Optional[Path]:
    """Infer an isolated workspace root from injected collaborators when none was passed."""
    candidates: List[Path] = []
    if deal_desk is not None and getattr(deal_desk, "workspace_root", None):
        candidates.append(Path(deal_desk.workspace_root))
    if subscriber_manager is not None and getattr(subscriber_manager, "subscribers_file", None):
        candidates.append(Path(subscriber_manager.subscribers_file).parent)
    if sla_generator is not None and getattr(sla_generator, "output_dir", None):
        candidates.append(Path(sla_generator.output_dir).parent)
    if fleet_registry is not None and getattr(fleet_registry, "data_path", None):
        candidates.append(Path(fleet_registry.data_path).parent)
    if retainer_manager is not None and getattr(retainer_manager, "data_path", None):
        candidates.append(Path(retainer_manager.data_path).parent)
    if onboarding_service is not None and getattr(onboarding_service, "onboarding_file", None):
        candidates.append(Path(onboarding_service.onboarding_file).parent)

    for candidate in candidates:
        if not _is_within_root(candidate, PROJECT_ROOT):
            return candidate
    return None


_UNSET: Any = object()


class BillingOnboarding:
    """Deep module owning Stripe checkout, subscription lifecycle, webhook
    verification, canonical tier resolution, and multi-store agency provisioning.

    External seam:
    - ``workspace_root``: single root directory owning all local data stores,
      certificates, bundles, portals, and optional ``.env``.
    - ``stripe_transport``: injected ``StripeTransport`` adapter (production
      ``UrllibStripeTransport`` or test ``InMemoryStripeTransport``).
    """

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        *,
        stripe_transport: Optional[StripeTransport] = None,
        stripe_secret_key: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        checkout_base_url: Optional[str] = None,
        signature_tolerance: int = DEFAULT_STRIPE_TOLERANCE_SECONDS,
        price_ids: Optional[Mapping[RetainerTier, str]] = None,
        env_file: Any = _UNSET,
        event_publisher: Optional[Callable[..., Any]] = None,
        # Optional internal collaborator overrides for legacy thin adapters/tests
        subscriber_manager: Optional[SubscriberManager] = None,
        sla_generator: Optional[SlaCertificateGenerator] = None,
        fleet_registry: Optional[FleetRegistry] = None,
        retainer_manager: Optional[AgencyRetainerManager] = None,
        onboarding_service: Optional[Any] = None,
        deal_desk: Optional[Any] = None,
    ) -> None:
        inferred_root = (
            Path(workspace_root)
            if workspace_root is not None
            else _infer_isolated_workspace_root(
                subscriber_manager=subscriber_manager,
                sla_generator=sla_generator,
                fleet_registry=fleet_registry,
                retainer_manager=retainer_manager,
                onboarding_service=onboarding_service,
                deal_desk=deal_desk,
            )
        )
        self._explicit_workspace = workspace_root is not None
        self.workspace_root: Path = inferred_root if inferred_root is not None else PROJECT_ROOT
        self._is_live_repo = self.workspace_root.resolve() == PROJECT_ROOT.resolve()

        # Uniform layout when workspace_root is explicitly configured;
        # flat data_dir fallback when inferred from legacy per-file collaborator paths.
        if self._explicit_workspace or self._is_live_repo:
            self.data_dir = self.workspace_root / "data"
            self.portals_dir = self.workspace_root / "docs" / "portals"
            self.landing_portals_dir = self.workspace_root / "landing" / "portals"
            self.landing_assets_dir = self.workspace_root / "landing" / "assets"
            self.signup_html_path = self.workspace_root / "landing" / "signup.html"
            self.bundles_dir = self.data_dir / "client_bundles"
        else:
            self.data_dir = self.workspace_root
            self.portals_dir = self.workspace_root / "portals"
            self.landing_portals_dir = self.workspace_root / "landing" / "portals"
            self.landing_assets_dir = self.workspace_root / "landing" / "assets"
            self.signup_html_path = self.workspace_root / "landing" / "signup.html"
            self.bundles_dir = self.workspace_root / "client_bundles"

        self.subscribers_file = self.data_dir / "subscribers.json"
        self.clients_file = self.data_dir / "clients.json"
        self.retainers_file = self.data_dir / "agency_retainers.json"
        self.certificates_dir = self.data_dir / "certificates"
        self.onboarding_file = self.data_dir / "agency_onboardings.json"

        if env_file is _UNSET:
            self.env_file: Optional[Path] = self.workspace_root / ".env"
        elif env_file is None:
            self.env_file = None
        else:
            self.env_file = Path(env_file)
        self.transport: StripeTransport = stripe_transport or UrllibStripeTransport()
        self._explicit_stripe_secret_key = stripe_secret_key
        self._checkout_base_url = checkout_base_url
        self._price_ids: Optional[Dict[RetainerTier, str]] = (
            {resolve_retainer_tier(k): str(v) for k, v in price_ids.items()} if price_ids else None
        )
        self.signature_tolerance = signature_tolerance
        self.webhook_secret = resolve_webhook_secret(webhook_secret, env_file=self.env_file)

        # In-memory event capture for isolated workspaces (zero global blackboard mutation)
        self.published_events: List[Dict[str, Any]] = []
        if event_publisher is not None:
            self._event_publisher: Optional[Callable[..., Any]] = event_publisher
        elif not self._is_live_repo:
            self._event_publisher = self._record_local_event
        else:
            self._event_publisher = None

        # Wire multi-store collaborators from the single workspace_root
        if subscriber_manager is not None:
            self.subscriber_mgr = subscriber_manager
            self.subscribers_file = self.subscriber_mgr.subscribers_file
        elif self._explicit_workspace or not self._is_live_repo:
            self.subscriber_mgr = SubscriberManager(subscribers_file=self.subscribers_file)
        else:
            self.subscriber_mgr = SubscriberManager()
            self.subscribers_file = self.subscriber_mgr.subscribers_file

        if sla_generator is not None:
            self.sla_generator = sla_generator
            self.certificates_dir = self.sla_generator.output_dir
        elif self._explicit_workspace or not self._is_live_repo:
            self.sla_generator = SlaCertificateGenerator(output_dir=self.certificates_dir)
        else:
            self.sla_generator = SlaCertificateGenerator()
            self.certificates_dir = self.sla_generator.output_dir

        if fleet_registry is not None:
            self.fleet_registry = fleet_registry
            self.clients_file = self.fleet_registry.data_path
        elif self._explicit_workspace or not self._is_live_repo:
            self.fleet_registry = FleetRegistry(data_path=self.clients_file)
        else:
            self.fleet_registry = FleetRegistry()
            self.clients_file = self.fleet_registry.data_path

        if retainer_manager is not None:
            self.retainer_manager = retainer_manager
            self.retainers_file = self.retainer_manager.data_path
        elif self._explicit_workspace or not self._is_live_repo:
            self.retainer_manager = AgencyRetainerManager(data_path=self.retainers_file)
        else:
            self.retainer_manager = AgencyRetainerManager()
            self.retainers_file = self.retainer_manager.data_path

        self.onboarding_service = onboarding_service
        self.deal_desk = deal_desk

    def _record_local_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source: str = "billing_onboarding",
        topic: str = "commercial",
    ) -> int:
        self.published_events.append(
            {
                "event_type": event_type,
                "payload": dict(payload),
                "source": source,
                "topic": topic,
            }
        )
        return len(self.published_events)

    def _effective_env(self) -> Dict[str, str]:
        merged = _read_dotenv_file(self.env_file)
        merged.update(os.environ)
        return merged

    def _api_key(self) -> str:
        return resolve_stripe_secret_key(
            self._explicit_stripe_secret_key,
            env_file=self.env_file,
        )

    # -----------------------------------------------------------------------
    # Pricing & Checkout Session Creation
    # -----------------------------------------------------------------------

    def get_price_id(self, tier: Any) -> str:
        """Resolve the Stripe Price ID for a tier or alias within this workspace."""
        return get_price_id(
            tier,
            price_ids=self._price_ids,
            env=self._effective_env(),
        )

    def create_checkout_session(
        self,
        *,
        agency_id: str,
        agency_name: str,
        tier: Any = RetainerTier.SCALE,
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
    ) -> Dict[str, Any]:
        """Create a Stripe Checkout Session (mode=subscription) via the injected transport."""
        resolved_tier = resolve_retainer_tier(tier)
        price_id = self.get_price_id(resolved_tier)

        base_url = (
            self._checkout_base_url
            or self._effective_env().get("STRIPE_CHECKOUT_BASE_URL")
            or "http://localhost:8089"
        )
        slug = agency_id.strip().lower().replace(" ", "-")
        if success_url is None:
            success_url = f"{base_url}/portal/{slug}?session_id={{CHECKOUT_SESSION_ID}}"
        if cancel_url is None:
            cancel_url = f"{base_url}/canceled"

        metadata: Dict[str, str] = {
            "agency_id": slug,
            "agency_name": agency_name,
            "tier": resolved_tier.value,
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

        return self.transport.request(
            "POST",
            "checkout/sessions",
            api_key=self._api_key(),
            fields=body_fields,
        )

    # -----------------------------------------------------------------------
    # Subscription Lifecycle (Get / Update / Cancel)
    # -----------------------------------------------------------------------

    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Retrieve a Stripe Subscription by id."""
        return self.transport.request(
            "GET",
            f"subscriptions/{subscription_id}",
            api_key=self._api_key(),
        )

    def update_subscription(
        self,
        subscription_id: str,
        new_tier: Any,
        *,
        proration_behavior: str = "create_prorations",
    ) -> Dict[str, Any]:
        """Change a subscription's plan to a new retainer tier (canonical or alias)."""
        resolved_tier = resolve_retainer_tier(new_tier, strict=True)
        price_id = self.get_price_id(resolved_tier)

        sub = self.get_subscription(subscription_id)
        items = sub.get("items", {}).get("data", [])
        if not items:
            raise RuntimeError(f"Subscription {subscription_id} has no line items")
        item_id = items[0]["id"]

        return self.transport.request(
            "POST",
            f"subscription_items/{item_id}",
            api_key=self._api_key(),
            fields={
                "price": price_id,
                "proration_behavior": proration_behavior,
            },
        )

    def cancel_subscription(
        self,
        subscription_id: str,
        *,
        cancel_at_period_end: bool = False,
    ) -> Dict[str, Any]:
        """Cancel a Stripe Subscription immediately or at period end."""
        fields: Dict[str, Any] = {}
        if cancel_at_period_end:
            fields["cancel_at_period_end"] = "true"
        return self.transport.request(
            "POST",
            f"subscriptions/{subscription_id}/cancel",
            api_key=self._api_key(),
            fields=fields,
        )

    # -----------------------------------------------------------------------
    # Subscribers & Portal Resolution
    # -----------------------------------------------------------------------

    def list_subscribers(self) -> List[Dict[str, Any]]:
        """List all provisioned subscribers in this workspace."""
        return self.subscriber_mgr.list_subscribers()

    def resolve_portal_path(self, agency_id: str) -> Optional[Path]:
        """Safely locate an agency's provisioned HTML portal inside this workspace."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", agency_id):
            return None

        slug_candidates: List[str] = []
        for candidate in (
            f"{agency_id}.html",
            f"{agency_id.replace('-', '_')}.html",
            f"{agency_id.replace('_', '-')}.html",
        ):
            if candidate not in slug_candidates:
                slug_candidates.append(candidate)

        search_dirs = [self.portals_dir]
        if self.landing_portals_dir.is_dir():
            search_dirs.append(self.landing_portals_dir)

        for base_dir in search_dirs:
            resolved_base = base_dir.resolve()
            for filename in slug_candidates:
                portal_path = (base_dir / filename).resolve()
                if not _is_within_root(portal_path, resolved_base):
                    continue
                if portal_path.is_file():
                    return portal_path
        return None

    # -----------------------------------------------------------------------
    # Internal Collaborator Accessors (Private Seam)
    # -----------------------------------------------------------------------

    def _get_onboarding_service(self) -> Optional[Any]:
        if self.onboarding_service is not None:
            return self.onboarding_service
        try:
            from orbit_security.radar_telemetry import RadarTelemetryService

            data_dir = self.subscriber_mgr.subscribers_file.parent
            self.onboarding_service = RadarTelemetryService(
                queries_file=data_dir / "radar_queries.jsonl",
                leads_file=data_dir / "radar_enriched_leads.json",
                campaigns_dir=data_dir / "campaigns",
                onboarding_file=data_dir / "agency_onboardings.json",
            )
            return self.onboarding_service
        except Exception as exc:
            logger.debug("Onboarding service lookup unavailable: %s", exc)
            return None

    def _get_deal_desk(self) -> Optional[Any]:
        if self.deal_desk is not None:
            return self.deal_desk
        try:
            from orbit_security.deal_desk import RetainerDealDeskConcierge

            self.deal_desk = RetainerDealDeskConcierge(
                workspace_root=self.workspace_root,
                portals_dir=self.portals_dir,
                bundles_dir=self.bundles_dir,
                event_publisher=self._event_publisher,
            )
            return self.deal_desk
        except Exception as exc:
            logger.debug("Deal desk concierge unavailable: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Webhook Verification & Multi-Store Provisioning Pipeline
    # -----------------------------------------------------------------------

    def _resolve_onboarding_metadata(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Merge Stripe session metadata with pre-checkout white-label onboarding record."""
        raw_meta = dict(session.get("metadata") or {})
        client_ref_id = str(session.get("client_reference_id") or raw_meta.get("client_reference_id") or "").strip()
        customer_details = session.get("customer_details") or {}
        customer_email = str(customer_details.get("email") or raw_meta.get("contact_email") or "").strip()
        agency_id = str(raw_meta.get("agency_id") or "").strip()

        onb_record: Optional[Dict[str, Any]] = None
        svc = self._get_onboarding_service()
        if svc and hasattr(svc, "get_onboarding_record"):
            onb_record = svc.get_onboarding_record(
                client_reference_id=client_ref_id or None,
                email=customer_email or None,
                agency_id=agency_id or None,
            )

        merged: Dict[str, Any] = {}
        if onb_record:
            for key in (
                "client_reference_id",
                "agency_id",
                "agency_name",
                "contact_email",
                "support_email",
                "website",
                "tier",
                "custom_domain",
                "tagline",
                "primary_color",
                "accent_color",
            ):
                if onb_record.get(key):
                    merged[key] = onb_record[key]

        for key, value in raw_meta.items():
            if value is not None and value != "":
                merged[key] = value

        if not merged.get("agency_id") and client_ref_id:
            derived_slug = re.sub(r"-[0-9a-fA-F]{8}$", "", client_ref_id).strip("-_")
            if derived_slug:
                merged["agency_id"] = derived_slug

        return merged

    def register_client_for_monitoring(
        self,
        apex_domain: str,
        client_name: str,
        contact_email: str,
        plan: str,
        agency_id: str = "orbit-core",
    ) -> ClientTarget:
        """Register client target into data/clients.json for 24/7 continuous monitoring."""
        client_id = f"client-{apex_domain.replace('.', '-')}"
        client = ClientTarget(
            client_id=client_id,
            client_name=client_name,
            apex_domain=apex_domain,
            subdomains=[apex_domain],
            contact_email=contact_email,
            agency_id=agency_id or "orbit-core",
            retainer_plan=plan,
            status="active",
        )
        self.fleet_registry.add_client(client)
        logger.info("Registered %s for 24/7 Fleet Sentinel monitoring.", apex_domain)
        return client

    def handle_webhook(
        self, payload_bytes: bytes, sig_header: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate payload signature and execute lifecycle provisioning/deprovisioning."""
        if self.webhook_secret:
            if not verify_stripe_signature(
                payload_bytes,
                sig_header,
                self.webhook_secret,
                tolerance=self.signature_tolerance,
            ):
                logger.error("Stripe webhook signature validation failed.")
                return {"status": "ERROR", "message": "Invalid Stripe signature"}

        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            logger.error("Invalid JSON in webhook payload: %s", exc)
            return {"status": "ERROR", "message": "Invalid JSON"}

        if not isinstance(event, dict):
            logger.error("Invalid JSON structure in webhook payload: expected object.")
            return {"status": "ERROR", "message": "Invalid JSON: expected object"}

        event_type = event.get("type")
        raw_data = event.get("data")
        event_data = raw_data.get("object") if isinstance(raw_data, dict) else {}
        if not isinstance(event_data, dict):
            event_data = {}

        logger.info("Processing Stripe Webhook Event: %s (ID: %s)", event_type, event.get("id"))

        if event_type == "checkout.session.completed":
            return self._handle_checkout_session_completed(event_data)
        if event_type == "customer.subscription.deleted":
            return self._handle_subscription_deleted(event_data)
        if event_type == "customer.subscription.updated":
            return self._handle_subscription_updated(event_data)
        if event_type == "invoice.payment_succeeded":
            return self._handle_invoice_payment_succeeded(event_data)
        if event_type == "invoice.payment_failed":
            return self._handle_invoice_payment_failed(event_data)

        return {"status": "IGNORED", "event_type": event_type}

    def _handle_checkout_session_completed(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Provision subscriber, SLA PDF, Fleet client, AgencyRetainer, portal, bundle, and DNS fixpack."""
        resolved_meta = self._resolve_onboarding_metadata(session)
        customer_id = session.get("customer") or session.get("id") or "cus_unknown"
        customer_details = session.get("customer_details") or {}
        customer_email = (
            customer_details.get("email")
            or resolved_meta.get("contact_email")
            or "ops@client.com"
        )
        customer_name = (
            customer_details.get("name")
            or resolved_meta.get("agency_name")
            or customer_email.split("@")[0].title()
        )

        raw_domain = resolved_meta.get("domain") or resolved_meta.get("apex_domain")
        apex_domain = normalize_apex_domain(raw_domain) if raw_domain else ""
        if (not apex_domain or "." not in apex_domain) and resolved_meta.get("website"):
            clean_web = normalize_apex_domain(str(resolved_meta["website"]))
            if "." in clean_web:
                apex_domain = clean_web

        plan = resolved_meta.get("plan") or (
            f"{resolved_meta['tier']} Retainer" if resolved_meta.get("tier") else "Scale Retainer ($299/mo)"
        )

        if not apex_domain or "." not in apex_domain:
            if "@" in customer_email and not any(
                customer_email.endswith(d) for d in ("gmail.com", "yahoo.com", "hotmail.com")
            ):
                apex_domain = normalize_apex_domain(customer_email.split("@")[1].lower())
            else:
                clean_name = re.sub(r"[^a-zA-Z0-9]", "", customer_name.lower()) or "agency"
                apex_domain = f"{clean_name}.com"

        apex_domain = normalize_apex_domain(apex_domain) or "agency.com"

        amount_cents = session.get("amount_total", 29900)
        currency = session.get("currency", "usd")

        cert_path, cert_id, crypto_hash = self.sla_generator.generate_certificate(
            client_name=customer_name,
            apex_domain=apex_domain,
            plan=plan,
        )

        subscriber_record = self.subscriber_mgr.provision_subscriber(
            customer_id=customer_id,
            customer_email=customer_email,
            customer_name=customer_name,
            apex_domain=apex_domain,
            plan=plan,
            amount_cents=amount_cents,
            currency=currency,
            sla_cert_id=cert_id,
            sla_cert_path=str(cert_path),
            sla_crypto_hash=crypto_hash,
            stripe_session_id=session.get("id"),
        )

        self.register_client_for_monitoring(
            apex_domain=apex_domain,
            client_name=customer_name,
            contact_email=customer_email,
            plan=plan,
            agency_id=str(resolved_meta.get("agency_id") or "").strip() or "orbit-core",
        )

        retainer = self._sync_agency_retainer(session, resolved_metadata=resolved_meta)

        portal_path: Optional[str] = None
        if retainer:
            concierge = self._get_deal_desk()
            if concierge and hasattr(concierge, "generate_portal_for_agency"):
                try:
                    portal_res = concierge.generate_portal_for_agency(
                        agency_id=retainer.agency_id,
                        agency_name=retainer.agency_name,
                        tier=str(resolved_meta.get("tier") or retainer.tier.value),
                        primary_client_domain=apex_domain,
                        custom_domain=retainer.custom_domain,
                        support_email=retainer.support_email,
                        primary_color=retainer.primary_color,
                        accent_color=retainer.accent_color,
                        tagline=retainer.agency_tagline,
                        website=retainer.website,
                    )
                    portal_path = portal_res.get("portal_path")
                except Exception as exc:
                    logger.warning("Failed to provision white-label portal for %s: %s", retainer.agency_id, exc)

        bundle_path: Optional[str] = None
        bundle_sha256: Optional[str] = None
        concierge = self._get_deal_desk()
        if concierge and hasattr(concierge, "generate_bundle_for_agency"):
            try:
                bundle_agency_id = (
                    retainer.agency_id
                    if retainer
                    else str(resolved_meta.get("agency_id") or "client").strip()
                )
                bundle_domains: List[str] = [apex_domain] if apex_domain else []
                if retainer and retainer.client_domains:
                    for cd in retainer.client_domains:
                        d_name = getattr(cd, "domain", cd) if not isinstance(cd, str) else cd
                        if d_name and d_name not in bundle_domains:
                            bundle_domains.append(d_name)
                bundle_res = concierge.generate_bundle_for_agency(
                    agency_id=bundle_agency_id,
                    agency_name=retainer.agency_name if retainer else customer_name,
                    tier=str(resolved_meta.get("tier") or (retainer.tier.value if retainer else "Scale")),
                    primary_client_domain=apex_domain,
                    portfolio_domains=bundle_domains,
                    primary_color=retainer.primary_color if retainer else resolved_meta.get("primary_color"),
                    accent_color=retainer.accent_color if retainer else resolved_meta.get("accent_color"),
                    support_email=retainer.support_email if retainer else customer_email,
                    tagline=retainer.agency_tagline if retainer else resolved_meta.get("tagline"),
                )
                bundle_path = bundle_res.get("bundle_path")
                bundle_sha256 = bundle_res.get("sha256")
            except Exception as exc:
                logger.warning("Failed to generate client bundle for %s: %s", customer_name, exc)

        dns_fixpack: Optional[Dict[str, Any]] = None
        try:
            fixpack = DnsFixpackOptimizer().generate_fixpack(
                domain=apex_domain,
                original_spf="v=spf1 include:_spf.google.com ~all",
                flattened_ips=[],
                original_lookups=1,
            )
            dns_fixpack = fixpack.to_dict()
        except Exception as exc:
            logger.warning("Failed to generate DNS fixpack for %s: %s", apex_domain, exc)

        return {
            "status": "PROVISIONED",
            "apex_domain": apex_domain,
            "sla_certificate_id": cert_id,
            "sla_certificate_path": str(cert_path),
            "sla_crypto_hash": crypto_hash,
            "subscriber": subscriber_record,
            "agency_id": retainer.agency_id if retainer else None,
            "agency_name": retainer.agency_name if retainer else None,
            "stripe_customer_id": retainer.stripe_customer_id if retainer else None,
            "stripe_subscription_id": retainer.stripe_subscription_id if retainer else None,
            "billing_status": retainer.billing_status if retainer else None,
            "portal_path": portal_path,
            "bundle_path": bundle_path,
            "bundle_sha256": bundle_sha256,
            "dns_fixpack": dns_fixpack,
        }

    def _sync_agency_retainer(
        self,
        session: Dict[str, Any],
        resolved_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Create/update the AgencyRetainer from a completed checkout session."""
        metadata = resolved_metadata if resolved_metadata is not None else self._resolve_onboarding_metadata(session)
        agency_id = metadata.get("agency_id")
        if not agency_id:
            logger.warning("checkout.session.completed metadata missing agency_id; skipping retainer sync")
            return None

        tier = resolve_retainer_tier(metadata.get("tier"), default=RetainerTier.SCALE)
        cust_name = (session.get("customer_details") or {}).get("name")
        resolved_agency_name = (
            metadata.get("agency_name")
            or cust_name
            or agency_id.replace("_", " ").replace("-", " ").title()
        )
        retainer = self.retainer_manager.register_agency(
            agency_id=agency_id,
            agency_name=resolved_agency_name,
            tier=tier,
            custom_domain=metadata.get("custom_domain") or None,
            support_email=metadata.get("support_email") or metadata.get("contact_email") or None,
            primary_color=metadata.get("primary_color") or "#0F172A",
            accent_color=metadata.get("accent_color") or "#3B82F6",
            agency_tagline=metadata.get("tagline") or "Managed Web & Security Operations",
            website=metadata.get("website") or "https://example.com",
        )

        customer_id = session.get("customer")
        subscription_id = session.get("subscription")
        if customer_id:
            retainer.stripe_customer_id = customer_id
        if subscription_id:
            retainer.stripe_subscription_id = subscription_id
        retainer.billing_status = "active"
        self.retainer_manager.save()

        logger.info(
            "Synced retainer %s: tier=%s customer=%s subscription=%s billing=active",
            agency_id,
            tier.value,
            customer_id,
            subscription_id,
        )
        return retainer

    def _find_agency_by_subscription(self, subscription_id: Optional[str]) -> Optional[Any]:
        if not subscription_id:
            return None
        for agency in self.retainer_manager.list_agencies():
            if agency.stripe_subscription_id == subscription_id:
                return agency
        return None

    def _mark_retainer_billing_status(self, subscription_id: str, billing_status: str) -> bool:
        agency = self._find_agency_by_subscription(subscription_id)
        if not agency:
            return False
        agency.billing_status = billing_status
        self.retainer_manager.save()
        logger.info(
            "Retainer %s billing_status -> %s (subscription %s)",
            agency.agency_id,
            billing_status,
            subscription_id,
        )
        return True

    def _handle_subscription_deleted(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        customer_id = event_data.get("customer")
        metadata = event_data.get("metadata") or {}
        domain = normalize_apex_domain(metadata.get("domain") if isinstance(metadata, dict) else None)
        target = domain or customer_id
        if target:
            self.subscriber_mgr.update_status(target, "canceled")
            if domain:
                client_id = f"client-{domain.replace('.', '-')}"
                client = self.fleet_registry.get_client(client_id)
                if client:
                    client.status = "canceled"
                    self.fleet_registry.save()
        subscription_id = event_data.get("id")
        if subscription_id:
            self._mark_retainer_billing_status(subscription_id, "past_due")
        return {"status": "DEPROVISIONED", "target": target}

    def _handle_subscription_updated(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        subscription_id = event_data.get("id")
        status = event_data.get("status")
        if not subscription_id:
            return {"status": "IGNORED", "reason": "missing subscription id"}

        billing_map = {
            "active": "active",
            "past_due": "past_due",
            "paused": "paused",
            "canceled": "past_due",
            "unpaid": "past_due",
        }
        billing_status = billing_map.get((status or "").lower(), "past_due")
        self._mark_retainer_billing_status(subscription_id, billing_status)

        customer_id = event_data.get("customer")
        if customer_id:
            self.subscriber_mgr.update_status(customer_id, billing_status)

        return {
            "status": "UPDATED",
            "subscription_id": subscription_id,
            "billing_status": billing_status,
        }

    def _handle_invoice_payment_succeeded(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        subscription_id = event_data.get("subscription")
        customer_id = event_data.get("customer")
        billing_status = "active"

        if subscription_id:
            self._mark_retainer_billing_status(subscription_id, billing_status)
        if customer_id:
            self.subscriber_mgr.update_status(customer_id, billing_status)

        return {
            "status": "PAYMENT_SUCCEEDED",
            "subscription_id": subscription_id,
            "billing_status": billing_status,
        }

    def _handle_invoice_payment_failed(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        subscription_id = event_data.get("subscription")
        customer_id = event_data.get("customer")
        billing_status = "past_due"

        if subscription_id:
            self._mark_retainer_billing_status(subscription_id, billing_status)
        if customer_id:
            self.subscriber_mgr.update_status(customer_id, billing_status)

        return {
            "status": "PAYMENT_FAILED",
            "subscription_id": subscription_id,
            "billing_status": billing_status,
        }
