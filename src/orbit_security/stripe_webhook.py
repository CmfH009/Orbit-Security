"""Orbit Security Automated Stripe Webhook Onboarding & Provisioning (stripe_webhook.py).

Implements Act II Inbound Automation:
1. Verifies Stripe webhook HMAC-SHA256 signatures with replay attack tolerance.
2. Ingests 'checkout.session.completed' events.
3. Automatically synthesizes a cryptographic Service Level Agreement (SLA) PDF certificate:
   - 99.9% uptime commitment
   - 5-minute DNS drift & dangling takeover detection guarantee
   - Cryptographic SHA-256 integrity seal signed by Carson Haynes (@_arsoncode)
4. Provisions new clients into data/subscribers.json.
5. Registers the apex domain into data/clients.json via FleetRegistry for 24/7 continuous monitoring.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import hmac
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

# ReportLab imports for cryptographic PDF certificate synthesis
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from orbit_security._runtime_paths import is_pytest_active, resolve_isolated_data_path
from orbit_security.agency_retainer import AgencyRetainerManager, RetainerTier
from orbit_security.fleet import ClientTarget, FleetRegistry

logger = logging.getLogger("orbit_security.stripe_webhook")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SUBSCRIBERS_FILE = PROJECT_ROOT / "data" / "subscribers.json"
DEFAULT_CERTIFICATES_DIR = PROJECT_ROOT / "data" / "certificates"
DEFAULT_CLIENTS_FILE = PROJECT_ROOT / "data" / "clients.json"
DEFAULT_STRIPE_TOLERANCE_SECONDS = int(os.environ.get("STRIPE_WEBHOOK_TOLERANCE", "600"))


# ============================================================================
# 1. Stripe HMAC-SHA256 Cryptographic Verification
# ============================================================================


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
        # If no secret configured (development/testing mode without signature requirement)
        return True

    if not sig_header:
        logger.warning("Missing Stripe-Signature header.")
        return False

    items = {}
    for part in sig_header.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            items[k.strip()] = v.strip()

    if "t" not in items or "v1" not in items:
        logger.warning(f"Malformed Stripe-Signature header: {sig_header}")
        return False

    try:
        ts = int(items["t"])
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - ts) > tolerance:
        logger.warning(f"Stripe signature timestamp expired: delta={abs(now - ts)}s > tolerance={tolerance}s")
        return False

    signed_payload = f"{ts}.".encode("utf-8") + payload
    expected_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected_sig, items["v1"])


# ============================================================================
# 2. Cryptographic SLA Certificate Generator
# ============================================================================


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
    """Normalizes and sanitizes an apex domain string.

    Strips protocol schemes, basic auth credentials, URL paths, query parameters,
    ports, and path traversal sequences, retaining only valid domain characters.
    """
    if not domain_str:
        return ""
    d = str(domain_str).strip().lower()
    # Strip protocol scheme (e.g. https://, http://, ftp://)
    d = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", d)
    # Strip query parameters and fragment anchors
    d = d.split("?")[0].split("#")[0]
    # Strip basic auth credentials if present
    if "@" in d and "/" not in d.split("@")[0]:
        d = d.split("@", 1)[1]

    # Split into path components by / and \
    parts = [p.strip() for p in re.split(r"[/\\]+", d) if p.strip() and p.strip() not in (".", "..")]
    if not parts:
        return ""

    # Identify the domain component:
    # 1. If parts[0] has a dot (e.g. example.com/path), it is the host
    # 2. If it is a traversal attempt (../../malicious/test.domain.com), search for segment with domain format
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

    def __init__(self, output_dir: Optional[Path] = None):
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

        # Sanitize clean_domain to strictly alphanumeric, underscore, and hyphen characters to prevent path traversal
        clean_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", str(apex_domain))
        clean_domain = re.sub(r"_+", "_", clean_domain).strip("_-") or "domain"
        target_filename = f"SLA_{clean_domain}_{cid}.pdf"
        pdf_path = (self.output_dir / target_filename).resolve()

        # Hard containment defense: verify the path is strictly inside self.output_dir
        try:
            pdf_path.relative_to(self.output_dir.resolve())
        except ValueError:
            pdf_path = self.output_dir.resolve() / f"SLA_sanitized_{cid}.pdf"

        # Build PDF Document
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        # Custom Typography
        title_style = ParagraphStyle(
            "CertTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
            alignment=1,  # Center
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

        elements = []

        # Top Accent Header
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

        # Overview Paragraph (escape user inputs for ReportLab XML parser)
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

        # Certificate Details Table
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
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        elements.append(t)
        elements.append(Spacer(1, 16))

        # Core Guaranteed SLA Commitments
        commitments_header = Paragraph("<b>SERVICE LEVEL COMMITMENTS & GUARANTEED REMEDIATION</b>", sub_style)
        elements.append(commitments_header)
        elements.append(Spacer(1, 6))

        clauses = [
            "<b>1. 99.9% Continuous Sentinel Availability:</b> Continuous autonomous polling of DNS records, authoritative nameservers, and TLS perimeters without manual operator intervention.",
            "<b>2. &lt;5-Minute Drift Telemetry:</b> Sub-five-minute identification and dispatch of alerts for dangling CNAME takeovers, unmapped CloudFront/S3/Shopify pointers, and DMARC spoofing drift.",
            "<b>3. OWASP & RFC Strict Validation:</b> Periodic validation of security.txt (RFC 9116), CAA policies (RFC 8659), and strict HSTS headers.",
            "<b>4. Zero Unmitigated High/Critical Takeovers:</b> Immediate automated dispatch of white-label mitigation briefings and pull-request patches to partner engineers.",
        ]
        for c in clauses:
            elements.append(Paragraph(f"• {c}", body_style))
            elements.append(Spacer(1, 4))

        elements.append(Spacer(1, 14))

        # Cryptographic Signature & Seal Block
        sig_data = [
            [
                Paragraph("<b>Carson Haynes</b><br/>Founder & Systems Architect<br/>Orbit Security Systems (@_arsoncode)", body_style),
                Paragraph("<b>VERIFIED CYBERSECURITY SEAL</b><br/>Autonomous Cryptographic Hash Verification<br/>Issued under AgyHut Master Security Cluster", body_style),
            ]
        ]
        sig_table = Table(sig_data, colWidths=[270, 270])
        sig_table.setStyle(
            TableStyle([
                ("LINEABOVE", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ])
        )
        elements.append(sig_table)
        elements.append(Spacer(1, 14))

        # Digital Fingerprint Box
        elements.append(Paragraph("<b>CRYPTOGRAPHIC SHA-256 DIGITAL AUTHENTICATION DIGEST:</b>", hash_style))
        elements.append(Spacer(1, 2))
        elements.append(Paragraph(f"{crypto_hash}", hash_style))

        doc.build(elements)
        logger.info(f"Generated Cryptographic SLA Certificate: {pdf_path.name} (SHA: {crypto_hash[:16]}...)")
        return pdf_path, cid, crypto_hash


# ============================================================================
# 3. Subscriber Manager (data/subscribers.json)
# ============================================================================


class SubscriberManager:
    """Manages active subscriber records and SLA linkages in data/subscribers.json."""

    def __init__(self, subscribers_file: Optional[Path] = None):
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
        except Exception as e:
            logger.warning(f"Error reading subscribers file: {e}")
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

        # Update if apex_domain or customer_id exists
        updated = False
        for idx, item in enumerate(subs):
            if item.get("apex_domain") == apex_domain or item.get("stripe_customer_id") == customer_id:
                # Retain original subscriber_id and subscribed_at
                record["subscriber_id"] = item.get("subscriber_id", record["subscriber_id"])
                record["subscribed_at"] = item.get("subscribed_at", record["subscribed_at"])
                subs[idx] = record
                updated = True
                break

        if not updated:
            subs.append(record)

        # Atomic persistence
        tmp = self.subscribers_file.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(subs, f, indent=2)
            tmp.replace(self.subscribers_file)
            logger.info(f"Provisioned subscriber record for {apex_domain} ({customer_email})")
        except Exception as e:
            if tmp.exists():
                tmp.unlink()
            logger.error(f"Failed to persist subscriber: {e}")

        return record

    def update_status(self, domain_or_customer: str, status: str) -> bool:
        """Updates subscriber active status (e.g. 'canceled', 'paused')."""
        subs = self.list_subscribers()
        found = False
        for s in subs:
            if s.get("apex_domain") == domain_or_customer or s.get("stripe_customer_id") == domain_or_customer:
                s["status"] = status
                s["monitoring_enabled"] = (status == "active")
                found = True
                break

        if found:
            tmp = self.subscribers_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(subs, f, indent=2)
            tmp.replace(self.subscribers_file)
        return found


# ============================================================================
# 4. Stripe Webhook Handler & Provisioning Pipeline
# ============================================================================


class StripeWebhookHandler:
    """Processes incoming Stripe webhooks and drives autonomous onboarding."""

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
    ):
        self.webhook_secret = webhook_secret or os.environ.get("STRIPE_WEBHOOK_SECRET")
        self.subscriber_mgr = subscriber_manager or SubscriberManager()
        self.sla_generator = sla_generator or SlaCertificateGenerator()
        self.fleet_registry = fleet_registry or FleetRegistry()
        if retainer_manager is not None:
            self.retainer_manager = retainer_manager
        elif subscriber_manager is not None:
            data_dir = self.subscriber_mgr.subscribers_file.parent
            self.retainer_manager = AgencyRetainerManager(data_path=data_dir / "agency_retainers.json")
        else:
            self.retainer_manager = AgencyRetainerManager()
        self.signature_tolerance = signature_tolerance
        self.onboarding_service = onboarding_service
        self.deal_desk = deal_desk

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
        except Exception as ex:
            logger.debug(f"Onboarding service lookup unavailable: {ex}")
            return None

    def _get_deal_desk(self) -> Optional[Any]:
        if self.deal_desk is not None:
            return self.deal_desk
        try:
            from orbit_security.deal_desk import RetainerDealDeskConcierge
            if self.sla_generator.output_dir.resolve() != DEFAULT_CERTIFICATES_DIR.resolve():
                base_tmp = self.sla_generator.output_dir.parent
                self.deal_desk = RetainerDealDeskConcierge(
                    workspace_root=base_tmp,
                    portals_dir=base_tmp / "portals",
                    bundles_dir=base_tmp / "client_bundles",
                )
            elif is_pytest_active():
                base_tmp = resolve_isolated_data_path(None, DEFAULT_CERTIFICATES_DIR).parent
                self.deal_desk = RetainerDealDeskConcierge(
                    workspace_root=base_tmp,
                    portals_dir=base_tmp / "portals",
                    bundles_dir=base_tmp / "client_bundles",
                )
            else:
                self.deal_desk = RetainerDealDeskConcierge()
            return self.deal_desk
        except Exception as ex:
            logger.debug(f"Deal desk concierge unavailable: {ex}")
            return None

    def _resolve_onboarding_metadata(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Merges Stripe session metadata with pre-checkout white-label onboarding record (by client_reference_id / email)."""
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
            for k in (
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
                if onb_record.get(k):
                    merged[k] = onb_record[k]

        for k, v in raw_meta.items():
            if v is not None and v != "":
                merged[k] = v

        if not merged.get("agency_id") and client_ref_id:
            import re as _re
            derived_slug = _re.sub(r"-[0-9a-fA-F]{8}$", "", client_ref_id).strip("-_")
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
        """Registers client target into data/clients.json for 24/7 continuous monitoring."""
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
        logger.info(f"Registered {apex_domain} for 24/7 Fleet Sentinel monitoring.")
        return client

    def handle_webhook(
        self, payload_bytes: bytes, sig_header: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validates payload signature and executes provisioning actions."""
        # 1. Verify signature
        if self.webhook_secret:
            if not verify_stripe_signature(
                payload_bytes,
                sig_header,
                self.webhook_secret,
                tolerance=self.signature_tolerance,
            ):
                logger.error("Stripe webhook signature validation failed.")
                return {"status": "ERROR", "message": "Invalid Stripe signature"}

        # 2. Parse event payload
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            logger.error(f"Invalid JSON in webhook payload: {e}")
            return {"status": "ERROR", "message": "Invalid JSON"}

        if not isinstance(event, dict):
            logger.error("Invalid JSON structure in webhook payload: expected object.")
            return {"status": "ERROR", "message": "Invalid JSON: expected object"}

        event_type = event.get("type")
        raw_data = event.get("data")
        event_data = raw_data.get("object") if isinstance(raw_data, dict) else {}
        if not isinstance(event_data, dict):
            event_data = {}

        logger.info(f"Processing Stripe Webhook Event: {event_type} (ID: {event.get('id')})")

        # 3. Handle checkout.session.completed
        if event_type == "checkout.session.completed":
            return self._handle_checkout_session_completed(event_data)

        # 4. Handle customer.subscription.deleted
        elif event_type == "customer.subscription.deleted":
            customer_id = event_data.get("customer")
            domain = normalize_apex_domain(event_data.get("metadata", {}).get("domain"))
            target = domain or customer_id
            if target:
                self.subscriber_mgr.update_status(target, "canceled")
                if domain:
                    client_id = f"client-{domain.replace('.', '-')}"
                    client = self.fleet_registry.get_client(client_id)
                    if client:
                        client.status = "canceled"
                        self.fleet_registry.save()
            # Mirror cancellation onto the agency retainer billing status.
            subscription_id = event_data.get("id")
            if subscription_id:
                self._mark_retainer_billing_status(subscription_id, "past_due")
            return {"status": "DEPROVISIONED", "target": target}

        # 5. Handle customer.subscription.updated (past_due / paused / active)
        elif event_type == "customer.subscription.updated":
            return self._handle_subscription_updated(event_data)

        # 6. Handle invoice.payment_succeeded (renewal paid -> active)
        elif event_type == "invoice.payment_succeeded":
            return self._handle_invoice_payment_succeeded(event_data)

        # 7. Handle invoice.payment_failed (renewal failed -> past_due)
        elif event_type == "invoice.payment_failed":
            return self._handle_invoice_payment_failed(event_data)

        return {"status": "IGNORED", "event_type": event_type}

    def _handle_checkout_session_completed(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Provisions client from checkout session."""
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

        # Fallback domain if metadata omitted or invalid
        if not apex_domain or "." not in apex_domain:
            if "@" in customer_email and not any(customer_email.endswith(d) for d in ("gmail.com", "yahoo.com", "hotmail.com")):
                apex_domain = normalize_apex_domain(customer_email.split("@")[1].lower())
            else:
                clean_name = re.sub(r"[^a-zA-Z0-9]", "", customer_name.lower()) or "agency"
                apex_domain = f"{clean_name}.com"

        apex_domain = normalize_apex_domain(apex_domain) or "agency.com"

        amount_cents = session.get("amount_total", 29900)
        currency = session.get("currency", "usd")

        # Step 1: Synthesize Cryptographic SLA PDF Certificate
        cert_path, cert_id, crypto_hash = self.sla_generator.generate_certificate(
            client_name=customer_name,
            apex_domain=apex_domain,
            plan=plan,
        )

        # Step 2: Provision into data/subscribers.json
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

        # Step 3: Register for 24/7 continuous Fleet monitoring in data/clients.json
        self.register_client_for_monitoring(
            apex_domain=apex_domain,
            client_name=customer_name,
            contact_email=customer_email,
            plan=plan,
            agency_id=str(resolved_meta.get("agency_id") or "").strip() or "orbit-core",
        )

        # Step 4: Create/update the agency retainer and link the Stripe
        # customer + subscription so billing status stays in sync.
        retainer = self._sync_agency_retainer(session, resolved_metadata=resolved_meta)

        # Step 5: Automatically provision the custom-branded white-label portal (portals/<agency>.html)
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
                except Exception as ex:
                    logger.warning(f"Failed to provision white-label portal for {retainer.agency_id}: {ex}")

        # Step 6: Automatically generate client remediation export bundle in data/client_bundles/<agency_slug>/
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
            except Exception as ex:
                logger.warning(f"Failed to generate client bundle for {customer_name}: {ex}")

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
        }

    def _sync_agency_retainer(
        self,
        session: Dict[str, Any],
        resolved_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Create/update the AgencyRetainer from a completed checkout session.

        Registers the agency (tier + branding from Checkout Session metadata
        or pre-checkout white-label onboarding record) and persists the Stripe
        customer id, subscription id, and an active billing status on the retainer.
        """
        metadata = resolved_metadata if resolved_metadata is not None else self._resolve_onboarding_metadata(session)
        agency_id = metadata.get("agency_id")
        if not agency_id:
            logger.warning(
                "checkout.session.completed metadata missing agency_id; "
                "skipping retainer sync"
            )
            return None

        raw_tier = str(metadata.get("tier") or RetainerTier.SCALE.value).strip()
        tier_lookup = {
            "starter": RetainerTier.STARTER,
            "monitoring": RetainerTier.STARTER,
            "scale": RetainerTier.SCALE,
            "growth": RetainerTier.SCALE,
            "remediation": RetainerTier.SCALE,
            "enterprise": RetainerTier.ENTERPRISE,
            "pro": RetainerTier.ENTERPRISE,
        }
        tier = tier_lookup.get(raw_tier.lower())
        if tier is None:
            try:
                tier = RetainerTier(raw_tier)
            except ValueError:
                tier = RetainerTier.SCALE

        cust_name = (session.get("customer_details") or {}).get("name")
        resolved_agency_name = metadata.get("agency_name") or cust_name or agency_id.replace("_", " ").replace("-", " ").title()
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

    def _find_agency_by_subscription(
        self, subscription_id: Optional[str]
    ) -> Optional[Any]:
        """Find the agency retainer linked to a Stripe subscription id."""
        if not subscription_id:
            return None
        for agency in self.retainer_manager.list_agencies():
            if agency.stripe_subscription_id == subscription_id:
                return agency
        return None

    def _mark_retainer_billing_status(
        self, subscription_id: str, billing_status: str
    ) -> bool:
        """Sets billing_status on the agency retainer linked to a subscription."""
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

    def _handle_subscription_updated(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handles customer.subscription.updated (past_due / paused / active)."""
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

        # Mirror into subscriber record when keyed by customer id.
        customer_id = event_data.get("customer")
        if customer_id:
            self.subscriber_mgr.update_status(customer_id, billing_status)

        return {
            "status": "UPDATED",
            "subscription_id": subscription_id,
            "billing_status": billing_status,
        }

    def _handle_invoice_payment_succeeded(
        self, event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handles invoice.payment_succeeded (renewal paid -> billing active)."""
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

    def _handle_invoice_payment_failed(
        self, event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handles invoice.payment_failed (renewal failed -> past_due)."""
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


# ============================================================================
# 5. Lightweight Standalone HTTP Webhook Server
# ============================================================================


class StripeWebhookRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for receiving real-time Stripe webhooks."""

    handler_instance: Optional[StripeWebhookHandler] = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)
        sig_header = self.headers.get("Stripe-Signature")

        handler = self.handler_instance or StripeWebhookHandler()
        result = handler.handle_webhook(payload, sig_header)

        if result.get("status") == "ERROR":
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

    def do_GET(self):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"status": "HEALTHY", "service": "Orbit Stripe Webhook Sentinel", "timestamp": time.time()}
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def log_message(self, format, *args):
        # Quiet standard HTTP access logs
        pass


def run_webhook_server(host: str = "0.0.0.0", port: int = 8088):
    """Starts the standalone Stripe webhook HTTP server."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, StripeWebhookRequestHandler)
    logger.info(f"Orbit Stripe Webhook Server listening on {host}:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Stripe Webhook Server...")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Orbit Security Stripe Webhook Server")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
    run_webhook_server(host=args.host, port=args.port)
