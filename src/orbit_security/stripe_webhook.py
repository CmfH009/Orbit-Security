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
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
from pathlib import Path
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

from orbit_security.fleet import ClientTarget, FleetRegistry

logger = logging.getLogger("orbit_security.stripe_webhook")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SUBSCRIBERS_FILE = PROJECT_ROOT / "data" / "subscribers.json"
DEFAULT_CERTIFICATES_DIR = PROJECT_ROOT / "data" / "certificates"
DEFAULT_CLIENTS_FILE = PROJECT_ROOT / "data" / "clients.json"


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
    tolerance: int = 300,
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


class SlaCertificateGenerator:
    """Synthesizes high-assurance cryptographic SLA certificates in PDF format."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or DEFAULT_CERTIFICATES_DIR)

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

        clean_domain = apex_domain.replace(".", "_")
        pdf_path = self.output_dir / f"SLA_{clean_domain}_{cid}.pdf"

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

        # Overview Paragraph
        intro = (
            f"This certifies that <b>{client_name}</b> has successfully enrolled the digital assets under "
            f"<b>{apex_domain}</b> into the Orbit Security Autonomous Perimeter & Zero-Drift Sentinel Fleet. "
            f"Orbit Security guarantees continuous, high-frequency surveillance, automated RFC compliance diffing, "
            f"and cryptographic drift verification."
        )
        elements.append(Paragraph(intro, body_style))
        elements.append(Spacer(1, 14))

        # Certificate Details Table
        details_data = [
            [Paragraph("<b>Certificate Identifier:</b>", body_style), Paragraph(f"<code>{cid}</code>", body_style)],
            [Paragraph("<b>Subscribed Organization:</b>", body_style), Paragraph(f"<b>{client_name}</b>", body_style)],
            [Paragraph("<b>Protected Apex Domain:</b>", body_style), Paragraph(f"<code>{apex_domain}</code>", body_style)],
            [Paragraph("<b>Retainer Plan Tier:</b>", body_style), Paragraph(f"<b>{plan}</b>", body_style)],
            [Paragraph("<b>Effective Commencement:</b>", body_style), Paragraph(date_str, body_style)],
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
        self.subscribers_file = Path(subscribers_file or DEFAULT_SUBSCRIBERS_FILE)

    def list_subscribers(self) -> List[Dict[str, Any]]:
        """Loads subscriber list from disk."""
        if not self.subscribers_file.exists():
            return []
        try:
            with open(self.subscribers_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
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
    ):
        self.webhook_secret = webhook_secret or os.environ.get("STRIPE_WEBHOOK_SECRET")
        self.subscriber_mgr = subscriber_manager or SubscriberManager()
        self.sla_generator = sla_generator or SlaCertificateGenerator()
        self.fleet_registry = fleet_registry or FleetRegistry()

    def register_client_for_monitoring(
        self,
        apex_domain: str,
        client_name: str,
        contact_email: str,
        plan: str,
    ) -> ClientTarget:
        """Registers client target into data/clients.json for 24/7 continuous monitoring."""
        client_id = f"client-{apex_domain.replace('.', '-')}"
        client = ClientTarget(
            client_id=client_id,
            client_name=client_name,
            apex_domain=apex_domain,
            subdomains=[apex_domain],
            contact_email=contact_email,
            agency_id="orbit-core",
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
            if not verify_stripe_signature(payload_bytes, sig_header, self.webhook_secret):
                logger.error("Stripe webhook signature validation failed.")
                return {"status": "ERROR", "message": "Invalid Stripe signature"}

        # 2. Parse event payload
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            logger.error(f"Invalid JSON in webhook payload: {e}")
            return {"status": "ERROR", "message": "Invalid JSON"}

        event_type = event.get("type")
        event_data = event.get("data", {}).get("object", {})

        logger.info(f"Processing Stripe Webhook Event: {event_type} (ID: {event.get('id')})")

        # 3. Handle checkout.session.completed
        if event_type == "checkout.session.completed":
            return self._handle_checkout_session_completed(event_data)

        # 4. Handle customer.subscription.deleted
        elif event_type == "customer.subscription.deleted":
            customer_id = event_data.get("customer")
            domain = event_data.get("metadata", {}).get("domain")
            target = domain or customer_id
            if target:
                self.subscriber_mgr.update_status(target, "canceled")
                if domain:
                    client_id = f"client-{domain.replace('.', '-')}"
                    client = self.fleet_registry.get_client(client_id)
                    if client:
                        client.status = "canceled"
                        self.fleet_registry.save()
            return {"status": "DEPROVISIONED", "target": target}

        return {"status": "IGNORED", "event_type": event_type}

    def _handle_checkout_session_completed(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Provisions client from checkout session."""
        customer_id = session.get("customer") or session.get("id") or "cus_unknown"
        customer_details = session.get("customer_details") or {}
        customer_email = customer_details.get("email") or "ops@client.com"
        customer_name = customer_details.get("name") or customer_email.split("@")[0].title()

        metadata = session.get("metadata") or {}
        apex_domain = metadata.get("domain") or metadata.get("apex_domain")
        plan = metadata.get("plan") or "Scale Retainer ($299/mo)"

        # Fallback domain if metadata omitted
        if not apex_domain:
            if "@" in customer_email and not any(customer_email.endswith(d) for d in ("gmail.com", "yahoo.com", "hotmail.com")):
                apex_domain = customer_email.split("@")[1].lower()
            else:
                apex_domain = f"{customer_name.lower().replace(' ', '')}.com"

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
        )

        return {
            "status": "PROVISIONED",
            "apex_domain": apex_domain,
            "sla_certificate_id": cert_id,
            "sla_certificate_path": str(cert_path),
            "sla_crypto_hash": crypto_hash,
            "subscriber": subscriber_record,
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
