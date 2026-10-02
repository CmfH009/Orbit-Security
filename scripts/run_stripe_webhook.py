#!/usr/bin/env python3
"""Runner script for Orbit Security Stripe Webhook Server (run_stripe_webhook.py).

Usage:
    python scripts/run_stripe_webhook.py --port 8088
    python scripts/run_stripe_webhook.py --test-event
    python scripts/run_stripe_webhook.py --list-subscribers
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

# Ensure src is in python path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.stripe_webhook import (
    StripeWebhookHandler,
    SubscriberManager,
    generate_stripe_signature,
    run_webhook_server,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [STRIPE-SENTINEL] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_stripe_webhook")


def list_subscribers():
    mgr = SubscriberManager()
    subs = mgr.list_subscribers()
    print(f"\n=== Orbit Security Active Subscribers ({len(subs)}) ===")
    if not subs:
        print("No active subscribers in data/subscribers.json.")
        return

    for s in subs:
        print(f"\n• Subscriber: {s.get('customer_name')} ({s.get('customer_email')})")
        print(f"  Apex Domain: {s.get('apex_domain')}")
        print(f"  Plan: {s.get('plan')} | Status: {s.get('status').upper()} | Monitored: {s.get('monitoring_enabled')}")
        print(f"  SLA Certificate: {s.get('sla_certificate_id')} ({s.get('sla_certificate_path')})")
        print(f"  Crypto Fingerprint: {s.get('sla_crypto_hash')}")


def dispatch_test_event():
    logger.info("Simulating test checkout.session.completed event...")
    test_secret = "whsec_test_local_key"
    handler = StripeWebhookHandler(webhook_secret=test_secret)

    event_payload = {
        "id": "evt_test_checkout_local",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_simulated_session_local",
                "customer": "cus_simulated_001",
                "customer_details": {
                    "email": "security@velvetcraft.com",
                    "name": "Velvet Craft Apparel",
                },
                "metadata": {
                    "domain": "velvetcraft.com",
                    "plan": "Scale Retainer ($299/mo)",
                },
                "amount_total": 29900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }

    payload_bytes = json.dumps(event_payload).encode("utf-8")
    sig_header = generate_stripe_signature(payload_bytes, test_secret)

    result = handler.handle_webhook(payload_bytes, sig_header)
    logger.info(f"Test Event Result: {result.get('status')}")
    print(f"\n[PROVISIONING SUMMARY]:\n{json.dumps(result, indent=2)}\n")


def main():
    parser = argparse.ArgumentParser(description="Orbit Stripe Webhook Sentinel")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--test-event", action="store_true", help="Simulate a test checkout.session.completed event")
    parser.add_argument("--list-subscribers", action="store_true", help="List all active subscribers")
    args = parser.parse_args()

    if args.list_subscribers:
        list_subscribers()
        return

    if args.test_event:
        dispatch_test_event()
        return

    run_webhook_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
