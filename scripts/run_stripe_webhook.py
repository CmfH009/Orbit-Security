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
import tempfile
from typing import Optional

# Ensure src is in python path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    _sys_scripts = Path("A:/system/scripts")
    if _sys_scripts.exists() and str(_sys_scripts) not in sys.path:
        sys.path.insert(0, str(_sys_scripts))
    import win_console
    win_console.make_stdout_safe()
    win_console.suppress_child_windows()
except Exception:
    pass

from orbit_security.agency_retainer import AgencyRetainerManager  # noqa: E402
from orbit_security.deal_desk import RetainerDealDeskConcierge  # noqa: E402
from orbit_security.fleet import FleetRegistry  # noqa: E402
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
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


def dispatch_test_event(
    output_dir: Optional[Path] = None,
    *,
    live: bool = False,
):
    logger.info("Simulating test checkout.session.completed event...")
    test_secret = "whsec_test_local_key"
    temp_ctx: Optional[tempfile.TemporaryDirectory[str]] = None

    if live:
        handler = StripeWebhookHandler(webhook_secret=test_secret)
        target_root: Optional[Path] = None
    else:
        if output_dir is None:
            temp_ctx = tempfile.TemporaryDirectory(prefix="orbit_webhook_dryrun_")
            target_root = Path(temp_ctx.name)
        else:
            target_root = Path(output_dir).resolve()
            target_root.mkdir(parents=True, exist_ok=True)
        handler = StripeWebhookHandler(
            webhook_secret=test_secret,
            subscriber_manager=SubscriberManager(subscribers_file=target_root / "subscribers.json"),
            sla_generator=SlaCertificateGenerator(output_dir=target_root / "certificates"),
            fleet_registry=FleetRegistry(data_path=target_root / "clients.json"),
            retainer_manager=AgencyRetainerManager(data_path=target_root / "agency_retainers.json"),
            deal_desk=RetainerDealDeskConcierge(
                workspace_root=target_root,
                portals_dir=target_root / "portals",
                bundles_dir=target_root / "client_bundles",
            ),
        )

    event_payload = {
        "id": "evt_test_checkout_local",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_simulated_session_local",
                "customer": "cus_simulated_001",
                "subscription": "sub_simulated_001",
                "customer_details": {
                    "email": "security@velvetcraft.com",
                    "name": "Velvet Craft Apparel",
                },
                "metadata": {
                    "agency_id": "velvet-craft-apparel",
                    "agency_name": "Velvet Craft Apparel",
                    "tier": "Scale",
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

    try:
        result = handler.handle_webhook(payload_bytes, sig_header)
        logger.info(f"Test Event Result: {result.get('status')}")
        if target_root is not None:
            result = dict(result)
            result["isolated_dry_run_root"] = str(target_root)
        print(f"\n[PROVISIONING SUMMARY]:\n{json.dumps(result, indent=2)}\n")
        return result
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Orbit Stripe Webhook Sentinel")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--test-event", action="store_true", help="Simulate a hermetic dry-run checkout.session.completed event")
    parser.add_argument("--output-dir", type=Path, default=None, help="Optional isolated output directory for --test-event")
    parser.add_argument("--live", action="store_true", help="Write --test-event into live data/* directories (unsafe for dry runs)")
    parser.add_argument("--list-subscribers", action="store_true", help="List all active subscribers")
    args = parser.parse_args()

    if args.list_subscribers:
        list_subscribers()
        return

    if args.test_event:
        dispatch_test_event(output_dir=args.output_dir, live=args.live)
        return

    run_webhook_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
