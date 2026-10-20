#!/usr/bin/env python3
"""Runner script for Orbit Security Stripe Checkout Signup Server (run_stripe_checkout.py).

Usage:
    python scripts/run_stripe_checkout.py --port 8089

Serves landing/signup.html at / and creates Stripe Checkout Sessions on
POST /create-checkout-session, 302-redirecting the browser to Stripe. On
success Stripe redirects back to /portal/<agency_id> (the generated
white-label portal at docs/portals/<slug>.html).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure local src/ is on sys.path (same pattern as other scripts/)
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.stripe_checkout import run_checkout_server  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [STRIPE-CHECKOUT] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_stripe_checkout")


def main():
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
    run_checkout_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
