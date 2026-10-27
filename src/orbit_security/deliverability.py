"""Deliverability guardrails for outbound cold outreach.

Sender reputation is a shared, slowly-recoverable resource: a cohort that bounces
above a few percent can get the sending domain throttled or blocklisted, which
kills every future campaign regardless of content quality.

This module computes the observed bounce rate from the two ledgers the outreach
pipelines already maintain and refuses to dispatch when the rate is unsafe.
It is deliberately a caller-side gate rather than a transport-level one, so
draft/.eml export paths and unit tests are unaffected.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DISPATCHED_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"
DEFAULT_BOUNCED_PATH = REPO_ROOT / "data" / "bounced_agencies.json"

# Gmail/Workspace guidance is to stay under 3%; 5% is the hard stop where a
# sending domain starts losing reputation. Anything above 10% should stop all
# sending until the list is cleaned.
DEFAULT_MAX_BOUNCE_RATE = 0.05
MIN_SAMPLE_SIZE = 20


class DeliverabilityBlocked(RuntimeError):
    """Raised when the observed bounce rate makes further sending unsafe."""


def _load_count(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    if isinstance(data, dict):
        return len(data)
    if isinstance(data, list):
        return len(data)
    return 0


def bounce_stats(
    dispatched_path: Optional[Path] = None,
    bounced_path: Optional[Path] = None,
) -> Tuple[int, int, float]:
    """Returns (dispatched, bounced, rate) from the outreach ledgers."""
    sent = _load_count(Path(dispatched_path or DEFAULT_DISPATCHED_PATH))
    bounced = _load_count(Path(bounced_path or DEFAULT_BOUNCED_PATH))
    rate = (bounced / sent) if sent else 0.0
    return sent, bounced, rate


def assert_deliverable(
    force: bool = False,
    max_bounce_rate: float = DEFAULT_MAX_BOUNCE_RATE,
    dispatched_path: Optional[Path] = None,
    bounced_path: Optional[Path] = None,
) -> Tuple[int, int, float]:
    """Blocks dispatch when the bounce rate exceeds ``max_bounce_rate``.

    Returns (dispatched, bounced, rate). Raises DeliverabilityBlocked when the
    rate is unsafe and neither ``force`` nor ORBIT_ALLOW_HIGH_BOUNCE=1 is set.
    Small samples (< MIN_SAMPLE_SIZE) are allowed through: a handful of early
    bounces is noise, not a reputation signal.
    """
    sent, bounced, rate = bounce_stats(dispatched_path, bounced_path)

    env_override = str(os.getenv("ORBIT_ALLOW_HIGH_BOUNCE", "")).strip().lower() in {
        "1", "true", "yes", "on",
    }

    if sent < MIN_SAMPLE_SIZE or rate <= max_bounce_rate:
        return sent, bounced, rate

    if force or env_override:
        return sent, bounced, rate

    raise DeliverabilityBlocked(
        f"Bounce rate {rate:.1%} ({bounced}/{sent}) exceeds the {max_bounce_rate:.0%} "
        "safe ceiling. Sending another cohort now risks throttling or blocklisting "
        "the sending domain. Clean the list (remove hard-bounced domains), let the "
        "rate recover, then re-run. Override with --allow-high-bounce or "
        "ORBIT_ALLOW_HIGH_BOUNCE=1."
    )
