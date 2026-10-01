"""Orbit Security Social Quota & Anti-Bot Governor (quota_manager.py).

Enforces strict hourly velocity limits, hard daily caps, time-of-day modulation,
and midnight UTC rollover management to prevent X anti-bot heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import logging
from typing import Any, Dict, Optional

from orbit_security.social_state import SocialStateManager

logger = logging.getLogger(__name__)


@dataclass
class QuotaBudget:
    # Hourly Burst Limits
    max_hourly_posts: int = 1
    max_hourly_replies: int = 3
    max_hourly_likes: int = 6
    max_hourly_reposts: int = 2
    max_hourly_follows: int = 3

    # Hard Daily Caps
    max_daily_posts: int = 12
    max_daily_replies: int = 20

    max_daily_likes: int = 50
    max_daily_reposts: int = 10
    max_daily_follows: int = 15


class SocialQuotaManager:
    """Calculates remaining action allowances per hour and per day."""

    def __init__(
        self,
        state_manager: SocialStateManager,
        budget: Optional[QuotaBudget] = None,
    ):
        self.state_manager = state_manager
        self.budget = budget or QuotaBudget()

        # In-memory hourly execution counters for current cycle
        self.hourly_executed: Dict[str, int] = {
            "POST": 0,
            "REPLY": 0,
            "LIKE": 0,
            "REPOST": 0,
            "FOLLOW": 0,
        }
        self.current_cycle_hour: Optional[int] = None
        self.last_rollover_date: str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def reset_hourly_cycle(self):
        """Resets the hourly burst tracking for a new execution cycle."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        self.current_cycle_hour = now_utc.hour
        for k in self.hourly_executed:
            self.hourly_executed[k] = 0

        # Check for midnight UTC rollover
        today_utc = now_utc.strftime("%Y-%m-%d")
        if today_utc != self.last_rollover_date:
            logger.info(f"Midnight UTC rollover detected: {self.last_rollover_date} -> {today_utc}")
            self.last_rollover_date = today_utc

    def get_time_of_day_multiplier(self) -> float:
        """Modulates activity based on agency business hours.
        - Peak (13:00 - 21:00 UTC): 1.0 (US/UK working day)
        - Shoulder (08:00 - 13:00 UTC / 21:00 - 01:00 UTC): 0.6
        - Dormant (01:00 - 08:00 UTC): 0.0 (Night quiet period)
        """
        hour = datetime.datetime.now(datetime.timezone.utc).hour
        if 13 <= hour < 21:
            return 1.0
        elif 8 <= hour < 13 or 21 <= hour < 24 or hour == 0:
            return 0.6
        else:
            return 0.0

    def can_perform(self, action_type: str) -> bool:
        """Determines if a given action is permissible within both hourly and daily quotas."""
        act_upper = action_type.upper()
        if act_upper in ("ORIGINAL_POST", "POST"):
            norm = "POST"
            hourly_limit = self.budget.max_hourly_posts
            daily_limit = self.budget.max_daily_posts
            daily_key = "posts_count"
        elif act_upper in ("REPLY", "COMMENT"):
            norm = "REPLY"
            hourly_limit = self.budget.max_hourly_replies
            daily_limit = self.budget.max_daily_replies
            daily_key = "replies_count"
        elif act_upper == "LIKE":
            norm = "LIKE"
            hourly_limit = self.budget.max_hourly_likes
            daily_limit = self.budget.max_daily_likes
            daily_key = "likes_count"
        elif act_upper in ("REPOST", "RETWEET", "QUOTE"):
            norm = "REPOST"
            hourly_limit = self.budget.max_hourly_reposts
            daily_limit = self.budget.max_daily_reposts
            daily_key = "reposts_count"
        elif act_upper == "FOLLOW":
            norm = "FOLLOW"
            hourly_limit = self.budget.max_hourly_follows
            daily_limit = self.budget.max_daily_follows
            daily_key = "follows_count"
        else:
            return False

        # Apply time-of-day curve
        multiplier = self.get_time_of_day_multiplier()
        if multiplier == 0.0:
            return False

        effective_hourly = max(1, int(round(hourly_limit * multiplier))) if hourly_limit > 0 else 0

        # Check hourly burst limit
        if self.hourly_executed.get(norm, 0) >= effective_hourly:
            return False

        # Check daily hard cap
        daily_metrics = self.state_manager.get_daily_metrics()
        current_daily_count = daily_metrics.get(daily_key, 0)
        if current_daily_count >= daily_limit:
            return False

        return True

    def record_hourly_action(self, action_type: str):
        """Increments in-memory hourly usage."""
        act_upper = action_type.upper()
        norm_map = {
            "ORIGINAL_POST": "POST",
            "POST": "POST",
            "REPLY": "REPLY",
            "COMMENT": "REPLY",
            "LIKE": "LIKE",
            "REPOST": "REPOST",
            "RETWEET": "REPOST",
            "QUOTE": "REPOST",
            "FOLLOW": "FOLLOW",
        }
        norm = norm_map.get(act_upper)
        if norm and norm in self.hourly_executed:
            self.hourly_executed[norm] += 1

    def get_status_summary(self) -> Dict[str, Any]:
        """Returns structured quota headroom snapshot."""
        daily = self.state_manager.get_daily_metrics()
        mult = self.get_time_of_day_multiplier()

        return {
            "time_of_day_band": "PEAK" if mult >= 1.0 else ("SHOULDER" if mult > 0.0 else "DORMANT"),
            "velocity_multiplier": mult,
            "hourly_executed": dict(self.hourly_executed),
            "hourly_limits": {
                "posts": self.budget.max_hourly_posts,
                "replies": self.budget.max_hourly_replies,
                "likes": self.budget.max_hourly_likes,
                "reposts": self.budget.max_hourly_reposts,
                "follows": self.budget.max_hourly_follows,
            },
            "daily_executed": daily,
            "daily_caps": {
                "posts": self.budget.max_daily_posts,
                "replies": self.budget.max_daily_replies,
                "likes": self.budget.max_daily_likes,
                "reposts": self.budget.max_daily_reposts,
                "follows": self.budget.max_daily_follows,
            },
        }
