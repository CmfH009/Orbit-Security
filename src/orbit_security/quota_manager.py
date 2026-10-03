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
    max_hourly_replies: int = 0  # Automated commenting/replies disabled to prevent platform flags
    max_hourly_likes: int = 6
    max_hourly_reposts: int = 2
    max_hourly_follows: int = 0  # Automated following disabled to prevent platform flags

    # Hard Daily Caps
    max_daily_posts: int = 2  # Scaled to twice a day (morning & evening cadence)
    max_daily_replies: int = 0  # Automated commenting/replies disabled

    max_daily_likes: int = 50
    max_daily_reposts: int = 10
    max_daily_follows: int = 0  # Automated following disabled

    # Minimum spacing between original posts in hours to distribute them across the day
    min_post_spacing_hours: float = 8.0


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

    def _get_now_utc(self) -> datetime.datetime:
        """Helper to get current UTC datetime, facilitating deterministic testing."""
        return datetime.datetime.now(datetime.timezone.utc)

    def reset_hourly_cycle(self):
        """Resets the hourly burst tracking for a new execution cycle."""
        now_utc = self._get_now_utc()
        self.current_cycle_hour = now_utc.hour
        for k in self.hourly_executed:
            self.hourly_executed[k] = 0

        # Check for midnight UTC rollover
        today_utc = now_utc.strftime("%Y-%m-%d")
        if today_utc != self.last_rollover_date:
            logger.info(f"Midnight UTC rollover detected: {self.last_rollover_date} -> {today_utc}")
            self.last_rollover_date = today_utc

    def get_time_of_day_multiplier(self) -> float:
        """Enforces uniform 24/7 active pacing without artificial quiet or dormant windows."""
        return 1.0

    def can_perform(
        self,
        action_type: str,
        allow_dormant: bool = False,
        ignore_spacing: bool = False,
    ) -> bool:
        """Determines if a given action is permissible within both hourly and daily quotas."""
        act_upper = action_type.upper()
        if act_upper in ("ORIGINAL_POST", "POST"):
            norm = "POST"
            hourly_limit = self.budget.max_hourly_posts
            daily_limit = self.budget.max_daily_posts
            daily_key = "posts_count"
        elif act_upper in ("REPLY", "COMMENT"):
            # Automated commenting and replies permanently disabled to prevent platform flags
            return False
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
            # Automated follows permanently disabled to prevent platform flags
            return False
        else:
            return False

        # Apply time-of-day curve
        multiplier = self.get_time_of_day_multiplier()
        if multiplier == 0.0:
            if not allow_dormant:
                return False
            multiplier = 0.6  # Default fallback multiplier for allowed dormant operations

        effective_hourly = max(1, int(round(hourly_limit * multiplier))) if hourly_limit > 0 else 0

        # Check hourly burst limit
        if self.hourly_executed.get(norm, 0) >= effective_hourly:
            return False

        # Check daily hard cap
        daily_metrics = self.state_manager.get_daily_metrics()
        current_daily_count = daily_metrics.get(daily_key, 0)
        if current_daily_count >= daily_limit:
            return False

        # For original posts: enforce minimum inter-post spacing so the 2 daily posts
        # are distributed across the day rather than fired in consecutive cycles
        if norm == "POST" and not ignore_spacing and self.budget.min_post_spacing_hours > 0:
            if hasattr(self.state_manager, "get_last_post_media_info"):
                last_post = self.state_manager.get_last_post_media_info()
                if last_post and last_post.get("created_at_utc"):
                    try:
                        last_ts = str(last_post["created_at_utc"])
                        if last_ts.endswith("Z"):
                            last_ts = last_ts[:-1] + "+00:00"
                        last_dt = datetime.datetime.fromisoformat(last_ts)
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=datetime.timezone.utc)
                        now_utc = self._get_now_utc()
                        elapsed_hours = (now_utc - last_dt).total_seconds() / 3600.0
                        if elapsed_hours < self.budget.min_post_spacing_hours:
                            logger.info(
                                f"Post spacing pacing: {elapsed_hours:.1f}h elapsed since last post "
                                f"(minimum {self.budget.min_post_spacing_hours}h required for 2/day cadence). Skipping POST."
                            )
                            return False
                    except Exception as e:
                        logger.warning(f"Error parsing last post timestamp: {e}")

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
            "min_post_spacing_hours": self.budget.min_post_spacing_hours,
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
