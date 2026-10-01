"""Orbit Security Performance & Bandit Flywheel Optimizer (flywheel_optimizer.py).

Agent Persona: @OrbitFlywheel
Mandate: Tracks audience resonance, impressions, and engagement metrics on X,
using a Multi-Armed Bandit algorithm to dynamically adapt content pillar allocations
and posting velocity for maximum organic growth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
import math
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple

from orbit_security.marketing_strategy import ContentPillar

logger = logging.getLogger(__name__)


@dataclass
class PillarPerformance:
    """Historical engagement metrics for a specific content pillar."""

    pillar: str
    posts_count: int = 0
    total_likes: int = 0
    total_reposts: int = 0
    total_replies: int = 0
    total_bookmarks: int = 0
    estimated_impressions: int = 0

    @property
    def engagement_score(self) -> float:
        """Computes weighted engagement index per post."""
        if self.posts_count == 0:
            return 1.0  # optimistic prior for un-sampled arms
        weight = (
            self.total_likes * 1.0
            + self.total_reposts * 3.0
            + self.total_replies * 2.5
            + self.total_bookmarks * 4.0
        )
        return round(weight / self.posts_count, 3)


class FlywheelOptimizer:
    """Adaptive Multi-Armed Bandit (Softmax / Boltzmann) content allocator."""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        temperature: float = 1.2,
        min_weight: float = 0.10,
    ):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.state_file = self.root / "data" / "flywheel_state.json"
        self.history_file = self.root / "data" / "social_history.json"
        self.temperature = temperature
        self.min_weight = min_weight
        self._load_state()

    def _load_state(self) -> None:
        """Loads persistent bandit weights and performance records."""
        self.performance: Dict[str, PillarPerformance] = {
            p.value: PillarPerformance(pillar=p.value) for p in ContentPillar
        }
        self.current_weights: Dict[str, float] = {
            ContentPillar.BREAK_AND_FIX.value: 0.40,
            ContentPillar.HIGH_IQ_WIT.value: 0.25,
            ContentPillar.MULTIMODAL_VISUAL.value: 0.20,
            ContentPillar.AGENCY_GROWTH.value: 0.15,
        }

        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.current_weights = data.get("current_weights", self.current_weights)
                    perf_data = data.get("performance", {})
                    for k, v in perf_data.items():
                        if k in self.performance:
                            self.performance[k] = PillarPerformance(**v)
            except Exception as e:
                logger.error(f"Error loading flywheel_state.json: {e}")

    def _save_state(self) -> None:
        """Persists updated weights and bandit parameters."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            payload = {
                "last_optimized_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "temperature": self.temperature,
                "current_weights": self.current_weights,
                "performance": {k: asdict(v) for k, v in self.performance.items()},
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving flywheel_state.json: {e}")

    def record_post_feedback(
        self,
        pillar: str,
        likes: int = 0,
        reposts: int = 0,
        replies: int = 0,
        bookmarks: int = 0,
    ) -> None:
        """Updates empirical engagement stats for a pillar."""
        if pillar not in self.performance:
            self.performance[pillar] = PillarPerformance(pillar=pillar)

        perf = self.performance[pillar]
        perf.posts_count += 1
        perf.total_likes += likes
        perf.total_reposts += reposts
        perf.total_replies += replies
        perf.total_bookmarks += bookmarks
        self._recalculate_weights()
        self._save_state()

    def _recalculate_weights(self) -> None:
        """Calculates Softmax exploration-exploitation weights across pillars."""
        scores = {p: self.performance[p].engagement_score for p in self.performance}

        # Softmax with temperature
        exp_scores = {
            p: math.exp(min(score / max(self.temperature, 0.1), 10.0))
            for p, score in scores.items()
        }
        total_exp = sum(exp_scores.values()) or 1.0

        raw_weights = {p: exp_scores[p] / total_exp for p in exp_scores}

        # Enforce minimum exploration weight per pillar
        adjusted: Dict[str, float] = {}
        for p, w in raw_weights.items():
            adjusted[p] = max(w, self.min_weight)

        total_adjusted = sum(adjusted.values())
        self.current_weights = {
            p: round(v / total_adjusted, 3) for p, v in adjusted.items()
        }
        logger.info(f"Flywheel updated content weights: {self.current_weights}")

    def sample_next_pillar(self) -> ContentPillar:
        """Samples the next content pillar according to the current bandit distribution."""
        pillars = list(self.current_weights.keys())
        weights = [self.current_weights[p] for p in pillars]
        chosen = random.choices(pillars, weights=weights, k=1)[0]
        return ContentPillar(chosen)
