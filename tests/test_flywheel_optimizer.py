"""Unit tests for Flywheel Optimizer (flywheel_optimizer.py)."""

from pathlib import Path
import tempfile
import pytest

from orbit_security.flywheel_optimizer import FlywheelOptimizer
from orbit_security.marketing_strategy import ContentPillar


def test_flywheel_initialization_and_weights():
    with tempfile.TemporaryDirectory() as tmpdir:
        flywheel = FlywheelOptimizer(project_root=Path(tmpdir))
        assert ContentPillar.BREAK_AND_FIX.value in flywheel.current_weights
        total_w = sum(flywheel.current_weights.values())
        assert abs(total_w - 1.0) < 0.05


def test_flywheel_feedback_adaptation():
    with tempfile.TemporaryDirectory() as tmpdir:
        flywheel = FlywheelOptimizer(project_root=Path(tmpdir))
        # Record massive engagement on high_iq_wit
        for _ in range(5):
            flywheel.record_post_feedback(
                pillar=ContentPillar.HIGH_IQ_WIT.value,
                likes=150,
                reposts=45,
                bookmarks=30,
            )

        # High IQ Wit weight should increase relative to min_weight
        assert flywheel.current_weights[ContentPillar.HIGH_IQ_WIT.value] > 0.25

        sampled = flywheel.sample_next_pillar()
        assert isinstance(sampled, ContentPillar)
