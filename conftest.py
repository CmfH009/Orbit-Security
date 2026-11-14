"""Pytest configuration for Orbit Security.

Ensures the repository root (and thus the ``orbit`` namespace package shipped
alongside the installed ``orbit_security`` src package) is importable
regardless of how pytest is invoked -- full collection (``uv run pytest``) or
explicit file arguments (``uv run pytest tests/test_foo.py``).

It also marks the boundary between this package and its sibling repository.
"""
from pathlib import Path
import os
import sys
import threading
import pytest


_ORIG_THREAD_START = threading.Thread.start


def _guarded_thread_start(self: threading.Thread) -> None:
    """Prevent sibling A:/system/bin/run_menu.py from spawning an infinite background
    telemetry poller inside pytest when cockpit server modules are imported."""
    target = getattr(self, "_target", None)
    if (
        callable(target)
        and getattr(target, "__name__", None) == "background_telemetry_scanner"
        and getattr(target, "__module__", "") == "run_menu"
    ):
        return None
    return _ORIG_THREAD_START(self)


def pytest_configure(config) -> None:
    if threading.Thread.start is not _guarded_thread_start:
        threading.Thread.start = _guarded_thread_start  # type: ignore[method-assign]


def pytest_unconfigure(config) -> None:
    if threading.Thread.start is _guarded_thread_start:
        threading.Thread.start = _ORIG_THREAD_START  # type: ignore[method-assign]

@pytest.fixture(autouse=True)
def _isolate_stripe_env(monkeypatch):
    """Isolate test environment from production webhook secrets loaded via .env."""
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)


_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ---------------------------------------------------------------------------
# Cross-repo integration tests
# ---------------------------------------------------------------------------
# These modules exercise daemons that live in the sibling AgyHut system repo
# (A:\system\scripts\orbit_daemon.py, nova_email_daemon.py), not in this
# package. They are meaningful on the operator's machine, but where that repo
# is absent -- a CI runner, or any machine that only has this checkout -- they
# cannot even be imported, and the import error aborts collection for the whole
# suite. Skipping them keeps the cross-repo boundary explicit and leaves the
# rest of the suite running.
#
# Set ORBIT_SKIP_SIBLING_TESTS=1 to force the skip (useful for reproducing a
# CI run locally).
_SIBLING_SCRIPTS = Path("A:/system/scripts")
if not _SIBLING_SCRIPTS.exists():
    _SIBLING_SCRIPTS = Path(r"C:\AgyHut\system\scripts")

_SIBLING_TEST_MODULES = [
    "tests/test_act2_inbound_automation.py",
    "tests/test_act3_capital_and_bounty.py",
    "tests/test_nova_email_daemon.py",
    "tests/test_supervisor_canary.py",
    "tests/test_mega_skill_orchestration.py",
    "tests/test_orbit_orchestrator_stress.py",
]

if os.environ.get("ORBIT_SKIP_SIBLING_TESTS") == "1" or not _SIBLING_SCRIPTS.exists():
    collect_ignore = list(_SIBLING_TEST_MODULES)
