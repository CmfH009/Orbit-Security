"""Regression tests for the X thread copy.

An over-long tweet is silently dropped by the X composer. That is how the
five-part vulnerability thread became a one-part thread with no error raised
anywhere: tweets 2-5 were 299-426 characters against a 280 character limit,
and the parent tweet URL could not be resolved afterwards.

These tests make the failure loud and impossible to ship.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
X_LIMIT = 280


def _load(name: str):
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _weighted_length(text: str) -> int:
    """X counts a URL as 23 characters; every other character counts as one."""
    total = 0
    last = 0
    for m in re.finditer(r"https?://\S+", text):
        total += len(text[last:m.start()]) + 23
        last = m.end()
    return total + len(text[last:])


THREAD_MODULES = [
    ("post_x_vulnerability_thread", "THREAD_TWEETS"),
    ("post_x_thread_continuation", "REMAINING_TWEETS"),
]


@pytest.mark.parametrize("module_name,var", THREAD_MODULES)
def test_every_thread_tweet_fits_the_x_limit(module_name, var):
    module = _load(module_name)
    tweets = getattr(module, var)
    assert tweets, f"{module_name}.{var} is empty"
    for item in tweets:
        index, body = item[0], item[1]
        length = _weighted_length(body)
        assert length <= X_LIMIT, (
            f"{module_name} tweet {index} is {length} weighted characters "
            f"(limit {X_LIMIT}). The X composer drops over-long tweets silently."
        )


@pytest.mark.parametrize("module_name,var", THREAD_MODULES)
def test_thread_guard_rejects_an_over_long_tweet(module_name, var):
    """The import-time guard must actually fire on bad copy."""
    module = _load(module_name)
    guard = getattr(module, "_assert_fits_x_limit", None)
    assert guard is not None, f"{module_name} has no length guard"
    with pytest.raises(AssertionError):
        guard([(99, "x" * (X_LIMIT + 1))], "synthetic")
    # ... and must accept good copy
    guard([(1, "ok")], "synthetic")


@pytest.mark.parametrize("module_name,var", THREAD_MODULES)
def test_thread_install_command_actually_resolves(module_name, var):
    """`pip install orbit-security` does not resolve on PyPI.

    The published thread told readers to run it. The working form installs
    from the GitHub source, which is verified to build and install.
    """
    module = _load(module_name)
    tweets = getattr(module, var)
    bodies = "\n".join(item[1] for item in tweets)
    assert "pip install \"orbit-security @ git+https://github.com/CmfH009/Orbit-Security.git\"" in bodies
    assert "pip install orbit-security`" not in bodies
