"""Pytest configuration for Orbit Security.

Ensures the repository root (and thus the ``orbit`` namespace package shipped
alongside the installed ``orbit_security`` src package) is importable
regardless of how pytest is invoked -- full collection (``uv run pytest``) or
explicit file arguments (``uv run pytest tests/test_foo.py``).
"""
from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
