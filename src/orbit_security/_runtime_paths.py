"""Shared pytest/test-runner data path isolation utilities."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Optional


def is_pytest_active() -> bool:
    """Returns True when code executes inside pytest."""
    return "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


def resolve_isolated_data_path(
    explicit_path: Optional[Path],
    default_path: Path,
    *,
    namespace: str = "orbit_security",
    seed_from_default: bool = False,
) -> Path:
    """Returns an isolated temp path during pytest runs so tests never mutate repo data/."""
    if explicit_path is not None:
        return Path(explicit_path)

    default_p = Path(default_path)
    if not is_pytest_active():
        return default_p

    sandbox_dir = Path(tempfile.gettempdir()) / f"{namespace}_pytest_data_{os.getpid()}"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    sandbox_file = sandbox_dir / default_p.name

    if seed_from_default and default_p.exists() and not sandbox_file.exists():
        try:
            shutil.copy2(default_p, sandbox_file)
        except Exception:
            pass

    return sandbox_file
