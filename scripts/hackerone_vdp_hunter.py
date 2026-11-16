#!/usr/bin/env python3
"""scripts/hackerone_vdp_hunter.py: Canonical CLI wrapper for HackerOne VDP Hunting.

Provides drop-in CLI execution (`python scripts/hackerone_vdp_hunter.py --dry-run`)
and re-exports all hunter components from scripts/hunt_hackerone_vdps.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
SRC_DIR = PROJECT_ROOT / "src"

for _p in (str(PROJECT_ROOT), str(SCRIPTS_DIR), str(SRC_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from hunt_hackerone_vdps import *  # noqa: F401, F403
from hunt_hackerone_vdps import main

if __name__ == "__main__":
    sys.exit(main())
