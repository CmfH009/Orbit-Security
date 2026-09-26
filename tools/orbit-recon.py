#!/usr/bin/env python3
"""Orbit Recon (orbit-recon.py)

Autonomous Attack Surface, DNS Hygiene & Perimeter Reconnaissance CLI
Part of the Orbit Security Intelligence Suite (https://cmfh009.github.io/Orbit-Security/)
"""

import sys
from pathlib import Path

# Add project src to path if running directly from repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.recon import main

if __name__ == "__main__":
    main()
