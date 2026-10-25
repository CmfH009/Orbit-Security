"""orbit_security.cli_recon: CLI entry point alias for Orbit Recon."""
from __future__ import annotations

import sys
from orbit_security.recon import main

if __name__ == "__main__":
    sys.exit(main() or 0)
