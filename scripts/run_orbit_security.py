"""Entry point for Orbit Security background worker daemon."""
from pathlib import Path
import sys

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent
_SRC_DIR = _REPO_ROOT / "src"

for p in (_REPO_ROOT, _SRC_DIR, _SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from scripts.run_inbox_agent import main
except ImportError:
    from run_inbox_agent import main

if __name__ == "__main__":
    main()
