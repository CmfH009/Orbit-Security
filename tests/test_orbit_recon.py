import pytest
import subprocess
import sys
import json
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.parent / "tools"
RECON_SCRIPT = TOOLS_DIR / "orbit-recon.py"


def test_orbit_recon_help():
    """Verify orbit-recon CLI shows help and banner."""
    res = subprocess.run(
        [sys.executable, str(RECON_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=True
    )
    assert "Orbit Recon" in res.stdout
    assert "target" in res.stdout


def test_orbit_recon_json_output():
    """Verify orbit-recon outputs valid structured JSON."""
    res = subprocess.run(
        [sys.executable, str(RECON_SCRIPT), "example.com", "--json"],
        capture_output=True,
        text=True,
        check=True
    )
    data = json.loads(res.stdout)
    assert data["target"] == "example.com"
    assert "score" in data
    assert "dns" in data
    assert "perimeter" in data
    assert isinstance(data["score"], int)
