import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.recon import calculate_score, run_recon

TOOLS_DIR = Path(__file__).parent.parent / "tools"
RECON_SCRIPT = TOOLS_DIR / "orbit-recon.py"


def test_orbit_recon_help():
    """Verify orbit-recon CLI shows help and usage."""
    res = subprocess.run(
        [sys.executable, str(RECON_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Orbit Recon" in res.stdout
    assert "target" in res.stdout


def test_orbit_recon_json_output():
    """Verify orbit-recon outputs valid structured JSON via CLI."""
    res = subprocess.run(
        [sys.executable, str(RECON_SCRIPT), "example.com", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(res.stdout)
    assert data["target"] == "example.com"
    assert "score" in data
    assert "dns" in data
    assert "perimeter" in data
    assert isinstance(data["score"], int)


def test_orbit_recon_deterministic_mocks():
    """Verify recon logic with deterministic offline mocks."""
    mock_dns_data = {
        "cname": "promo.unbouncepages.com",
        "a_records": [],
        "mx_records": ["mail.acme.com"],
        "dangling_risk": True,
        "matched_service": "Unbounce",
        "remediation": "Delete dangling CNAME.",
    }
    mock_web_data = {
        "status_code": 200,
        "headers_found": {"Strict-Transport-Security": "max-age=31536000"},
        "missing_headers": [
            {"header": "Content-Security-Policy", "description": "..."},
            {"header": "X-Frame-Options", "description": "..."},
        ],
        "exposures": [{"path": "/.env", "status": 200, "verified": True}],
    }

    score = calculate_score(mock_dns_data, mock_web_data)
    # 100 - 40 (dangling_risk) - 30 (1 exposure) - (2 missing headers * 8 = 16) = 14
    assert score == 14

    with patch("orbit_security.recon.resolve_dns", return_value=mock_dns_data):
        with patch("orbit_security.recon.check_headers_and_exposures", return_value=mock_web_data):
            results = run_recon("acme-test.com", json_output=False)
            assert results["score"] == 14
            assert results["dns"]["matched_service"] == "Unbounce"
            assert results["dns"]["dangling_risk"] is True
            assert len(results["perimeter"]["exposures"]) == 1


def test_orbit_recon_ssrf_blocked():
    """Verify orbit-recon blocks internal IP targets."""
    results = run_recon("127.0.0.1", json_output=False)
    assert "error" in results["dns"]
    assert "SSRF blocked" in results["dns"]["error"]
