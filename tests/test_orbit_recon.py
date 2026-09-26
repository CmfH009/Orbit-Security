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


def test_run_bulk_recon(tmp_path):
    """Verify run_bulk_recon scans multiple targets and exports markdown matrix."""
    from orbit_security.recon import run_bulk_recon

    mock_clean_dns = {"cname": None, "a_records": ["93.184.216.34"], "dangling_risk": False}
    mock_clean_web = {"status_code": 200, "headers_found": {"Strict-Transport-Security": "1"}, "missing_headers": [], "exposures": []}

    md_file = tmp_path / "fleet_matrix.md"

    with patch("orbit_security.recon.resolve_dns", return_value=mock_clean_dns):
        with patch("orbit_security.recon.check_headers_and_exposures", return_value=mock_clean_web):
            results = run_bulk_recon(
                targets=["client1.com", "client2.com"],
                json_output=True,
                markdown_path=str(md_file),
                fail_on_critical=False,
            )
            assert len(results) == 2
            assert results[0]["target"] == "client1.com"
            assert results[1]["target"] == "client2.com"
            assert results[0]["has_takeover"] is False

    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "Orbit Security: Bulk Perimeter Audit Matrix" in content
    assert "`client1.com`" in content
    assert "`client2.com`" in content


def test_run_bulk_recon_fail_on_critical():
    """Verify run_bulk_recon exits with code 1 if fail_on_critical is set and critical risk is found."""
    from orbit_security.recon import run_bulk_recon

    mock_risky_dns = {"cname": "bad.trafficmanager.net", "dangling_risk": True, "matched_service": "Azure Traffic Manager"}
    mock_risky_web = {"status_code": 200, "headers_found": {}, "missing_headers": [], "exposures": []}

    with patch("orbit_security.recon.resolve_dns", return_value=mock_risky_dns):
        with patch("orbit_security.recon.check_headers_and_exposures", return_value=mock_risky_web):
            with pytest.raises(SystemExit) as exc_info:
                run_bulk_recon(
                    targets=["vulnerable-client.com"],
                    json_output=True,
                    fail_on_critical=True,
                )
            assert exc_info.value.code == 1

