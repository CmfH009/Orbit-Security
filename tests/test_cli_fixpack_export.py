"""Unit tests for Coordinator CLI Wiring & Fix Pack Integration (Milestone M4).

Verifies:
1. Root CLI invocation: `python -m orbit_security.cli --domain orbitsecurity.ai --export-fixpack`
   - Generates a valid ZIP archive containing `dns_fixes.tf`, `<domain>.zone`, and `security.txt`.
2. Target alias: `python -m orbit_security.cli --target orbitsecurity.ai --export-fixpack`
3. Custom output directory via `--output-dir`.
4. Subcommand support: `orbit-security remediate domain --export-fixpack`.
5. Missing domain rejection with exit code 1.
6. Malformed/SSRF domain validation rejection.
7. Orbit Recon CLI: `python -m orbit_security.recon --target domain --export-fixpack`
8. Orbit Recon CLI JSON output includes `fixpack` payload.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
import pytest

from orbit_security.cli import main as cli_main
from orbit_security.recon import main as recon_main, run_recon


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_cli_export_fixpack_root_domain(temp_dir, monkeypatch, capsys):
    """Root invocation `python -m orbit_security.cli --domain orbitsecurity.ai --export-fixpack` succeeds."""
    domain = "orbitsecurity.ai"
    out_dir = temp_dir / "root_cli_out"

    test_args = [
        "orbit-security",
        "--domain",
        domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    exit_code = cli_main()
    assert exit_code == 0

    captured = capsys.readouterr().out
    assert "1-Click DNS Fix Pack successfully generated" in captured

    expected_zip = out_dir / "orbitsecurity_ai_dns_fixpack.zip"
    assert expected_zip.exists()
    assert zipfile.is_zipfile(expected_zip)

    with zipfile.ZipFile(expected_zip, "r") as zf:
        namelist = zf.namelist()
        assert "dns_fixes.tf" in namelist
        assert f"{domain}.zone" in namelist
        assert "security.txt" in namelist
        assert "fixpack_manifest.json" in namelist


def test_cli_export_fixpack_target_alias(temp_dir, monkeypatch, capsys):
    """Alias `--target` functions identically to `--domain`."""
    domain = "agencytarget.com"
    out_dir = temp_dir / "alias_out"

    test_args = [
        "orbit-security",
        "--target",
        domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    exit_code = cli_main()
    assert exit_code == 0

    expected_zip = out_dir / "agencytarget_com_dns_fixpack.zip"
    assert expected_zip.exists()
    assert zipfile.is_zipfile(expected_zip)


def test_cli_export_fixpack_missing_domain_fails(monkeypatch):
    """Export fixpack without target domain exits code 1."""
    test_args = [
        "orbit-security",
        "--export-fixpack",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 1


def test_cli_export_fixpack_invalid_domain_fails(monkeypatch):
    """Passing an invalid or SSRF domain fails security validation."""
    test_args = [
        "orbit-security",
        "--domain",
        "127.0.0.1",
        "--export-fixpack",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 1


def test_cli_remediate_subcommand_with_fixpack(temp_dir, monkeypatch, capsys):
    """Subcommand `orbit-security remediate domain --export-fixpack` triggers fixpack export."""
    domain = "remediatesub.io"
    out_dir = temp_dir / "subcommand_out"

    test_args = [
        "orbit-security",
        "remediate",
        domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    exit_code = cli_main()
    assert exit_code == 0

    expected_zip = out_dir / "remediatesub_io_dns_fixpack.zip"
    assert expected_zip.exists()
    assert zipfile.is_zipfile(expected_zip)


def test_recon_export_fixpack_direct(temp_dir):
    """run_recon with export_fixpack=True creates bundle in results."""
    domain = "recontest.org"
    out_dir = temp_dir / "recon_direct"

    res = run_recon(
        domain,
        json_output=True,
        export_fixpack=True,
        output_dir=str(out_dir),
    )

    assert "fixpack" in res
    assert res["fixpack"]["ok"] is True
    fixpack_p = Path(res["fixpack"]["fixpack_path"])
    assert fixpack_p.exists()
    assert zipfile.is_zipfile(fixpack_p)


def test_recon_cli_export_fixpack(temp_dir, monkeypatch, capsys):
    """orbit-recon CLI generates fixpack when --export-fixpack is passed."""
    domain = "reconcli.net"
    out_dir = temp_dir / "recon_cli"

    test_args = [
        "orbit-recon",
        domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    recon_main()

    captured = capsys.readouterr().out
    assert "1-Click DNS Fix Pack" in captured

    expected_zip = out_dir / "reconcli_net_dns_fixpack.zip"
    assert expected_zip.exists()
    assert zipfile.is_zipfile(expected_zip)


def test_recon_cli_json_export_fixpack(temp_dir, monkeypatch, capsys):
    """orbit-recon CLI --json --export-fixpack contains fixpack dict."""
    domain = "reconjson.io"
    out_dir = temp_dir / "recon_json"

    test_args = [
        "orbit-recon",
        "--target",
        domain,
        "--json",
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    recon_main()

    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "fixpack" in data
    assert data["fixpack"]["ok"] is True
    assert Path(data["fixpack"]["fixpack_path"]).exists()


def test_cli_scan_subcommand_with_fixpack(temp_dir, monkeypatch, capsys):
    """Subcommand `orbit-security scan domain --export-fixpack` runs scan and exports fixpack."""
    from unittest.mock import AsyncMock, MagicMock, patch

    domain = "scansub.org"
    out_dir = temp_dir / "scan_sub_out"

    dummy_result = MagicMock()
    dummy_result.domain = domain
    dummy_result.grade = "B"
    dummy_result.score = 85
    dummy_result.osint_intel = {}
    dummy_result.takeover_findings = [
        {
            "id": "FIND-SCAN-01",
            "title": "Dangling CNAME Test",
            "subdomain": f"shop.{domain}",
            "cname_target": "custom.myshopify.com",
            "saas_provider": "Shopify",
            "severity": "CRITICAL",
        }
    ]

    test_args = [
        "orbit-security",
        "scan",
        domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with patch("orbit_security.cli.OrbitSecurityScanner") as mock_scanner_cls:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan_domain = AsyncMock(return_value=dummy_result)

        exit_code = cli_main()
        assert exit_code is None or exit_code == 0
        mock_scanner.scan_domain.assert_awaited_once()

    captured = capsys.readouterr().out
    assert "1-Click DNS Fix Pack successfully generated" in captured

    expected_zip = out_dir / "scansub_org_dns_fixpack.zip"
    assert expected_zip.exists()
    assert zipfile.is_zipfile(expected_zip)

