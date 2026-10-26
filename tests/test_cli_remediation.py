from pathlib import Path
from unittest.mock import patch
import pytest
from orbit_security.remediation import DnsRemediationGenerator
from orbit_security.cli import main


def test_generate_full_package_creates_all_files(tmp_path):
    domain = "testremediate.com"
    out_dir = tmp_path / "campaign_out"
    
    pkg = DnsRemediationGenerator.generate_full_package(
        domain=domain,
        output_dir=out_dir,
        policy="quarantine",
        report_email="security@testremediate.com",
        generate_pdf=False,
    )
    
    assert pkg["domain"] == domain
    assert (out_dir / "remediation.zone").exists()
    assert (out_dir / "remediation.tf").exists()
    assert (out_dir / "security.txt").exists()
    assert (out_dir / "remediation_summary.txt").exists()
    
    zone_content = (out_dir / "remediation.zone").read_text(encoding="utf-8")
    assert "v=DMARC1" in zone_content
    assert "v=spf1" in zone_content
    
    tf_content = (out_dir / "remediation.tf").read_text(encoding="utf-8")
    assert 'resource "cloudflare_record"' in tf_content


def test_generate_full_package_with_pdf(tmp_path):
    domain = "testpdf.com"
    out_dir = tmp_path / "pdf_out"
    
    with patch("orbit_security.reporter.ReportGenerator.generate_pdf") as mock_pdf:
        pkg = DnsRemediationGenerator.generate_full_package(
            domain=domain,
            output_dir=out_dir,
            policy="reject",
            report_email="dmarc@testpdf.com",
            generate_pdf=True,
        )
        assert mock_pdf.called
        assert pkg["pdf_file"] is not None


def test_cli_remediate_command(tmp_path, capsys):
    domain = "clitest.org"
    out_dir = tmp_path / "cli_out"
    
    with patch("sys.argv", ["orbit-security", "remediate", domain, "--output-dir", str(out_dir), "--no-pdf"]):
        main()
    
    captured = capsys.readouterr().out
    assert f"Remediation package generated for {domain}" in captured
    assert (out_dir / "remediation.zone").exists()
    assert (out_dir / "remediation.tf").exists()
    assert (out_dir / "security.txt").exists()
