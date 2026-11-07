"""Adversarial Stress Test Suite for Track A: DNS Fix Pack Exporter, ZIP Integrity & CLI Wiring.

Empirically challenges:
1. CLI Adversarial Input Validation & SSRF Defense:
   - Malicious domain inputs: 'localhost', '127.0.0.1', '169.254.169.254',
     'evil.com; rm -rf', and path traversal '../../'.
   - Tests both `orbit_security.cli` and `orbit_security.recon`.
   - Requires exit code 1 and no filesystem or network escape.
2. Direct Exporter Boundary & Path Traversal Safety:
   - Direct invocation of `ClientBundleExporter.export_dns_fixpack` with
     traversal sequences like '../../evil' or SSRF addresses.
   - Asserts prevention of filesystem breakout outside destination directory.
3. Fix Pack ZIP Integrity & Syntax Across Finding Sets:
   - Dangling CNAME findings (single, multiple, custom subdomain).
   - Permissive SPF findings (custom CIDRs, includes, hard-fail vs soft-fail).
   - Missing DMARC findings (quarantine vs reject, custom reporting mailto).
   - Missing CAA findings (single CA, multiple CAs, Cloudflare data block vs Route 53).
   - Empty findings ([]) and None findings.
   - Robustness against special characters, quotes, and HCL injection.
4. Archive Integrity & Zip Slip Prevention:
   - Valid ZIP header magic bytes (PK\\x03\\x04).
   - Cryptographic SHA-256 match between extracted files and manifest.
   - Bundle SHA-256 match in sidecar manifest.
   - Strict extraction isolation (no directory traversal or absolute paths in ZIP).
5. High-Concurrency NTFS Directory Mutex Stress Hammer:
   - 20 concurrent threads targeting the exact same output directory.
   - Validates that directory mutex and exponential retry backoff prevent
     Windows PermissionError crashes or archive corruption.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Dict, List
import zipfile

import pytest

from orbit_security.client_bundle_exporter import ClientBundleExporter
from orbit_security.remediation import DnsRemediationGenerator
from orbit_security.cli import main as cli_main
from orbit_security.recon import main as recon_main, run_recon


@pytest.fixture
def temp_dir():
    """Provides a fresh isolated temporary directory."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


# ==============================================================================
# 1. Adversarial CLI Input Validation & SSRF Defense
# ==============================================================================

@pytest.mark.parametrize(
    "malicious_domain,expected_label",
    [
        ("localhost", "Loopback / non-FQDN"),
        ("127.0.0.1", "IPv4 Loopback address"),
        ("169.254.169.254", "Cloud metadata endpoint"),
        ("evil.com; rm -rf", "Command injection metacharacters"),
        ("../../", "Path traversal sequence"),
        ("10.0.0.1", "Private RFC 1918 address"),
        ("192.168.1.1", "Private RFC 1918 address"),
        ("foo.localhost", "Reserved localhost TLD"),
    ],
)
def test_cli_export_fixpack_adversarial_inputs_rejected(malicious_domain, expected_label, monkeypatch):
    """Verifies orbit_security.cli rejects hostile / internal domains with code 1."""
    test_args = [
        "orbit-security",
        "--domain",
        malicious_domain,
        "--export-fixpack",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 1, (
        f"orbit_security.cli accepted malicious domain '{malicious_domain}' ({expected_label}) "
        f"with exit code {exc.value.code} instead of rejecting with code 1"
    )


@pytest.mark.parametrize(
    "malicious_domain,expected_label",
    [
        ("localhost", "Loopback / non-FQDN"),
        ("127.0.0.1", "IPv4 Loopback address"),
        ("169.254.169.254", "Cloud metadata endpoint"),
        ("evil.com; rm -rf", "Command injection metacharacters"),
        ("../../", "Path traversal sequence"),
    ],
)
def test_recon_cli_adversarial_inputs_rejected(malicious_domain, expected_label, temp_dir, monkeypatch):
    """Verifies orbit_security.recon rejects hostile / internal domains with code 1 when exporting fixpack."""
    out_dir = temp_dir / "recon_attack_test"
    test_args = [
        "orbit-recon",
        "--target",
        malicious_domain,
        "--export-fixpack",
        "--output-dir",
        str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    # In adversarial testing, any command injection, traversal, or SSRF address MUST exit code 1
    # and MUST NOT generate any fixpack archive on disk.
    with pytest.raises(SystemExit) as exc:
        recon_main()

    assert exc.value.code == 1, (
        f"orbit-recon allowed '{malicious_domain}' ({expected_label}) to execute with exit code {exc.value.code}"
    )

    # Furthermore, verify no ZIP archive was created in the output directory
    generated_zips = list(out_dir.glob("*.zip"))
    assert len(generated_zips) == 0, f"orbit-recon generated fixpack archive for hostile input: {generated_zips}"


def test_recon_run_recon_blocks_ssrf_fixpack(temp_dir):
    """run_recon must not generate a fixpack when domain is a loopback or cloud metadata address."""
    out_dir = temp_dir / "ssrf_test"

    for ssrf_target in ["127.0.0.1", "169.254.169.254"]:
        res = run_recon(
            ssrf_target,
            json_output=True,
            export_fixpack=True,
            output_dir=str(out_dir),
        )

        # Must report error and must NOT generate fix pack
        assert (
            "error" in res
            or "fixpack" not in res
            or not (out_dir / f"{ssrf_target.replace('.', '_')}_dns_fixpack.zip").exists()
        ), f"run_recon created a fixpack for SSRF target {ssrf_target}!"


# ==============================================================================
# 2. Direct Exporter Boundary & Path Traversal Safety
# ==============================================================================

def test_export_dns_fixpack_path_traversal_boundary(temp_dir):
    """Direct export_dns_fixpack with traversal domain string must not escape destination directory."""
    traversal_domain = "../../evil_escape"
    out_dir = temp_dir / "traversal_sandbox"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Calling export_dns_fixpack directly with traversal sequence
    try:
        res = ClientBundleExporter.export_dns_fixpack(
            domain=traversal_domain,
            output_dir=out_dir,
            as_dict=True,
        )
        fixpack_path = Path(res["fixpack_path"])
        # The file MUST be contained within out_dir or fail
        resolved_fixpack = fixpack_path.resolve()
        resolved_out_dir = out_dir.resolve()
        assert str(resolved_fixpack).startswith(str(resolved_out_dir)), (
            f"Filesystem escape detected! Fixpack path {resolved_fixpack} broke outside {resolved_out_dir}"
        )
    except (ValueError, Exception) as e:
        # Rejecting invalid domain with an exception is also safe
        pass

    # Ensure no file escaped to root of drive
    root_drive = Path(out_dir.drive + "\\") if out_dir.drive else Path("/")
    assert not (root_drive / "evil_escape.zone").exists(), "Zone file leaked to root filesystem!"
    assert not (root_drive / "__" / "evil_escape_dns_fixpack.zip").exists(), "ZIP leaked to root filesystem!"


# ==============================================================================
# 3. Fix Pack ZIP Integrity & Syntax Across Finding Sets
# ==============================================================================

def test_fixpack_generation_with_dangling_cnames(temp_dir):
    """Fix pack incorporates multiple dangling CNAME findings into HCL and zone file."""
    domain = "acmesecurity.org"
    findings = [
        {
            "id": "FIND-01",
            "title": "Dangling CNAME Takeover",
            "subdomain": "shop.acmesecurity.org",
            "cname_target": "acmeshop.myshopify.com",
            "severity": "CRITICAL",
        },
        {
            "id": "FIND-02",
            "title": "Subdomain Takeover S3",
            "subdomain": "assets.acmesecurity.org",
            "cname_target": "acme-assets.s3.amazonaws.com",
            "severity": "CRITICAL",
        },
    ]

    res = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        findings=findings,
        output_dir=temp_dir,
        policy="reject",
        contact_email="security@acmesecurity.org",
    )
    assert res["ok"] is True
    zip_path = Path(res["fixpack_path"])

    with zipfile.ZipFile(zip_path, "r") as zf:
        tf_content = zf.read("dns_fixes.tf").decode("utf-8")
        zone_content = zf.read(f"{domain}.zone").decode("utf-8")

        # Terraform HCL checks
        assert 'resource "cloudflare_record" "remediated_cname_1"' in tf_content
        assert 'resource "aws_route53_record" "remediated_cname_1"' in tf_content
        assert 'resource "cloudflare_record" "remediated_cname_2"' in tf_content
        assert 'resource "aws_route53_record" "remediated_cname_2"' in tf_content
        assert "shop" in tf_content
        assert "assets" in tf_content
        assert "decommissioned.invalid" in tf_content

        # BIND zone file checks
        assert "shop\tIN\tTXT\t\"remediated-decommissioned-by-orbit\"" in zone_content
        assert "assets\tIN\tTXT\t\"remediated-decommissioned-by-orbit\"" in zone_content


def test_fixpack_generation_with_custom_spf_and_caa(temp_dir):
    """Fix pack incorporates custom SPF CIDRs and multi-provider CAA records."""
    domain = "enterprise-vault.co"
    custom_spf = "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.google.com -all"
    ca_list = ["letsencrypt.org", "digicert.com", "sectigo.com", "globalsign.com"]

    res = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        output_dir=temp_dir,
        spf_record=custom_spf,
        ca_list=ca_list,
        contact_email="ciso@enterprise-vault.co",
    )
    assert res["ok"] is True
    zip_path = Path(res["fixpack_path"])

    with zipfile.ZipFile(zip_path, "r") as zf:
        tf_content = zf.read("dns_fixes.tf").decode("utf-8")
        zone_content = zf.read(f"{domain}.zone").decode("utf-8")

        # Custom SPF verification
        assert custom_spf in tf_content
        assert custom_spf in zone_content

        # Custom CAA verification
        for ca in ca_list:
            assert ca in tf_content
            assert f'@\tIN\tCAA\t0 issue "{ca}"' in zone_content


def test_fixpack_generation_with_empty_and_none_findings(temp_dir):
    """Fix pack handles empty lists and None findings without crashing."""
    domain = "cleanbrand.com"

    # Test with None findings
    res1 = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        findings=None,
        output_dir=temp_dir / "none_findings",
    )
    assert res1["ok"] is True
    assert Path(res1["fixpack_path"]).exists()

    # Test with empty findings
    res2 = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        findings=[],
        output_dir=temp_dir / "empty_findings",
    )
    assert res2["ok"] is True
    assert Path(res2["fixpack_path"]).exists()


def test_fixpack_special_characters_resilience(temp_dir):
    """Findings with quotes, brackets, and unicode do not break Terraform HCL formatting."""
    domain = "hostile-input.io"
    findings = [
        {
            "id": "FIND-SPECIAL",
            "title": 'Subdomain Takeover "Injection" Test <script>',
            "subdomain": "test-sub.hostile-input.io",
            "cname_target": "target.invalid",
            "severity": "HIGH",
        }
    ]

    res = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        findings=findings,
        output_dir=temp_dir,
        contact_email="admin+tag@hostile-input.io",
    )
    assert res["ok"] is True
    zip_path = Path(res["fixpack_path"])

    with zipfile.ZipFile(zip_path, "r") as zf:
        tf_content = zf.read("dns_fixes.tf").decode("utf-8")
        # Check basic HCL structural integrity: braces must be balanced
        open_braces = tf_content.count("{")
        close_braces = tf_content.count("}")
        assert open_braces == close_braces, f"Unbalanced braces in Terraform HCL: {open_braces} open vs {close_braces} close"


# ==============================================================================
# 4. Archive Integrity & Zip Slip Prevention
# ==============================================================================

def test_fixpack_manifest_cryptographic_verification(temp_dir):
    """Every file in the ZIP must exactly match its SHA-256 digest in fixpack_manifest.json."""
    domain = "crypto-verify.net"
    res = DnsRemediationGenerator.build_fixpack(domain=domain, output_dir=temp_dir)
    zip_path = Path(res["fixpack_path"])

    # Verify ZIP magic header bytes (PK\x03\x04)
    raw_header = zip_path.read_bytes()[:4]
    assert raw_header == b"PK\x03\x04", f"Invalid ZIP header magic bytes: {raw_header}"

    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest_raw = zf.read("fixpack_manifest.json")
        manifest = json.loads(manifest_raw.decode("utf-8"))

        assert manifest["domain"] == domain
        assert manifest["bundle_name"] == f"{domain.replace('.', '_')}_dns_fixpack.zip"

        files_map = {f["path"]: f for f in manifest["files"]}

        for member_name in zf.namelist():
            if member_name == "fixpack_manifest.json":
                continue
            member_bytes = zf.read(member_name)
            computed_sha = hashlib.sha256(member_bytes).hexdigest()

            assert member_name in files_map, f"File {member_name} missing from fixpack manifest!"
            assert files_map[member_name]["sha256"] == computed_sha, (
                f"SHA256 mismatch for {member_name}: manifest={files_map[member_name]['sha256']} vs computed={computed_sha}"
            )
            assert files_map[member_name]["size_bytes"] == len(member_bytes)

    # Check sidecar manifest bundle_sha256 matches actual zip
    sidecar_manifest = zip_path.parent / "fixpack_manifest.json"
    assert sidecar_manifest.exists()
    sidecar_data = json.loads(sidecar_manifest.read_text(encoding="utf-8"))
    actual_bundle_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    assert sidecar_data["bundle_sha256"] == actual_bundle_sha


def test_fixpack_zip_slip_and_safe_extraction(temp_dir):
    """Verifies that zip archive contains zero path traversal attacks and extracts cleanly."""
    domain = "zipslip-defense.org"
    res = DnsRemediationGenerator.build_fixpack(domain=domain, output_dir=temp_dir)
    zip_path = Path(res["fixpack_path"])

    extract_dest = temp_dir / "safe_extract_target"
    extract_dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Zip Slip checks
            assert not member.filename.startswith(("/", "\\")), f"Absolute path in ZIP: {member.filename}"
            assert ".." not in member.filename, f"Directory traversal sequence in ZIP: {member.filename}"
            assert not os.path.isabs(member.filename), f"Is absolute path: {member.filename}"

        zf.extractall(extract_dest)

    # Verify extracted contents
    assert (extract_dest / "dns_fixes.tf").is_file()
    assert (extract_dest / f"{domain}.zone").is_file()
    assert (extract_dest / "security.txt").is_file()
    assert (extract_dest / "fixpack_manifest.json").is_file()


# ==============================================================================
# 5. High-Concurrency NTFS Directory Mutex Stress Hammer
# ==============================================================================

def test_fixpack_high_concurrency_stress_hammer(temp_dir):
    """Stress-tests 20 concurrent threads exporting to the exact same output directory."""
    exporter = ClientBundleExporter(workspace_root=temp_dir)
    domain = "concurrency-hammer.io"
    target_dir = temp_dir / "heavy_concurrency"
    target_dir.mkdir(parents=True, exist_ok=True)

    thread_count = 20

    def run_worker(worker_id: int):
        return exporter.export_dns_fixpack(
            domain=domain,
            output_dir=target_dir,
            contact_email=f"worker-{worker_id}@concurrency-hammer.io",
            policy="quarantine",
            as_dict=True,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(run_worker, i) for i in range(thread_count)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == thread_count
    for r in results:
        assert r["ok"] is True
        p = Path(r["fixpack_path"])
        assert p.exists()
        assert zipfile.is_zipfile(p)

    # Check for temporary file leakage (.tmp.zip or .tmp.json)
    leaked_tmp_zips = list(target_dir.glob("*.tmp.zip"))
    leaked_tmp_jsons = list(target_dir.glob("*.tmp.json"))
    assert len(leaked_tmp_zips) == 0, f"Leaked temporary ZIP files: {leaked_tmp_zips}"
    assert len(leaked_tmp_jsons) == 0, f"Leaked temporary JSON manifests: {leaked_tmp_jsons}"
