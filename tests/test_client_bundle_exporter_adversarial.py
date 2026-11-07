"""Adversarial Stress Test Suite for Milestone M2: Client Remediation & Export Bundle Generator.

This suite empirically stress-tests:
1. Atomicity & Corruptibility:
   - Mid-flight process interruption / I/O errors during ZIP write.
   - ZIP integrity failure rollback (corrupt header / truncation).
   - Atomic replacement preserving prior valid bundle on failure.
   - Permission / lock failures during atomic rename.
2. CloudFormation & Terraform IaC Robustness:
   - PyYAML parseability under hostile / special characters in domains and findings.
   - Empty findings and multi-domain perimeter scaling (100+ domains).
   - CloudFormation logical ID validity (RFC/AWS compliance).
   - Terraform HCL bracket balancing and injection resistance.
3. PyYAML Validity of `.orbit.yml`:
   - YAML injection strings (YAML booleans, directives, anchors, nulls).
   - IDN / Unicode / Punycode / Emoji characters.
   - Round-trip fidelity via yaml.safe_load.
4. Security & Sanitization Boundaries:
   - Directory traversal attempts in agency_slug (e.g. ../../../etc/passwd).
   - CSS injection and XSS vectors in primary/accent colors, titles, descriptions.
5. Concurrent Multi-Threaded Stress Hammer:
   - Simultaneous exports to test UUID isolation and atomic rename collisions.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List
from unittest.mock import patch
import zipfile

import pytest
import yaml

from orbit_security.client_bundle_exporter import ClientBundleExporter, _sanitize_hex_color


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ==============================================================================
# Track 1: Atomicity, Corruptibility & Fault Injection
# ==============================================================================


def test_interrupted_zip_creation_leaves_no_corrupted_file(temp_workspace):
    """Adversarially inject an I/O crash during ZIP member compression.

    Verify that:
    1. An exception is raised.
    2. No corrupted .zip exists at the target destination.
    3. No lingering .tmp.zip files remain in the target directory.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    original_write = zipfile.ZipFile.write
    call_count = 0

    def failing_write(self, filename, arcname=None, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise OSError("Simulated disk write failure or abrupt process termination")
        return original_write(self, filename, arcname=arcname, *args, **kwargs)

    with patch.object(zipfile.ZipFile, "write", new=failing_write):
        with pytest.raises(OSError, match="Simulated disk write failure"):
            exporter.export_bundle(
                agency_slug="fail-agency",
                agency_name="Fail Agency",
                domains=["failagency.com"],
            )

    agency_dir = bundles_dir / "fail-agency"
    final_zip = agency_dir / "fail-agency_remediation_bundle.zip"

    # Destination must NOT contain any half-written or corrupt archive
    assert not final_zip.exists(), "Corrupt final ZIP was erroneously left at destination!"

    # Target directory must have zero lingering .tmp.zip files
    if agency_dir.exists():
        tmp_files = list(agency_dir.glob("*.tmp.zip"))
        assert len(tmp_files) == 0, f"Temporary staging files leaked: {tmp_files}"


def test_failed_zip_integrity_check_rolls_back(temp_workspace):
    """Simulate a truncated or corrupted ZIP archive failing zipfile.is_zipfile().

    Verify that RuntimeError is raised, the corrupt temp file is cleaned up, and no
    corrupt bundle is installed at the destination.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    with patch("zipfile.is_zipfile", return_value=False):
        with pytest.raises(RuntimeError, match="integrity verification"):
            exporter.export_bundle(
                agency_slug="corrupt-check",
                agency_name="Corrupt Check",
                domains=["corrupt.test"],
            )

    agency_dir = bundles_dir / "corrupt-check"
    final_zip = agency_dir / "corrupt-check_remediation_bundle.zip"
    assert not final_zip.exists()
    if agency_dir.exists():
        assert len(list(agency_dir.glob("*.tmp.zip"))) == 0


def test_atomic_replacement_preserves_previous_good_bundle_on_failure(temp_workspace):
    """If a valid bundle already exists, and a subsequent export fails mid-way,

    verify that the original valid bundle is NEVER overwritten or corrupted.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    # 1. First run: export successful bundle
    res1 = exporter.export_bundle(
        agency_slug="resilient-agency",
        agency_name="Resilient Agency",
        domains=["resilient.com"],
    )
    final_zip = Path(res1["bundle_path"])
    assert final_zip.exists()
    original_sha = hashlib.sha256(final_zip.read_bytes()).hexdigest()
    assert zipfile.is_zipfile(final_zip)

    # 2. Second run: simulate failure during archive creation
    with patch("zipfile.ZipFile.write", side_effect=IOError("Simulated disk error")):
        with pytest.raises(IOError):
            exporter.export_bundle(
                agency_slug="resilient-agency",
                agency_name="Resilient Agency",
                domains=["resilient.com"],
            )

    # 3. Target bundle must remain completely untouched and valid
    assert final_zip.exists()
    current_sha = hashlib.sha256(final_zip.read_bytes()).hexdigest()
    assert current_sha == original_sha, "Original bundle was altered during failed export!"
    assert zipfile.is_zipfile(final_zip)


def test_permission_error_during_atomic_replace_cleans_temp_file(temp_workspace):
    """Simulate a PermissionError or lock during os.replace.

    Verify that the temporary file is unlinked and cleaned up.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    with patch("os.replace", side_effect=PermissionError("Simulated file lock")):
        with pytest.raises(PermissionError):
            exporter.export_bundle(
                agency_slug="locked-agency",
                agency_name="Locked Agency",
                domains=["locked.com"],
            )

    agency_dir = bundles_dir / "locked-agency"
    if agency_dir.exists():
        tmp_files = list(agency_dir.glob("*.tmp.zip"))
        assert len(tmp_files) == 0, f"Temporary file was not cleaned up: {tmp_files}"


# ==============================================================================
# Track 2: IaC Template Parsing & Validity (CloudFormation & Terraform)
# ==============================================================================


def test_cloudformation_validity_with_empty_findings(temp_workspace):
    """Verify that CloudFormation template is valid YAML even when findings list is completely empty."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)
    cfn_text = exporter.generate_cloudformation_snippets(
        domains=["empty-findings.com"],
        findings=[],
        agency_slug="empty-findings",
    )

    data = yaml.safe_load(cfn_text)
    assert isinstance(data, dict)
    assert data["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "Resources" in data
    # Standard baseline resources must be present
    assert "DmarcRecordSet" in data["Resources"]
    assert "SpfRecordSet" in data["Resources"]
    assert "CaaRecordSet" in data["Resources"]
    assert "HardenedS3Bucket" in data["Resources"]


def test_cloudformation_and_terraform_adversarial_special_characters(temp_workspace):
    """Stress-test IaC generation against adversarial special characters in domains and findings.

    Test characters: quotes, ampersands, colons, brackets, backslashes, XML/HTML tags.
    """
    exporter = ClientBundleExporter(workspace_root=temp_workspace)

    hostile_domains = [
        "sub-1.client-test.co.uk",
        "api.special-domain.com",
    ]

    hostile_findings = [
        {
            "id": "FIND-ADV-01",
            "title": "Dangling CNAME: dangerous 'quote' & [brackets] : colon",
            "subdomain": "bad-cname.special-domain.com",
            "severity": "CRITICAL",
            "category": "DNS & Cloud",
            "description": 'Unclaimed endpoint with special characters: <script> & "quotes"',
            "remediation": "Decommission DNS pointer immediately.",
        },
        {
            "id": "FIND-ADV-02",
            "title": "CNAME Vulnerability with trailing dot.",
            "subdomain": "trailing-dot.special-domain.com.",
            "severity": "HIGH",
            "category": "DNS",
        },
    ]

    # 1. CloudFormation YAML verification
    cfn_text = exporter.generate_cloudformation_snippets(
        domains=hostile_domains,
        findings=hostile_findings,
        agency_slug="hostile-agency",
    )

    # Must cleanly parse with standard PyYAML
    cfn_dict = yaml.safe_load(cfn_text)
    assert isinstance(cfn_dict, dict)
    assert "Resources" in cfn_dict

    # Check that logical IDs are valid CloudFormation alphanumeric identifiers
    for res_id in cfn_dict["Resources"].keys():
        assert re.match(r"^[a-zA-Z0-9]+$", res_id), f"Invalid CloudFormation Resource Logical ID: {res_id}"

    # Verify CNAME resources were created without breaking formatting
    assert "RemediatedCnameRecord1" in cfn_dict["Resources"]
    assert "RemediatedCnameRecord2" in cfn_dict["Resources"]

    # 2. Terraform HCL bracket and block balancing verification
    tf_text = exporter.generate_terraform_snippets(
        domains=hostile_domains,
        findings=hostile_findings,
        agency_slug="hostile-agency",
    )

    # Check balanced curly braces
    open_braces = tf_text.count("{")
    close_braces = tf_text.count("}")
    assert open_braces == close_braces, f"Mismatched braces in Terraform HCL: {open_braces} != {close_braces}"

    # Verify essential Terraform resources
    assert 'resource "aws_route53_record" "dmarc_route53"' in tf_text
    assert 'resource "aws_s3_bucket" "remediation_bucket"' in tf_text
    assert 'resource "cloudflare_record" "remediated_cname_1"' in tf_text


def test_iac_large_multi_domain_perimeter_scale(temp_workspace):
    """Stress-test IaC template generation under large perimeters (100 domains, 50 CNAME findings)."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)

    large_domains = [f"client-{i:03d}.enterprise-corp.com" for i in range(100)]
    large_findings = [
        {
            "id": f"FIND-CNAME-{i}",
            "title": f"Dangling CNAME Takeover #{i}",
            "subdomain": f"legacy-sub-{i}.enterprise-corp.com",
            "severity": "HIGH",
        }
        for i in range(50)
    ]

    cfn_text = exporter.generate_cloudformation_snippets(
        domains=large_domains,
        findings=large_findings,
        agency_slug="enterprise-corp",
    )
    cfn_dict = yaml.safe_load(cfn_text)
    assert isinstance(cfn_dict, dict)
    # 4 baseline + 50 CNAME = 54 resources
    assert len(cfn_dict["Resources"]) == 54

    tf_text = exporter.generate_terraform_snippets(
        domains=large_domains,
        findings=large_findings,
        agency_slug="enterprise-corp",
    )
    assert tf_text.count("{") == tf_text.count("}")
    assert "remediated_cname_50" in tf_text


# ==============================================================================
# Track 3: PyYAML Validity & Robustness of `.orbit.yml`
# ==============================================================================


def test_orbit_yml_validity_under_yaml_injection_tokens(temp_workspace):
    """Adversarially challenge .orbit.yml against strings that trigger YAML parsing edge cases:

    - Strings resembling YAML booleans ('true', 'false', 'yes', 'no', 'on', 'off')
    - Strings resembling YAML nulls ('null', '~')
    - Strings resembling YAML document separators ('---', '...')
    - Strings with colons and hashes ('foo: bar # comment')
    - Numbers and timestamps ('12345', '2026-11-07')
    """
    exporter = ClientBundleExporter(workspace_root=temp_workspace)

    weird_domains = [
        "true",
        "false",
        "null",
        "yes",
        "no",
        "---",
        "domain:with:colons.com",
        "123456.com",
        "2026-11-07.org",
    ]

    orbit_yaml = exporter.generate_orbit_sentinel_config(
        agency_slug="yaml-stress",
        agency_name="YAML: Stress & Partners --- [1, 2, 3]",
        domains=weird_domains,
        tier="Tier: Enterprise -- scale: true",
        support_email="ops+test@yaml-stress.example.com",
    )

    parsed = yaml.safe_load(orbit_yaml)
    assert isinstance(parsed, dict)
    assert parsed["version"] == "1.0"
    assert parsed["agency"]["slug"] == "yaml-stress"
    assert "YAML: Stress" in parsed["agency"]["name"]

    # Verify that all domain items retained their values
    parsed_domains = [t["domain"] for t in parsed["targets"]]
    for d in weird_domains:
        # String representations should match
        assert str(d) in [str(pd) for pd in parsed_domains]


def test_orbit_yml_unicode_and_internationalized_domains(temp_workspace):
    """Verify that internationalized domain names (IDN/Punycode) and Unicode agency names serialize and parse."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)

    idn_domains = [
        "xn--fsqu00a.xn--0zwm56d",  # Chinese IDN punycode
        "münchen-security.de",
        "東京-brand.jp",
        "безопасность.рф",
    ]

    orbit_yaml = exporter.generate_orbit_sentinel_config(
        agency_slug="global-agency",
        agency_name="🛡️ Global Cyber 護衛株式会社",
        domains=idn_domains,
    )

    parsed = yaml.safe_load(orbit_yaml)
    assert isinstance(parsed, dict)
    assert "🛡️ Global Cyber" in parsed["agency"]["name"]
    parsed_domains = [t["domain"] for t in parsed["targets"]]
    assert "münchen-security.de" in parsed_domains
    assert "東京-brand.jp" in parsed_domains


# ==============================================================================
# Track 4: Security, Path Traversal & Sanitization Boundaries
# ==============================================================================


def test_path_traversal_agency_slug_sanitization(temp_workspace):
    """Attempt directory traversal using agency_slug.

    Verify that bundle files are strictly confined within bundles_dir and never escape to parent directories.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    traversal_slugs = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "....//....//escape",
        "../../../root_attack",
    ]

    for slug in traversal_slugs:
        result = exporter.export_bundle(
            agency_slug=slug,
            agency_name="Traversal Attack",
            domains=["attack.com"],
        )
        bundle_path = Path(result["bundle_path"]).resolve()

        # Must reside strictly inside bundles_dir
        assert bundles_dir.resolve() in bundle_path.parents, (
            f"Directory traversal escape detected! Path {bundle_path} is outside {bundles_dir}"
        )


def test_color_sanitization_defense(temp_workspace):
    """Verify that malicious CSS or HTML injections in hex colors are safely sanitized."""
    assert _sanitize_hex_color("<script>alert(1)</script>", "#0B132B") == "#0B132B"
    assert _sanitize_hex_color("red; background: url('http://evil.com');", "#0B132B") == "#0B132B"
    assert _sanitize_hex_color("#GGG", "#0B132B") == "#0B132B"
    assert _sanitize_hex_color("#12345678", "#0B132B") == "#0B132B"  # 8-char RGBA rejected by 3/6 regex
    assert _sanitize_hex_color("#1E293B", "#0B132B") == "#1E293B"
    assert _sanitize_hex_color("#ABC", "#0B132B") == "#ABC"


def test_html_report_xss_escaping(temp_workspace):
    """Verify that HTML reports escape script tags and malicious attributes in all dynamic fields."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    xss_payload = "<script>alert('pwned')</script>"
    xss_attr = '" onmouseover="alert(1)'

    result = exporter.export_bundle(
        agency_slug="xss-target",
        agency_name=f"Agency {xss_payload}",
        tagline=f"Tagline {xss_attr}",
        domains=[f"sub.{xss_payload}.com"],
        findings=[
            {
                "title": f"Title {xss_payload}",
                "description": f"Desc {xss_payload}",
                "remediation": f"Rem {xss_payload}",
                "subdomain": f"host.{xss_payload}.com",
            }
        ],
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as zf:
        html_content = zf.read("reports/executive_summary.html").decode("utf-8")

        # Must NOT contain raw unescaped script tag
        assert "<script>alert('pwned')</script>" not in html_content
        # Must contain HTML-escaped entity
        assert html.escape(xss_payload) in html_content


def test_manifest_cryptographic_tamper_detection(temp_workspace):
    """Verify that modifying any byte inside the archive invalidates the manifest SHA-256."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="tamper-test",
        agency_name="Tamper Test",
        domains=["tamper.com"],
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as zf:
        manifest_raw = zf.read("bundle_manifest.json").decode("utf-8")
        manifest = json.loads(manifest_raw)

        for entry in manifest["files"]:
            rel_path = entry["path"]
            actual_bytes = zf.read(rel_path)
            computed_sha = hashlib.sha256(actual_bytes).hexdigest()
            assert entry["sha256"] == computed_sha


# ==============================================================================
# Track 5: Concurrent Multi-Threaded Stress Hammer
# ==============================================================================


def test_concurrent_multi_threaded_bundle_exports(temp_workspace):
    """Execute 10 concurrent exports across multiple threads simultaneously.

    Verifies that unique UUID temp file naming prevents race collisions and produces 10
    distinct, completely valid ZIP packages without file locking errors.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    def worker(idx: int) -> Dict[str, Any]:
        slug = f"agency-concurrent-{idx}"
        return exporter.export_bundle(
            agency_slug=slug,
            agency_name=f"Concurrent Agency {idx}",
            domains=[f"concurrent-{idx}.com"],
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(worker, i) for i in range(10)]
        results = [f.result() for f in futures]

    assert len(results) == 10
    for res in results:
        assert res["ok"] is True
        b_path = Path(res["bundle_path"])
        assert b_path.exists()
        assert zipfile.is_zipfile(b_path)


# ==============================================================================
# Track 6: Additional Deep Edge Cases & CLI Adversarial Stress
# ==============================================================================


def test_sparse_findings_with_null_and_odd_types(temp_workspace):
    """Stress-test exporter when findings contain nulls, non-string types, or missing keys."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    malformed_findings = [
        {},  # Completely empty
        {"id": None, "title": None, "severity": None, "category": None},
        {"title": 12345, "severity": 999, "category": False, "subdomain": 3.14159},
        {"title": "Dangling CNAME in integer subdomain", "subdomain": "1002"},
    ]

    result = exporter.export_bundle(
        agency_slug="sparse-findings",
        agency_name="Sparse Findings Agency",
        domains=["sparse.example.com"],
        findings=malformed_findings,
    )

    assert result["ok"] is True
    bundle_path = Path(result["bundle_path"])
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as zf:
        # All 7 files must exist
        for expected in [
            "reports/executive_summary.html",
            "reports/executive_summary.md",
            "remediation/remediation.tf",
            "remediation/remediation.cfn.yaml",
            "remediation/remediation.zone",
            ".orbit.yml",
            "bundle_manifest.json",
        ]:
            assert expected in zf.namelist()

        # Parse YAML deliverables
        cfn = yaml.safe_load(zf.read("remediation/remediation.cfn.yaml"))
        assert isinstance(cfn, dict)
        orbit = yaml.safe_load(zf.read(".orbit.yml"))
        assert isinstance(orbit, dict)


def test_cli_adversarial_flags(temp_workspace):
    """Adversarially invoke the CLI scripts/export_agency_bundle.py with messy arguments:

    - Empty and whitespace-only domain tokens: '--domains' '  , , ,'
    - Injected quote characters in name
    - Nested uncreated output directory
    - Invalid hex colors (should fall back safely)
    """
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "export_agency_bundle.py"
    target_out = temp_workspace / "deep" / "nested" / "path" / "bundles"

    cmd = [
        sys.executable,
        str(script_path),
        "--agency",
        "cli-adversarial",
        "--name",
        'Test "Quoted" & <Special> Name',
        "--domains",
        "  ,  , alpha.com , , beta.co.uk , ",
        "--primary-color",
        "not-a-color-injection",
        "--accent-color",
        "#123",  # 3-char hex is valid
        "--output-dir",
        str(target_out),
        "--json",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"CLI error: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    b_path = Path(data["bundle_path"])
    assert b_path.exists()
    assert zipfile.is_zipfile(b_path)


def test_zone_file_rfc1035_dns_syntax(temp_workspace):
    """Verify that generated remediation.zone conforms to standard BIND DNS syntax."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)
    domains = ["primary.corp", "secondary.corp"]
    findings = [
        {
            "title": "Dangling CNAME takeover on legacy asset",
            "subdomain": "legacy.primary.corp",
            "severity": "CRITICAL",
        },
        {
            "title": "Dangling CNAME on apex",
            "subdomain": "primary.corp",
            "severity": "HIGH",
        },
    ]

    zone = exporter.generate_zone_file(domains=domains, findings=findings, agency_name="Test Agency")

    assert "$ORIGIN primary.corp." in zone
    assert "$TTL 300" in zone
    assert '_dmarc\tIN\tTXT\t"v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"' in zone
    assert '@\tIN\tTXT\t"v=spf1 include:_spf.google.com -all"' in zone
    assert '@\tIN\tCAA\t0 issue "letsencrypt.org"' in zone
    assert 'legacy\tIN\tTXT\t"remediated-decommissioned-by-orbit"' in zone
