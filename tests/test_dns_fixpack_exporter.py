"""Unit tests for 1-Click DNS Fix Pack Exporter and Remediation Generator (Milestone M2).

Verifies:
1. Terraform HCL generation (dns_fixes.tf):
   - Cloudflare and AWS Route 53 providers and variable definitions.
   - DMARC, SPF, DKIM, CAA, and dangling CNAME record resources.
2. BIND Zone file generation (<domain>.zone):
   - RFC 1035 standard zone format ($ORIGIN, $TTL).
   - DMARC, SPF, DKIM, CAA, and decommissioned CNAME TXT records.
3. RFC 9116 Security Policy generation (security.txt):
   - Contact, Expires, Preferred-Languages, Canonical, Policy directives.
4. Atomic Fix Pack ZIP packaging:
   - Valid ZIP header magic bytes (PK\\x03\\x04).
   - Inclusion of dns_fixes.tf, <domain>.zone, security.txt, and fixpack_manifest.json.
   - Cryptographic SHA-256 manifest verification against file digests and bundle digest.
   - Safe uncompressed entry extraction and Zip Slip prevention.
5. ClientBundleExporter integration:
   - export_dns_fixpack() returns Path to atomic ZIP.
   - Concurrent calls protected by directory mutex without Windows NTFS file lock collisions.
6. Finding-driven customization:
   - Ingestion of dangling CNAME, permissive SPF, and missing DMARC findings.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List
import zipfile

import pytest

from orbit_security.client_bundle_exporter import ClientBundleExporter
from orbit_security.remediation import DnsRemediationGenerator


@pytest.fixture
def temp_workspace():
    """Provides an isolated temporary workspace directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_findings() -> List[Dict[str, Any]]:
    return [
        {
            "id": "FIND-TAKEOVER-01",
            "title": "Dangling CNAME Subdomain Takeover",
            "subdomain": "blog.orbitsecurity.ai",
            "cname_target": "custom-orbit.ghost.io",
            "saas_provider": "Ghost",
            "severity": "CRITICAL",
            "category": "DNS",
            "description": "Subdomain points to an unclaimed Ghost publication.",
        },
        {
            "id": "FIND-DMARC-01",
            "title": "Missing Strict DMARC Policy",
            "subdomain": "_dmarc.orbitsecurity.ai",
            "severity": "HIGH",
            "category": "Email",
            "description": "DMARC policy is p=none or missing.",
        },
        {
            "id": "FIND-SPF-01",
            "title": "Permissive SPF Configuration",
            "subdomain": "orbitsecurity.ai",
            "severity": "MEDIUM",
            "category": "Email",
            "description": "SPF record uses soft-fail ~all instead of strict hard-fail -all.",
        },
    ]


# ==============================================================================
# 1. Terraform HCL Generation Tests (dns_fixes.tf)
# ==============================================================================


def test_generate_dns_fixes_tf_basic():
    """Generates valid Terraform HCL containing Cloudflare and Route53 resources."""
    domain = "orbitsecurity.ai"
    tf_hcl = DnsRemediationGenerator.generate_dns_fixes_tf(domain)

    # Provider and variable blocks
    assert 'terraform {' in tf_hcl
    assert 'source  = "cloudflare/cloudflare"' in tf_hcl
    assert 'source  = "hashicorp/aws"' in tf_hcl
    assert 'variable "cloudflare_zone_id"' in tf_hcl
    assert 'variable "route53_zone_id"' in tf_hcl

    # DMARC resources
    assert 'resource "cloudflare_record" "dmarc"' in tf_hcl
    assert 'resource "aws_route53_record" "dmarc"' in tf_hcl
    assert 'v=DMARC1;' in tf_hcl
    assert '_dmarc' in tf_hcl

    # SPF resources
    assert 'resource "cloudflare_record" "spf"' in tf_hcl
    assert 'resource "aws_route53_record" "spf"' in tf_hcl
    assert 'v=spf1' in tf_hcl
    assert '-all' in tf_hcl

    # DKIM resources
    assert 'resource "cloudflare_record" "dkim"' in tf_hcl
    assert 'resource "aws_route53_record" "dkim"' in tf_hcl
    assert 'v=DKIM1;' in tf_hcl

    # CAA resources
    assert 'resource "cloudflare_record" "caa_letsencrypt"' in tf_hcl or 'resource "cloudflare_record" "caa"' in tf_hcl
    assert 'resource "aws_route53_record" "caa"' in tf_hcl
    assert 'letsencrypt.org' in tf_hcl


def test_generate_dns_fixes_tf_with_findings_and_customization(sample_findings):
    """Terraform HCL incorporates detected findings like dangling CNAMEs and custom policies."""
    domain = "orbitsecurity.ai"
    tf_hcl = DnsRemediationGenerator.generate_dns_fixes_tf(
        domain=domain,
        findings=sample_findings,
        policy="reject",
        report_email="dmarc-reports@orbitsecurity.ai",
        spf_record="v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all",
        ca_list=["letsencrypt.org", "digicert.com", "globalsign.com"],
    )

    # Custom DMARC policy & reporting
    assert "p=reject;" in tf_hcl
    assert "rua=mailto:dmarc-reports@orbitsecurity.ai" in tf_hcl

    # Custom SPF record
    assert "ip4:192.0.2.0/24" in tf_hcl

    # Dangling CNAME remediation
    assert "remediated_cname" in tf_hcl
    assert "blog" in tf_hcl
    assert "decommissioned.invalid" in tf_hcl

    # Custom CA list
    assert "globalsign.com" in tf_hcl


# ==============================================================================
# 2. RFC 1035 BIND Zone File Generation Tests (<domain>.zone)
# ==============================================================================


def test_generate_zone_file_rfc1035_standard():
    """Generates standard RFC 1035 BIND zone file with $ORIGIN, $TTL, and core records."""
    domain = "orbitsecurity.ai"
    zone = DnsRemediationGenerator.generate_zone_file(domain)

    # Standard directives
    assert f"$ORIGIN {domain}." in zone
    assert "$TTL 300" in zone

    # Core DNS records
    assert '_dmarc\tIN\tTXT\t"v=DMARC1;' in zone
    assert '@\tIN\tTXT\t"v=spf1' in zone
    assert 'default._domainkey\tIN\tTXT\t"v=DKIM1;' in zone
    assert '@\tIN\tCAA\t0 issue "letsencrypt.org"' in zone
    assert '@\tIN\tCAA\t0 issue "digicert.com"' in zone


def test_generate_zone_file_with_findings(sample_findings):
    """Zone file includes custom SPF, reporting, and dangling CNAME decommission records."""
    domain = "orbitsecurity.ai"
    zone = DnsRemediationGenerator.generate_zone_file(
        domain=domain,
        findings=sample_findings,
        policy="quarantine",
        report_email="sec-ops@orbitsecurity.ai",
        spf_record="v=spf1 ip4:198.51.100.1 -all",
    )

    assert "rua=mailto:sec-ops@orbitsecurity.ai" in zone
    assert "ip4:198.51.100.1 -all" in zone
    assert "remediated-decommissioned-by-orbit" in zone
    assert "blog" in zone


# ==============================================================================
# 3. RFC 9116 Security Policy Generation Tests (security.txt)
# ==============================================================================


def test_generate_security_txt_rfc9116():
    """Generates RFC 9116 compliant security.txt content."""
    domain = "orbitsecurity.ai"
    email = "security@orbitsecurity.ai"
    sec_txt = DnsRemediationGenerator.generate_security_txt(
        domain=domain,
        contact_email=email,
        policy_url="https://orbitsecurity.ai/disclosure",
        days_valid=180,
    )

    assert f"Contact: mailto:{email}" in sec_txt
    assert "Expires: " in sec_txt
    assert "Preferred-Languages: en" in sec_txt
    assert f"Canonical: https://{domain}/.well-known/security.txt" in sec_txt
    assert "Policy: https://orbitsecurity.ai/disclosure" in sec_txt


# ==============================================================================
# 4. Atomic Fix Pack ZIP Packaging Tests (build_fixpack & export_dns_fixpack)
# ==============================================================================


def test_build_fixpack_creates_atomic_zip(temp_workspace, sample_findings):
    """build_fixpack generates an atomic ZIP with manifest and all required fix files."""
    domain = "orbitsecurity.ai"
    result = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        findings=sample_findings,
        output_dir=temp_workspace,
        policy="reject",
        contact_email="security@orbitsecurity.ai",
    )

    assert result["ok"] is True
    fixpack_path = Path(result["fixpack_path"])
    assert fixpack_path.exists()
    assert fixpack_path.is_file()

    # Verify ZIP magic header bytes (PK\x03\x04)
    raw_header = fixpack_path.read_bytes()[:4]
    assert raw_header == b"PK\x03\x04"

    # Verify archive member entries
    with zipfile.ZipFile(fixpack_path, "r") as zf:
        namelist = zf.namelist()
        assert "dns_fixes.tf" in namelist
        assert f"{domain}.zone" in namelist or f"{domain.replace('.', '_')}.zone" in namelist
        assert "security.txt" in namelist
        assert "fixpack_manifest.json" in namelist

        # Verify manifest content and file checksums
        manifest_data = json.loads(zf.read("fixpack_manifest.json").decode("utf-8"))
        assert manifest_data["domain"] == domain
        assert "files" in manifest_data

        for entry in manifest_data["files"]:
            filename = entry["path"]
            if filename == "fixpack_manifest.json":
                continue
            file_bytes = zf.read(filename)
            computed_sha = hashlib.sha256(file_bytes).hexdigest()
            assert entry["sha256"] == computed_sha
            assert entry["size_bytes"] == len(file_bytes)

    # Verify overall bundle SHA256 matches
    bundle_sha = hashlib.sha256(fixpack_path.read_bytes()).hexdigest()
    assert result["sha256"] == bundle_sha

    # Verify sidecar manifest if present
    sidecar_path = fixpack_path.parent / "fixpack_manifest.json"
    if sidecar_path.exists():
        sidecar_data = json.loads(sidecar_path.read_text(encoding="utf-8"))
        assert sidecar_data.get("bundle_sha256") == bundle_sha


def test_client_bundle_exporter_export_dns_fixpack(temp_workspace, sample_findings):
    """ClientBundleExporter.export_dns_fixpack() creates and returns Path to atomic ZIP."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)
    domain = "orbitsecurity.ai"

    # Calling as instance method returning Path
    out_path = exporter.export_dns_fixpack(
        domain=domain,
        findings=sample_findings,
        output_dir=temp_workspace / "exports",
    )

    assert isinstance(out_path, Path)
    assert out_path.exists()
    assert zipfile.is_zipfile(out_path)

    # Calling as class method also functions seamlessly
    class_call_path = ClientBundleExporter.export_dns_fixpack(
        domain="clientcorp.com",
        output_dir=temp_workspace / "exports_class",
    )
    assert isinstance(class_call_path, Path)
    assert class_call_path.exists()
    assert zipfile.is_zipfile(class_call_path)

    # Calling with as_dict=True returns structured dict
    dict_result = exporter.export_dns_fixpack(
        domain=domain,
        output_dir=temp_workspace / "exports_dict",
        as_dict=True,
    )
    assert isinstance(dict_result, dict)
    assert dict_result["ok"] is True
    assert Path(dict_result["fixpack_path"]).exists()


def test_fixpack_safe_extraction_and_zip_slip_prevention(temp_workspace):
    """Validates that all archive members extract safely without Zip Slip traversal vulnerabilities."""
    domain = "orbitsecurity.ai"
    result = DnsRemediationGenerator.build_fixpack(
        domain=domain,
        output_dir=temp_workspace,
    )
    zip_path = Path(result["fixpack_path"])

    extract_dest = temp_workspace / "extracted"
    extract_dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Check for directory traversal sequences
            assert not member.filename.startswith(("/", "\\"))
            assert ".." not in member.filename
            assert not os.path.isabs(member.filename)

        zf.extractall(extract_dest)

    # Confirm extracted files exist inside destination
    assert (extract_dest / "dns_fixes.tf").exists()
    assert (extract_dest / "security.txt").exists()
    assert (extract_dest / "fixpack_manifest.json").exists()


def test_fixpack_concurrent_export_directory_mutex(temp_workspace):
    """Ensures concurrent exports to the same target directory do not crash or corrupt files."""
    exporter = ClientBundleExporter(workspace_root=temp_workspace)
    domain = "concurrent-brand.io"
    target_dir = temp_workspace / "concurrent_runs"
    target_dir.mkdir(parents=True, exist_ok=True)

    def worker_run(worker_id: int):
        return exporter.export_dns_fixpack(
            domain=domain,
            output_dir=target_dir,
            contact_email=f"ops-{worker_id}@concurrent-brand.io",
            as_dict=True,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_run, i) for i in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    for r in results:
        assert r["ok"] is True
        p = Path(r["fixpack_path"])
        assert p.exists()
        assert zipfile.is_zipfile(p)


def test_fixpack_subdomain_suffix_stripping_and_target_field_regression():
    """Verifies suffix stripping preserves prefix substrings and accepts 'domain'/'target' finding fields."""
    domain = "io.com"
    findings = [
        {
            "title": "Dangling CNAME Takeover",
            "domain": "studio.com.io.com",
            "cname_target": "unclaimed.s3.amazonaws.com",
        },
        {
            "title": "Subdomain Takeover",
            "target": "io.com-staging.io.com",
            "cname_target": "staging.ghost.io",
        },
    ]
    tf_hcl = DnsRemediationGenerator.generate_dns_fixes_tf(domain=domain, findings=findings)
    zone = DnsRemediationGenerator.generate_zone_file(domain=domain, findings=findings)

    assert 'name    = "studio.com"' in tf_hcl
    assert 'name    = "io.com-staging"' in tf_hcl
    assert 'studio.com\tIN\tTXT\t"remediated-decommissioned-by-orbit"' in zone
    assert 'io.com-staging\tIN\tTXT\t"remediated-decommissioned-by-orbit"' in zone

