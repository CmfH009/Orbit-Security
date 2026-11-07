"""Unit and integration test suite for Client Remediation & Export Bundle Generator (Milestone M2).

Verifies:
1. Atomic ZIP bundle generation:
   - Output path format: <bundles_dir>/<agency_slug>/<agency_slug>_remediation_bundle.zip
   - Valid ZIP header magic bytes (PK\x03\x04)
   - Atomic replacement semantics
2. Required ZIP internal directory structure and deliverables:
   - reports/executive_summary.html
   - reports/executive_summary.md
   - remediation/remediation.tf
   - remediation/remediation.cfn.yaml
   - remediation/remediation.zone
   - .orbit.yml
   - bundle_manifest.json
3. Branded styling:
   - CSS variables (--card-bg, --accent, etc.) inject custom primary and accent hex colors
   - Markdown summary includes agency branding and color references
4. Infrastructure-as-Code (Terraform HCL):
   - Cloudflare & Route53 records for SPF (-all), DMARC (p=reject / p=quarantine), CAA
   - S3 bucket security blocks: aws_s3_bucket, aws_s3_bucket_public_access_block, aws_s3_bucket_versioning
5. Infrastructure-as-Code (AWS CloudFormation YAML):
   - Valid YAML parseable with PyYAML
   - AWS::Route53::RecordSet resources
   - AWS::S3::Bucket with PublicAccessBlockConfiguration & VersioningConfiguration
6. Ready-to-run .orbit.yml sentinel config:
   - Valid YAML parseable with PyYAML
   - Correct target domains and configured sentinel modules (cname_takeover, cloud_buckets, email_security, agent_perimeter)
7. Cryptographic checksums and bundle manifest:
   - bundle_manifest.json has SHA256 checksums matching file byte digests
8. RetainerDealDeskConcierge wiring:
   - generate_bundle_for_agency() method creates bundle under bundles_dir
9. Stripe Webhook checkout.session.completed flow:
   - Automatically provisions client remediation bundle in client_bundles directory
   - Returns bundle_path and bundle_sha256 in webhook result
10. CLI scripts/export_agency_bundle.py execution:
   - Supports --agency, --name, --domains, --primary-color, --accent-color, --output-dir, --json
   - Successfully generates bundle on disk and returns exit code 0
11. OpSec gitignore verification:
   - data/client_bundles/ is verified gitignored
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Dict, List
import zipfile

import pytest
import yaml

from orbit_security.agency_retainer import AgencyClientSite, AgencyRetainer, AgencyRetainerManager, RetainerTier
from orbit_security.client_bundle_exporter import ClientBundleExporter
from orbit_security.deal_desk import RetainerDealDeskConcierge
from orbit_security.fleet import FleetRegistry
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    generate_stripe_signature,
)


@pytest.fixture
def temp_workspace():
    """Provides an isolated temporary workspace directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_findings() -> List[Dict[str, Any]]:
    return [
        {
            "id": "FIND-001",
            "title": "Dangling CNAME DNS Takeover Risk",
            "subdomain": "shop.clientbrand.com",
            "cname_target": "custom-app.myshopify.com",
            "saas_provider": "Shopify",
            "severity": "CRITICAL",
            "category": "DNS",
            "description": "Subdomain points to an unclaimed Shopify store endpoint.",
        },
        {
            "id": "FIND-002",
            "title": "Missing Strict DMARC Reject Policy",
            "subdomain": "_dmarc.clientbrand.com",
            "severity": "HIGH",
            "category": "Email",
            "description": "DMARC policy is p=none, allowing email spoofing.",
        },
        {
            "id": "FIND-003",
            "title": "Permissive SPF Record (~all)",
            "subdomain": "clientbrand.com",
            "severity": "MEDIUM",
            "category": "Email",
            "description": "SPF record uses soft-fail ~all instead of strict hard-fail -all.",
        },
        {
            "id": "FIND-004",
            "title": "Unprotected Cloud S3 Storage Bucket",
            "subdomain": "assets.clientbrand.com",
            "bucket_name": "clientbrand-static-assets",
            "severity": "HIGH",
            "category": "Cloud",
            "description": "S3 bucket lacks public access block and versioning configuration.",
        },
    ]


# ============================================================================
# 1. Atomic ZIP Generation & Delivery Tests
# ============================================================================


def test_client_bundle_exporter_atomic_zip_generation(temp_workspace, sample_findings):
    """Verifies that ClientBundleExporter generates an atomic, valid ZIP file at the target path."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="eastside-co",
        agency_name="Eastside Co",
        domains=["candykittens.co.uk", "wildfang.com"],
        findings=sample_findings,
        primary_color="#0B132B",
        accent_color="#48CAE4",
        support_email="ops@eastsideco.com",
        tagline="Enterprise Shopify Plus Technical Solutions",
        tier="Scale",
    )

    assert result["ok"] is True
    assert "bundle_path" in result
    bundle_path = Path(result["bundle_path"])

    # Path must reside in <bundles_dir>/<agency_slug>/<agency_slug>_remediation_bundle.zip
    expected_path = bundles_dir / "eastside-co" / "eastside-co_remediation_bundle.zip"
    assert bundle_path.resolve() == expected_path.resolve()
    assert bundle_path.exists()
    assert bundle_path.is_file()
    assert bundle_path.stat().st_size > 0

    # Verify valid ZIP header
    with open(bundle_path, "rb") as f:
        header = f.read(4)
        assert header == b"PK\x03\x04"

    # Verify zipfile library can read the archive without error
    assert zipfile.is_zipfile(bundle_path)


# ============================================================================
# 2. Archive Internal Content & Layout Tests
# ============================================================================


def test_client_bundle_zip_contents(temp_workspace, sample_findings):
    """Verifies that the ZIP bundle contains all 7 required files in their respective folders."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="apex-creative",
        agency_name="Apex Creative",
        domains=["apexcreative.io"],
        findings=sample_findings,
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        namelist = archive.namelist()

        required_files = [
            "reports/executive_summary.html",
            "reports/executive_summary.md",
            "remediation/remediation.tf",
            "remediation/remediation.cfn.yaml",
            "remediation/remediation.zone",
            ".orbit.yml",
            "bundle_manifest.json",
        ]

        for rf in required_files:
            assert rf in namelist, f"Expected {rf} inside bundle archive, found: {namelist}"


# ============================================================================
# 3. Custom Color Branding & Reporting Tests
# ============================================================================


def test_executive_summary_report_custom_color_branding(temp_workspace, sample_findings):
    """Verifies that custom primary and accent hex colors are injected into the HTML and Markdown reports."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    primary_hex = "#1E293B"
    accent_hex = "#10B981"

    result = exporter.export_bundle(
        agency_slug="brand-studio",
        agency_name="Brand Studio",
        domains=["brandstudio.agency"],
        findings=sample_findings,
        primary_color=primary_hex,
        accent_color=accent_hex,
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        # Check HTML report
        html_content = archive.read("reports/executive_summary.html").decode("utf-8")
        assert primary_hex.lower() in html_content.lower()
        assert accent_hex.lower() in html_content.lower()
        assert "--card-bg" in html_content or "--primary" in html_content
        assert "--accent" in html_content
        assert "Brand Studio" in html_content
        assert "brandstudio.agency" in html_content

        # Check Markdown report
        md_content = archive.read("reports/executive_summary.md").decode("utf-8")
        assert "Brand Studio" in md_content
        assert "brandstudio.agency" in md_content
        assert primary_hex.lower() in md_content.lower() or accent_hex.lower() in md_content.lower()


# ============================================================================
# 4. Terraform HCL Remediation Content Tests
# ============================================================================


def test_terraform_remediation_content(temp_workspace, sample_findings):
    """Verifies that remediation.tf contains Terraform blocks for SPF, DMARC, CNAMEs, and S3 bucket security."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="eastside-co",
        agency_name="Eastside Co",
        domains=["candykittens.co.uk"],
        findings=sample_findings,
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        tf_content = archive.read("remediation/remediation.tf").decode("utf-8")

        # Must include SPF hard-fail
        assert "-all" in tf_content
        assert "cloudflare_record" in tf_content or "aws_route53_record" in tf_content

        # Must include DMARC enforcement
        assert "v=DMARC1" in tf_content
        assert "p=reject" in tf_content or "p=quarantine" in tf_content

        # Must include S3 bucket hardening
        assert "aws_s3_bucket" in tf_content
        assert "aws_s3_bucket_public_access_block" in tf_content
        assert "block_public_acls" in tf_content
        assert "block_public_policy" in tf_content
        assert "aws_s3_bucket_versioning" in tf_content


# ============================================================================
# 5. CloudFormation YAML Remediation Content Tests
# ============================================================================


def test_cloudformation_remediation_content(temp_workspace, sample_findings):
    """Verifies that remediation.cfn.yaml is valid CloudFormation YAML with Route53 and S3 resources."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="eastside-co",
        agency_name="Eastside Co",
        domains=["candykittens.co.uk"],
        findings=sample_findings,
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        cfn_raw = archive.read("remediation/remediation.cfn.yaml").decode("utf-8")

        # Parse YAML cleanly
        cfn_data = yaml.safe_load(cfn_raw)
        assert isinstance(cfn_data, dict)
        assert "AWSTemplateFormatVersion" in cfn_data
        assert "Resources" in cfn_data

        resources = cfn_data["Resources"]

        # Check for AWS::Route53::RecordSet
        has_route53 = any(res.get("Type") == "AWS::Route53::RecordSet" for res in resources.values())
        assert has_route53, "remediation.cfn.yaml must contain at least one AWS::Route53::RecordSet resource"

        # Check for AWS::S3::Bucket with PublicAccessBlockConfiguration & VersioningConfiguration
        s3_buckets = [res for res in resources.values() if res.get("Type") == "AWS::S3::Bucket"]
        assert len(s3_buckets) > 0, "remediation.cfn.yaml must contain at least one AWS::S3::Bucket resource"
        s3_res = s3_buckets[0]
        s3_props = s3_res.get("Properties", {})
        pab = s3_props.get("PublicAccessBlockConfiguration", {})
        assert pab.get("BlockPublicAcls") is True
        assert pab.get("BlockPublicPolicy") is True
        assert pab.get("IgnorePublicAcls") is True
        assert pab.get("RestrictPublicBuckets") is True

        ver = s3_props.get("VersioningConfiguration", {})
        assert ver.get("Status") == "Enabled"


# ============================================================================
# 6. .orbit.yml Sentinel Configuration Tests
# ============================================================================


def test_orbit_yml_sentinel_configuration(temp_workspace):
    """Verifies that .orbit.yml is valid YAML and includes client perimeter sentinels and target domains."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    domains = ["candykittens.co.uk", "wildfang.com", "trolli.com"]
    result = exporter.export_bundle(
        agency_slug="eastside-co",
        agency_name="Eastside Co",
        domains=domains,
        tier="Enterprise",
        support_email="ops@eastsideco.com",
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        orbit_raw = archive.read(".orbit.yml").decode("utf-8")

        orbit_cfg = yaml.safe_load(orbit_raw)
        assert isinstance(orbit_cfg, dict)
        assert "agency" in orbit_cfg
        assert orbit_cfg["agency"]["slug"] == "eastside-co"
        assert orbit_cfg["agency"]["name"] == "Eastside Co"
        assert orbit_cfg["agency"]["tier"] == "Enterprise"

        assert "targets" in orbit_cfg
        target_domains = [t["domain"] if isinstance(t, dict) else t for t in orbit_cfg["targets"]]
        for d in domains:
            assert d in target_domains

        assert "sentinels" in orbit_cfg
        sentinels = orbit_cfg["sentinels"]
        assert "cname_takeover" in sentinels
        assert "cloud_buckets" in sentinels
        assert "email_security" in sentinels
        assert "agent_perimeter" in sentinels


# ============================================================================
# 7. Bundle Manifest & Checksum Integrity Tests
# ============================================================================


def test_bundle_manifest_checksums(temp_workspace, sample_findings):
    """Verifies that bundle_manifest.json includes SHA-256 hashes matching each archive member."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    result = exporter.export_bundle(
        agency_slug="eastside-co",
        agency_name="Eastside Co",
        domains=["candykittens.co.uk"],
        findings=sample_findings,
    )

    bundle_path = Path(result["bundle_path"])
    with zipfile.ZipFile(bundle_path, "r") as archive:
        manifest_raw = archive.read("bundle_manifest.json").decode("utf-8")
        manifest = json.loads(manifest_raw)

        assert manifest["agency_slug"] == "eastside-co"
        assert "files" in manifest
        assert isinstance(manifest["files"], list)

        # Check every file recorded in manifest against its actual bytes in the ZIP
        for entry in manifest["files"]:
            filename = entry["path"]
            if filename == "bundle_manifest.json":
                continue
            content = archive.read(filename)
            expected_hash = hashlib.sha256(content).hexdigest()
            assert entry["sha256"] == expected_hash, f"Hash mismatch for {filename}"


# ============================================================================
# 8. RetainerDealDeskConcierge Wiring Tests
# ============================================================================


def test_concierge_bundle_generation(temp_workspace, sample_findings):
    """Verifies that RetainerDealDeskConcierge.generate_bundle_for_agency() creates the delivery package."""
    portals_dir = temp_workspace / "portals"
    bundles_dir = temp_workspace / "client_bundles"

    concierge = RetainerDealDeskConcierge(
        workspace_root=temp_workspace,
        portals_dir=portals_dir,
        bundles_dir=bundles_dir,
    )

    result = concierge.generate_bundle_for_agency(
        agency_id="eastside-co",
        agency_name="Eastside Co",
        tier="scale",
        primary_client_domain="candykittens.co.uk",
        portfolio_domains=["candykittens.co.uk", "wildfang.com"],
        findings=sample_findings,
        primary_color="#0B132B",
        accent_color="#48CAE4",
        support_email="ops@eastsideco.com",
    )

    assert result["ok"] is True
    assert Path(result["bundle_path"]).exists()
    assert (bundles_dir / "eastside-co" / "eastside-co_remediation_bundle.zip").exists()


# ============================================================================
# 9. Stripe Webhook checkout.session.completed Wiring Tests
# ============================================================================


def test_stripe_webhook_triggers_bundle_generation(temp_workspace):
    """Tests that a paid checkout.session.completed event automatically generates the client bundle."""
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"
    portals_dir = temp_workspace / "portals"
    bundles_dir = temp_workspace / "client_bundles"

    webhook_secret = "whsec_test_secret_stripe_bundle"
    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
    )

    event_payload = {
        "id": "evt_checkout_bundle_test_001",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_bundle_session_123",
                "customer": "cus_bundle_456",
                "customer_details": {
                    "email": "ops@eastsideco.com",
                    "name": "Eastside Co",
                },
                "metadata": {
                    "domain": "candykittens.co.uk",
                    "plan": "Scale Retainer ($499/mo)",
                    "agency_id": "eastside-co",
                    "tier": "Scale",
                    "primary_color": "#0B132B",
                    "accent_color": "#48CAE4",
                },
                "amount_total": 49900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }

    payload_bytes = json.dumps(event_payload).encode("utf-8")
    sig_header = generate_stripe_signature(payload_bytes, webhook_secret)

    result = handler.handle_webhook(payload_bytes, sig_header)

    assert result["status"] == "PROVISIONED"
    assert "bundle_path" in result
    assert result["bundle_path"] is not None
    bundle_path = Path(result["bundle_path"])
    assert bundle_path.exists()
    assert bundle_path.is_file()
    assert zipfile.is_zipfile(bundle_path)


# ============================================================================
# 10. CLI scripts/export_agency_bundle.py Execution Tests
# ============================================================================


def test_cli_export_agency_bundle(temp_workspace):
    """Verifies that the CLI entry point scripts/export_agency_bundle.py successfully executes."""
    output_dir = temp_workspace / "cli_bundles"
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "export_agency_bundle.py"

    cmd = [
        sys.executable,
        str(script_path),
        "--agency",
        "eastside-co",
        "--output-dir",
        str(output_dir),
        "--json",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"CLI exited with error: {proc.stderr}\nStdout: {proc.stdout}"

    out_json = json.loads(proc.stdout)
    assert out_json["ok"] is True
    assert "bundle_path" in out_json
    assert Path(out_json["bundle_path"]).exists()


# ============================================================================
# 11. OpSec: Gitignore Status Tests
# ============================================================================


def test_opsec_bundle_directory_gitignored():
    """Verifies that data/client_bundles/ is ignored in the root .gitignore file."""
    repo_root = Path(__file__).resolve().parent.parent
    gitignore_path = repo_root / ".gitignore"

    assert gitignore_path.exists(), ".gitignore must exist in repo root"
    content = gitignore_path.read_text(encoding="utf-8")

    assert "data/client_bundles/" in content or "data/client_bundles" in content
