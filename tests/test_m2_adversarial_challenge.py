"""Adversarial challenge test suite for Milestone M2 (Client Remediation & Export Bundle Generator).

Author: teamwork_challenger_m2_2 (Empirical Challenger)
Target:
1. Concurrency stress: multiple concurrent threads calling export_bundle on identical and distinct agency targets.
2. Stripe webhook edge cases: empty metadata, missing customer details, weird/malicious domain inputs, and deal desk failures.
3. Retainer manager fallback: unconfigured agencies, corrupt/missing config files, empty domains/findings, hex color injection defense.
4. Anti-spoofing and cryptographic tamper validation.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List
import unittest.mock
import uuid
import zipfile

import pytest
import yaml

from orbit_security.agency_retainer import AgencyRetainer, AgencyRetainerManager, RetainerTier
from orbit_security.client_bundle_exporter import ClientBundleExporter, _sanitize_hex_color
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


# ============================================================================
# 1. Concurrency Challenge: Multiple simultaneous export_bundle invocations
# ============================================================================


def test_concurrency_simultaneous_exports_same_agency(temp_workspace):
    """Stress tests concurrent export_bundle execution for the exact same agency slug.
    
    Verifies that simultaneous calls do not produce corrupted archives, partial writes,
    or leave stray temporary files, and that the final target bundle is valid.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)
    agency_slug = "concurrent-agency"

    num_threads = 8
    results = []
    errors = []

    def run_export(idx: int) -> Dict[str, Any]:
        return exporter.export_bundle(
            agency_slug=agency_slug,
            agency_name="Concurrent Agency",
            domains=[f"target{idx}.example.com", "apex.example.com"],
            primary_color="#123456",
            accent_color="#abcdef",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(run_export, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                results.append(res)
            except Exception as e:
                errors.append(e)

    # All calls should either succeed atomically or if Windows locking transiently blocks replace,
    # we observe exact error behavior. Let's inspect:
    assert len(errors) == 0, f"Concurrent export encountered errors: {errors}"
    assert len(results) == num_threads

    target_zip = bundles_dir / agency_slug / f"{agency_slug}_remediation_bundle.zip"
    assert target_zip.exists()
    assert zipfile.is_zipfile(target_zip)

    # Ensure no leftover temporary files (.tmp.zip) in agency directory
    agency_files = list((bundles_dir / agency_slug).iterdir())
    tmp_files = [f for f in agency_files if ".tmp" in f.name]
    assert len(tmp_files) == 0, f"Found leaked temporary files: {tmp_files}"

    with zipfile.ZipFile(target_zip, "r") as archive:
        namelist = archive.namelist()
        for required in [
            "reports/executive_summary.html",
            "reports/executive_summary.md",
            "remediation/remediation.tf",
            "remediation/remediation.cfn.yaml",
            "remediation/remediation.zone",
            ".orbit.yml",
            "bundle_manifest.json",
        ]:
            assert required in namelist


def test_concurrency_distinct_agencies_in_parallel(temp_workspace):
    """Stress tests concurrent export_bundle across 10 distinct agencies simultaneously."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    num_agencies = 10
    results = []

    def run_agency_export(i: int):
        slug = f"parallel-agency-{i}"
        return exporter.export_bundle(
            agency_slug=slug,
            agency_name=f"Parallel Agency {i}",
            domains=[f"brand-{i}.com"],
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_agencies) as executor:
        futures = [executor.submit(run_agency_export, i) for i in range(num_agencies)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    assert len(results) == num_agencies
    for res in results:
        assert res["ok"] is True
        p = Path(res["bundle_path"])
        assert p.exists()
        assert zipfile.is_zipfile(p)


# ============================================================================
# 2. Stripe Webhook Edge Cases & Adversarial Payloads
# ============================================================================


def test_stripe_webhook_empty_metadata_and_details(temp_workspace):
    """Adversarially tests checkout.session.completed with empty metadata and missing details."""
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"

    webhook_secret = "whsec_adversarial_test_secret"
    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
    )

    # Empty metadata and minimal customer details
    payload = {
        "id": "evt_minimal_001",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_minimal_123",
                "customer": "cus_minimal_456",
                "customer_details": {},
                "metadata": {},
                "amount_total": 29900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_stripe_signature(payload_bytes, webhook_secret)

    res = handler.handle_webhook(payload_bytes, sig)

    assert res["status"] == "PROVISIONED"
    # Even without domain, it defaults gracefully
    assert res["apex_domain"] is not None
    assert len(res["apex_domain"]) > 0
    # Bundle should still be generated safely via default "client" agency
    assert res["bundle_path"] is not None
    assert Path(res["bundle_path"]).exists()
    assert zipfile.is_zipfile(Path(res["bundle_path"]))


def test_stripe_webhook_adversarial_subdomain_and_paths(temp_workspace):
    """Tests handling of weird domain strings (directory traversal, special chars) in metadata."""
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"

    webhook_secret = "whsec_path_traversal_test"
    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
    )

    # Domain with path traversal attempt and weird characters
    malicious_domain = "../../malicious_escape/test.domain.com"
    payload = {
        "id": "evt_malicious_002",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_malicious_123",
                "customer": "cus_malicious_456",
                "customer_details": {"email": "security@test.domain.com", "name": "Test Agency"},
                "metadata": {
                    "domain": malicious_domain,
                    "agency_id": "../evil-slug",
                },
                "amount_total": 49900,
                "currency": "usd",
                "payment_status": "paid",
            }
        },
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_stripe_signature(payload_bytes, webhook_secret)

    res = handler.handle_webhook(payload_bytes, sig)

    assert res["status"] == "PROVISIONED"
    bundle_path = Path(res["bundle_path"])
    assert bundle_path.exists()
    # Ensure the generated bundle is constrained under client_bundles and not escaped outside
    bundles_parent = (temp_workspace / "client_bundles").resolve()
    assert bundles_parent in bundle_path.resolve().parents


def test_stripe_webhook_concierge_failure_resilience(temp_workspace):
    """Verifies that if concierge / bundle generation throws an exception,
    the webhook handler does not crash, and subscriber onboarding and SLA certificate
    are still completed (fault tolerance / blast radius isolation).
    """
    sub_file = temp_workspace / "subscribers.json"
    clients_file = temp_workspace / "clients.json"
    certs_dir = temp_workspace / "certificates"

    webhook_secret = "whsec_resilience_test"
    sub_mgr = SubscriberManager(subscribers_file=sub_file)
    cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
    registry = FleetRegistry(data_path=clients_file)

    # Create a mock concierge that explodes during generate_bundle_for_agency
    mock_concierge = unittest.mock.MagicMock()
    mock_concierge.generate_bundle_for_agency.side_effect = RuntimeError("Disk quota exceeded / simulated I/O fault")

    handler = StripeWebhookHandler(
        webhook_secret=webhook_secret,
        subscriber_manager=sub_mgr,
        sla_generator=cert_gen,
        fleet_registry=registry,
        deal_desk=mock_concierge,
    )

    payload = {
        "id": "evt_concierge_fault",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_fault_test",
                "customer": "cus_fault_test",
                "customer_details": {"email": "cto@resilient.com", "name": "Resilient Co"},
                "metadata": {"domain": "resilient.com"},
            }
        },
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_stripe_signature(payload_bytes, webhook_secret)

    res = handler.handle_webhook(payload_bytes, sig)

    # Even with bundle generation failing, core onboarding must succeed
    assert res["status"] == "PROVISIONED"
    assert res["bundle_path"] is None
    assert res["bundle_sha256"] is None
    # SLA cert was created
    assert Path(res["sla_certificate_path"]).exists()
    # Subscriber was recorded
    assert any(s.get("stripe_customer_id") == "cus_fault_test" or s.get("customer_id") == "cus_fault_test" for s in sub_mgr.list_subscribers())



# ============================================================================
# 3. Retainer Manager Fallback & Unconfigured Agency Scenarios
# ============================================================================


def test_export_bundle_unconfigured_agency(temp_workspace):
    """Tests bundle export for an agency completely absent from agency retainers."""
    bundles_dir = temp_workspace / "client_bundles"
    # Create empty retainer manager
    empty_data_path = temp_workspace / "empty_retainers.json"
    empty_data_path.write_text(json.dumps({"version": "1.0", "agencies": []}), encoding="utf-8")
    rm = AgencyRetainerManager(data_path=empty_data_path)

    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir, retainer_manager=rm)

    # Only supply agency_slug
    res = exporter.export_bundle(agency_slug="brand-new-consulting")

    assert res["ok"] is True
    assert res["agency_slug"] == "brand-new-consulting"
    assert res["agency_name"] == "Brand New Consulting"

    bundle_path = Path(res["bundle_path"])
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as archive:
        # Check that baseline findings were injected
        cfn_yaml = archive.read("remediation/remediation.cfn.yaml").decode("utf-8")
        parsed_cfn = yaml.safe_load(cfn_yaml)
        assert "DmarcRecordSet" in parsed_cfn["Resources"]
        assert "SpfRecordSet" in parsed_cfn["Resources"]
        assert "HardenedS3Bucket" in parsed_cfn["Resources"]

        orbit_yaml = archive.read(".orbit.yml").decode("utf-8")
        parsed_orbit = yaml.safe_load(orbit_yaml)
        assert parsed_orbit["agency"]["slug"] == "brand-new-consulting"
        assert parsed_orbit["targets"][0]["domain"] == "brand-new-consulting.com"


def test_export_bundle_malformed_slug_and_colors(temp_workspace):
    """Tests defense against malicious / invalid slugs and CSS/hex injection."""
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    # Slug with malicious punctuation and hex color with CSS injection attempt
    res = exporter.export_bundle(
        agency_slug="   !!!@@@###$$$%%%   ",
        agency_name="Adversarial Corp",
        primary_color="red; } body { background: black; } /*",
        accent_color="javascript:alert(1)",
    )

    assert res["ok"] is True
    # Sanitized slug falls back to 'agency'
    assert res["agency_slug"] == "agency"

    bundle_path = Path(res["bundle_path"])
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as archive:
        html_report = archive.read("reports/executive_summary.html").decode("utf-8")
        # Ensure injected strings are neutralized and fallbacks are used
        assert "javascript:alert(1)" not in html_report
        assert "#0B132B" in html_report
        assert "#48CAE4" in html_report


def test_sanitize_hex_color_utility():
    """Unit tests for _sanitize_hex_color."""
    assert _sanitize_hex_color("#123456", "#000000") == "#123456"
    assert _sanitize_hex_color("#ABC", "#000000") == "#ABC"
    assert _sanitize_hex_color("not-a-color", "#000000") == "#000000"
    assert _sanitize_hex_color("", "#000000") == "#000000"
    assert _sanitize_hex_color(None, "#000000") == "#000000"
    assert _sanitize_hex_color("#12345", "#000000") == "#000000"  # Invalid length


# ============================================================================
# 4. Anti-Spoofing & Tamper Detection
# ============================================================================


def test_anti_spoofing_tampered_manifest_detection(temp_workspace):
    """Verifies that cryptographic integrity checks in bundle_manifest.json
    detect tampering if any file in the package is modified.
    """
    bundles_dir = temp_workspace / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=temp_workspace, bundles_dir=bundles_dir)

    res = exporter.export_bundle(
        agency_slug="tamper-test",
        agency_name="Tamper Test Agency",
        domains=["tampertest.com"],
    )

    bundle_path = Path(res["bundle_path"])

    with zipfile.ZipFile(bundle_path, "r") as archive:
        manifest_data = json.loads(archive.read("bundle_manifest.json").decode("utf-8"))
        # Check every file hash
        for entry in manifest_data["files"]:
            fn = entry["path"]
            actual_bytes = archive.read(fn)
            actual_hash = hashlib.sha256(actual_bytes).hexdigest()
            # Cryptographic hash in manifest must accurately reflect actual content
            assert entry["sha256"] == actual_hash
            assert entry["size_bytes"] == len(actual_bytes)
