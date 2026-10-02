"""Unit tests for Act IV Product 1: GhostDNS Standalone Micro-SaaS (ghost_dns.py).

Covers:
  - Seed targets and multi-tenant registration.
  - Authoritative DNS baseline snapshotting.
  - DNS drift detection sentinel (detecting CNAME, A, MX record shifts).
  - Dangling SaaS CNAME takeover detection (AWS S3, Unbounce, GitHub Pages).
  - Headless audit execution, hygiene scoring, and JSON report generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from orbit_security.ghost_dns import (
    DnsBaseline,
    GhostDNSAuditReport,
    GhostDNSManager,
    GhostDNSTarget,
)
from orbit_security.models import Severity


class TestGhostDNS:
    def test_default_seed_targets(self, tmp_path):
        targets_file = tmp_path / "ghostdns_targets.json"
        baselines_file = tmp_path / "ghostdns_baselines.json"
        manager = GhostDNSManager(targets_file=targets_file, baselines_file=baselines_file)

        assert len(manager.targets) >= 2
        assert "store-candykittens" in manager.targets
        assert "agency-eastside" in manager.targets
        assert targets_file.exists()

    def test_register_target_and_capture_baseline(self, tmp_path):
        targets_file = tmp_path / "ghostdns_targets.json"
        baselines_file = tmp_path / "ghostdns_baselines.json"
        manager = GhostDNSManager(targets_file=targets_file, baselines_file=baselines_file)

        target = manager.register_target(
            domain="brand-store.com",
            client_name="Brand Store DTC",
            plan="Store",
            subdomains=["shop.brand-store.com", "cdn.brand-store.com"],
        )
        assert target.domain == "brand-store.com"
        assert target.plan == "Store"

        mock_recs = {
            "A": ["104.21.55.2"],
            "CNAME": ["shops.myshopify.com"],
            "MX": ["mail.brand-store.com"],
        }
        baseline = manager.capture_baseline("brand-store.com", mock_records=mock_recs)
        assert baseline.domain == "brand-store.com"
        assert baseline.records["CNAME"] == ["shops.myshopify.com"]

        # Re-load from disk
        reloaded = GhostDNSManager(targets_file=targets_file, baselines_file=baselines_file)
        assert "brand-store-com" in reloaded.targets
        assert "brand-store.com" in reloaded.baselines

    def test_dns_drift_detection_no_change(self, tmp_path):
        manager = GhostDNSManager(
            targets_file=tmp_path / "targets.json",
            baselines_file=tmp_path / "baselines.json",
        )
        mock_recs = {"CNAME": ["shops.myshopify.com"], "A": ["104.21.55.2"]}
        manager.capture_baseline("mystore.com", mock_records=mock_recs)

        # Same records queried -> zero drift
        anomalies = manager.check_dns_drift("mystore.com", current_records=mock_recs)
        assert len(anomalies) == 0

    def test_dns_drift_detection_cname_shifted(self, tmp_path):
        manager = GhostDNSManager(
            targets_file=tmp_path / "targets.json",
            baselines_file=tmp_path / "baselines.json",
        )
        initial_recs = {"CNAME": ["unbouncepages.com"], "A": ["1.1.1.1"]}
        manager.capture_baseline("campaign.mystore.com", mock_records=initial_recs)

        # CNAME shifted to rogue pointer
        shifted_recs = {"CNAME": ["rogue-server.attacker.com"], "A": ["1.1.1.1"]}
        anomalies = manager.check_dns_drift("campaign.mystore.com", current_records=shifted_recs)

        assert len(anomalies) == 1
        anom = anomalies[0]
        assert anom.record_type == "CNAME"
        assert anom.severity == Severity.HIGH
        assert "rogue-server.attacker.com" in anom.current_values

    def test_scan_for_dangling_cname_s3(self, tmp_path):
        manager = GhostDNSManager(
            targets_file=tmp_path / "targets.json",
            baselines_file=tmp_path / "baselines.json",
        )
        res = manager.scan_for_dangling_cname(
            domain="assets.store.com",
            mock_cname="store-assets.s3.amazonaws.com",
            mock_body="<Code>NoSuchBucket</Code>",
        )
        assert res is not None
        assert res["provider"] == "AWS S3"
        assert res["cname_target"] == "store-assets.s3.amazonaws.com"
        assert res["severity"] == "CRITICAL"

    def test_execute_audit_full(self, tmp_path):
        manager = GhostDNSManager(
            targets_file=tmp_path / "targets.json",
            baselines_file=tmp_path / "baselines.json",
        )
        manager.register_target("audit-store.com", client_name="Audit Store")
        manager.capture_baseline("audit-store.com", mock_records={"CNAME": ["shops.myshopify.com"]})

        # Test clean audit
        clean_report = manager.execute_audit(
            "audit-store.com",
            mock_records={"CNAME": ["shops.myshopify.com"]},
            mock_cname="shops.myshopify.com",
            mock_body="Welcome to real store",
        )
        assert clean_report.score >= 95
        assert clean_report.grade == "A+"
        assert clean_report.is_vulnerable is False

        # Test vulnerable audit (dangling CNAME)
        vuln_report = manager.execute_audit(
            "audit-store.com",
            mock_records={"CNAME": ["audit-store.unbouncepages.com"]},
            mock_cname="audit-store.unbouncepages.com",
            mock_body="The requested URL was not found on this server",
        )
        assert vuln_report.is_vulnerable is True
        assert len(vuln_report.dangling_cnames) == 1
        assert vuln_report.score < 70
