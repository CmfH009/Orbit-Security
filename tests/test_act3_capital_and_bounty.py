"""End-to-End Master Test Suite for Act III: Capital Expansion & Automated Bug Bounty Radar.

Verifies the complete Act III specification:
1. Automated Bug Bounty Radar (HackerOne / Bugcrowd):
   - Ingests public bug bounty program target scopes with broad wildcards (*.target.com).
   - Detects dangling CNAMEs on third-party SaaS services (AWS S3, GitHub Pages, Unbounce, Fastly, Shopify).
   - Identifies SPF/DMARC mail-spoofing vectors.
   - Respects off-peak execution schedule via orbit_daemon.py (2:00 AM - 5:00 AM MST).
   - Generates structured vulnerability disclosure reports conforming to HackerOne markdown standards.
2. Agency White-Label Retainer Tier ($299 - $499/mo):
   - Shifts from single $59/mo client plans to agency multi-tenant retainers.
   - Manages Starter ($299/mo, 15 domains) and Scale ($499/mo, 50 domains) quotas.
   - Generates co-branded portals (scripts/generate_agency_portal.py) allowing web development
     agencies to brand security reports with their own logo, colors, and custom agency domain.
3. Master Supervisor & CLI Integration:
   - orbit_daemon.py bounty-sweep execution and daemon state telemetry.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.agency_retainer import (
    AgencyClientSite,
    AgencyPortalRenderer,
    AgencyRetainer,
    AgencyRetainerManager,
    RetainerTier,
)
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyRadarSupervisor,
    BountyScopeIngester,
    BountyTakeoverSweeper,
    BountyVulnerability,
    HackerOneDisclosureGenerator,
    OffPeakWindow,
)
from orbit_security.models import Severity

SYSTEM_SCRIPTS = (
    Path("A:/system/scripts") if Path("A:/system/scripts").exists() else Path(r"C:\AgyHut\system\scripts")
)
if str(SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SYSTEM_SCRIPTS))

from orbit_daemon import BountyRadarSupervisorWorker, OrbitMasterSupervisor


# ============================================================================
# Act III Master Test 1: Bug Bounty Scope Ingestion & Takeover Sweeper
# ============================================================================

class TestAct3BugBountyRadar:
    """Tests the automated bug bounty radar and disclosure pipeline."""

    def test_h1_and_bugcrowd_scope_ingestion(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        ingester = BountyScopeIngester(data_path=data_file)

        # Ingest HackerOne JSON scope export
        h1_scope = {
            "handle": "shopify_plus_test",
            "name": "Shopify Plus Test",
            "max_bounty": 50000,
            "targets": {
                "in_scope": [
                    {"asset_identifier": "*.myshopify.com"},
                    {"asset_identifier": "*.shopifyapps.com"},
                ],
                "out_of_scope": [{"asset_identifier": "community.shopify.com"}],
            },
        }
        h1_progs = ingester.ingest_hackerone_scope(h1_scope)
        assert len(h1_progs) == 1
        assert h1_progs[0].program_id == "shopify_plus_test"
        assert "*.myshopify.com" in h1_progs[0].in_scope

        # Ingest Bugcrowd scope export
        bc_scope = [
            {
                "code": "hyatt_hotels",
                "name": "Hyatt Hotels",
                "max_payout": 15000,
                "targets": [{"uri": "*.hyatt.com"}],
            }
        ]
        bc_progs = ingester.ingest_bugcrowd_scope(bc_scope)
        assert len(bc_progs) == 1
        assert bc_progs[0].program_id == "hyatt_hotels"
        assert bc_progs[0].platform == "bugcrowd"

    def test_wildcard_expansion_and_takeover_detection(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets", "blog", "shop", "cdn"])
        expanded = sweeper.expand_wildcards(["*.target.com"], ["blog.target.com"], max_per_wildcard=5)
        assert "target.com" in expanded
        assert "assets.target.com" in expanded
        assert "shop.target.com" in expanded
        assert "blog.target.com" not in expanded  # Out of scope

        # Detect S3 dangling CNAME
        res_s3 = sweeper.check_subdomain_takeover(
            domain="assets.target.com",
            mock_cname="target-assets.s3.amazonaws.com",
            mock_body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        )
        assert res_s3 is not None
        sig, cname, evidence = res_s3
        assert sig.name == "AWS S3"
        assert "NoSuchBucket" in evidence

        # Detect GitHub Pages dangling CNAME
        res_gh = sweeper.check_subdomain_takeover(
            domain="docs.target.com",
            mock_cname="target-docs.github.io",
            mock_body="There isn't a GitHub Pages site here",
        )
        assert res_gh is not None
        assert res_gh[0].name == "GitHub Pages"

    def test_mail_spoofing_detection(self):
        sweeper = BountyTakeoverSweeper()
        # Missing DMARC
        vuln1 = sweeper.check_mail_spoofing("unprotected.org", mock_spf="v=spf1 ~all", mock_dmarc="")
        assert vuln1 is not None
        assert "Missing DMARC" in vuln1[0]
        assert vuln1[2] == Severity.HIGH

        # Permissive p=none
        vuln2 = sweeper.check_mail_spoofing("lax.org", mock_spf="v=spf1 ~all", mock_dmarc="v=DMARC1; p=none;")
        assert vuln2 is not None
        assert "p=none" in vuln2[0]
        assert vuln2[2] == Severity.MEDIUM

    def test_hackerone_markdown_disclosure_generation(self, tmp_path):
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="blog.myshopify.com",
            cname_target="shopify-blog.unbouncepages.com",
            flaw_type="subdomain_takeover",
            provider="Unbounce",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            evidence="Dangling CNAME matched Unbounce signature: 'The requested URL was not found on this server'",
            cwe_id="CWE-284: Improper Access Control",
            remediation="Remove orphaned CNAME record in DNS manager.",
        )

        md = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [Subdomain Takeover]" in md
        assert "blog.myshopify.com" in md
        assert "Shopify" in md
        assert "CWE-284" in md
        assert "7.5" in md
        assert "dig blog.myshopify.com CNAME +short" in md
        assert "Responsible Disclosure Notice" in md

        saved_file = HackerOneDisclosureGenerator.save_disclosure(vuln, output_dir=tmp_path)
        assert saved_file.exists()
        assert "shopify_subdomain_takeover_blog_myshopify_com" in saved_file.name

    def test_off_peak_window_and_supervisor_sweep(self, tmp_path):
        # Verify 2:00 AM - 5:00 AM MST calculation
        dt_in = datetime.datetime(2026, 10, 2, 9, 30, tzinfo=datetime.timezone.utc)  # 2:30 AM MST
        assert OffPeakWindow.is_off_peak(dt_in, start_hour=2, end_hour=5, tz_offset_hours=-7) is True

        dt_out = datetime.datetime(2026, 10, 2, 18, 0, tzinfo=datetime.timezone.utc)  # 11:00 AM MST
        assert OffPeakWindow.is_off_peak(dt_out, start_hour=2, end_hour=5, tz_offset_hours=-7) is False

        # Run supervisor sweep with mock finding
        data_file = tmp_path / "bounty_programs.json"
        state_file = tmp_path / "bounty_state.json"
        disclosures_dir = tmp_path / "disclosures"

        ingester = BountyScopeIngester(data_path=data_file)
        sweeper = BountyTakeoverSweeper()
        supervisor = BountyRadarSupervisor(ingester=ingester, sweeper=sweeper, state_file=state_file)

        mock_v = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="dev.myshopify.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            evidence="NoSuchBucket",
        )

        with patch.object(sweeper, "sweep_program", return_value=[mock_v]):
            res = supervisor.run_sweep(
                program_id="shopify",
                force_now=True,
                save_disclosures=True,
                output_dir=disclosures_dir,
            )
            assert res["status"] == "COMPLETED"
            assert res["vulnerabilities_found"] == 1
            assert len(res["disclosed_files"]) == 1
            assert Path(res["disclosed_files"][0]).exists()


# ============================================================================
# Act III Master Test 2: Agency White-Label Retainer Tier ($299 - $499/mo)
# ============================================================================

class TestAct3AgencyWhiteLabelRetainers:
    """Tests the agency multi-tenant retainers, branding, and portal generation."""

    def test_agency_tier_pricing_and_quota_limits(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)

        # Starter tier ($299/mo, max 15 domains)
        starter = manager.register_agency(
            agency_id="barrel-test",
            agency_name="Barrel Test",
            tier=RetainerTier.STARTER,
        )
        assert starter.monthly_price == 299
        assert starter.get_policy().max_domains == 15

        for i in range(15):
            manager.add_client_domain("barrel-test", f"brand{i}.com")
        assert len(starter.client_domains) == 15
        assert starter.can_add_domain() is False

        with pytest.raises(ValueError, match="reached its Starter tier domain limit"):
            manager.add_client_domain("barrel-test", "brand16.com")

        # Scale tier ($499/mo, max 50 domains, custom portal)
        scale = manager.register_agency(
            agency_id="eastside-test",
            agency_name="Eastside Test",
            tier=RetainerTier.SCALE,
            custom_domain="security.eastsidetest.com",
        )
        assert scale.monthly_price == 499
        assert scale.get_policy().max_domains == 50
        assert scale.get_policy().custom_portal_enabled is True

    def test_co_branded_portal_generation(self, tmp_path):
        docs_dir = tmp_path / "docs" / "portals"
        landing_dir = tmp_path / "landing" / "portals"

        agency = AgencyRetainer(
            agency_id="eastside-co",
            agency_name="Eastside Co",
            tier=RetainerTier.SCALE,
            monthly_price=499,
            custom_domain="security.eastsideco.com",
            agency_tagline="Enterprise Shopify Plus Technical Solutions",
            primary_color="#0B132B",
            accent_color="#48CAE4",
            support_email="ops@eastsideco.com",
            client_domains=[
                AgencyClientSite(domain="candykittens.co.uk", client_name="Candy Kittens", last_score=85, last_grade="B"),
                AgencyClientSite(domain="wildfang.com", client_name="Wildfang Apparel", last_score=95, last_grade="A+"),
            ],
        )

        docs_path, landing_path = AgencyPortalRenderer.save_portal(
            agency, output_dir=docs_dir, landing_dir=landing_dir
        )

        assert docs_path.exists()
        assert landing_path.exists()

        content = docs_path.read_text(encoding="utf-8")
        assert "Eastside Co" in content
        assert "security.eastsideco.com" in content
        assert "#0B132B" in content
        assert "#48CAE4" in content
        assert "Candy Kittens" in content
        assert "candykittens.co.uk" in content
        assert "Scale SLA Retainer Active" in content
        assert "$499" in content
        assert "auditDomain(" in content
        assert "downloadReport(" in content


# ============================================================================
# Act III Master Test 3: Supervisor Daemon & CLI Integration
# ============================================================================

class TestAct3DaemonIntegration:
    """Tests the orbit_daemon.py worker and CLI integration for Bug Bounty Radar."""

    def test_daemon_bounty_worker_initialization(self):
        worker = BountyRadarSupervisorWorker()
        assert worker.sweep_interval_seconds == 86400.0
        assert hasattr(worker, "is_off_peak")
        assert hasattr(worker, "execute_sweep")

    def test_supervisor_includes_bounty_state(self):
        supervisor = OrbitMasterSupervisor()
        assert hasattr(supervisor, "bounty_worker")
        assert hasattr(supervisor, "bounty_state")
        assert supervisor.bounty_state.get("status") == "INITIALIZED"

    def test_bounty_sweep_cli_execution_quick(self):
        worker = BountyRadarSupervisorWorker()
        # Execute quick mock sweep
        res = worker.execute_sweep(force_now=True, program_id="shopify", quick=True)
        assert res.get("status") == "COMPLETED"
        assert res.get("programs_scanned") == 1
        assert "vulnerabilities_found" in res
