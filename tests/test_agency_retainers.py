"""Unit tests for Act III Subsystem 2: Agency White-Label Retainer Tier (agency_retainer.py).

Covers:
  - Agency retainer tiers ($299 Starter, $499 Scale, $999 Enterprise).
  - Quota enforcement (15 domains for Starter, 50 for Scale).
  - Agency registration, domain addition and removal.
  - Updating client audit metrics (scores, grades, findings counts).
  - Standalone co-branded HTML portal rendering and file persistence.
  - Integration with scripts/generate_agency_portal.py.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from orbit_security.agency_retainer import (
    AgencyClientSite,
    AgencyPortalRenderer,
    AgencyRetainer,
    AgencyRetainerManager,
    RetainerTier,
    TIER_POLICIES,
)


class TestAgencyRetainers:
    def test_tier_policies(self):
        starter = TIER_POLICIES[RetainerTier.STARTER]
        assert starter.monthly_price == 299
        assert starter.max_domains == 15
        assert starter.scan_frequency == "weekly"

        scale = TIER_POLICIES[RetainerTier.SCALE]
        assert scale.monthly_price == 499
        assert scale.max_domains == 50
        assert scale.custom_portal_enabled is True
        assert scale.sla_certificates_enabled is True

        enterprise = TIER_POLICIES[RetainerTier.ENTERPRISE]
        assert enterprise.monthly_price == 999
        assert enterprise.max_domains == -1
        assert enterprise.video_roasts_enabled is True

    def test_default_seeded_agencies(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)
        agencies = manager.list_agencies()
        assert len(agencies) >= 4
        agency_ids = [a.agency_id for a in agencies]
        assert "eastside-co" in agency_ids
        assert "we-make-websites" in agency_ids
        assert "barrel" in agency_ids
        assert "swanky" in agency_ids
        assert data_file.exists()

    def test_register_new_agency_and_persistence(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)

        agency = manager.register_agency(
            agency_id="domaine-agency",
            agency_name="Domaine",
            tier=RetainerTier.SCALE,
            custom_domain="security.domaine.com",
            primary_color="#18181B",
            accent_color="#EC4899",
            support_email="ops@domaine.com",
            agency_tagline="World-Class Shopify Plus Engineering",
        )
        assert agency.agency_id == "domaine-agency"
        assert agency.monthly_price == 499
        assert agency.custom_domain == "security.domaine.com"

        # Reload from disk
        reloaded = AgencyRetainerManager(data_path=data_file)
        saved = reloaded.get_agency("domaine-agency")
        assert saved is not None
        assert saved.agency_name == "Domaine"
        assert saved.primary_color == "#18181B"
        assert saved.accent_color == "#EC4899"

    def test_client_domain_quota_enforcement(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)

        # Register Starter agency (max 15 domains)
        starter = manager.register_agency(
            agency_id="boutique-web",
            agency_name="Boutique Web Studio",
            tier=RetainerTier.STARTER,
        )

        # Add 15 domains successfully
        for i in range(15):
            ok = manager.add_client_domain(
                agency_id="boutique-web",
                domain=f"client{i}.example.com",
                client_name=f"Client {i}",
            )
            assert ok is True

        assert len(starter.client_domains) == 15
        assert starter.can_add_domain() is False

        # Attempting to add 16th domain should raise ValueError
        with pytest.raises(ValueError, match="reached its Starter tier domain limit"):
            manager.add_client_domain(
                agency_id="boutique-web",
                domain="overflow.example.com",
            )

    def test_remove_client_domain(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)
        agency = manager.register_agency(
            agency_id="test-agency",
            agency_name="Test Agency",
            tier=RetainerTier.SCALE,
        )
        manager.add_client_domain("test-agency", "remove-me.com")
        assert len(agency.client_domains) == 1

        removed = manager.remove_client_domain("test-agency", "remove-me.com")
        assert removed is True
        assert len(agency.client_domains) == 0

        # Removing non-existent domain returns False
        assert manager.remove_client_domain("test-agency", "nonexistent.com") is False

    def test_update_site_audit_score(self, tmp_path):
        data_file = tmp_path / "agency_retainers.json"
        manager = AgencyRetainerManager(data_path=data_file)
        agency = manager.register_agency(
            agency_id="audit-agency",
            agency_name="Audit Agency",
            tier=RetainerTier.SCALE,
        )
        manager.add_client_domain("audit-agency", "store.example.com", "Example Store")

        updated = manager.update_site_audit(
            agency_id="audit-agency",
            domain="store.example.com",
            score=72,
            grade="C",
            critical_count=1,
            high_count=2,
            medium_count=3,
        )
        assert updated is True

        site = agency.client_domains[0]
        assert site.last_score == 72
        assert site.last_grade == "C"
        assert site.critical_findings == 1
        assert site.high_findings == 2
        assert site.medium_findings == 3
        assert site.last_scanned is not None


class TestAgencyPortalRenderer:
    def test_render_portal_html_content(self):
        agency = AgencyRetainer(
            agency_id="eastside-co",
            agency_name="Eastside Co",
            tier=RetainerTier.SCALE,
            monthly_price=499,
            custom_domain="security.eastsideco.com",
            agency_tagline="Enterprise Shopify Plus Technical Solutions",
            primary_color="#0B132B",
            accent_color="#48CAE4",
            client_domains=[
                AgencyClientSite(domain="candykittens.co.uk", client_name="Candy Kittens", last_score=85, last_grade="B"),
                AgencyClientSite(domain="wildfang.com", client_name="Wildfang Apparel", last_score=95, last_grade="A+"),
            ],
        )

        html_text = AgencyPortalRenderer.render_portal_html(agency)
        assert "<!DOCTYPE html>" in html_text
        assert "Eastside Co" in html_text
        assert "security.eastsideco.com" in html_text
        assert "#0B132B" in html_text
        assert "#48CAE4" in html_text
        assert "Candy Kittens" in html_text
        assert "candykittens.co.uk" in html_text
        assert "Wildfang Apparel" in html_text
        assert "auditDomain(" in html_text
        assert "downloadReport(" in html_text
        assert "Scale SLA Retainer Active" in html_text

    def test_save_portal_files(self, tmp_path):
        docs_dir = tmp_path / "docs" / "portals"
        landing_dir = tmp_path / "landing" / "portals"

        agency = AgencyRetainer(
            agency_id="test-save-agency",
            agency_name="Test Save Agency",
            tier=RetainerTier.SCALE,
        )

        docs_path, landing_path = AgencyPortalRenderer.save_portal(
            agency, output_dir=docs_dir, landing_dir=landing_dir
        )
        assert docs_path.exists()
        assert docs_path.name == "test-save-agency.html"
        assert landing_path.exists()
        assert landing_path.name == "test-save-agency.html"
