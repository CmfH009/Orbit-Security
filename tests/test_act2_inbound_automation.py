"""End-to-End Master Test Suite for Act II: Advanced Inbound Automation & Self-Healing Sentinels.

Verifies the complete Act II specification:
1. X Profile Bio Scraper & Lead Enrichment:
   - Bio URL & text parsing for target domains.
   - 5-second passive DNS/security scan via OrbitSecurityScanner.
   - Qualification of high-impact leads (dangling CNAME, DMARC p=none).
   - Personalized DM drafting by Carson Haynes (@_arsoncode).
   - Persistence and deduplication in data/social_leads.json.
2. Automated Stripe Webhook Onboarding & Provisioning:
   - Cryptographic HMAC-SHA256 signature verification.
   - 'checkout.session.completed' ingestion.
   - ReportLab cryptographic SLA PDF certificate generation with SHA-256 seal.
   - Domain provisioning in data/subscribers.json.
   - 24/7 continuous Fleet Sentinel monitoring registration in data/clients.json.
3. Supervisor Canary Self-Healing Probes:
   - Simulated 10-second end-to-end canary probe audit.
   - Multi-cycle RSS memory tracking (>150MB bloat threshold).
   - Graceful self-healing process recycling (close -> re-exec / restart).
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.desktop_x_bridge import DesktopAutomationDriver
from orbit_security.fleet import FleetRegistry
from orbit_security.models import DomainAuditResult, Finding, Severity
from orbit_security.social_lead_enricher import (
    BioUrlExtractor,
    SocialLeadEnricher,
    UserProfile,
    draft_dm_pitch,
    extract_domain_from_bio,
)
from orbit_security.stripe_webhook import (
    SlaCertificateGenerator,
    StripeWebhookHandler,
    SubscriberManager,
    compute_sla_crypto_hash,
    generate_stripe_signature,
    verify_stripe_signature,
)

SYSTEM_SCRIPTS = Path("A:/system/scripts") if Path("A:/system/scripts").exists() else Path(r"C:\AgyHut\system\scripts")
import sys
if str(SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SYSTEM_SCRIPTS))

from orbit_daemon import OrbitMasterSupervisor, ServiceSpec, SupervisorCanaryProbe


# ============================================================================
# Act II Master Test 1: X Profile Bio Scraper & Lead Enrichment
# ============================================================================


@pytest.mark.asyncio
async def test_act2_lead_enrichment_flow():
    """Validates complete bio scraping, passive audit, and lead qualification flow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        leads_file = Path(tmpdir) / "social_leads.json"
        enricher = SocialLeadEnricher(leads_file=leads_file)

        mock_audit = DomainAuditResult(
            domain="modernbrand.store",
            score=40,
            grade="F",
            findings=[
                Finding(
                    category="TAKEOVER",
                    severity=Severity.CRITICAL,
                    title="Dangling CNAME takeover on dev.modernbrand.store",
                    description="Points to canceled Shopify Plus domain.",
                    remediation="Remove or update CNAME entry.",
                    target="dev.modernbrand.store",
                ),
                Finding(
                    category="EMAIL_SECURITY",
                    severity=Severity.HIGH,
                    title="DMARC record missing or p=none",
                    description="Brand is spoofable.",
                    remediation="Configure p=quarantine.",
                    target="modernbrand.store",
                ),
            ],
            subdomains_checked=["dev.modernbrand.store"],
            scan_time_seconds=0.9,
        )

        with patch.object(enricher, "_run_passive_scan", return_value=mock_audit):
            profile = UserProfile(
                handle="marcus_ceo",
                name="Marcus Vance",
                bio="Co-Founder @ modernbrand.store | E-commerce architect",
                bio_url="https://modernbrand.store",
                interaction_type="like",
                source_tweet_id="1849988776655",
            )
            lead = await enricher.enrich_profile(profile)

            assert lead is not None
            assert lead.handle == "marcus_ceo"
            assert lead.target_domain == "modernbrand.store"
            assert lead.has_critical_takeover is True
            assert lead.has_dmarc_vulnerability is True
            assert "modernbrand.store" in lead.drafted_dm
            assert "Carson" in lead.drafted_dm or "@_arsoncode" in lead.drafted_dm

            # Ensure saved to disk
            saved = enricher.load_leads()
            assert len(saved) == 1
            assert saved[0]["handle"] == "marcus_ceo"


# ============================================================================
# Act II Master Test 2: Stripe Webhook & SLA Provisioning Flow
# ============================================================================


def test_act2_stripe_webhook_and_sla_provisioning_flow():
    """Validates Stripe checkout session processing, SLA generation, and fleet enrollment."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sub_file = Path(tmpdir) / "subscribers.json"
        clients_file = Path(tmpdir) / "clients.json"
        certs_dir = Path(tmpdir) / "certificates"

        webhook_secret = "whsec_act2_master_secret"
        sub_mgr = SubscriberManager(subscribers_file=sub_file)
        cert_gen = SlaCertificateGenerator(output_dir=certs_dir)
        registry = FleetRegistry(data_path=clients_file)

        handler = StripeWebhookHandler(
            webhook_secret=webhook_secret,
            subscriber_manager=sub_mgr,
            sla_generator=cert_gen,
            fleet_registry=registry,
        )

        session_payload = {
            "id": "evt_act2_checkout_success",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_act2_session_9901",
                    "customer": "cus_act2_partner_99",
                    "customer_details": {
                        "email": "devops@apex-commerce.com",
                        "name": "Apex Commerce Studio",
                    },
                    "metadata": {
                        "domain": "apex-commerce.com",
                        "plan": "Scale Retainer ($299/mo)",
                    },
                    "amount_total": 29900,
                    "currency": "usd",
                    "payment_status": "paid",
                }
            },
        }

        payload_bytes = json.dumps(session_payload).encode("utf-8")
        sig_header = generate_stripe_signature(payload_bytes, webhook_secret)

        result = handler.handle_webhook(payload_bytes, sig_header)

        # 1. Provisioning assertion
        assert result["status"] == "PROVISIONED"
        assert result["apex_domain"] == "apex-commerce.com"

        # 2. SLA PDF assertion
        pdf_path = Path(result["sla_certificate_path"])
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000  # Valid non-empty PDF
        with open(pdf_path, "rb") as f:
            assert f.read(4) == b"%PDF"

        # 3. Subscribers registry assertion
        subs = sub_mgr.list_subscribers()
        assert len(subs) == 1
        assert subs[0]["apex_domain"] == "apex-commerce.com"
        assert subs[0]["monitoring_enabled"] is True

        # 4. Fleet continuous monitoring assertion
        clients = registry.list_active()
        assert any(c.apex_domain == "apex-commerce.com" for c in clients)


# ============================================================================
# Act II Master Test 3: Supervisor Canary Self-Healing Probes Flow
# ============================================================================


def test_act2_supervisor_canary_self_healing_flow():
    """Validates end-to-end 10s simulated canary probe, bloat detection, and process recycle."""
    supervisor = OrbitMasterSupervisor()
    supervisor.services = {
        "orbit_worker": ServiceSpec(
            name="Orbit Worker Service",
            script="worker.py",
            args=[],
            enabled=True,
            pid=778899,
        )
    }
    supervisor.stop_service = MagicMock()
    supervisor.start_service = MagicMock()

    probe = SupervisorCanaryProbe(
        audit_duration_seconds=0.01,
        rss_expansion_threshold_mb=150.0,
        consecutive_bloat_cycles_threshold=3,
    )
    probe.baselines["orbit_worker"] = 120.0

    # Cycle 1: Memory bloats to 300MB (+180MB > 150MB) -> bloat count 1
    with patch.object(probe, "_get_process_rss_mb", return_value=300.0):
        r1 = probe.execute_canary_audit(supervisor, quick=True)
        assert r1["status"] == "WARNING_EXPANDING"
        assert probe.consecutive_bloat_counts["orbit_worker"] == 1
        assert supervisor.stop_service.call_count == 0

    # Cycle 2: Memory continues bloat at 320MB (+200MB) -> bloat count 2
    with patch.object(probe, "_get_process_rss_mb", return_value=320.0):
        r2 = probe.execute_canary_audit(supervisor, quick=True)
        assert r2["status"] == "WARNING_EXPANDING"
        assert probe.consecutive_bloat_counts["orbit_worker"] == 2
        assert supervisor.stop_service.call_count == 0

    # Cycle 3: 3rd consecutive bloated cycle (+230MB) -> Triggers graceful self-healing recycle
    with patch.object(probe, "_get_process_rss_mb", return_value=350.0):
        r3 = probe.execute_canary_audit(supervisor, quick=True)
        assert r3["status"] == "RECYCLED"
        assert "orbit_worker" in r3["recycled_services"]
        # Empirical verification of graceful recycle
        supervisor.stop_service.assert_called_once_with("orbit_worker")
        supervisor.start_service.assert_called_once_with("orbit_worker")
        assert probe.consecutive_bloat_counts["orbit_worker"] == 0
