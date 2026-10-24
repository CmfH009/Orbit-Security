"""Unit tests for Act III Subsystem 1: Automated Bug Bounty Radar (bounty_radar.py).

Covers:
  - HackerOne & Bugcrowd scope ingestion.
  - Wildcard subdomain expansion and out-of-scope filtering.
  - Dangling CNAME SaaS subdomain takeover detection.
  - Mail spoofing vector detection (missing DMARC, p=none, SPF +all).
  - Structured HackerOne markdown disclosure generation.
  - Off-peak execution window calculations (2:00 AM - 5:00 AM MST).
  - BountyRadarSupervisor state management and automated sweeps.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.bounty_radar import (
    BountyProgram,
    BountyRadarSupervisor,
    BountyScopeIngester,
    BountyTakeoverSweeper,
    BountyVulnerability,
    CVSSv31Calculator,
    HackerOneDisclosureGenerator,
    OffPeakWindow,
    ResponsibleDisclosureDrafter,
    is_vulnerability_in_scope,
)
from orbit_security.models import Severity


class TestBountyScopeIngester:
    def test_default_seeded_programs(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        ingester = BountyScopeIngester(data_path=data_file)
        programs = ingester.list_programs()
        assert len(programs) >= 5
        prog_ids = [p.program_id for p in programs]
        assert "shopify" in prog_ids
        assert "gitlab" in prog_ids
        assert "starbucks" in prog_ids
        assert data_file.exists()

    def test_ingest_hackerone_scope_dict(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        ingester = BountyScopeIngester(data_path=data_file)

        h1_payload = {
            "handle": "target_corp",
            "name": "Target Corp",
            "max_bounty": 20000,
            "targets": {
                "in_scope": [
                    {"asset_identifier": "*.targetcorp.com", "eligible_for_bounty": True},
                    {"asset_identifier": "*.corp-assets.net", "eligible_for_bounty": True},
                ],
                "out_of_scope": [
                    {"asset_identifier": "internal.targetcorp.com"},
                ],
            },
        }

        ingested = ingester.ingest_hackerone_scope(h1_payload)
        assert len(ingested) == 1
        prog = ingested[0]
        assert prog.program_id == "target_corp"
        assert prog.platform == "hackerone"
        assert "*.targetcorp.com" in prog.in_scope
        assert "internal.targetcorp.com" in prog.out_of_scope
        assert prog.max_bounty == 20000

        # Reload from disk
        reloaded = BountyScopeIngester(data_path=data_file)
        assert reloaded.get_program("target_corp") is not None

    def test_ingest_bugcrowd_scope_list(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        ingester = BountyScopeIngester(data_path=data_file)

        bc_payload = [
            {
                "code": "cloud_secure",
                "name": "Cloud Secure Inc",
                "max_payout": 8000,
                "targets": [
                    {"uri": "*.cloudsecure.io"},
                    {"uri": "api.cloudsecure.com"},
                ],
                "out_of_scope": ["demo.cloudsecure.io"],
            }
        ]

        ingested = ingester.ingest_bugcrowd_scope(bc_payload)
        assert len(ingested) == 1
        prog = ingested[0]
        assert prog.program_id == "cloud_secure"
        assert prog.platform == "bugcrowd"
        assert "*.cloudsecure.io" in prog.in_scope
        assert "demo.cloudsecure.io" in prog.out_of_scope


class TestBountyTakeoverSweeper:
    def test_expand_wildcards(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets", "blog", "cdn", "shop"])
        in_scope = ["*.acme.com", "portal.acme-partners.com"]
        out_of_scope = ["blog.acme.com"]

        candidates = sweeper.expand_wildcards(in_scope, out_of_scope, max_per_wildcard=10)
        assert "acme.com" in candidates
        assert "assets.acme.com" in candidates
        assert "cdn.acme.com" in candidates
        assert "shop.acme.com" in candidates
        assert "portal.acme-partners.com" in candidates
        assert "blog.acme.com" not in candidates  # Filtered out_of_scope

    def test_expand_wildcards_wildcard_out_of_scope(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["dev", "staging", "api", "vpn"])
        in_scope = ["*.corp.com", "admin.internal.corp.com"]
        out_of_scope = ["*.internal.corp.com", "staging.corp.com"]

        candidates = sweeper.expand_wildcards(in_scope, out_of_scope, max_per_wildcard=10)
        assert "corp.com" in candidates
        assert "dev.corp.com" in candidates
        assert "api.corp.com" in candidates
        assert "staging.corp.com" not in candidates  # Direct match excluded
        assert "admin.internal.corp.com" not in candidates  # Wildcard *.internal.corp.com excluded


    def test_fetch_crtsh_subdomains_success(self):
        sweeper = BountyTakeoverSweeper()
        mock_response = MagicMock()
        mock_context = mock_response.__enter__.return_value
        mock_context.status = 200
        mock_payload = [
            {"name_value": "api.acme.com\nlegacy-docs.acme.com"},
            {"name_value": "*.acme.com"},
            {"name_value": "acme.com"},
            {"name_value": "cdn.acme.com"},
        ]
        mock_context.read.return_value = json.dumps(mock_payload).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            subs = sweeper.fetch_crtsh_subdomains("acme.com", max_results=10)
            assert "api.acme.com" in subs
            assert "legacy-docs.acme.com" in subs
            assert "cdn.acme.com" in subs
            assert "acme.com" not in subs  # Apex excluded from subdomain list

    def test_fetch_crtsh_subdomains_timeout_fallback(self):
        sweeper = BountyTakeoverSweeper()
        with patch("urllib.request.urlopen", side_effect=Exception("Connection timed out")):
            subs = sweeper.fetch_crtsh_subdomains("acme.com")
            assert subs == [], "On timeout or network error, fetch_crtsh_subdomains must gracefully return empty list"

    def test_expand_wildcards_with_passive_ct(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets"])
        with patch.object(sweeper, "fetch_crtsh_subdomains", return_value=["legacy-portal.acme.com"]):
            candidates = sweeper.expand_wildcards(["*.acme.com"], max_per_wildcard=5, use_passive_ct=True)
            assert "acme.com" in candidates
            assert "legacy-portal.acme.com" in candidates
            assert "assets.acme.com" in candidates

    def test_check_subdomain_takeover_aws_s3_match(self):
        sweeper = BountyTakeoverSweeper()
        # Mock CNAME pointing to S3 and HTTP body NoSuchBucket
        res = sweeper.check_subdomain_takeover(
            domain="assets.acme.com",
            mock_cname="acme-assets.s3.amazonaws.com",
            mock_body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        )
        assert res is not None
        sig, cname, evidence = res
        assert sig.name == "AWS S3"
        assert cname == "acme-assets.s3.amazonaws.com"
        assert "NoSuchBucket" in evidence

    def test_check_subdomain_takeover_github_pages_match(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.check_subdomain_takeover(
            domain="docs.acme.com",
            mock_cname="acme.github.io",
            mock_body="<html><body>There isn't a GitHub Pages site here.</body></html>",
        )
        assert res is not None
        sig, cname, evidence = res
        assert sig.name == "GitHub Pages"
        assert "GitHub Pages" in evidence

    def test_check_subdomain_takeover_no_vulnerability(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.check_subdomain_takeover(
            domain="shop.acme.com",
            mock_cname="shops.myshopify.com",
            mock_body="<html><body>Welcome to Acme Store! Real Content</body></html>",
        )
        assert res is None

    def test_check_mail_spoofing_missing_dmarc(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.check_mail_spoofing(
            domain="vulnerable.org",
            mock_spf="v=spf1 include:_spf.google.com ~all",
            mock_dmarc="",  # Missing
        )
        assert res is not None
        title, evidence, sev, cvss = res
        assert "Missing DMARC Policy" in title
        assert sev == Severity.HIGH
        assert cvss == 7.5

    def test_check_mail_spoofing_dmarc_none_monitoring(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.check_mail_spoofing(
            domain="target.com",
            mock_spf="v=spf1 include:_spf.google.com ~all",
            mock_dmarc="v=DMARC1; p=none; rua=mailto:dmarc@target.com",
        )
        assert res is not None
        title, evidence, sev, cvss = res
        assert "p=none" in title
        assert sev == Severity.MEDIUM
        assert cvss == 5.3

    def test_check_mail_spoofing_secure_dmarc(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.check_mail_spoofing(
            domain="secure.com",
            mock_spf="v=spf1 include:_spf.google.com -all",
            mock_dmarc="v=DMARC1; p=reject; sp=reject; pct=100",
        )
        assert res is None

    def test_check_mail_spoofing_subdomain_inherits_apex_reject(self):
        sweeper = BountyTakeoverSweeper()
        # Mock resolver resolving _dmarc.shopify.com to p=reject
        with patch.object(sweeper.resolver, "resolve") as mock_resolve:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=DMARC1; p=reject; pct=100;"]
            # When querying _dmarc.cdn.shopify.com raise Exception, when querying _dmarc.shopify.com return mock_rdata
            def side_effect(qname, qtype):
                if str(qname) == "_dmarc.cdn.shopify.com":
                    raise Exception("No record")
                if str(qname) == "_dmarc.shopify.com":
                    return [mock_rdata]
                raise Exception("Unknown")
            mock_resolve.side_effect = side_effect

            res = sweeper.check_mail_spoofing(domain="cdn.shopify.com")
            assert res is None, "Subdomain inheriting apex p=reject must not be flagged"

    def test_check_mail_spoofing_subdomain_without_mx_ignored(self):
        sweeper = BountyTakeoverSweeper()
        # Subdomain with no DMARC and no MX
        with patch.object(sweeper.resolver, "resolve", side_effect=Exception("No record")):
            res = sweeper.check_mail_spoofing(domain="assets.unprotected.org", mock_mx=[])
            assert res is None, "Static subdomain without MX must not be reported as mail spoofing"

    def test_check_subdomain_takeover_beanstalk_active_host_not_vulnerable(self):
        sweeper = BountyTakeoverSweeper()
        # Mock CNAME to elasticbeanstalk.com, but target resolves to active A record
        with patch.object(sweeper.resolver, "resolve") as mock_resolve:
            mock_cname_rdata = MagicMock()
            mock_cname_rdata.target = "active-app.us-east-1.elasticbeanstalk.com."
            mock_a_rdata = MagicMock()

            def side_effect(qname, qtype):
                if qtype == "CNAME":
                    return [mock_cname_rdata]
                if qtype == "A":
                    return [mock_a_rdata]
                raise Exception("Unknown")
            mock_resolve.side_effect = side_effect

            res = sweeper.check_subdomain_takeover("api.acme.com")
            assert res is None, "Active Beanstalk host resolving to A record must not be flagged"

    def test_check_subdomain_takeover_beanstalk_nxdomain_is_vulnerable(self):
        sweeper = BountyTakeoverSweeper()
        import dns.resolver
        # Mock CNAME to elasticbeanstalk.com, target returns NXDOMAIN
        with patch.object(sweeper.resolver, "resolve") as mock_resolve:
            mock_cname_rdata = MagicMock()
            mock_cname_rdata.target = "dead-app.us-east-1.elasticbeanstalk.com."

            def side_effect(qname, qtype):
                if qtype == "CNAME":
                    return [mock_cname_rdata]
                if qtype == "A":
                    raise dns.resolver.NXDOMAIN()
                raise Exception("Unknown")
            mock_resolve.side_effect = side_effect

            res = sweeper.check_subdomain_takeover("api.acme.com")
            assert res is not None
            sig, cname, evidence = res
            assert sig.name == "AWS Elastic Beanstalk"
            assert "NXDOMAIN response" in evidence

    def test_check_subdomain_takeover_cloudfront_with_valid_ssl_not_vulnerable(self):
        sweeper = BountyTakeoverSweeper()
        with patch.object(sweeper.resolver, "resolve") as mock_resolve:
            mock_cname_rdata = MagicMock()
            mock_cname_rdata.target = "d1234.cloudfront.net."
            mock_resolve.return_value = [mock_cname_rdata]

            with patch.object(sweeper, "_probe_http_body", return_value="<TITLE>ERROR: The request could not be satisfied</TITLE>"):
                with patch.object(sweeper, "is_ssl_cert_bound_to_domain", return_value=True):
                    res = sweeper.check_subdomain_takeover("static.acme.com")
                    assert res is None, "CloudFront distribution with active custom cert must not be flagged"

    def test_check_subdomain_takeover_fastly_with_valid_ssl_not_vulnerable(self):
        sweeper = BountyTakeoverSweeper()
        with patch.object(sweeper.resolver, "resolve") as mock_resolve:
            mock_cname_rdata = MagicMock()
            mock_cname_rdata.target = "example.fastly.net."
            mock_resolve.return_value = [mock_cname_rdata]

            with patch.object(sweeper, "_probe_http_body", return_value="Fastly error: unknown domain"):
                with patch.object(sweeper, "is_ssl_cert_bound_to_domain", return_value=True):
                    res = sweeper.check_subdomain_takeover("cdn.acme.com")
                    assert res is None, "Fastly host with active custom cert must not be flagged"

    def test_probe_http_body_200_ok_suppressed(self):
        sweeper = BountyTakeoverSweeper()
        mock_response = MagicMock()
        mock_context = mock_response.__enter__.return_value
        mock_context.status = 200
        mock_context.read.return_value = b"<html>Normal documentation mentioning NoSuchBucket error</html>"

        with patch("urllib.request.urlopen", return_value=mock_response):
            body = sweeper._probe_http_body("docs.acme.com")
            assert body == "", "Active 200 OK response body must be suppressed to avoid false positives"


class TestHackerOneDisclosureGenerator:
    def test_generate_h1_takeover_report(self):
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="blog.shopifyapps.com",
            cname_target="shopifyapps.s3.amazonaws.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=7.5,
            evidence="Dangling CNAME matched AWS S3 NoSuchBucket fingerprint.",
            remediation="Delete dangling CNAME record or claim S3 bucket.",
        )

        md = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [Subdomain Takeover]" in md
        assert "blog.shopifyapps.com" in md
        assert "CWE-284" in md
        assert "CVSS 3.1: **7.5**" in md
        assert "dig blog.shopifyapps.com CNAME +short" in md
        assert "curl -i -s https://blog.shopifyapps.com" in md
        assert "Responsible Disclosure Notice" in md

    def test_save_disclosure_markdown(self, tmp_path):
        vuln = BountyVulnerability(
            program_id="gitlab",
            program_name="GitLab",
            platform="hackerone",
            target_domain="events.gitlab.com",
            cname_target="gitlab-events.unbouncepages.com",
            flaw_type="subdomain_takeover",
            provider="Unbounce",
            severity=Severity.HIGH,
            cvss_score=7.5,
            evidence="The requested URL was not found on this server",
            remediation="Remove orphaned CNAME",
        )

        saved_path = HackerOneDisclosureGenerator.save_disclosure(vuln, output_dir=tmp_path)
        assert saved_path.exists()
        content = saved_path.read_text(encoding="utf-8")
        assert "events.gitlab.com" in content
        assert "Unbounce" in content


class TestOffPeakWindow:
    def test_is_off_peak_in_window(self):
        # 03:30 AM MST is 10:30 UTC
        dt = datetime.datetime(2026, 10, 2, 10, 30, tzinfo=datetime.timezone.utc)
        assert OffPeakWindow.is_off_peak(dt, start_hour=2, end_hour=5, tz_offset_hours=-7) is True

    def test_is_off_peak_outside_window(self):
        # 14:00 MST is 21:00 UTC
        dt = datetime.datetime(2026, 10, 2, 21, 0, tzinfo=datetime.timezone.utc)
        assert OffPeakWindow.is_off_peak(dt, start_hour=2, end_hour=5, tz_offset_hours=-7) is False


class TestBountyRadarSupervisor:
    def test_run_sweep_force_now(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        state_file = tmp_path / "bounty_state.json"
        disclosures_dir = tmp_path / "disclosures"

        ingester = BountyScopeIngester(data_path=data_file)
        # Create single small test program
        test_prog = BountyProgram(
            program_id="test_corp",
            name="Test Corp",
            platform="hackerone",
            in_scope=["*.testcorp.com"],
            max_bounty=5000,
        )
        ingester.programs = {"test_corp": test_prog}
        ingester.save()

        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets"])
        supervisor = BountyRadarSupervisor(ingester=ingester, sweeper=sweeper, state_file=state_file)

        # Mock sweep_program to simulate 1 finding
        mock_vuln = BountyVulnerability(
            program_id="test_corp",
            program_name="Test Corp",
            platform="hackerone",
            target_domain="assets.testcorp.com",
            cname_target="testcorp.s3.amazonaws.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            evidence="NoSuchBucket",
        )

        with patch.object(sweeper, "sweep_program", return_value=[mock_vuln]):
            res = supervisor.run_sweep(
                force_now=True,
                max_domains_per_program=2,
                save_disclosures=True,
                output_dir=disclosures_dir,
            )

            assert res["status"] == "COMPLETED"
            assert res["programs_scanned"] == 1
            assert res["vulnerabilities_found"] == 1
            assert len(res["disclosed_files"]) == 1
            assert Path(res["disclosed_files"][0]).exists()

            # State check
            assert supervisor.state["total_sweeps"] == 1
            assert supervisor.state["total_vulnerabilities_found"] == 1

    def test_dispatch_bounty_alert_high_confidence(self):
        mock_dispatcher = MagicMock()
        mock_dispatcher.send_bounty_alert.return_value = {"slack": True, "discord": True}
        mock_dispatcher.send_windows_toast.return_value = True

        supervisor = BountyRadarSupervisor(dispatcher=mock_dispatcher)
        prog = BountyProgram(program_id="shopify", name="Shopify", max_bounty=50000)
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="promo.shopify.com",
            cname_target="target.s3.amazonaws.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            evidence="NoSuchBucket",
            bounty_viability="HIGH_CONFIDENCE",
        )

        res = supervisor.dispatch_bounty_alert(vuln, prog, send_toast=True)
        assert res["dispatched"] is True
        mock_dispatcher.send_bounty_alert.assert_called_once()

    def test_dispatch_bounty_alert_suppressed_for_informational(self):
        mock_dispatcher = MagicMock()
        supervisor = BountyRadarSupervisor(dispatcher=mock_dispatcher)
        prog = BountyProgram(program_id="shopify", name="Shopify")
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="mail.shopify.com",
            flaw_type="mail_spoofing",
            bounty_viability="INFORMATIONAL_LOW",
        )

        res = supervisor.dispatch_bounty_alert(vuln, prog)
        assert res["dispatched"] is False
        assert res["reason"] == "VIABILITY_NOT_HIGH_CONFIDENCE"
        mock_dispatcher.send_bounty_alert.assert_not_called()

    def test_run_sweep_alerts_only_high_confidence(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        state_file = tmp_path / "bounty_state.json"
        ingester = BountyScopeIngester(data_path=data_file)
        test_prog = BountyProgram(
            program_id="shopify",
            name="Shopify",
            in_scope=["*.shopify.com"],
            max_bounty=50000,
        )
        ingester.programs = {"shopify": test_prog}
        ingester.save()

        sweeper = BountyTakeoverSweeper()
        mock_dispatcher = MagicMock()
        mock_dispatcher.send_bounty_alert.return_value = {"slack": True, "discord": False}
        mock_dispatcher.send_windows_toast.return_value = False

        supervisor = BountyRadarSupervisor(
            ingester=ingester,
            sweeper=sweeper,
            state_file=state_file,
            dispatcher=mock_dispatcher,
        )

        high_vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="assets.shopify.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            bounty_viability="HIGH_CONFIDENCE",
        )
        info_vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="mail.shopify.com",
            flaw_type="mail_spoofing",
            bounty_viability="INFORMATIONAL_LOW",
        )

        with patch.object(sweeper, "sweep_program", return_value=[high_vuln, info_vuln]):
            res = supervisor.run_sweep(force_now=True, save_disclosures=False)
            assert res["status"] == "COMPLETED"
            assert mock_dispatcher.send_bounty_alert.call_count == 1
            call_payload = mock_dispatcher.send_bounty_alert.call_args[1]["payload"]
            assert call_payload.target_domain == "assets.shopify.com"
            assert call_payload.bounty_viability == "HIGH_CONFIDENCE"


class TestChaosScopeIngester:
    def test_ingest_chaos_scope_cash_only_filter(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        ingester = BountyScopeIngester(data_path=data_file)

        chaos_data = {
            "programs": [
                {
                    "name": "Acme Corp",
                    "url": "https://acme.org/security",
                    "bounty": True,
                    "bounty_tier": "cash",
                    "max_bounty": 25000,
                    "domains": ["acme.org", "api.acme.org"],
                    "out_of_scope": ["dev.acme.org"],
                },
                {
                    "name": "Points Only Inc",
                    "url": "https://pointsonly.org",
                    "bounty": False,
                    "bounty_tier": "points",
                    "domains": ["pointsonly.org"],
                },
            ]
        }

        programs = ingester.ingest_chaos_scope(chaos_data, cash_only=True)
        assert len(programs) == 1
        prog = programs[0]
        assert prog.program_id == "acme_corp"
        assert prog.bounty_tier == "cash"
        assert "*.acme.org" in prog.in_scope
        assert "dev.acme.org" in prog.out_of_scope

    def test_sync_from_feed_local_file(self, tmp_path):
        data_file = tmp_path / "bounty_programs.json"
        feed_file = tmp_path / "chaos_feed.json"
        ingester = BountyScopeIngester(data_path=data_file)

        feed_file.write_text(json.dumps([
            {
                "name": "Fleet Corp",
                "url": "https://fleet.io",
                "bounty": True,
                "bounty_tier": "cash",
                "max_bounty": 15000,
                "domains": ["fleet.io"],
            }
        ]), encoding="utf-8")

        synced = ingester.sync_from_feed(str(feed_file), feed_type="chaos")
        assert len(synced) == 1
        assert synced[0].program_id == "fleet_corp"
        assert synced[0].max_bounty == 15000



class TestHackerOneFeedIngestion:
    FEED = [
        {
            "handle": "good_corp", "name": "Good Corp", "offers_bounties": True,
            "submission_state": "open", "url": "https://hackerone.com/good_corp",
            "targets": {
                "in_scope": [
                    {"asset_identifier": "*.goodcorp.com", "asset_type": "WILDCARD", "eligible_for_bounty": True},
                    {"asset_identifier": "https://app.goodcorp.io/login", "asset_type": "URL", "eligible_for_bounty": True},
                    {"asset_identifier": "https://github.com/goodcorp/repo", "asset_type": "SOURCE_CODE", "eligible_for_bounty": True},
                    {"asset_identifier": "com.goodcorp.app", "asset_type": "GOOGLE_PLAY_APP_ID", "eligible_for_bounty": True},
                    {"asset_identifier": "10.0.0.1", "asset_type": "OTHER", "eligible_for_bounty": True},
                    {"asset_identifier": "*.noscore.com", "asset_type": "WILDCARD", "eligible_for_bounty": False},
                ],
                "out_of_scope": [{"asset_identifier": "blog.goodcorp.com", "asset_type": "URL"}],
            },
        },
        {"handle": "swag_only", "name": "Swag", "offers_bounties": False, "submission_state": "open",
         "targets": {"in_scope": [{"asset_identifier": "*.swag.com", "asset_type": "WILDCARD", "eligible_for_bounty": True}], "out_of_scope": []}},
        {"handle": "closed_corp", "name": "Closed", "offers_bounties": True, "submission_state": "paused",
         "targets": {"in_scope": [{"asset_identifier": "*.closed.com", "asset_type": "WILDCARD", "eligible_for_bounty": True}], "out_of_scope": []}},
        {"handle": "no_web", "name": "NoWeb", "offers_bounties": True, "submission_state": "open",
         "targets": {"in_scope": [{"asset_identifier": "https://github.com/x/y", "asset_type": "SOURCE_CODE", "eligible_for_bounty": True}], "out_of_scope": []}},
    ]

    def test_filters_to_open_cash_web_assets(self, tmp_path):
        ing = BountyScopeIngester(data_path=tmp_path / "p.json")
        ing.programs = {}
        out = ing.ingest_hackerone_feed(self.FEED)
        assert [p.program_id for p in out] == ["good_corp"]
        prog = out[0]
        assert sorted(prog.in_scope) == ["*.goodcorp.com", "app.goodcorp.io"]
        assert prog.out_of_scope == ["blog.goodcorp.com"]
        assert prog.bounty_tier == "cash"

    def test_max_programs_cap_and_no_clobber_of_seed(self, tmp_path):
        ing = BountyScopeIngester(data_path=tmp_path / "p.json")
        before = set(ing.programs)
        feed = [dict(self.FEED[0], handle=f"c{i}") for i in range(5)]
        out = ing.ingest_hackerone_feed(feed, max_programs=3)
        assert len(out) == 3
        assert before.issubset(set(ing.programs))


class TestSweepFleetCap:
    def test_run_sweep_caps_programs_per_cycle(self, tmp_path):
        ing = BountyScopeIngester(data_path=tmp_path / "p.json")
        ing.programs = {
            f"p{i}": BountyProgram(program_id=f"p{i}", name=f"P{i}", in_scope=[f"*.p{i}.com"])
            for i in range(30)
        }
        sweeper = BountyTakeoverSweeper()
        sup = BountyRadarSupervisor(ingester=ing, sweeper=sweeper, state_file=tmp_path / "s.json", dispatcher=MagicMock())
        with patch.object(sweeper, "sweep_program", return_value=[]) as sp:
            res = sup.run_sweep(force_now=True, save_disclosures=False, max_programs=25)
        assert sp.call_count == 25
        assert res["programs_scanned"] == 25


class TestCVSSv31CalculatorAndDisclosureDrafter:
    def test_cvss_subdomain_takeover(self):
        score, vector = CVSSv31Calculator.calculate_score("N", "L", "N", "N", "U", "N", "H", "N")
        assert score == 7.5
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"

    def test_cvss_scope_changed(self):
        score, vector = CVSSv31Calculator.calculate_score("N", "L", "N", "R", "C", "L", "L", "N")
        assert score == 6.1
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def test_cvss_zero_impact(self):
        score, vector = CVSSv31Calculator.calculate_score("N", "L", "N", "N", "U", "N", "N", "N")
        assert score == 0.0

    def test_responsible_disclosure_drafter_multi_platform(self, tmp_path):
        vuln = BountyVulnerability(
            program_id="acme",
            program_name="Acme Corp",
            platform="hackerone",
            target_domain="blog.acme.com",
            cname_target="acme.github.io",
            flaw_type="subdomain_takeover",
            provider="GitHub Pages",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            evidence="CNAME acme.github.io -> HTTP 404 There isn't a GitHub Pages site here",
            cwe_id="CWE-284: Improper Access Control",
            remediation="Remove dangling CNAME or claim tenant",
            bounty_viability="HIGH_CONFIDENCE",
        )

        h1_md = ResponsibleDisclosureDrafter.generate_h1_report(vuln)
        assert "# [Subdomain Takeover]" in h1_md
        assert "blog.acme.com" in h1_md
        assert "CVSS 3.1: **7.5**" in h1_md

        bc_md = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "# Bugcrowd Vulnerability Report:" in bc_md
        assert "Target Asset:** `blog.acme.com`" in bc_md
        assert "Subdomain Takeover" in bc_md

        email_txt = ResponsibleDisclosureDrafter.generate_security_txt_email(vuln)
        assert "Subject: [SECURITY ADVISORY] Responsible Disclosure:" in email_txt
        assert "To: security@acme.com" in email_txt
        assert "X-CVSS-Score: 7.5" in email_txt

        bundle = ResponsibleDisclosureDrafter.save_bundle(vuln, output_dir=tmp_path)
        assert "hackerone" in bundle and bundle["hackerone"].exists()
        assert "bugcrowd" in bundle and bundle["bugcrowd"].exists()
        assert "email" in bundle and bundle["email"].exists()

    def test_sweep_program_with_advanced_sentinels(self):
        sweeper = BountyTakeoverSweeper()
        prog = BountyProgram(
            program_id="fintech_corp",
            name="Fintech Corp",
            platform="hackerone",
            in_scope=["api.fintech.com"],
        )

        mock_smug = {
            "api.fintech.com": {
                "cl_te": {"latency_ms": 2500.0, "status": 504}
            }
        }
        mock_oa = {
            "api.fintech.com": {
                "oidc": {
                    "issuer": "https://api.fintech.com",
                    "id_token_signing_alg_values_supported": ["none", "RS256"]
                }
            }
        }
        mock_dep = {
            "api.fintech.com": {
                "source_text": "const auth = require('@fintech/internal-sec');",
                "npm": {"@fintech/internal-sec": 404}
            }
        }

        vulns = sweeper.sweep_program(
            prog,
            audit_smuggling=True,
            audit_oauth=True,
            audit_dependency=True,
            mock_smuggling_responses=mock_smug,
            mock_oauth_responses=mock_oa,
            mock_dependency_responses=mock_dep,
        )

        flaw_types = {v.flaw_type for v in vulns}
        assert "http_request_smuggling_cl_te" in flaw_types
        assert "oidc_insecure_signing_alg" in flaw_types
        assert "dependency_confusion_namespace_takeover" in flaw_types
        assert all(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in vulns)


class TestMultiVectorDisclosureDispatch:
    """Tests verifying that all 8 vulnerability categories dispatch to specialized report templates,
    correct PoCs, and never leak DMARC / email spoofing content into non-mail reports.
    """

    FORBIDDEN_MAIL_STRINGS = [
        "dig _dmarc",
        "dig {target} TXT +short",
        "_dmarc.",
        "Missing DMARC",
        "p=reject",
        "CEO fraud",
        "invoice fraud",
        "Email Spoofing",
        "email spoofing",
        "Mail Exchange (MX) records",
    ]

    def test_cors_wildcard_origin_h1_and_bugcrowd(self):
        vuln = BountyVulnerability(
            program_id="amazonvrp",
            program_name="Amazon VRP",
            platform="hackerone",
            target_domain="api.amazon.ae",
            flaw_type="cors_wildcard_origin",
            provider="API Gateway CORS",
            severity=Severity.LOW,
            cvss_score=3.7,
            evidence="Access-Control-Allow-Origin: *",
            cwe_id="CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
            remediation="Validate Origin header against whitelist.",
            bounty_viability="INFORMATIONAL_LOW",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [CORS Misconfiguration]" in h1
        assert "Permissive Wildcard Access-Control-Allow-Origin" in h1
        assert "Origin: https://evil.com" in h1
        assert "Access-Control-Allow-Origin" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1, f"Found forbidden mail string '{forbidden}' in CORS H1 report"

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Application Security Misconfiguration > Cross-Origin Resource Sharing (CORS)" in bc
        assert "CORS Policy Misconfiguration on api.amazon.ae" in bc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in bc, f"Found forbidden mail string '{forbidden}' in CORS Bugcrowd report"

        email = ResponsibleDisclosureDrafter.generate_security_txt_email(vuln)
        assert "Cross-Origin Resource Sharing" in email
        assert "email authentication policies" not in email

    def test_cors_credentials_reflection(self):
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="admin.shopify.com",
            flaw_type="cors_arbitrary_origin_with_credentials",
            provider="API Gateway CORS",
            severity=Severity.HIGH,
            cvss_score=8.1,
            evidence="Access-Control-Allow-Origin: https://evil.com; Access-Control-Allow-Credentials: true",
        )
        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [CORS Misconfiguration] Arbitrary Origin Reflection with Credentials" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1

    def test_graphql_introspection(self):
        vuln = BountyVulnerability(
            program_id="gitlab",
            program_name="GitLab",
            platform="hackerone",
            target_domain="gitlab.com",
            flaw_type="graphql_introspection",
            provider="GraphQL",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            evidence="GraphQL endpoint returned full __schema JSON",
            cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            remediation="Disable schema introspection in production.",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [Information Disclosure] Public GraphQL Schema Introspection on gitlab.com" in h1
        assert "__schema" in h1
        assert "POST https://gitlab.com/graphql" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Information Disclosure > Exposed GraphQL Schema Introspection" in bc
        assert "Exposed GraphQL Schema Introspection on gitlab.com" in bc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in bc

        email = ResponsibleDisclosureDrafter.generate_security_txt_email(vuln)
        assert "GraphQL schema introspection" in email
        assert "email authentication policies" not in email

    def test_cloud_storage_takeover_and_open_bucket(self):
        vuln_takeover = BountyVulnerability(
            program_id="starbucks",
            program_name="Starbucks",
            platform="hackerone",
            target_domain="static.starbucks.com",
            cname_target="starbucks-static.s3.amazonaws.com",
            flaw_type="cloud_storage_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=8.6,
            evidence="NoSuchBucket error",
        )
        h1_takeover = HackerOneDisclosureGenerator.generate_h1_report(vuln_takeover)
        assert "# [Cloud Storage Takeover] Unclaimed Storage Bucket on static.starbucks.com" in h1_takeover
        assert "dig static.starbucks.com CNAME +short" in h1_takeover
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1_takeover

        bc_takeover = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln_takeover)
        assert "Server Security Misconfiguration > Unclaimed Cloud Storage Bucket" in bc_takeover

        vuln_open = BountyVulnerability(
            program_id="starbucks",
            program_name="Starbucks",
            platform="hackerone",
            target_domain="backups.starbucks.com",
            flaw_type="open_cloud_bucket",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=7.5,
            evidence="<ListBucketResult> public XML index",
        )
        h1_open = HackerOneDisclosureGenerator.generate_h1_report(vuln_open)
        assert "# [Cloud Storage] Open Public Bucket Directory Listing on backups.starbucks.com" in h1_open
        assert "<ListBucketResult>" in h1_open
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1_open

        bc_open = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln_open)
        assert "Information Disclosure > Public Cloud Storage Listing" in bc_open

    def test_http_request_smuggling(self):
        vuln = BountyVulnerability(
            program_id="yahoo",
            program_name="Yahoo",
            platform="hackerone",
            target_domain="mail.yahoo.com",
            flaw_type="http_request_smuggling_cl_te",
            provider="HTTP Reverse Proxy",
            severity=Severity.CRITICAL,
            cvss_score=9.1,
            evidence="Frontend CL / Backend TE desync (HTTP 504 timeout on ambiguous chunk)",
            cwe_id="CWE-444: Inconsistent Interpretation of HTTP Requests",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "# [HTTP Request Smuggling] Frontend CL / Backend TE Desynchronization on mail.yahoo.com" in h1
        assert "Transfer-Encoding: chunked" in h1
        assert "Content-Length: 4" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Server Security Misconfiguration > HTTP Request Smuggling" in bc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in bc

    def test_oauth_and_oidc_flaws(self):
        vuln_oauth = BountyVulnerability(
            program_id="oauth_corp",
            program_name="OAuth Corp",
            platform="hackerone",
            target_domain="auth.oauthcorp.com",
            flaw_type="oauth_redirect_uri_hijack",
            provider="OAuth Provider",
            severity=Severity.HIGH,
            cvss_score=8.1,
            evidence="redirect_uri=https://auth.oauthcorp.com.evil.com accepted without error",
            cwe_id="CWE-601: URL Redirection to Untrusted Site",
        )
        h1_oauth = HackerOneDisclosureGenerator.generate_h1_report(vuln_oauth)
        assert "[OAuth 2.0] Authorization Code / Token Theft via Redirect URI Hijack on auth.oauthcorp.com" in h1_oauth
        assert "oauth/authorize" in h1_oauth
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1_oauth

        vuln_oidc = BountyVulnerability(
            program_id="oauth_corp",
            program_name="OAuth Corp",
            platform="hackerone",
            target_domain="auth.oauthcorp.com",
            flaw_type="oidc_insecure_signing_alg",
            provider="OIDC Provider",
            severity=Severity.HIGH,
            cvss_score=8.1,
            evidence="id_token_signing_alg_values_supported contains 'none'",
        )
        h1_oidc = HackerOneDisclosureGenerator.generate_h1_report(vuln_oidc)
        assert "[OIDC] Insecure JWT Token Signing Algorithm (alg: none) Supported on auth.oauthcorp.com" in h1_oidc
        assert ".well-known/openid-configuration" in h1_oidc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1_oidc

    def test_dependency_confusion(self):
        vuln = BountyVulnerability(
            program_id="fintech",
            program_name="Fintech",
            platform="hackerone",
            target_domain="fintech.com",
            flaw_type="dependency_confusion_namespace_takeover",
            provider="npm Registry",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            evidence="Internal package @fintech/internal-payments returned HTTP 404 on npm registry",
            cwe_id="CWE-427: Uncontrolled Search Path Element",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "[Supply Chain] Unclaimed Internal Package Namespace on Public Registry (fintech.com)" in h1
        assert "registry.npmjs.org" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Supply Chain Security > Internal Package Namespace Takeover" in bc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in bc

    def test_mail_spoofing_outputs_dmarc(self):
        vuln = BountyVulnerability(
            program_id="apex_inc",
            program_name="Apex Inc",
            platform="hackerone",
            target_domain="apexinc.com",
            flaw_type="mail_spoofing",
            provider=None,
            severity=Severity.HIGH,
            cvss_score=7.5,
            evidence="Domain 'apexinc.com' has NO DMARC record published at _dmarc.apexinc.com",
            bounty_viability="INFORMATIONAL_LOW",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "[Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on apexinc.com" in h1
        assert "dig _dmarc.apexinc.com TXT +short" in h1
        assert "dig apexinc.com TXT +short" in h1
        assert "p=reject" in h1
        assert "CEO fraud" in h1
        assert "Mail Exchange (MX) records" in h1

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Email Security Misconfiguration > Missing DMARC Policy" in bc
        assert "dig _dmarc.apexinc.com TXT +short" in bc

        email = ResponsibleDisclosureDrafter.generate_security_txt_email(vuln)
        assert "email authentication policies" in email

    def test_generic_fallback_for_unknown_flaw_type(self):
        vuln = BountyVulnerability(
            program_id="custom_prog",
            program_name="Custom Program",
            platform="hackerone",
            target_domain="app.custom.com",
            flaw_type="custom_memory_corruption_leak",
            provider="Custom Service",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            evidence="Observed anomalous response header leaking memory pointer 0x7ffd9a",
        )

        h1 = HackerOneDisclosureGenerator.generate_h1_report(vuln)
        assert "[Custom Memory Corruption Leak] Security Misconfiguration Identified on app.custom.com" in h1
        assert "curl -i -s https://app.custom.com/" in h1
        assert "0x7ffd9a" in h1
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in h1, f"Fallback must not contain '{forbidden}'"

        bc = ResponsibleDisclosureDrafter.generate_bugcrowd_report(vuln)
        assert "Server Security Misconfiguration > General" in bc
        assert "Security Vulnerability (Custom Memory Corruption Leak) on app.custom.com" in bc
        for forbidden in self.FORBIDDEN_MAIL_STRINGS:
            assert forbidden not in bc


class TestBountyProgramScopeFiltering:
    """Tests verifying program policy scope filtering (excluded_vulnerabilities)."""

    def test_is_vulnerability_in_scope_helper(self):
        prog = BountyProgram(
            program_id="amazonvrp",
            name="Amazon VRP",
            platform="hackerone",
            in_scope=["*.amazon.com", "*.amazon.ae"],
            excluded_vulnerabilities=["mail_spoofing", "dmarc", "cors_wildcard_origin", "unauthenticated_cors"],
        )

        # Excluded
        assert prog.is_vulnerability_in_scope("mail_spoofing") is False
        assert prog.is_vulnerability_in_scope("dmarc") is False
        assert prog.is_vulnerability_in_scope("cors_wildcard_origin") is False
        assert prog.is_vulnerability_in_scope("cors_wildcard") is False
        assert is_vulnerability_in_scope(prog, "mail_spoofing") is False

        # Permitted / in-scope
        assert prog.is_vulnerability_in_scope("subdomain_takeover") is True
        assert prog.is_vulnerability_in_scope("graphql_introspection") is True
        assert prog.is_vulnerability_in_scope("cloud_storage_takeover") is True
        assert prog.is_vulnerability_in_scope("http_request_smuggling_cl_te") is True
        assert prog.is_vulnerability_in_scope("dependency_confusion_namespace_takeover") is True

    def test_sweep_program_skips_excluded_vulnerabilities(self):
        sweeper = BountyTakeoverSweeper()
        prog = BountyProgram(
            program_id="filtered_prog",
            name="Filtered Program",
            platform="hackerone",
            in_scope=["api.filtered.com"],
            excluded_vulnerabilities=["mail_spoofing", "dmarc", "cors_wildcard_origin"],
        )

        mock_cors = {
            "api.filtered.com": {
                "origin_reflected": "*",
                "credentials": "false",
                "vulnerable": True,
                "flaw_type": "cors_wildcard_origin",
                "bounty_viability": "INFORMATIONAL_LOW",
                "evidence": "Access-Control-Allow-Origin: *",
            }
        }
        mock_spfs = {"api.filtered.com": "v=spf1 ~all"}
        mock_dmarcs = {"api.filtered.com": ""}

        vulns = sweeper.sweep_program(
            prog,
            audit_cors=True,
            mock_cors_responses=mock_cors,
            mock_spfs=mock_spfs,
            mock_dmarcs=mock_dmarcs,
        )

        flaw_types = {v.flaw_type for v in vulns}
        assert "mail_spoofing" not in flaw_types, "mail_spoofing must be skipped when excluded by program policy"
        assert "cors_wildcard_origin" not in flaw_types, "cors_wildcard_origin must be skipped when excluded by program policy"
        assert len(vulns) == 0

    def test_save_disclosure_skips_excluded_vulnerability(self, tmp_path):
        prog = BountyProgram(
            program_id="amazonvrp",
            name="Amazon VRP",
            platform="hackerone",
            in_scope=["*.amazon.ae"],
            excluded_vulnerabilities=["cors_wildcard_origin", "mail_spoofing"],
        )

        vuln_excluded = BountyVulnerability(
            program_id="amazonvrp",
            program_name="Amazon VRP",
            platform="hackerone",
            target_domain="amazon.ae",
            flaw_type="cors_wildcard_origin",
            evidence="Access-Control-Allow-Origin: *",
        )

        result_path = HackerOneDisclosureGenerator.save_disclosure(vuln_excluded, program=prog, output_dir=tmp_path)
        assert result_path is None, "save_disclosure must return None and not write file when flaw is excluded"
        assert len(list(tmp_path.iterdir())) == 0

        # When program is None or flaw is in-scope, file should be written
        vuln_allowed = BountyVulnerability(
            program_id="amazonvrp",
            program_name="Amazon VRP",
            platform="hackerone",
            target_domain="sub.amazon.ae",
            flaw_type="subdomain_takeover",
            cname_target="unclaimed.s3.amazonaws.com",
            evidence="NoSuchBucket",
        )
        saved_path = HackerOneDisclosureGenerator.save_disclosure(vuln_allowed, program=prog, output_dir=tmp_path)
        assert saved_path is not None and saved_path.exists()

    def test_save_bundle_and_crypto_bundle_skip_excluded_vulnerability(self, tmp_path):
        prog = BountyProgram(
            program_id="shopify",
            name="Shopify",
            platform="hackerone",
            in_scope=["*.shopify.com"],
            excluded_vulnerabilities=["mail_spoofing", "missing_dmarc"],
        )

        vuln_mail = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="shopify.com",
            flaw_type="mail_spoofing",
            evidence="No DMARC record",
        )

        bundle = ResponsibleDisclosureDrafter.save_bundle(vuln_mail, program=prog, output_dir=tmp_path)
        assert bundle == {}, "save_bundle must return empty dict when flaw is excluded"

        crypto = ResponsibleDisclosureDrafter.export_cryptographic_bundle(vuln_mail, program=prog, output_dir=tmp_path)
        assert crypto.get("status") == "SKIPPED_OUT_OF_SCOPE"
        assert "excluded" in crypto.get("reason", "")


