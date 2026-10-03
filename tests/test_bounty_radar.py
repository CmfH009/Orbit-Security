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
    HackerOneDisclosureGenerator,
    OffPeakWindow,
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
