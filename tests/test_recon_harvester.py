"""Unit tests for Phase A passive reconnaissance, CT streaming, archive harvesting, and JS route extraction."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.bounty_radar import BountyTakeoverSweeper
from orbit_security.recon_harvester import (
    CertificateTransparencyStreamer,
    ArchiveHarvester,
    JsRouteExtractor,
)


class TestCertificateTransparencyStreamer:
    """Tests for Certificate Transparency and TLS SAN harvesting."""

    def test_normalize_host_valid(self):
        assert CertificateTransparencyStreamer.normalize_host("api.target.com") == "api.target.com"
        assert CertificateTransparencyStreamer.normalize_host("*.sub.target.com") == "sub.target.com"
        assert CertificateTransparencyStreamer.normalize_host("https://admin.target.com/dashboard") == "admin.target.com"
        assert CertificateTransparencyStreamer.normalize_host("UPPERCASE.TARGET.COM") == "uppercase.target.com"
        assert CertificateTransparencyStreamer.normalize_host("portal.target.com:8443") == "portal.target.com"

    def test_normalize_host_invalid(self):
        assert CertificateTransparencyStreamer.normalize_host("") is None
        assert CertificateTransparencyStreamer.normalize_host("   ") is None
        assert CertificateTransparencyStreamer.normalize_host("127.0.0.1") is None
        assert CertificateTransparencyStreamer.normalize_host("192.168.1.100") is None
        assert CertificateTransparencyStreamer.normalize_host("target") is None
        assert CertificateTransparencyStreamer.normalize_host("invalid host with spaces.com") is None
        assert CertificateTransparencyStreamer.normalize_host("http://") is None

    def test_fetch_crtsh_success(self):
        mock_response = MagicMock()
        mock_context = mock_response.__enter__.return_value
        mock_context.status = 200
        mock_payload = [
            {"name_value": "api.shopify.com\ncheckout.shopify.com"},
            {"name_value": "*.shopify.com"},
            {"name_value": "shopify.com"},
            {"name_value": "other-shopify.com"},  # Not a subdomain of shopify.com
            {"name_value": "admin.shopify.com"},
        ]
        mock_context.read.return_value = json.dumps(mock_payload).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            subs = CertificateTransparencyStreamer.fetch_crtsh("shopify.com", max_results=10)
            assert "api.shopify.com" in subs
            assert "checkout.shopify.com" in subs
            assert "admin.shopify.com" in subs
            assert "shopify.com" not in subs  # Apex excluded from subdomain list
            assert "other-shopify.com" not in subs  # Not a true dot-subdomain

    def test_fetch_crtsh_error_handling(self):
        with patch("urllib.request.urlopen", side_effect=Exception("Connection reset")):
            subs = CertificateTransparencyStreamer.fetch_crtsh("shopify.com")
            assert subs == []

    def test_probe_tls_sans_ssrf_protection(self):
        assert CertificateTransparencyStreamer.probe_tls_sans("127.0.0.1") == []
        assert CertificateTransparencyStreamer.probe_tls_sans("localhost") == []
        assert CertificateTransparencyStreamer.probe_tls_sans("169.254.169.254") == []
        assert CertificateTransparencyStreamer.probe_tls_sans("10.0.0.1") == []

    def test_probe_tls_sans_success(self):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subjectAltName": [
                ("DNS", "shopify.com"),
                ("DNS", "cdn.shopify.com"),
                ("DNS", "*.myshopify.com"),
                ("DNS", "internal-api.shopify.com"),
                ("IP Address", "192.168.1.1"),
            ]
        }
        mock_sock_cm = MagicMock()
        mock_sock_cm.__enter__.return_value = mock_sock
        mock_ssock_cm = MagicMock()
        mock_ssock_cm.__enter__.return_value = mock_ssock

        with patch("socket.create_connection", return_value=mock_sock_cm), \
             patch("ssl.create_default_context") as mock_ssl_ctx:
            mock_ctx_instance = MagicMock()
            mock_ctx_instance.wrap_socket.return_value = mock_ssock_cm
            mock_ssl_ctx.return_value = mock_ctx_instance

            sans = CertificateTransparencyStreamer.probe_tls_sans("shopify.com")
            assert "shopify.com" in sans
            assert "cdn.shopify.com" in sans
            assert "myshopify.com" in sans
            assert "internal-api.shopify.com" in sans

    def test_discover_subdomains_filtering(self):
        with patch.object(
            CertificateTransparencyStreamer,
            "fetch_crtsh",
            return_value=["api.target.com", "dev.target.com", "secret.internal.target.com", "out.target.com"],
        ), patch.object(
            CertificateTransparencyStreamer,
            "probe_tls_sans",
            return_value=["cdn.target.com", "target.com"],
        ):
            discovered = CertificateTransparencyStreamer.discover_subdomains(
                apex_domain="target.com",
                in_scope=["*.target.com"],
                out_of_scope=["out.target.com", "*.internal.target.com"],
                probe_tls=True,
                max_results=50,
            )

            assert "api.target.com" in discovered
            assert "dev.target.com" in discovered
            assert "cdn.target.com" in discovered
            # Verify exclusions
            assert "out.target.com" not in discovered
            assert "secret.internal.target.com" not in discovered


class TestArchiveHarvester:
    """Tests for Wayback Machine CDX and AlienVault OTX historical asset mining."""

    def test_query_wayback_cdx_success(self):
        mock_response = MagicMock()
        mock_context = mock_response.__enter__.return_value
        mock_context.status = 200
        mock_rows = [
            ["http://legacy.shopify.com/app/index.html"],
            ["https://portal.shopify.com/login"],
            ["http://shopify.com/"],  # Apex
            ["http://other-shopify.com/"],  # Cross-apex
            ["ftp://old-vault.shopify.com/data"],
        ]
        mock_context.read.return_value = json.dumps(mock_rows).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            subs = ArchiveHarvester.query_wayback_cdx("shopify.com", max_results=10)
            assert "legacy.shopify.com" in subs
            assert "portal.shopify.com" in subs
            assert "old-vault.shopify.com" in subs
            assert "shopify.com" not in subs
            assert "other-shopify.com" not in subs

    def test_query_wayback_cdx_error_fallback(self):
        with patch("urllib.request.urlopen", side_effect=Exception("HTTP 503 Service Unavailable")):
            subs = ArchiveHarvester.query_wayback_cdx("shopify.com")
            assert subs == []

    def test_query_alienvault_otx_success(self):
        mock_response = MagicMock()
        mock_context = mock_response.__enter__.return_value
        mock_context.status = 200
        mock_data = {
            "passive_dns": [
                {"hostname": "staging-checkout.shopify.com", "address": "1.2.3.4"},
                {"hostname": "vpn.shopify.com", "address": "5.6.7.8"},
                {"hostname": "shopify.com", "address": "9.10.11.12"},
                {"hostname": "notshopify.com", "address": "13.14.15.16"},
            ]
        }
        mock_context.read.return_value = json.dumps(mock_data).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            subs = ArchiveHarvester.query_alienvault_otx("shopify.com", max_results=10)
            assert "staging-checkout.shopify.com" in subs
            assert "vpn.shopify.com" in subs
            assert "shopify.com" not in subs
            assert "notshopify.com" not in subs

    def test_query_alienvault_otx_error_fallback(self):
        with patch("urllib.request.urlopen", side_effect=Exception("Timeout")):
            subs = ArchiveHarvester.query_alienvault_otx("shopify.com")
            assert subs == []

    def test_harvest_historical_assets_aggregated(self):
        with patch.object(
            ArchiveHarvester, "query_wayback_cdx", return_value=["alpha.shopify.com", "shared.shopify.com"]
        ), patch.object(
            ArchiveHarvester, "query_alienvault_otx", return_value=["beta.shopify.com", "shared.shopify.com"]
        ):
            res = ArchiveHarvester.harvest_historical_assets("shopify.com", max_results=10)
            assert res["apex_domain"] == "shopify.com"
            assert res["total_historical_subdomains"] == 3
            assert res["sources"]["wayback_count"] == 2
            assert res["sources"]["otx_count"] == 2
            assert res["subdomains"] == ["alpha.shopify.com", "beta.shopify.com", "shared.shopify.com"]


class TestJsRouteExtractor:
    """Tests for JavaScript static route extraction, cloud storage discovery, and secret scanning."""

    def test_extract_script_urls(self):
        html = """
        <html>
          <head>
            <script src="/static/js/bundle.main.123.js"></script>
            <script src="https://cdn.target.com/vendor.min.js"></script>
            <script src="relative/path/app.js"></script>
          </head>
        </html>
        """
        urls = JsRouteExtractor.extract_script_urls(html, "https://target.com/login")
        assert "https://target.com/static/js/bundle.main.123.js" in urls
        assert "https://cdn.target.com/vendor.min.js" in urls
        assert "https://target.com/relative/path/app.js" in urls

    def test_extract_endpoints_and_assets(self):
        sample_js = """
        const API_BASE = '/api/v2/users';
        const GQL = '/graphql/v1';
        const AUTH = '/auth/oauth/token';
        const S3_BUCKET = 'https://acme-customer-receipts.s3.amazonaws.com/uploads';
        const GCS_BUCKET = 'https://storage-acme.storage.googleapis.com/assets';
        const AZURE = 'https://acmedata.blob.core.windows.net/logs';
        const DO = 'https://cdn-space.digitaloceanspaces.com/img';
        const INTERNAL_SUB = 'https://staging-portal.target.com/debug';
        const API_KEY = "ak_live_abcdef1234567890";
        """
        res = JsRouteExtractor.extract_endpoints_and_assets(sample_js, "target.com")

        assert "/api/v2/users" in res["api_routes"]
        assert "/graphql/v1" in res["api_routes"]
        assert "/auth/oauth/token" in res["api_routes"]

        assert "acme-customer-receipts.s3.amazonaws.com" in res["cloud_storage"]
        assert "storage-acme.storage.googleapis.com" in res["cloud_storage"]
        assert "acmedata.blob.core.windows.net" in res["cloud_storage"]
        assert "cdn-space.digitaloceanspaces.com" in res["cloud_storage"]

        assert "staging-portal.target.com" in res["internal_subdomains"]
        assert len(res["potential_env_keys"]) > 0
        assert res["potential_env_keys"][0]["key"] == "API_KEY"
        assert res["potential_env_keys"][0]["masked_val"].startswith("ak_l")

    def test_analyze_target_scripts_ssrf_blocked(self):
        res = JsRouteExtractor.analyze_target_scripts("http://127.0.0.1/app.html")
        assert "error" in res
        assert "blocked by SSRF filter" in res["error"]

        res2 = JsRouteExtractor.analyze_target_scripts("http://169.254.169.254/metadata")
        assert "error" in res2
        assert "blocked by SSRF filter" in res2["error"]

    def test_analyze_target_scripts_integration(self):
        mock_html_resp = MagicMock()
        mock_html_ctx = mock_html_resp.__enter__.return_value
        mock_html_ctx.read.return_value = b'<html><script src="/static/app.js"></script></html>'

        mock_js_resp = MagicMock()
        mock_js_ctx = mock_js_resp.__enter__.return_value
        mock_js_ctx.read.return_value = b"const endpoint = '/api/internal/fleet'; const s3 = 'https://my-bucket.s3.amazonaws.com';"

        with patch("urllib.request.urlopen", side_effect=[mock_html_resp, mock_js_resp]):
            res = JsRouteExtractor.analyze_target_scripts("https://target.com")
            assert "/api/internal/fleet" in res["api_routes"]
            assert "my-bucket.s3.amazonaws.com" in res["cloud_storage"]


class TestBountySweeperReconIntegration:
    """Tests integrating recon_harvester with BountyTakeoverSweeper."""

    def test_expand_wildcards_with_archive_harvest(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets"])
        mock_archive_res = {
            "subdomains": ["archived-portal.acme.com", "legacy-api.acme.com"]
        }
        with patch(
            "orbit_security.recon_harvester.ArchiveHarvester.harvest_historical_assets",
            return_value=mock_archive_res,
        ):
            candidates = sweeper.expand_wildcards(
                ["*.acme.com"],
                max_per_wildcard=5,
                use_passive_ct=False,
                use_archive_harvest=True,
            )
            assert "acme.com" in candidates
            assert "archived-portal.acme.com" in candidates
            assert "legacy-api.acme.com" in candidates

    def test_harvest_javascript_routes_sweeper(self):
        sweeper = BountyTakeoverSweeper()
        mock_analysis = {
            "target_url": "https://target.com",
            "api_routes": ["/api/v1/auth"],
            "cloud_storage": ["target-bucket.s3.amazonaws.com"],
            "internal_subdomains": ["dev.target.com"],
            "potential_env_keys": [],
        }
        with patch(
            "orbit_security.recon_harvester.JsRouteExtractor.analyze_target_scripts",
            return_value=mock_analysis,
        ):
            res = sweeper.harvest_javascript_routes("https://target.com")
            assert res["api_routes"] == ["/api/v1/auth"]
            assert res["cloud_storage"] == ["target-bucket.s3.amazonaws.com"]
