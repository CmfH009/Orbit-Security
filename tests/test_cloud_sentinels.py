"""Unit tests for Phase B: Cloud Perimeter & Misconfiguration Sentinels.

Tests:
1. CloudBucketTakeoverSentinel (S3, GCS, Azure Blob dangling buckets and open listings).
2. GraphQLIntrospectionSentinel (exposed GraphQL introspection schemas).
3. CorsMisconfigurationSentinel (arbitrary origin reflection and null origin trust with credentials).
4. BountyTakeoverSweeper integration with cloud sentinels.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from orbit_security.bounty_radar import BountyProgram, BountyTakeoverSweeper
from orbit_security.cloud_sentinels import (
    CloudBucketTakeoverSentinel,
    GraphQLIntrospectionSentinel,
    CorsMisconfigurationSentinel,
)
from orbit_security.models import Severity


class TestCloudBucketTakeoverSentinel:
    """Tests for orphaned S3/GCS/Azure storage buckets and public data exposure."""

    def test_identify_provider_from_cname(self):
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("mybucket.s3.amazonaws.com") == "AWS S3"
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("assets.s3-website-us-east-1.amazonaws.com") == "AWS S3"
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("data.c.storage.googleapis.com") == "Google Cloud Storage"
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("cdn.blob.core.windows.net") == "Azure Blob Storage"
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("files.digitaloceanspaces.com") == "DigitalOcean Spaces"
        assert CloudBucketTakeoverSentinel.identify_provider_from_cname("unrelated.cloudfront.net") is None

    def test_audit_aws_s3_takeover(self):
        mock_body = "<?xml version='1.0' encoding='UTF-8'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
        res = CloudBucketTakeoverSentinel.audit_target(
            target_domain="assets.target.com",
            cname_target="assets.target.com.s3.amazonaws.com",
            mock_body=mock_body,
            mock_status=404,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "cloud_storage_takeover"
        assert res["provider"] == "AWS S3"
        assert res["severity"] == Severity.HIGH
        assert res["cvss_score"] == 8.6
        assert "NoSuchBucket" in res["evidence"]
        assert res["bounty_viability"] == "HIGH_CONFIDENCE"

    def test_audit_gcs_takeover(self):
        mock_body = "The specified bucket does not exist"
        res = CloudBucketTakeoverSentinel.audit_target(
            target_domain="storage.target.com",
            cname_target="c.storage.googleapis.com",
            mock_body=mock_body,
            mock_status=404,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "cloud_storage_takeover"
        assert res["provider"] == "Google Cloud Storage"
        assert res["cvss_score"] == 8.6

    def test_audit_azure_blob_takeover(self):
        mock_body = "<?xml version='1.0' encoding='utf-8'?><Error><Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message></Error>"
        res = CloudBucketTakeoverSentinel.audit_target(
            target_domain="blobs.target.com",
            cname_target="targetdata.blob.core.windows.net",
            mock_body=mock_body,
            mock_status=404,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "cloud_storage_takeover"
        assert res["provider"] == "Azure Blob Storage"
        assert res["cvss_score"] == 8.6

    def test_audit_open_bucket_listing(self):
        mock_body = "<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'><Name>customer-backups</Name><Contents><Key>db.sql</Key></Contents></ListBucketResult>"
        res = CloudBucketTakeoverSentinel.audit_target(
            target_domain="backups.target.com",
            cname_target="customer-backups.s3.amazonaws.com",
            mock_body=mock_body,
            mock_status=200,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "open_cloud_bucket"
        assert res["cvss_score"] == 7.5
        assert "Public cloud storage bucket listing" in res["evidence"]

    def test_audit_safe_bucket_suppressed(self):
        mock_body = "<html><body><h1>Welcome to Acme Production</h1></body></html>"
        res = CloudBucketTakeoverSentinel.audit_target(
            target_domain="static.target.com",
            cname_target="static.s3.amazonaws.com",
            mock_body=mock_body,
            mock_status=200,
        )
        assert res is None

    def test_probe_http_body_ssrf_blocked(self):
        status, body = CloudBucketTakeoverSentinel.probe_http_body("127.0.0.1")
        assert status == 0
        assert body == ""

        status, body = CloudBucketTakeoverSentinel.probe_http_body("http://169.254.169.254/latest/meta-data")
        assert status == 0
        assert body == ""


class TestGraphQLIntrospectionSentinel:
    """Tests for exposed GraphQL schema introspection endpoints."""

    def test_audit_graphql_introspection_enabled(self):
        mock_paths = {
            "/api/graphql": {
                "data": {
                    "__schema": {
                        "queryType": {"name": "RootQuery"},
                        "types": [{"name": "User"}, {"name": "AdminConfig"}],
                    }
                }
            }
        }
        res = GraphQLIntrospectionSentinel.audit_target(
            target_domain="api.target.com",
            mock_paths=mock_paths,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "graphql_introspection"
        assert res["provider"] == "GraphQL"
        assert res["endpoint_path"] == "/api/graphql"
        assert res["severity"] == Severity.MEDIUM
        assert res["cvss_score"] == 5.3
        assert "RootQuery" in res["evidence"]
        assert "disable schema introspection" in res["remediation"].lower()

    def test_audit_graphql_introspection_disabled(self):
        mock_paths = {
            "/graphql": {
                "errors": [{"message": "Introspection is disabled for production"}]
            }
        }
        res = GraphQLIntrospectionSentinel.audit_target(
            target_domain="api.target.com",
            mock_paths=mock_paths,
        )
        assert res is None

    def test_audit_graphql_ssrf_blocked(self):
        res = GraphQLIntrospectionSentinel.audit_target("127.0.0.1")
        assert res is None


class TestCorsMisconfigurationSentinel:
    """Tests for arbitrary origin reflection and null origin trust with credentials."""

    def test_audit_cors_arbitrary_origin_with_credentials(self):
        mock_responses = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                "access-control-allow-credentials": "true",
            }
        }
        res = CorsMisconfigurationSentinel.audit_target(
            target_domain="api.target.com",
            mock_responses=mock_responses,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "cors_arbitrary_origin_with_credentials"
        assert res["severity"] == Severity.HIGH
        assert res["cvss_score"] == 8.1
        assert "blindly reflects untrusted Origin" in res["evidence"]
        assert res["bounty_viability"] == "HIGH_CONFIDENCE"

    def test_audit_cors_null_origin_with_credentials(self):
        mock_responses = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": "https://allowed.target.com",
            },
            CorsMisconfigurationSentinel.NULL_ORIGIN: {
                "access-control-allow-origin": "null",
                "access-control-allow-credentials": "true",
            },
        }
        res = CorsMisconfigurationSentinel.audit_target(
            target_domain="account.target.com",
            mock_responses=mock_responses,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["flaw_type"] == "cors_null_origin_with_credentials"
        assert res["severity"] == Severity.HIGH
        assert res["cvss_score"] == 7.1
        assert "Origin 'null'" in res["evidence"]

    def test_audit_cors_wildcard(self):
        mock_responses = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": "*",
            },
            CorsMisconfigurationSentinel.NULL_ORIGIN: {
                "access-control-allow-origin": "*",
            },
        }
        res = CorsMisconfigurationSentinel.audit_target(
            target_domain="public-data.target.com",
            mock_responses=mock_responses,
        )
        assert res is not None
        assert res["flaw_type"] == "cors_wildcard_origin"
        assert res["severity"] == Severity.LOW
        assert res["cvss_score"] == 3.7
        assert res["bounty_viability"] == "INFORMATIONAL_LOW"

    def test_audit_cors_secure_static_origin(self):
        mock_responses = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": "https://target.com",
                "access-control-allow-credentials": "true",
            },
            CorsMisconfigurationSentinel.NULL_ORIGIN: {},
        }
        res = CorsMisconfigurationSentinel.audit_target(
            target_domain="secure.target.com",
            mock_responses=mock_responses,
        )
        assert res is None

    def test_audit_cors_ssrf_blocked(self):
        res = CorsMisconfigurationSentinel.audit_target("127.0.0.1")
        assert res is None


class TestBountySweeperCloudIntegration:
    """Tests integrating cloud sentinels into BountyTakeoverSweeper."""

    def test_sweeper_audit_cloud_storage_bucket(self):
        sweeper = BountyTakeoverSweeper()
        res = sweeper.audit_cloud_storage_bucket(
            target_domain="assets.shopify.com",
            cname_target="assets.shopify.com.s3.amazonaws.com",
            mock_body="<Error><Code>NoSuchBucket</Code></Error>",
            mock_status=404,
        )
        assert res is not None
        assert res["vulnerable"] is True
        assert res["provider"] == "AWS S3"

    def test_sweeper_audit_graphql_introspection(self):
        sweeper = BountyTakeoverSweeper()
        mock_paths = {
            "/graphql": {
                "data": {"__schema": {"queryType": {"name": "Query"}}}
            }
        }
        res = sweeper.audit_graphql_introspection("shopify.com", mock_paths=mock_paths)
        assert res is not None
        assert res["flaw_type"] == "graphql_introspection"

    def test_sweeper_audit_cors_misconfiguration(self):
        sweeper = BountyTakeoverSweeper()
        mock_responses = {
            CorsMisconfigurationSentinel.TEST_ORIGIN: {
                "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                "access-control-allow-credentials": "true",
            }
        }
        res = sweeper.audit_cors_misconfiguration("api.shopify.com", mock_responses=mock_responses)
        assert res is not None
        assert res["flaw_type"] == "cors_arbitrary_origin_with_credentials"

    def test_sweep_program_with_cloud_sentinels(self):
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets", "graphql", "api"])
        program = BountyProgram(
            program_id="test_cloud",
            name="Test Cloud Program",
            platform="hackerone",
            policy_url="https://hackerone.com/test_cloud",
            in_scope=["assets.testcloud.com", "graphql.testcloud.com", "api.testcloud.com"],
            out_of_scope=[],
            bounty_tier="cash",
            max_bounty=25000,
        )

        mock_bodies = {
            "assets.testcloud.com": "<Error><Code>NoSuchBucket</Code></Error>",
        }
        mock_cnames = {
            "assets.testcloud.com": "testcloud-assets.s3.amazonaws.com",
        }
        mock_graphql = {
            "graphql.testcloud.com": {
                "/graphql": {"data": {"__schema": {"queryType": {"name": "Query"}}}}
            }
        }
        mock_cors = {
            "api.testcloud.com": {
                CorsMisconfigurationSentinel.TEST_ORIGIN: {
                    "access-control-allow-origin": CorsMisconfigurationSentinel.TEST_ORIGIN,
                    "access-control-allow-credentials": "true",
                }
            }
        }

        vulns = sweeper.sweep_program(
            program,
            max_domains=5,
            audit_cloud_buckets=True,
            audit_graphql=True,
            audit_cors=True,
            mock_bodies=mock_bodies,
            mock_cnames=mock_cnames,
            mock_graphql_responses=mock_graphql,
            mock_cors_responses=mock_cors,
        )

        flaw_types = {v.flaw_type for v in vulns}
        assert "cloud_storage_takeover" in flaw_types
        assert "graphql_introspection" in flaw_types
        assert "cors_arbitrary_origin_with_credentials" in flaw_types

        # Verify CVSS scores & vectors on generated vulnerabilities
        s3_vuln = next(v for v in vulns if v.flaw_type == "cloud_storage_takeover")
        assert s3_vuln.cvss_score == 8.6
        assert s3_vuln.provider == "AWS S3"

        gql_vuln = next(v for v in vulns if v.flaw_type == "graphql_introspection")
        assert gql_vuln.cvss_score == 5.3

        cors_vuln = next(v for v in vulns if v.flaw_type == "cors_arbitrary_origin_with_credentials")
        assert cors_vuln.cvss_score == 8.1
