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
        assert res["severity"] == Severity.MEDIUM
        assert res["cvss_score"] == 5.4
        assert "blindly reflects untrusted Origin" in res["evidence"]
        assert res["bounty_viability"] == "CONDITIONAL"

        res_auth = CorsMisconfigurationSentinel.audit_target(
            target_domain="api.target.com",
            mock_responses=mock_responses,
            authenticated_proof=True,
        )
        assert res_auth is not None
        assert res_auth["severity"] == Severity.HIGH
        assert res_auth["cvss_score"] == 8.1
        assert res_auth["bounty_viability"] == "HIGH_CONFIDENCE"

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
        assert res["severity"] == Severity.MEDIUM
        assert res["cvss_score"] == 5.4
        assert res["bounty_viability"] == "CONDITIONAL"
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


class TestPassiveTlsAndEmailSentinels:
    """Tests PassiveTlsCipherSentinel and EmailAuthPolicyAnalyzer edge cases and Blackboard emission."""

    def test_tls_posture_deprecated_protocol_weak_cipher_expired_and_san_mismatch(self, tmp_path):
        from orbit_security.blackboard import Blackboard
        from orbit_security.cloud_sentinels import PassiveTlsCipherSentinel

        bb = Blackboard(db_path=tmp_path / "tls_bb.db")
        res = PassiveTlsCipherSentinel.evaluate_tls_posture(
            domain="legacy.target.com",
            tls_version="TLSv1.0",
            cipher_suite="TLS_RSA_WITH_RC4_128_MD5",
            days_remaining=-5,
            san_domains=["other.target.com", "*.sub.target.com"],
            blackboard=bb,
        )
        assert res["vulnerable"] is True
        assert res["severity"] == "CRITICAL"
        codes = {i["code"] for i in res["issues"]}
        assert "DEPRECATED_TLS_PROTOCOL" in codes
        assert "WEAK_CIPHER_SUITE" in codes
        assert "CERTIFICATE_EXPIRED" in codes
        assert "SAN_HOSTNAME_MISMATCH" in codes

        events = bb.get_recent(limit=10, topic="perimeter")
        assert any(e["event_type"] == "TLS_POSTURE_ANOMALY" for e in events)

    def test_tls_posture_wildcard_san_and_healthy_cert(self):
        from orbit_security.cloud_sentinels import PassiveTlsCipherSentinel

        res = PassiveTlsCipherSentinel.evaluate_tls_posture(
            domain="api.target.com",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            days_remaining=60,
            san_domains=["*.target.com"],
        )
        assert res["vulnerable"] is False
        assert res["severity"] == "SAFE"
        assert res["issues"] == []

    def test_email_auth_policy_analyzer_spoofable_and_lookup_limit(self, tmp_path):
        from orbit_security.blackboard import Blackboard
        from orbit_security.cloud_sentinels import EmailAuthPolicyAnalyzer

        bb = Blackboard(db_path=tmp_path / "email_bb.db")
        spf_many = "v=spf1 " + " ".join(f"include:spf{i}.example.com" for i in range(11)) + " +all"
        res = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
            domain="spoofable.example.com",
            spf_record=spf_many,
            dmarc_record="v=DMARC1; p=none; pct=50",
            dkim_selectors={"default": "v=DKIM1; k=rsa; p=short"},
            blackboard=bb,
        )
        assert res["spoofable"] is True
        assert res["severity"] == "CRITICAL"
        codes = {f["code"] for f in res["findings"]}
        assert "SPF_PERMISSIVE_PLUS_ALL" in codes
        assert "SPF_LOOKUP_LIMIT_EXCEEDED" in codes
        assert "DMARC_POLICY_NONE" in codes
        assert "DMARC_PARTIAL_PCT" in codes
        assert "DKIM_NO_VALID_SELECTORS" in codes

        events = bb.get_recent(limit=10, topic="perimeter")
        assert any(e["event_type"] == "EMAIL_AUTH_POSTURE_EVALUATED" for e in events)


class TestCloudSentinelsAndSandbox:
    """Tests transport short-circuiting and sandbox verification for cloud sentinels."""

    def test_graphql_and_cors_live_transport_failure_short_circuits(self):
        import urllib.error
        import urllib.request

        with patch("orbit_security.cloud_sentinels.is_safe_host", return_value=True), patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ) as mock_urlopen:
            gql_res = GraphQLIntrospectionSentinel.audit_target("dead.target.com", timeout=0.5)
            assert gql_res is None
            assert mock_urlopen.call_count == 1

        with patch("orbit_security.cloud_sentinels.is_safe_host", return_value=True), patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ) as mock_urlopen_cors:
            cors_res = CorsMisconfigurationSentinel.audit_target("dead.target.com", timeout=0.5)
            assert cors_res is None
            assert mock_urlopen_cors.call_count == 1

    def test_sandbox_script_generation_and_verification_for_cloud_sentinels(self):
        from orbit_security.exploit_sandbox import OperatorExploitSandbox, ScriptGenerator

        gql_finding = {
            "target_domain": "api.target.com",
            "flaw_type": "graphql_introspection",
            "endpoint_path": "/api/graphql",
            "evidence": "Production GraphQL schema introspection is enabled at 'https://api.target.com/api/graphql'.",
        }
        py_gql = ScriptGenerator.generate_python_script(gql_finding)
        curl_gql = ScriptGenerator.generate_curl_script(gql_finding)
        assert "https://api.target.com/api/graphql" in py_gql
        assert "https://api.target.com/api/graphql" in curl_gql

        null_cors_finding = {
            "target_domain": "auth.target.com",
            "flaw_type": "cors_null_origin_with_credentials",
            "evidence": "Dangerous CORS policy on 'auth.target.com': Server explicitly trusts Origin 'null'",
        }
        py_null = ScriptGenerator.generate_python_script(null_cors_finding)
        assert '"Origin": "null"' in py_null
        rep_null = OperatorExploitSandbox.verify_vulnerability(
            null_cors_finding,
            mock_execution={
                "exit_code": 0,
                "stdout": "STATUS: 200\nACAO: null\nACAC: true\n",
                "stderr": "",
                "status_code": 200,
                "response_headers": {"acao": "null", "acac": "true"},
            },
        )
        assert rep_null.diff.is_confirmed is True
        assert rep_null.diff.confidence_score >= 0.90

        arb_cors_finding = {
            "target_domain": "api.target.com",
            "flaw_type": "cors_arbitrary_origin_with_credentials",
            "evidence": "Server blindly reflects untrusted Origin 'https://untrusted-adversary.com'",
        }
        py_arb = ScriptGenerator.generate_python_script(arb_cors_finding)
        assert '"Origin": "https://untrusted-adversary.com"' in py_arb
        rep_arb = OperatorExploitSandbox.verify_vulnerability(
            arb_cors_finding,
            mock_execution={
                "exit_code": 0,
                "stdout": "STATUS: 200\nACAO: https://untrusted-adversary.com\nACAC: true\n",
                "stderr": "",
                "status_code": 200,
                "response_headers": {"acao": "https://untrusted-adversary.com", "acac": "true"},
            },
        )
        assert rep_arb.diff.is_confirmed is True
        assert rep_arb.diff.confidence_score >= 0.90

