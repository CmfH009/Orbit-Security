"""tests/test_vdp_high_signal_detectors.py: Unit tests for orbit_security.vdp_high_signal_detectors."""

from __future__ import annotations

import json
import unittest

from orbit_security.vdp_high_signal_detectors import (
    EXTENDED_SENSITIVE_PATHS,
    check_extended_sensitive_exposures,
    evaluate_cloud_reference_response,
    evaluate_cors_response,
    extract_cloud_urls_from_text,
    extract_same_origin_script_urls,
    scan_text_for_high_confidence_secrets,
)


class TestExtendedSensitiveExposures(unittest.TestCase):
    def test_extended_sensitive_paths_constant(self):
        self.assertEqual(
            EXTENDED_SENSITIVE_PATHS,
            (
                "/.git/config",
                "/.svn/entries",
                "/.DS_Store",
                "/server-status",
                "/actuator/mappings",
                "/actuator/beans",
            ),
        )

    def test_git_config_positive_and_redacts_credentials(self):
        git_cfg = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            '[remote "origin"]\n'
            "\turl = https://deploy_bot:SuperSecretPass99@github.com/acme/private-api.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
        res = check_extended_sensitive_exposures("/.git/config", 200, git_cfg)
        self.assertIsNotNone(res)
        self.assertEqual(res["path"], "/.git/config")
        self.assertEqual(res["finding_type"], "exposed_git")
        self.assertEqual(res["severity"], "medium")
        self.assertNotIn("SuperSecretPass99", res["snippet"])
        self.assertNotIn("deploy_bot:SuperSecretPass99", res["snippet"])
        self.assertIn("<REDACTED>", res["snippet"])
        self.assertIn("github.com/acme/private-api.git", res["snippet"])

    def test_git_config_positive_minimal_core_variants(self):
        cfg_repo_ver = "[core]\n\trepositoryformatversion = 0\n"
        res1 = check_extended_sensitive_exposures("/.git/config", 200, cfg_repo_ver)
        self.assertIsNotNone(res1)
        self.assertEqual(res1["finding_type"], "exposed_git")

        cfg_remote = '[core]\n[remote "upstream"]\n\turl = https://github.com/acme/app.git\n'
        res2 = check_extended_sensitive_exposures("/.git/config", 200, cfg_remote)
        self.assertIsNotNone(res2)
        self.assertEqual(res2["finding_type"], "exposed_git")

    def test_git_config_rejects_html_spa_non_200_and_noise(self):
        self.assertIsNone(check_extended_sensitive_exposures("/.git/config", 404, "[core]\nrepositoryformatversion = 0"))
        self.assertIsNone(check_extended_sensitive_exposures("/.git/config", 200, ""))
        self.assertIsNone(
            check_extended_sensitive_exposures(
                "/.git/config",
                200,
                "<!DOCTYPE html><html><body>[core] repositoryformatversion = 0</body></html>",
            )
        )
        self.assertIsNone(
            check_extended_sensitive_exposures(
                "/.git/config",
                200,
                "<script>window.__DATA__ = '[core] repositoryformatversion = 0';</script>",
            )
        )
        self.assertIsNone(check_extended_sensitive_exposures("/.git/config", 200, "[core]\nbare = false\n"))

    def test_svn_entries_positive_and_negative_cases(self):
        svn_body = "10\n\ndir\n412\nhttps://svn.internal.example.com/repo/trunk\nhttps://svn.internal.example.com/repo\n"
        res = check_extended_sensitive_exposures("/.svn/entries", 200, svn_body)
        self.assertIsNotNone(res)
        self.assertEqual(res["finding_type"], "exposed_svn")
        self.assertEqual(res["severity"], "medium")

        svn_crlf = "10\r\nsvn://svn.example.com/project\r\n"
        res_crlf = check_extended_sensitive_exposures("/.svn/entries", 200, svn_crlf)
        self.assertIsNotNone(res_crlf)
        self.assertEqual(res_crlf["finding_type"], "exposed_svn")

        # Reject HTML tags and non-SVN text
        self.assertIsNone(
            check_extended_sensitive_exposures(
                "/.svn/entries", 200, "<html><body>10\ndir\nhttps://example.com</body></html>"
            )
        )
        self.assertIsNone(
            check_extended_sensitive_exposures("/.svn/entries", 200, "10\n<div>dir</div>\nhttps://example.com")
        )
        self.assertIsNone(check_extended_sensitive_exposures("/.svn/entries", 200, "10\njust a number\n"))
        self.assertIsNone(check_extended_sensitive_exposures("/.svn/entries", 200, "dir\nhttps://example.com"))
        self.assertIsNone(check_extended_sensitive_exposures("/.svn/entries", 403, svn_body))

    def test_ds_store_requires_bud1_and_sensitive_filename(self):
        # UTF-16BE style real .DS_Store with .env and backup.sql
        utf16_env = "".join(f"\x00{ch}" for ch in ".env.production")
        utf16_sql = "".join(f"\x00{ch}" for ch in "db_backup.sql")
        ds_sensitive = f"\x00\x00\x00\x01Bud1\x00\x00\x10\x00{utf16_env}\x00\x00{utf16_sql}"
        res = check_extended_sensitive_exposures("/.DS_Store", 200, ds_sensitive)
        self.assertIsNotNone(res)
        self.assertEqual(res["finding_type"], "exposed_ds_store")
        self.assertEqual(res["severity"], "medium")

        # Benign macOS folder metadata -> MUST NOT trigger (avoids Informative)
        utf16_benign = "".join(f"\x00{ch}" for ch in "index.htmlstyles.csslogo.pngfavicon.icomonkey.jpg")
        ds_benign = f"\x00\x00\x00\x01Bud1\x00\x00\x10\x00{utf16_benign}"
        self.assertIsNone(check_extended_sensitive_exposures("/.DS_Store", 200, ds_benign))

        # HTML fallback or missing Bud1 header -> reject
        self.assertIsNone(
            check_extended_sensitive_exposures("/.DS_Store", 200, "<!doctype html><html>Bud1 .env admin</html>")
        )
        self.assertIsNone(
            check_extended_sensitive_exposures("/.DS_Store", 200, "random text .env config admin backup")
        )
        self.assertIsNone(check_extended_sensitive_exposures("/.DS_Store", 404, ds_sensitive))

    def test_server_status_positive_and_redacts_ipv4_and_ipv6(self):
        apache_html = (
            '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n'
            "<html><head><title>Apache Status</title></head><body>\n"
            "<h1>Apache Server Status for api.example.com</h1>\n"
            "<dl><dt>Server Version: Apache/2.4.57 (Unix)</dt>\n"
            "<dt>Total Accesses: 9412 - Total Traffic: 42.1 MB</dt>\n"
            "<dt>Scoreboard: __W__.._..</dt></dl>\n"
            "<table><tr><th>Srv</th><th>PID</th><th>Client</th><th>Protocol</th><th>VHost</th><th>Request</th></tr>\n"
            "<tr><td>0-0</td><td>101</td><td>203.0.113.45</td><td>http/1.1</td><td>api.example.com:443</td><td>GET /admin/users HTTP/1.1</td></tr>\n"
            "<tr><td>0-1</td><td>102</td><td>2001:db8:85a3::8a2e:370:7334</td><td>h2</td><td>api.example.com:443</td><td>POST /v1/auth HTTP/1.1</td></tr>\n"
            "</table></body></html>"
        )
        res = check_extended_sensitive_exposures("/server-status", 200, apache_html)
        self.assertIsNotNone(res)
        self.assertEqual(res["finding_type"], "exposed_server_status")
        self.assertEqual(res["severity"], "medium")
        self.assertIn("Apache Server Status for", res["snippet"])
        self.assertNotIn("203.0.113.45", res["snippet"])
        self.assertNotIn("2001:db8:85a3::8a2e:370:7334", res["snippet"])
        self.assertIn("<REDACTED", res["snippet"])
        self.assertFalse(res["snippet"].lstrip().lower().startswith(("<html", "<!doctype")))

        # Missing request table markers (Client/VHost/Request) -> reject
        incomplete_status = (
            "<html><body><h1>Apache Server Status for example.com</h1>"
            "<p>Total Accesses: 50</p><p>Scoreboard: _W_</p></body></html>"
        )
        self.assertIsNone(check_extended_sensitive_exposures("/server-status", 200, incomplete_status))

        # Generic HTML SPA -> reject
        self.assertIsNone(
            check_extended_sensitive_exposures("/server-status", 200, "<!doctype html><html><body>Not Found</body></html>")
        )
        self.assertIsNone(check_extended_sensitive_exposures("/server-status", 403, apache_html))

    def test_actuator_mappings_and_beans(self):
        mappings_json = json.dumps(
            {
                "contexts": {
                    "application": {
                        "mappings": {
                            "dispatcherServlets": {
                                "dispatcherServlet": [
                                    {"handler": "com.acme.AdminController#users()", "predicate": "{GET [/internal/users]}"}
                                ]
                            }
                        }
                    }
                }
            }
        )
        res_m = check_extended_sensitive_exposures("/actuator/mappings", 200, mappings_json)
        self.assertIsNotNone(res_m)
        self.assertEqual(res_m["finding_type"], "exposed_actuator")
        self.assertEqual(res_m["severity"], "medium")

        beans_json = json.dumps(
            {
                "contexts": {
                    "application": {
                        "beans": {
                            "secretTokenService": {
                                "aliases": [],
                                "scope": "singleton",
                                "type": "com.acme.SecretTokenService",
                            }
                        }
                    }
                }
            }
        )
        res_b = check_extended_sensitive_exposures("/actuator/beans", 200, beans_json)
        self.assertIsNotNone(res_b)
        self.assertEqual(res_b["finding_type"], "exposed_actuator")
        self.assertEqual(res_b["severity"], "medium")

        # Reject empty contexts, wrong schema, HTML fallback, non-200
        self.assertIsNone(check_extended_sensitive_exposures("/actuator/mappings", 200, '{"contexts": {}}'))
        self.assertIsNone(
            check_extended_sensitive_exposures("/actuator/mappings", 200, '{"contexts": {"application": {}}}')
        )
        self.assertIsNone(check_extended_sensitive_exposures("/actuator/beans", 200, '{"status": "UP"}'))
        self.assertIsNone(
            check_extended_sensitive_exposures(
                "/actuator/mappings", 200, '<!doctype html><html><body>{"contexts": {}}</body></html>'
            )
        )
        self.assertIsNone(check_extended_sensitive_exposures("/actuator/mappings", 401, mappings_json))


class TestCloudStorageAndFirebaseExtractor(unittest.TestCase):
    def test_extract_cloud_urls_from_text_all_providers_and_dedup(self):
        text = """
        <script>
            const cdn1 = "https://acme-assets.s3.amazonaws.com/static/app.js";
            const cdn1Dup = "https://acme-assets.s3.amazonaws.com/static/logo.png";
            const s3Regional = "https://acme-eu-backups.s3.eu-west-1.amazonaws.com/db.sql";
            const s3Path = "https://s3.amazonaws.com/acme-legacy-uploads/avatar.jpg";
            const gcs = "https://storage.googleapis.com/acme-gcs-media/video.mp4";
            const azureBase = "https://acmestorageprod.blob.core.windows.net/exports/report.csv";
            const azureList = "https://acmestorage2.blob.core.windows.net/backups?restype=container&comp=list";
            const fb = "https://acme-rtdb-prod.firebaseio.com/v1/public.json";
            const nonBucketGcsApi = "https://storage.googleapis.com/storage/v1/b/test";
        </script>
        """
        refs = extract_cloud_urls_from_text(text)
        probe_urls = {r["probe_url"] for r in refs}
        self.assertIn("https://acme-assets.s3.amazonaws.com/", probe_urls)
        self.assertIn("https://acme-eu-backups.s3.eu-west-1.amazonaws.com/", probe_urls)
        self.assertIn("https://s3.amazonaws.com/acme-legacy-uploads/", probe_urls)
        self.assertIn("https://storage.googleapis.com/acme-gcs-media/", probe_urls)
        self.assertIn("https://acmestorageprod.blob.core.windows.net/exports?restype=container&comp=list", probe_urls)
        self.assertIn("https://acmestorage2.blob.core.windows.net/backups?restype=container&comp=list", probe_urls)
        self.assertIn("https://acme-rtdb-prod.firebaseio.com/.json?shallow=true", probe_urls)
        # Deduplication: acme-assets appears twice in text, once in output
        self.assertEqual(
            sum(1 for r in refs if r["bucket_or_project"] == "acme-assets"),
            1,
        )
        # Every dict has all required keys
        for ref in refs:
            self.assertEqual(
                set(ref.keys()),
                {"provider", "bucket_or_project", "probe_url", "source_url"},
            )
        self.assertFalse(any(r["bucket_or_project"] == "storage" for r in refs))

        # Lookalike host suffixes must NOT match cloud providers
        lookalikes = (
            "https://trap.s3.amazonaws.com.evil.com/app.js "
            "https://trap.firebaseio.com.attacker.net/data.json"
        )
        self.assertEqual(extract_cloud_urls_from_text(lookalikes), [])

    def test_evaluate_dangling_referenced_buckets(self):
        s3_ref = {
            "provider": "AWS S3",
            "bucket_or_project": "dangling-acme",
            "probe_url": "https://dangling-acme.s3.amazonaws.com/",
            "source_url": "https://dangling-acme.s3.amazonaws.com/app.js",
        }
        s3_xml_404 = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<Error><Code>NoSuchBucket</Code>"
            "<Message>The specified bucket does not exist</Message>"
            "<BucketName>dangling-acme</BucketName></Error>"
        )
        res_s3 = evaluate_cloud_reference_response(s3_ref, 404, s3_xml_404)
        self.assertIsNotNone(res_s3)
        self.assertEqual(res_s3["finding_type"], "dangling_referenced_bucket")
        self.assertEqual(res_s3["severity"], "high")

        azure_ref = {
            "provider": "Azure Blob Storage",
            "bucket_or_project": "goneacct/files",
            "probe_url": "https://goneacct.blob.core.windows.net/files?restype=container&comp=list",
            "source_url": "https://goneacct.blob.core.windows.net/files/a.txt",
        }
        azure_xml_404 = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<Error><Code>AccountNotFound</Code>"
            "<Message>The specified account does not exist.</Message></Error>"
        )
        res_az = evaluate_cloud_reference_response(azure_ref, 404, azure_xml_404)
        self.assertIsNotNone(res_az)
        self.assertEqual(res_az["finding_type"], "dangling_referenced_bucket")
        self.assertEqual(res_az["severity"], "high")

        # Reject Azure ContainerNotFound (account exists, not takeoverable) and HTML 404s
        azure_container_404 = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<Error><Code>ContainerNotFound</Code>"
            "<Message>The specified container does not exist.</Message></Error>"
        )
        self.assertIsNone(evaluate_cloud_reference_response(azure_ref, 404, azure_container_404))
        self.assertIsNone(
            evaluate_cloud_reference_response(s3_ref, 404, "<!doctype html><html><body>NoSuchBucket</body></html>")
        )

    def test_evaluate_open_bucket_filters_static_web_assets(self):
        gcs_ref = {
            "provider": "Google Cloud Storage",
            "bucket_or_project": "acme-media",
            "probe_url": "https://storage.googleapis.com/acme-media/",
            "source_url": "https://storage.googleapis.com/acme-media/logo.png",
        }
        static_only_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ListBucketResult><Name>acme-media</Name>"
            "<Contents><Key>css/app.css</Key></Contents>"
            "<Contents><Key>js/bundle.js</Key></Contents>"
            "<Contents><Key>js/bundle.js.map</Key></Contents>"
            "<Contents><Key>img/logo.png</Key></Contents>"
            "<Contents><Key>blog/hero.jpg</Key></Contents>"
            "<Contents><Key>icons/menu.svg</Key></Contents>"
            "<Contents><Key>fonts/sans.woff</Key></Contents>"
            "<Contents><Key>favicon.ico</Key></Contents>"
            "</ListBucketResult>"
        )
        self.assertIsNone(evaluate_cloud_reference_response(gcs_ref, 200, static_only_xml))

        sensitive_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ListBucketResult><Name>acme-media</Name>"
            "<Contents><Key>css/app.css</Key></Contents>"
            "<Contents><Key>backups/prod_dump.sql</Key></Contents>"
            "<Contents><Key>private/customer_exports.csv</Key></Contents>"
            "</ListBucketResult>"
        )
        res = evaluate_cloud_reference_response(gcs_ref, 200, sensitive_xml)
        self.assertIsNotNone(res)
        self.assertEqual(res["finding_type"], "open_bucket")
        self.assertEqual(res["severity"], "medium")
        self.assertIn("backups/prod_dump.sql", res["sample_keys"])

        # Sensitive token inside static extension (.js) still triggers!
        sensitive_js_xml = (
            "<ListBucketResult><Name>acme-media</Name>"
            "<Contents><Key>static/admin-config.js</Key></Contents>"
            "</ListBucketResult>"
        )
        res_js = evaluate_cloud_reference_response(gcs_ref, 200, sensitive_js_xml)
        self.assertIsNotNone(res_js)
        self.assertEqual(res_js["finding_type"], "open_bucket")

    def test_evaluate_firebase_rtdb_response(self):
        fb_ref = {
            "provider": "Firebase Realtime DB",
            "bucket_or_project": "acme-rtdb-prod",
            "probe_url": "https://acme-rtdb-prod.firebaseio.com/.json?shallow=true",
            "source_url": "https://acme-rtdb-prod.firebaseio.com/",
        }
        res = evaluate_cloud_reference_response(fb_ref, 200, '{"users": true, "orders": true}')
        self.assertIsNotNone(res)
        self.assertEqual(res["finding_type"], "exposed_firebase_db")
        self.assertEqual(res["severity"], "high")
        self.assertIn("users", res["snippet"])

        # Reject empty null, empty {}, error dicts, non-200, and HTML
        self.assertIsNone(evaluate_cloud_reference_response(fb_ref, 200, "null"))
        self.assertIsNone(evaluate_cloud_reference_response(fb_ref, 200, "{}"))
        self.assertIsNone(evaluate_cloud_reference_response(fb_ref, 200, '{"error": "Permission denied"}'))
        self.assertIsNone(evaluate_cloud_reference_response(fb_ref, 401, '{"error": "Permission denied"}'))
        self.assertIsNone(evaluate_cloud_reference_response(fb_ref, 200, "<html><body>Not found</body></html>"))


class TestCredentialedCorsDetector(unittest.TestCase):
    def test_cors_positive_json_dict_and_list(self):
        origin = "https://untrusted-adversary.example"
        headers = {
            "Access-Control-Allow-Origin": origin,
            "access-control-allow-credentials": "TRUE",
            "Content-Type": "application/json; charset=utf-8",
        }
        res_dict = evaluate_cors_response(
            "https://api.example.com/v1/me", origin, 200, headers, '{"id": 42, "email": "a@example.com"}'
        )
        self.assertIsNotNone(res_dict)
        self.assertEqual(res_dict["finding_type"], "cors_credentialed_reflection")
        self.assertEqual(res_dict["severity"], "medium")

        res_list = evaluate_cors_response("https://api.example.com/v1/items", origin, 200, headers, '[{"id": 1}]')
        self.assertIsNotNone(res_list)
        self.assertEqual(res_list["finding_type"], "cors_credentialed_reflection")

    def test_cors_rejects_wildcard_html_empty_json_and_missing_creds(self):
        origin = "https://untrusted-adversary.example"
        # Wildcard *
        self.assertIsNone(
            evaluate_cors_response(
                "https://api.example.com/v1/me",
                origin,
                200,
                {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
                '{"ok": true}',
            )
        )
        # Missing Allow-Credentials: true
        self.assertIsNone(
            evaluate_cors_response(
                "https://api.example.com/v1/me",
                origin,
                200,
                {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "false"},
                '{"ok": true}',
            )
        )
        # Non-200
        self.assertIsNone(
            evaluate_cors_response(
                "https://api.example.com/v1/me",
                origin,
                401,
                {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"},
                '{"error": "unauthorized"}',
            )
        )
        # HTML/SPA page & text/html content-type
        self.assertIsNone(
            evaluate_cors_response(
                "https://app.example.com/",
                origin,
                200,
                {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                    "Content-Type": "text/html; charset=utf-8",
                },
                "<!doctype html><html><body>SPA</body></html>",
            )
        )
        self.assertIsNone(
            evaluate_cors_response(
                "https://app.example.com/",
                origin,
                200,
                {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                    "Content-Type": "text/html",
                },
                '{"ok": true}',
            )
        )
        # Empty JSON {} or []
        self.assertIsNone(
            evaluate_cors_response(
                "https://api.example.com/v1/empty",
                origin,
                200,
                {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"},
                "{}",
            )
        )
        self.assertIsNone(
            evaluate_cors_response(
                "https://api.example.com/v1/empty",
                origin,
                200,
                {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"},
                "[]",
            )
        )


class TestHighConfidenceSecretAndScriptExtractor(unittest.TestCase):
    def test_high_confidence_secrets_detected_and_redacted(self):
        dummy_stripe = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        dummy_slack_tok = "xoxb-" + "123456789012-" + "123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
        dummy_slack_hook = "https://hooks.slack.com/services/" + "T01234567/" + "B01234567/AbCdEfGhIjKlMnOpQrStUvWx"
        dummy_gh36 = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        dummy_gh_fine = "github_pat_" + "11ABCDEFG0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh"
        dummy_sg = "SG." + "abcdefghijklmnopqrstuv." + "abcdefghijklmnopqrstuvwxyz0123456789abcdefg"

        cases = [
            (
                'const cfg = { accessKeyId: "AKIA1234567890ABCDEF", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSecret123" };',
                "AKIA1234567890ABCDEF",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSecret123",
            ),
            (
                '{"aws_access_key_id": "AKIAABCDEF1234567890", "aws_secret_access_key": "JsonQuotedSecretKeyValue99"}',
                "AKIAABCDEF1234567890",
                "JsonQuotedSecretKeyValue99",
            ),
            (
                f'window.STRIPE_KEY = "{dummy_stripe}";',
                dummy_stripe,
                None,
            ),
            (
                f'const slackToken = "{dummy_slack_tok}";',
                dummy_slack_tok,
                None,
            ),
            (
                f'const hook = "{dummy_slack_hook}";',
                dummy_slack_hook,
                None,
            ),
            (
                f'const gh36 = "{dummy_gh36}";',
                dummy_gh36,
                None,
            ),
            (
                f'const ghFine = "{dummy_gh_fine}";',
                dummy_gh_fine,
                None,
            ),
            (
                f'const sg = "{dummy_sg}";',
                dummy_sg,
                None,
            ),
            (
                'const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA123456\\n-----END RSA PRIVATE KEY-----";',
                "MIIEowIBAAKCAQEA123456",
                None,
            ),
            (
                'const ecPem = "-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEEIPecKeyBody123\\n-----END EC PRIVATE KEY-----";',
                "MHcCAQEEIPecKeyBody123",
                None,
            ),
        ]
        for body, raw_secret, secondary_secret in cases:
            res = scan_text_for_high_confidence_secrets("https://app.example.com/static/app.js", 200, body)
            self.assertIsNotNone(res, f"Expected secret detection for body: {body}")
            self.assertEqual(res["finding_type"], "exposed_js_secret")
            self.assertEqual(res["severity"], "high")
            self.assertIn("<REDACTED>", res["snippet"])
            self.assertNotIn(raw_secret, res["snippet"])
            if secondary_secret:
                self.assertNotIn(secondary_secret, res["snippet"])

    def test_rejects_public_keys_uuids_and_distant_akia(self):
        # Public keys, sitekeys, UUIDs, PEM public keys -> NEVER flag
        benign_js = (
            'const stripePub = "pk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz123456";\n'
            'const stripeTest = "pk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz123456";\n'
            'const gmaps = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";\n'
            'const recaptcha = "6Lc6BQUAAAAABcDeFgHiJkLmNoPqRsTuVwXyZ12";\n'
            'const tenantUuid = "550e8400-e29b-41d4-a716-446655440000";\n'
            'const pubKey = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\\n-----END PUBLIC KEY-----";\n'
        )
        self.assertIsNone(scan_text_for_high_confidence_secrets("https://app.example.com/app.js", 200, benign_js))

        # Standalone AKIA without nearby secret assignment
        akia_alone = 'const keyId = "AKIA1234567890ABCDEF";'
        self.assertIsNone(scan_text_for_high_confidence_secrets("https://app.example.com/app.js", 200, akia_alone))

        # AKIA > 300 chars away from secretAccessKey
        akia_far = 'const keyId = "AKIA1234567890ABCDEF"; ' + ("x" * 350) + ' const secretAccessKey = "abcdef1234567890";'
        self.assertIsNone(scan_text_for_high_confidence_secrets("https://app.example.com/app.js", 200, akia_far))

        # Non-200 status rejected
        self.assertIsNone(
            scan_text_for_high_confidence_secrets(
                "https://app.example.com/app.js", 404, 'const k = "' + ("sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456") + '";'
            )
        )

    def test_extract_same_origin_script_urls(self):
        html = """
        <!doctype html>
        <html>
        <head>
            <script src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>
            <script src="//cdn.thirdparty.net/vendor.js"></script>
            <script data-src="https://evil.example/bad.js" src="/static/app.bundle.js"></script>
            <script src="assets/runtime.js#v1"></script>
            <script src="https://app.example.com/static/app.bundle.js"></script>
            <script src="https://app.example.com:8443/admin.js"></script>
            <script src="http://app.example.com/insecure.js"></script>
            <script src="https://app.example.com/static/extra.js"></script>
        </head>
        </html>
        """
        urls = extract_same_origin_script_urls("https://app.example.com/", html, limit=2)
        self.assertEqual(
            urls,
            [
                "https://app.example.com/static/app.bundle.js",
                "https://app.example.com/assets/runtime.js",
            ],
        )


if __name__ == "__main__":
    unittest.main()
