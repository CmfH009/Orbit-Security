"""Adversarial Regression Test Suite for HackerOne VDP & OSINT Subsystems.

Validates the implementation and security invariants of:
- Sherlock OSINT runner (src/orbit_security/sherlock_osint.py)
- VDP high-signal detectors (src/orbit_security/vdp_high_signal_detectors.py)
- VDP recon sources and safe-host guards (src/orbit_security/vdp_recon_sources.py)
- HackerOne VDP hunter SSRF and redirect guards (src/orbit_security/hackerone_vdp_hunter.py)
- Bounty vault compiler & secret-scrubbing CORS replay (scripts/bounty_vault_generator.py)
- Blackboard event pruning and bounded retention (src/orbit_security/blackboard.py)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any, Dict
import unittest
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from src.orbit_security.sherlock_osint import (
    HANDLE_RE,
    SITE_RE,
    SherlockMatch,
    SherlockSweepResult,
    _parse_sherlock_json,
    _validate_handles,
    _validate_sites,
    run_sherlock_osint,
)
from src.orbit_security.vdp_high_signal_detectors import (
    check_extended_sensitive_exposures,
    evaluate_cors_response,
    extract_cloud_urls_from_text,
    scan_text_for_high_confidence_secrets,
)
from src.orbit_security.vdp_recon_sources import (
    extract_explicit_scope_hosts,
    is_safe_host,
    load_non_empty_ct_cache,
    purge_empty_ct_cache_entries,
    save_non_empty_ct_cache,
)
from src.orbit_security.blackboard import Blackboard, publish_event
from scripts.bounty_vault_generator import (
    build_vault_manifest,
    classify_finding_tier,
    verify_live_targets,
)
from src.orbit_security.hackerone_vdp_hunter import (
    _SafeVdpRedirectHandler,
    fetch_http_sample,
)


class TestSherlockOsintAdversarial(unittest.TestCase):
    """Adversarial input validation and execution tests for Sherlock OSINT."""

    def test_handle_validation_accepts_clean_handles_and_strips_at(self):
        handles = _validate_handles(["@arsoncarson", "chaynes009", "  @dev_test-1.0  ", "chaynes009"])
        assert handles == ["arsoncarson", "chaynes009", "dev_test-1.0"]

    def test_handle_validation_rejects_malicious_and_invalid_handles(self):
        invalid_cases = [
            "user; rm -rf /",
            "user`whoami`",
            "user$(id)",
            "-leadinghyphen",
            "has space",
            "a" * 65,  # Exceeds 64 chars
            "",
            "   ",
        ]
        for bad in invalid_cases:
            with pytest.raises(ValueError):
                _validate_handles([bad])

    def test_site_filter_validation(self):
        valid = _validate_sites(["Twitter", "GitHub", "Keybase", "HackerOne"])
        assert valid == ["Twitter", "GitHub", "Keybase", "HackerOne"]

        # Sites with invalid characters like semicolons, pipes, or shell metachars
        invalid = ["site; dangerous", "site|inject", "site$var", "site`whoami`"]
        for bad in invalid:
            with pytest.raises(ValueError):
                _validate_sites([bad])

    def test_site_filter_rejects_leading_hyphens_and_flag_injection(self):
        invalid_flags = [
            "--output",
            "-o",
            "--site",
            "-v",
            " -flag",
            "--json",
        ]
        for bad in invalid_flags:
            with pytest.raises(ValueError, match="Invalid site filter"):
                _validate_sites([bad])

    def test_parse_sherlock_json_ignores_non_claimed_or_missing_status(self):
        sample = {
            "ValidSite": {"status": "Claimed", "url_user": "https://valid.org/user"},
            "UnclaimedSite": {"status": "Available", "url_user": "https://unclaimed.org/user"},
            "IllegalSite": {"status": "Illegal", "url_user": "https://illegal.org/user"},
            "EmptyStatus": {"status": "", "url_user": "https://empty.org/user"},
            "MissingStatus": {"url_user": "https://missing.org/user"},
        }
        matches = _parse_sherlock_json("testuser", sample)
        assert len(matches) == 1
        assert matches[0].site == "ValidSite"
        assert matches[0].status == "Claimed"

    def test_parse_sherlock_json_handles_varied_and_malformed_structures(self):
        sample = {
            "GitHub": {
                "status": "Claimed",
                "url_user": "https://github.com/arsoncode",
                "url_main": "https://github.com",
                "http_status": 200,
            },
            "Keybase": {
                "status": {"status": "Claimed"},
                "url_user": "https://keybase.io/arsoncode",
                "http_status": "200",
            },
            "UnclaimedSite": {
                "status": "Available",
                "url_user": "https://example.com/unclaimed",
            },
            "BrokenSite": "not a dict",
            "EmptyUrl": {
                "status": "Claimed",
                "url_user": "",
            },
            "BadStatus": {
                "status": "Claimed",
                "url_user": "https://example.com/user",
                "http_status": "not_an_int",
            },
        }
        matches = _parse_sherlock_json("arsoncode", sample)
        assert len(matches) == 3
        by_site = {m.site: m for m in matches}

        assert by_site["GitHub"].http_status == 200
        assert by_site["GitHub"].url_user == "https://github.com/arsoncode"
        assert by_site["Keybase"].http_status == 200
        assert by_site["BadStatus"].http_status is None

    def test_run_sherlock_osint_executable_missing_returns_graceful_error(self):
        # When an invalid executable is specified, it catches FileNotFoundError gracefully
        res = run_sherlock_osint(["arsoncode"], executable="C:/nonexistent/sherlock.exe")
        assert len(res.errors) >= 1
        assert "cannot find the file" in res.errors[0].lower() or "failed" in res.errors[0].lower()
        assert res.findings == []


class TestVdpHighSignalDetectorsAdversarial(unittest.TestCase):
    """Adversarial test cases for high-signal non-destructive VDP detectors."""

    def test_git_config_rejection_of_html_spa_false_positives(self):
        spa_responses = [
            "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>Page not found</body></html>",
            "<html lang='en'><body><div id='root'></div><script src='/app.js'></script></body></html>",
            "   <!doctype html> <p>Catch-all router fallback</p>",
        ]
        for html_body in spa_responses:
            res = check_extended_sensitive_exposures("/.git/config", status=200, body=html_body)
            assert res is None, f"Expected HTML SPA body to be rejected, but got: {res}"

    def test_git_config_acceptance_of_genuine_git_config(self):
        real_git = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "[remote \"origin\"]\n"
            "\turl = git@github.com:example/repo.git\n"
        )
        res = check_extended_sensitive_exposures("/.git/config", status=200, body=real_git)
        assert res is not None
        assert res["finding_type"] == "exposed_git"
        assert res["severity"] == "medium"
        assert "repositoryformatversion" in res["snippet"]

    def test_svn_entries_detector_rejects_html_and_accepts_valid_entries(self):
        # Fake HTML containing 'dir'
        fake_html = "<html><body>Directory listing for svn</body></html>"
        assert check_extended_sensitive_exposures("/.svn/entries", status=200, body=fake_html) is None

        # Real SVN format 10
        real_svn = "10\ndir\n12345\nhttps://svn.example.com/svn/trunk\nhttps://svn.example.com/svn\n"
        res = check_extended_sensitive_exposures("/.svn/entries", status=200, body=real_svn)
        assert res is not None
        assert res["finding_type"] == "exposed_svn"
        assert "svn.example.com" in res["snippet"]

    def test_ds_store_detector_requires_sensitive_patterns_in_binary(self):
        # Benign DS_Store with no sensitive filenames
        benign_ds = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00Pictures\x00\x00Desktop"
        benign_str = benign_ds.decode("latin-1")
        assert check_extended_sensitive_exposures("/.DS_Store", status=200, body=benign_str) is None

        # Sensitive DS_Store containing .env and secret
        sensitive_ds = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00.env.production\x00\x00secret_backup.sql"
        sensitive_str = sensitive_ds.decode("latin-1")
        res = check_extended_sensitive_exposures("/.DS_Store", status=200, body=sensitive_str)
        assert res is not None
        assert res["finding_type"] == "exposed_ds_store"
        assert ".env" in res["snippet"] or "secret" in res["snippet"]

    def test_spring_boot_actuator_detection(self):
        actuator_json = json.dumps({
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": [{"handler": "org.example.Controller"}]}}
                }
            }
        })
        res = check_extended_sensitive_exposures("/actuator/mappings", status=200, body=actuator_json)
        assert res is not None
        assert res["finding_type"] == "exposed_actuator"

        # HTML fallback on actuator path is rejected
        html_actuator = "<html><body>Custom 404</body></html>"
        assert check_extended_sensitive_exposures("/actuator/mappings", status=200, body=html_actuator) is None

    def test_cors_evaluation_rejects_wildcard_and_accepts_reflected_origin_on_json(self):
        # 1. Spec violation: ACAO * with ACAC true is blocked by browsers and rejected by detector
        headers_wildcard = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        res_wildcard = evaluate_cors_response(
            url="https://api.example.com/me",
            tested_origin="https://evil.com",
            status=200,
            headers=headers_wildcard,
            body="{\"user_id\": 123}",
        )
        assert res_wildcard is None

        # 2. Dangerous: Origin reflected with ACAC true on sensitive JSON
        headers_reflected = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
            "Content-Type": "application/json",
        }
        body_sensitive = json.dumps({"account_id": 99, "email": "carson@example.com", "csrf_token": "abc123xyz"})
        res_reflected = evaluate_cors_response(
            url="https://api.example.com/user/profile",
            tested_origin="https://evil.com",
            status=200,
            headers=headers_reflected,
            body=body_sensitive,
        )
        assert res_reflected is not None
        assert res_reflected["finding_type"] == "cors_credentialed_reflection"
        assert res_reflected["severity"] == "medium"
        assert "evil.com" in res_reflected["snippet"]

    def test_extract_cloud_urls_from_text_scrubs_basic_auth(self):
        text = (
            "Bucket URL: https://admin:supersecret@mycompany-backups.s3.amazonaws.com/data/dump.sql\n"
            "Google storage: https://storage.googleapis.com/prod-reports/q3_financials.csv\n"
        )
        urls = extract_cloud_urls_from_text(text)
        assert len(urls) >= 1
        for u in urls:
            source_url = u["source_url"]
            assert "supersecret" not in source_url


class TestVdpReconSourcesAdversarial(unittest.TestCase):
    """Adversarial validation of safe-host policy and recon source caching."""

    def test_is_safe_host_blocks_direct_ips_and_internal_names(self):
        prohibited = [
            "localhost",
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.16.5.10",
            "192.168.1.1",
            "169.254.169.254",  # AWS IMDS
            "0.0.0.0",
            "metadata.google.internal",
            "internal.local",
        ]
        for host in prohibited:
            assert is_safe_host(host) is False, f"Expected {host!r} to be blocked by is_safe_host"

    def test_extract_explicit_scope_hosts_cleans_wildcards_and_rejects_ineligible(self):
        scopes = [
            {"asset_identifier": "api.github.com", "asset_type": "URL", "eligible_for_submission": True},
            {"asset_identifier": "192.168.1.1", "asset_type": "IP_ADDRESS", "eligible_for_submission": True},
            {"asset_identifier": "out-of-scope.example.com", "asset_type": "URL", "eligible_for_submission": False},
        ]
        hosts = extract_explicit_scope_hosts(scopes)
        assert "192.168.1.1" not in hosts
        assert "out-of-scope.example.com" not in hosts

    def test_ct_cache_persistence_handles_corrupt_files_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            cache_file = Path(td) / "ct_cache.json"

            # 1. Nonexistent file returns None
            assert load_non_empty_ct_cache(cache_file, "example.com") is None

            # 2. Corrupt / invalid JSON returns None without throwing
            cache_file.write_text("{corrupt: json!]", encoding="utf-8")
            assert load_non_empty_ct_cache(cache_file, "example.com") is None

            # 3. Clean save and load
            data = ["api.example.com", "cdn.example.com"]
            saved = save_non_empty_ct_cache(cache_file, "example.com", data)
            assert saved is True
            loaded = load_non_empty_ct_cache(cache_file, "example.com")
            assert loaded == ["api.example.com", "cdn.example.com"]

            # 4. Empty subdomains return False and do not overwrite
            assert save_non_empty_ct_cache(cache_file, "empty.org", []) is False

    def test_save_non_empty_ct_cache_multithreaded_concurrency(self):
        with tempfile.TemporaryDirectory() as td:
            cache_file = Path(td) / "concurrent_ct_cache.json"

            def worker(root_idx: int) -> bool:
                root = f"program{root_idx}.example.com"
                subs = [f"sub1.{root}", f"sub2.{root}"]
                return save_non_empty_ct_cache(cache_file, root, subs)

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(worker, range(10)))

            assert all(results)
            assert cache_file.exists()
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            assert len(data) == 10
            for i in range(10):
                root = f"program{i}.example.com"
                assert root in data
                assert len(data[root]["subdomains"]) == 2


class TestBountyVaultGeneratorAdversarial(unittest.TestCase):
    """Adversarial tests for vault compilation and credential-scrubbing."""

    def test_classified_tiers_match_security_contracts(self):
        tier1_finding = {
            "verdict": "OPEN_BUCKET_LISTING",
            "program": "Spotify",
            "code": 200,
            "score": 6,
        }
        assert classify_finding_tier(tier1_finding) == "TIER_1_READY"

        tier2_finding = {
            "verdict": "REFLECTED_PUBLIC_HTML",
            "program": "MercadoLibre",
            "code": 200,
            "score": 5,
        }
        assert classify_finding_tier(tier2_finding) == "TIER_2_NEEDS_AUTH_PROOF"

        tier3_finding = {
            "verdict": "BENIGN_FALSE_POSITIVE",
            "program": "Unknown",
            "code": 404,
            "score": 0,
        }
        assert classify_finding_tier(tier3_finding) == "TIER_3_SUPPRESSED"

    def test_build_vault_manifest_handles_slug_collisions_without_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "vault"
            matrix_path = Path(td) / "matrix.json"
            entries = [
                {
                    "program": "PayPal Corp",
                    "program_id": "pp_corp_1",
                    "verdict": "OPEN_BUCKET_LISTING",
                    "score": 6,
                    "code": 200,
                    "host": "cdn1.paypal.com",
                    "url": "https://cdn1.paypal.com/",
                },
                {
                    "program": "PayPal-Corp",
                    "program_id": "pp_corp_2",
                    "verdict": "OPEN_BUCKET_LISTING",
                    "score": 6,
                    "code": 200,
                    "host": "cdn2.paypal.com",
                    "url": "https://cdn2.paypal.com/",
                },
            ]
            matrix_path.write_text(json.dumps(entries), encoding="utf-8")
            manifest = build_vault_manifest(matrix_path=matrix_path, output_dir=out_dir, dry_run=False)
            consolidated = out_dir / "consolidated_dossiers"
            assert (consolidated / "paypal_corp_open_bucket_listing.md").exists()
            assert (consolidated / "paypal_corp_open_bucket_listing_pp_corp_2.md").exists()
            assert "cdn1.paypal.com" in (consolidated / "paypal_corp_open_bucket_listing.md").read_text(encoding="utf-8")
            assert "cdn2.paypal.com" in (consolidated / "paypal_corp_open_bucket_listing_pp_corp_2.md").read_text(encoding="utf-8")


class TestBlackboardRetentionAdversarial(unittest.TestCase):
    """Adversarial retention tests for SQLite WAL blackboard event pruning."""

    def test_bounded_retention_pruning_drops_expired_and_exceeded_rows(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test_blackboard.db"
            bb = Blackboard(db_path=db_path)

            now = time.time()
            day_sec = 86400.0

            # Insert 10 events: 5 telemetry (3 expired, 2 fresh) and 5 alerts (2 expired, 3 fresh)
            with bb._connection() as conn:
                cur = conn.cursor()
                for i in range(10):
                    topic = "telemetry" if i < 5 else "alerts"
                    # Make older events 5 days ago, newer events 1 hour ago
                    age = (5.0 * day_sec) if (i % 5 < 3) else 3600.0
                    event_time = now - age
                    cur.execute(
                        "INSERT INTO blackboard_events (topic, event_type, source, payload, created_at, processed) "
                        "VALUES (?, ?, ?, ?, ?, 0);",
                        (topic, "TEST_EVENT", "test_suite", json.dumps({"idx": i}), event_time),
                    )
                conn.commit()

            # Verify initial count
            with bb._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM blackboard_events;")
                assert cur.fetchone()[0] == 10

            # Prune with telemetry_max_age_days = 3.0 and general max_age_days = 4.0
            # Expired telemetry (>3 days): 3 rows
            # Expired general (>4 days): 2 rows
            stats = bb.prune_stale_events(
                max_age_days=4.0,
                max_rows=100,
                telemetry_max_age_days=3.0,
                telemetry_max_rows=100,
            )
            assert stats["telemetry_ttl_deleted"] == 3
            assert stats["ttl_deleted"] == 3
            assert stats["remaining"] == 4

            # Verify remaining events are strictly the fresh ones
            with bb._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM blackboard_events;")
                assert cur.fetchone()[0] == 4

    def test_publish_event_isolated_under_pytest(self):
        # Under pytest, publish_event should return a valid synthetic/blackboard ID without writing to prod orbit_events.db
        ev_id = publish_event(
            event_type="TEST_PYTEST_ISOLATION",
            payload={"test": "isolation_verification"},
            source="pytest_runner",
            topic="test",
        )
        assert isinstance(ev_id, int)
        assert ev_id > 0


class TestHackerOneVdpHunterSsrfGuards(unittest.TestCase):
    """Adversarial SSRF and redirect validation for HackerOne VDP hunter."""

    def test_fetch_http_sample_blocks_userinfo_hostname_ssrf(self):
        malicious_urls = [
            "http://admin:secret@127.0.0.1:8080/internal",
            "http://user:pass@localhost:3000/",
            "http://root:pass@169.254.169.254/latest/meta-data/",
            "http://test:pw@10.0.0.1/admin",
            "http://admin@192.168.1.1:80/",
        ]
        for url in malicious_urls:
            status, headers, body = fetch_http_sample(url)
            assert status == 0, f"Expected 0 for blocked SSRF URL {url}, got {status}"
            assert headers == {}
            assert body == ""

    def test_safe_vdp_redirect_handler_blocks_private_and_metadata_targets(self):
        handler = _SafeVdpRedirectHandler()
        mock_req = urllib.request.Request("https://example.com/start")

        blocked_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:8000/private",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.200.1.1:8443/internal",
            "http://user:pass@127.0.0.1/secret",
        ]
        for target in blocked_targets:
            res = handler.redirect_request(mock_req, None, 302, "Found", {}, target)
            assert res is None, f"Expected redirect to {target!r} to be blocked (None), got {res!r}"

        # Legitimate public HTTPS redirect should be allowed
        valid_res = handler.redirect_request(mock_req, None, 302, "Found", {}, "https://api.github.com/v1")
        assert valid_res is not None
        assert isinstance(valid_res, urllib.request.Request)


if __name__ == "__main__":
    unittest.main()
