"""tests/test_hackerone_profile_audit.py: Unit tests for scripts/audit_hackerone_profile.py."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from audit_hackerone_profile import (
    evaluate_profile_completeness,
    fetch_hackerone_profile_snapshot,
    fetch_public_graphql_profile,
    load_hackerone_credentials,
    summarize_reports,
)


class _MockHTTPResponse:
    """Minimal context-manager mock for urllib.request.urlopen responses."""

    def __init__(self, payload: dict, status: int = 200):
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_MockHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestEvaluateProfileCompleteness(unittest.TestCase):
    def test_baseline_incomplete_profile_flags_missing_fields_and_casual_avatar(self):
        reporter_attrs = {
            "username": "arsoncarson",
            "name": "Carson Haynes",
            "bio": "",
            "website": None,
            "location": "",
            "profile_picture": {
                "110x110": "https://hackerone.com/rails/active_storage/blobs/redirect/abc/lakeday2022lil.jpg",
                "260x260": "https://profile-photos.hackerone-user-content.com/variants/abc/8c2777",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 20)
        self.assertEqual(result["max_score"], 100)
        self.assertTrue(result["checks"]["name"]["passed"])
        self.assertFalse(result["checks"]["bio"]["passed"])
        self.assertFalse(result["checks"]["website"]["passed"])
        self.assertFalse(result["checks"]["location"]["passed"])
        self.assertFalse(result["checks"]["profile_picture"]["passed"])
        joined_recs = " ".join(result["recommendations"]).lower()
        self.assertIn("bio", joined_recs)
        self.assertIn("website", joined_recs)
        self.assertIn("location", joined_recs)
        self.assertIn("avatar", joined_recs)

    def test_short_bio_and_non_https_website_fail_checks(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "Security guy.",
            "website": "http://example.com",
            "location": "United States",
            "profile_picture": {
                "110x110": "https://profile-photos.hackerone-user-content.com/variants/custom/orbit_x_avatar_2026.jpg",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 50)  # name (20) + location (15) + profile_picture (15)
        self.assertFalse(result["checks"]["bio"]["passed"])
        self.assertFalse(result["checks"]["website"]["passed"])
        self.assertTrue(result["checks"]["location"]["passed"])
        self.assertTrue(result["checks"]["profile_picture"]["passed"])

    def test_default_placeholder_avatar_flagged(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "Founder & Principal Systems Architect @ Orbit Security focusing on perimeter hygiene.",
            "website": "https://cmfh009.github.io/Orbit-Security/",
            "location": "United States",
            "profile_picture": {
                "110x110": "https://hackerone.com/assets/avatars/default-avatar.png",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 85)
        self.assertFalse(result["checks"]["profile_picture"]["passed"])

    def test_complete_profile_scores_100(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "Founder & Principal Systems Architect @ Orbit Security. Autonomous perimeter reconnaissance & cloud security.",
            "website": "https://cmfh009.github.io/Orbit-Security/",
            "location": "United States",
            "profile_picture": {
                "110x110": "https://hackerone.com/rails/active_storage/representations/orbit_x_avatar_2026.jpg",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 100)
        self.assertEqual(result["recommendations"], [])

    def test_graphql_intro_and_social_handles_score_100(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "",
            "intro": (
                "**Founder & Principal Systems Architect at Orbit Security.** "
                "Specializing in dangling CNAMEs, cloud storage exposure, and DMARC security."
            ),
            "website": "https://cmfh009.github.io/Orbit-Security/",
            "location": "",
            "linkedin_handle": "arsoncarson",
            "github_handle": "CmfH009",
            "twitter_handle": "_arsoncode",
            "profile_picture": {
                "82x82": "https://hackerone.com/rails/active_storage/representations/orbit_cats_radar.jpg",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 100)
        self.assertTrue(result["checks"]["bio"]["passed"])
        self.assertTrue(result["checks"]["location"]["passed"])
        self.assertEqual(result["recommendations"], [])

    def test_truncated_intro_is_flagged_and_fails_bio_check(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "",
            "intro": "**Founder & Principal Systems Architect.** " + ("x" * 830) + " Zero destructive payloads",
            "website": "https://cmfh009.github.io/Orbit-Security/",
            "location": "",
            "linkedin_handle": "arsoncarson",
            "github_handle": "CmfH009",
            "profile_picture": {
                "82x82": "https://hackerone.com/rails/active_storage/representations/orbit_cats_radar.jpg",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 70)
        self.assertFalse(result["checks"]["bio"]["passed"])
        joined_recs = " ".join(result["recommendations"])
        self.assertIn("Intro appears truncated at HackerOne's 900-character limit", joined_recs)

    def test_single_social_handle_without_location_still_fails_location_check(self):
        reporter_attrs = {
            "name": "Carson Haynes",
            "bio": "Founder & Principal Systems Architect @ Orbit Security focusing on perimeter hygiene.",
            "website": "https://cmfh009.github.io/Orbit-Security/",
            "location": "",
            "linkedin_handle": "arsoncarson",
            "profile_picture": {
                "82x82": "https://hackerone.com/rails/active_storage/representations/orbit_cats_radar.jpg",
            },
        }

        result = evaluate_profile_completeness(reporter_attrs)

        self.assertEqual(result["score"], 85)
        self.assertFalse(result["checks"]["location"]["passed"])


class TestSummarizeReports(unittest.TestCase):
    def test_summarizes_counts_by_state_and_titles(self):
        reports_data = [
            {
                "id": "4082587",
                "attributes": {
                    "title": "[Email Spoofing] Missing DMARC Enforcement",
                    "state": "editing",
                    "created_at": "2026-10-04T00:00:00Z",
                },
            },
            {
                "id": "4204024",
                "attributes": {
                    "title": "Dangling DNS CNAME on test.hulu.com",
                    "state": "new",
                    "created_at": "2026-11-01T00:00:00Z",
                },
            },
            {
                "id": "4204025",
                "attributes": {
                    "title": "Dangling DNS CNAME on shop.hukitchen.com",
                    "state": "new",
                    "created_at": "2026-11-02T00:00:00Z",
                },
            },
        ]

        summary = summarize_reports(reports_data)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_state"], {"editing": 1, "new": 2})
        self.assertEqual(len(summary["reports"]), 3)
        self.assertEqual(summary["reports"][0]["id"], "4082587")
        self.assertEqual(summary["reports"][1]["state"], "new")

    def test_empty_reports_list(self):
        summary = summarize_reports([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["by_state"], {})
        self.assertEqual(summary["reports"], [])


class TestFetchHackerOneProfileSnapshot(unittest.TestCase):
    def test_fetches_and_aggregates_snapshot_without_network(self):
        reports_payload = {
            "data": [
                {
                    "id": "4082587",
                    "attributes": {
                        "title": "[Email Spoofing] Missing DMARC",
                        "state": "editing",
                        "created_at": "2026-10-04T00:00:00Z",
                    },
                },
                {
                    "id": "4204024",
                    "attributes": {
                        "title": "Dangling Fastly CNAME",
                        "state": "new",
                        "created_at": "2026-11-01T00:00:00Z",
                    },
                },
            ]
        }
        report_detail_payload = {
            "data": {
                "id": "4082587",
                "relationships": {
                    "reporter": {
                        "data": {
                            "id": "4617898",
                            "type": "user",
                            "attributes": {
                                "username": "arsoncarson",
                                "name": "Carson Haynes",
                                "reputation": 100,
                                "bio": "",
                                "website": None,
                                "location": "",
                                "profile_picture": {
                                    "110x110": "https://hackerone.com/.../lakeday2022lil.jpg"
                                },
                                "created_at": "2026-10-03T16:22:02.424Z",
                            },
                        }
                    }
                },
            }
        }
        balance_payload = {"data": {"balance": "0.00", "currency": "USD"}}

        def fake_urlopen(request, timeout=15):
            url = request.full_url
            auth_header = request.headers.get("Authorization", "")
            self.assertTrue(auth_header.startswith("Basic "))
            if "/v1/hackers/me/reports" in url:
                return _MockHTTPResponse(reports_payload)
            if "/v1/hackers/reports/4082587" in url:
                return _MockHTTPResponse(report_detail_payload)
            if "/v1/hackers/payments/balance" in url:
                return _MockHTTPResponse(balance_payload)
            raise AssertionError(f"Unexpected URL requested: {url}")

        with (
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("audit_hackerone_profile.fetch_public_graphql_profile", return_value={}),
        ):
            snapshot = fetch_hackerone_profile_snapshot("arsoncarson", "test-token")

        self.assertEqual(snapshot["username"], "arsoncarson")
        self.assertEqual(snapshot["user_id"], "4617898")
        self.assertEqual(snapshot["profile"]["reputation"], 100)
        self.assertEqual(snapshot["completeness"]["score"], 20)
        self.assertEqual(snapshot["reports"]["total"], 2)
        self.assertEqual(snapshot["reports"]["by_state"], {"editing": 1, "new": 1})
        self.assertEqual(snapshot["balance"], {"balance": "0.00", "currency": "USD"})

    def test_snapshot_merges_non_empty_graphql_fields(self):
        reports_payload = {"data": [{"id": "4082587", "attributes": {"title": "Test", "state": "new"}}]}
        report_detail_payload = {
            "data": {
                "id": "4082587",
                "relationships": {
                    "reporter": {
                        "data": {
                            "id": "4617898",
                            "attributes": {
                                "username": "arsoncarson",
                                "name": "Carson Haynes",
                                "bio": "",
                                "website": "https://cmfh009.github.io/Orbit-Security/",
                                "location": "",
                                "profile_picture": {
                                    "82x82": "https://hackerone.com/.../orbit_cats_radar.jpg"
                                },
                            },
                        }
                    }
                },
            }
        }
        graphql_profile = {
            "intro": "**Founder & Principal Systems Architect at Orbit Security.** Focused on DNS/CNAME takeovers and cloud hygiene.",
            "linkedin_handle": "arsoncarson",
            "github_handle": "CmfH009",
            "twitter_handle": "_arsoncode",
            "bio": "",
            "location": "",
        }

        def fake_urlopen(request, timeout=15):
            if "/v1/hackers/me/reports" in request.full_url:
                return _MockHTTPResponse(reports_payload)
            if "/v1/hackers/reports/4082587" in request.full_url:
                return _MockHTTPResponse(report_detail_payload)
            if "/v1/hackers/payments/balance" in request.full_url:
                return _MockHTTPResponse({"data": {"balance": 0.0}})
            raise AssertionError(f"Unexpected URL requested: {request.full_url}")

        with (
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("audit_hackerone_profile.fetch_public_graphql_profile", return_value=graphql_profile),
        ):
            snapshot = fetch_hackerone_profile_snapshot("arsoncarson", "test-token")

        self.assertEqual(snapshot["profile"]["linkedin_handle"], "arsoncarson")
        self.assertEqual(snapshot["profile"]["github_handle"], "CmfH009")
        self.assertEqual(snapshot["completeness"]["score"], 100)


class TestFetchPublicGraphqlProfile(unittest.TestCase):
    def test_fetches_csrf_and_parses_graphql_user_fields(self):
        class _MockOpener:
            def open(self, req, timeout=15):
                url = req.full_url if hasattr(req, "full_url") else req
                if "hackerone.com/graphql" in str(url):
                    self.assert_csrf = req.headers.get("X-csrf-token") or req.headers.get("X-Csrf-Token")
                    return _MockHTTPResponse(
                        {
                            "data": {
                                "user": {
                                    "bio": "",
                                    "intro": "Orbit Security researcher profile.",
                                    "website": "https://cmfh009.github.io/Orbit-Security/",
                                    "location": "",
                                    "linkedin_handle": "arsoncarson",
                                    "github_handle": "CmfH009",
                                    "twitter_handle": "_arsoncode",
                                }
                            }
                        }
                    )

                class _HTMLResp:
                    def read(self):
                        return b'<html><head><meta name="csrf-token" content="tok123"></head></html>'

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        return False

                return _HTMLResp()

        mock_opener = _MockOpener()
        with patch("urllib.request.build_opener", return_value=mock_opener):
            result = fetch_public_graphql_profile("arsoncarson")

        self.assertEqual(mock_opener.assert_csrf, "tok123")
        self.assertEqual(result["linkedin_handle"], "arsoncarson")
        self.assertEqual(result["github_handle"], "CmfH009")
        self.assertEqual(result["twitter_handle"], "_arsoncode")

    def test_returns_empty_dict_when_graphql_unreachable(self):
        with patch("urllib.request.build_opener", side_effect=RuntimeError("network down")):
            self.assertEqual(fetch_public_graphql_profile("arsoncarson"), {})


class TestLoadCredentials(unittest.TestCase):
    def test_loads_from_env_file_when_os_environ_missing(self):
        tmp_env = PROJECT_ROOT / "tests" / ".tmp_h1_test.env"
        tmp_env.write_text(
            'HACKERONE_API_USERNAME="demo_user"\nHACKERONE_API_TOKEN=\'demo_secret\'\n',
            encoding="utf-8",
        )
        try:
            with patch.dict("os.environ", {}, clear=True):
                user, token = load_hackerone_credentials(env_path=tmp_env)
            self.assertEqual(user, "demo_user")
            self.assertEqual(token, "demo_secret")
        finally:
            if tmp_env.exists():
                tmp_env.unlink()


if __name__ == "__main__":
    unittest.main()
