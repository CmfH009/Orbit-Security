"""tests/test_submit_spotify_h1.py: Unit tests for scripts/submit_spotify_h1.py."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from submit_spotify_h1 import (
    SPOTIFY_PODSIGHTS_SCOPE_ID,
    SPOTIFY_WEAKNESS_CWE200_ID,
    build_spotify_report_payload,
    has_existing_spotify_report,
    submit_spotify_report,
    verify_live_bucket,
)


class _MockHTTPResponse:
    def __init__(self, body: bytes | str | dict, status: int = 200, headers: dict | None = None):
        if isinstance(body, dict):
            self._body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            self._body = body.encode("utf-8")
        else:
            self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_MockHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestBuildPayloadAndDuplicateGuard(unittest.TestCase):
    def test_build_spotify_report_payload_targets_podsights_scope(self):
        payload = build_spotify_report_payload()
        data = payload["data"]
        attrs = data["attributes"]

        self.assertEqual(data["type"], "report")
        self.assertEqual(attrs["team_handle"], "spotify")
        self.assertEqual(attrs["structured_scope_id"], SPOTIFY_PODSIGHTS_SCOPE_ID)
        self.assertEqual(attrs["structured_scope_id"], 95514)
        self.assertEqual(attrs["weakness_id"], SPOTIFY_WEAKNESS_CWE200_ID)
        self.assertEqual(attrs["weakness_id"], 18)
        self.assertEqual(attrs["severity_rating"], "medium")
        self.assertIn("cdn.pdst.fm", attrs["title"])
        self.assertIn("cdn.byspotify.com", attrs["title"])
        self.assertIn("spaa-cdn", attrs["title"])
        self.assertIn("cdn.pdst.fm", attrs["vulnerability_information"])
        self.assertIn("cdn.byspotify.com", attrs["vulnerability_information"])
        self.assertIn("spaa-cdn", attrs["impact"])

    def test_has_existing_spotify_report_detects_matching_titles(self):
        reports = [
            {"id": "4204024", "attributes": {"title": "Dangling DNS CNAME on test.hulu.com"}},
            {"id": "4204025", "attributes": {"title": "Dangling DNS CNAME on shop.hukitchen.com"}},
        ]
        self.assertEqual(has_existing_spotify_report(reports), (False, None))

        reports_with_dup = reports + [
            {"id": "9900112", "attributes": {"title": "Open Bucket spaa-cdn on CDN.PDST.FM"}}
        ]
        self.assertEqual(has_existing_spotify_report(reports_with_dup), (True, "9900112"))


class TestVerifyLiveBucket(unittest.TestCase):
    def test_verify_live_bucket_confirms_xml_and_pdf_head(self):
        def fake_urlopen(req, timeout=15):
            if req.get_method() == "HEAD":
                return _MockHTTPResponse(
                    b"",
                    status=200,
                    headers={"Content-Length": "2153328", "Content-Type": "application/pdf"},
                )
            return _MockHTTPResponse(
                "<ListBucketResult><Name>spaa-cdn</Name></ListBucketResult>",
                status=200,
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = verify_live_bucket()

        self.assertTrue(res["ok"])
        self.assertEqual(len(res["endpoints"]), 2)
        self.assertEqual(len(res["pdf_heads"]), 2)
        self.assertTrue(all(ep["bucket_name"] == "spaa-cdn" for ep in res["endpoints"]))

    def test_verify_live_bucket_handles_errors_gracefully(self):
        with patch("urllib.request.urlopen", side_effect=RuntimeError("timeout")):
            res = verify_live_bucket()
        self.assertFalse(res["ok"])


class TestSubmitSpotifyReport(unittest.TestCase):
    def test_dry_run_skips_post_and_returns_ready(self):
        calls = []

        def fake_urlopen(req, timeout=20):
            calls.append((req.get_method(), req.full_url))
            return _MockHTTPResponse(
                {"data": [{"id": "4204024", "attributes": {"title": "Hulu CNAME"}}]}
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = submit_spotify_report("arsoncarson", "tok", dry_run=True)

        self.assertEqual(res["status"], "DRY_RUN_READY")
        self.assertFalse(res["duplicate_found"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "GET")

    def test_duplicate_aborts_without_post(self):
        calls = []

        def fake_urlopen(req, timeout=20):
            calls.append(req.get_method())
            return _MockHTTPResponse(
                {"data": [{"id": "8888", "attributes": {"title": "Open bucket on cdn.byspotify.com"}}]}
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = submit_spotify_report("arsoncarson", "tok", dry_run=False)

        self.assertEqual(res["status"], "DUPLICATE_ABORTED")
        self.assertTrue(res["duplicate_found"])
        self.assertEqual(res["existing_report_id"], "8888")
        self.assertEqual(calls, ["GET"])

    def test_live_handles_kyc_id_verification_400(self):
        err_body = json.dumps(
            {
                "errors": [
                    {
                        "status": 400,
                        "title": "Invalid Parameter",
                        "detail": "The parameter 'Id_verification' Identity verification is required before you can submit to this program.",
                        "source": {"parameter": "Id_verification"},
                    }
                ]
            }
        ).encode("utf-8")

        def fake_urlopen(req, timeout=20):
            if req.get_method() == "GET":
                return _MockHTTPResponse({"data": []})
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                hdrs={},
                fp=io.BytesIO(err_body),
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = submit_spotify_report("arsoncarson", "tok", dry_run=False)

        self.assertEqual(res["status"], "BLOCKED_KYC_ID_VERIFICATION")
        self.assertEqual(res["http_status"], 400)
        self.assertIn("Id_verification", res["error_detail"])

    def test_live_handles_201_created(self):
        def fake_urlopen(req, timeout=20):
            if req.get_method() == "GET":
                return _MockHTTPResponse({"data": []})
            return _MockHTTPResponse(
                {
                    "data": {
                        "id": "5555555",
                        "type": "report",
                        "attributes": {
                            "state": "new",
                            "created_at": "2026-11-16T15:00:00Z",
                        },
                    }
                },
                status=201,
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = submit_spotify_report("arsoncarson", "tok", dry_run=False)

        self.assertEqual(res["status"], "SUBMITTED")
        self.assertEqual(res["http_status"], 201)
        self.assertEqual(res["report_id"], "5555555")
        self.assertEqual(res["report_url"], "https://hackerone.com/reports/5555555")


if __name__ == "__main__":
    unittest.main()
