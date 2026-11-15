"""tests/test_vdp_recon_sources.py: Unit tests for orbit_security.vdp_recon_sources."""

from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error

from orbit_security.vdp_recon_sources import (
    discover_multi_source_subdomains,
    extract_explicit_scope_hosts,
    is_program_signal_eligible,
    load_non_empty_ct_cache,
    purge_empty_ct_cache_entries,
    save_non_empty_ct_cache,
)


class _MockResponse:
    def __init__(self, body: str | dict | list, status: int = 200):
        if isinstance(body, (dict, list)):
            self._raw = json.dumps(body).encode("utf-8")
        else:
            self._raw = body.encode("utf-8")
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self._raw if n < 0 else self._raw[:n]

    def __enter__(self) -> "_MockResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestNonEmptyCtCache(unittest.TestCase):
    def test_save_skips_empty_subdomains_without_creating_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "nested" / "vdp_ct_cache.json"
            self.assertFalse(save_non_empty_ct_cache(cache_path, "acme.example", []))
            self.assertFalse(save_non_empty_ct_cache(cache_path, "acme.example", ["", "   "]))
            self.assertFalse(cache_path.exists())

    def test_save_and_load_non_empty_cache_roundtrip_and_atomic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "vdp_ct_cache.json"
            written = save_non_empty_ct_cache(
                cache_path,
                "Acme.Example.",
                ["api.acme.example", "dev.acme.example", "api.acme.example"],
            )
            self.assertTrue(written)
            self.assertTrue(cache_path.exists())
            self.assertEqual([p for p in Path(tmpdir).iterdir() if p.name != "vdp_ct_cache.json"], [])

            loaded = load_non_empty_ct_cache(cache_path, "acme.example")
            self.assertEqual(loaded, ["api.acme.example", "dev.acme.example"])

            # Empty save must not overwrite existing valid entry
            self.assertFalse(save_non_empty_ct_cache(cache_path, "acme.example", []))
            self.assertEqual(
                load_non_empty_ct_cache(cache_path, "acme.example"),
                ["api.acme.example", "dev.acme.example"],
            )

    def test_load_rejects_empty_expired_or_invalid_cache_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "vdp_ct_cache.json"
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "missing.example"))

            now = time.time()
            cache_path.write_text(
                json.dumps(
                    {
                        "empty.example": {"timestamp": now, "subdomains": []},
                        "blank.example": {"timestamp": now, "subdomains": ["", "   "]},
                        "badtype.example": {"timestamp": now, "subdomains": "not-a-list"},
                        "expired.example": {"timestamp": now - 90000.0, "subdomains": ["a.expired.example"]},
                        "missingts.example": {"subdomains": ["a.missingts.example"]},
                        "badts.example": {"timestamp": "not-a-float", "subdomains": ["a.badts.example"]},
                        "nondict.example": ["invalid"],
                    }
                ),
                encoding="utf-8",
            )
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "empty.example"))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "blank.example"))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "badtype.example"))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "expired.example", ttl_seconds=86400.0))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "missingts.example", ttl_seconds=1e12))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "badts.example"))
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "nondict.example"))

            cache_path.write_text("{broken json", encoding="utf-8")
            self.assertIsNone(load_non_empty_ct_cache(cache_path, "empty.example"))

    def test_purge_empty_ct_cache_entries_cleans_and_preserves_valid_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "vdp_ct_cache.json"
            self.assertEqual(purge_empty_ct_cache_entries(cache_path), [])

            now = time.time()
            cache_path.write_text(
                json.dumps(
                    {
                        "zebra.example": {"timestamp": now, "subdomains": []},
                        "alpha.example": {"timestamp": now, "subdomains": ["", " "]},
                        "valid.example": {"timestamp": now, "subdomains": ["app.valid.example"]},
                        "corrupt.example": {"timestamp": now, "subdomains": None},
                        "broken_obj.example": "unexpected",
                    }
                ),
                encoding="utf-8",
            )

            purged = purge_empty_ct_cache_entries(cache_path)
            self.assertEqual(
                purged,
                ["alpha.example", "broken_obj.example", "corrupt.example", "zebra.example"],
            )
            remaining = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(list(remaining.keys()), ["valid.example"])
            self.assertEqual(remaining["valid.example"]["subdomains"], ["app.valid.example"])
            self.assertEqual(purge_empty_ct_cache_entries(cache_path), [])


class TestDiscoverMultiSourceSubdomains(unittest.TestCase):
    def test_merges_all_six_primary_sources_and_normalizes_strictly(self):
        seen_urls = []
        seen_lock = threading.Lock()

        def _fake_urlopen(req, timeout=10):
            url = req.full_url
            with seen_lock:
                seen_urls.append(url)
            if "certspotter.com" in url:
                return _MockResponse(
                    [
                        {
                            "dns_names": [
                                "*.acme.example",
                                "  API.Acme.Example. ",
                                "*.staging.acme.example",
                                "other.domain.com",
                                "bad host.acme.example",
                                "port.acme.example:8443",
                            ]
                        }
                    ]
                )
            if "anubisdb.com" in url:
                return _MockResponse(
                    [
                        "shop.acme.example",
                        "evilacme.example",
                        "*.*.bad.acme.example",
                    ]
                )
            if "otx.alienvault.com" in url:
                return _MockResponse(
                    {
                        "passive_dns": [
                            {"hostname": "otx-portal.acme.example"},
                            {"hostname": "bad_char.acme.example"},
                            {"hostname": "acme.example"},
                        ]
                    }
                )
            if "web.archive.org/cdx" in url:
                return _MockResponse(
                    [
                        ["original"],
                        ["https://legacy.acme.example:8443/login?next=1"],
                        ["http://not-ours.org/acme.example"],
                    ]
                )
            if "api.hackertarget.com" in url:
                return _MockResponse("ht.acme.example,1.2.3.4\n-invalid.acme.example,1.2.3.4\n")
            if "rapiddns.io" in url:
                return _MockResponse(
                    "<table><tr><td>Rapid1.Acme.Example</td><td>bad..acme.example</td></tr></table>"
                )
            if "crt.sh" in url:
                raise AssertionError("crt.sh should not be queried when primary sources return >= 5 hosts and use_crtsh=False")
            return _MockResponse("", status=404)

        subs = discover_multi_source_subdomains(
            "Acme.Example.",
            use_crtsh=False,
            use_subfinder=False,
            urlopen_fn=_fake_urlopen,
        )
        self.assertEqual(
            subs,
            {
                "api.acme.example",
                "staging.acme.example",
                "shop.acme.example",
                "otx-portal.acme.example",
                "legacy.acme.example",
                "ht.acme.example",
                "rapid1.acme.example",
            },
        )
        self.assertFalse(any("crt.sh" in u for u in seen_urls))

    def test_triggers_crtsh_when_primary_under_five_or_explicit_and_isolates_errors(self):
        seen_urls = []
        seen_lock = threading.Lock()

        def _fake_urlopen(req, timeout=10):
            url = req.full_url
            with seen_lock:
                seen_urls.append(url)
            if "certspotter.com" in url:
                raise urllib.error.HTTPError(url, 429, "Too Many Requests", None, io.BytesIO(b"rate limit"))
            if "anubisdb.com" in url:
                return _MockResponse(["one.acme.example"])
            if "otx.alienvault.com" in url:
                raise TimeoutError("timed out")
            if "web.archive.org" in url:
                return _MockResponse("<html>502 Bad Gateway</html>")
            if "api.hackertarget.com" in url:
                return _MockResponse("API count exceeded - Increase Quota with Membership")
            if "rapiddns.io" in url:
                return _MockResponse("", status=503)
            if "crt.sh" in url:
                return _MockResponse(
                    [
                        {
                            "common_name": "*.crt.acme.example",
                            "name_value": "crt.acme.example\nbad space.acme.example\ntwo.acme.example",
                        }
                    ]
                )
            return _MockResponse("", status=404)

        subs = discover_multi_source_subdomains(
            "acme.example",
            use_crtsh=False,
            use_subfinder=False,
            urlopen_fn=_fake_urlopen,
        )
        self.assertEqual(subs, {"one.acme.example", "crt.acme.example", "two.acme.example"})
        self.assertTrue(any("crt.sh/?q=%25.acme.example&output=json" in u for u in seen_urls))

    @patch("orbit_security.vdp_recon_sources.shutil.which")
    @patch("urllib.request.urlopen")
    def test_defaults_to_urllib_request_urlopen_when_patched(self, mock_urlopen, mock_which):
        def _side_effect(req, timeout=10):
            url = req.full_url
            if "certspotter" in url:
                return _MockResponse([{"dns_names": ["try.acme.example"]}])
            if "anubisdb" in url:
                return _MockResponse(["shop.acme.example"])
            return _MockResponse("", status=404)

        mock_urlopen.side_effect = _side_effect
        subs = discover_multi_source_subdomains("acme.example")
        self.assertEqual(subs, {"try.acme.example", "shop.acme.example"})
        mock_which.assert_not_called()

    def test_explicit_use_crtsh_queries_crtsh_even_above_threshold(self):
        seen_urls = []
        seen_lock = threading.Lock()

        def _fake_urlopen(req, timeout=10):
            url = req.full_url
            with seen_lock:
                seen_urls.append(url)
            if "anubisdb.com" in url:
                return _MockResponse([f"s{i}.acme.example" for i in range(6)])
            if "crt.sh" in url:
                return _MockResponse([{"common_name": "extra-crt.acme.example", "name_value": ""}])
            return _MockResponse("", status=404)

        subs = discover_multi_source_subdomains(
            "acme.example",
            use_crtsh=True,
            use_subfinder=False,
            urlopen_fn=_fake_urlopen,
        )
        self.assertIn("extra-crt.acme.example", subs)
        self.assertTrue(any("crt.sh" in u for u in seen_urls))

    @patch("orbit_security.vdp_recon_sources.subprocess.run")
    @patch("orbit_security.vdp_recon_sources.shutil.which", return_value="/usr/local/bin/subfinder")
    def test_optional_subfinder_merges_and_handles_timeout(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["subfinder"],
            returncode=0,
            stdout="sf1.acme.example\n*.sf2.acme.example\nunrelated.com\nacme.example\n",
            stderr="",
        )
        subs = discover_multi_source_subdomains(
            "acme.example",
            use_subfinder=True,
            timeout=10,
            urlopen_fn=lambda req, timeout=10: _MockResponse("", status=404),
        )
        self.assertEqual(subs, {"sf1.acme.example", "sf2.acme.example"})
        mock_which.assert_called_once_with("subfinder")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["/usr/local/bin/subfinder", "-d", "acme.example", "-silent", "-timeout", "10"])

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["subfinder"],
            timeout=15,
            output="partial.acme.example\nbad host.acme.example\n",
        )
        subs_timeout = discover_multi_source_subdomains(
            "acme.example",
            use_subfinder=True,
            timeout=10,
            urlopen_fn=lambda req, timeout=10: _MockResponse("", status=404),
        )
        self.assertEqual(subs_timeout, {"partial.acme.example"})

    @patch("orbit_security.vdp_recon_sources.subprocess.run")
    @patch("orbit_security.vdp_recon_sources.shutil.which", return_value="/usr/local/bin/subfinder")
    def test_primary_sources_run_concurrently_and_skip_subfinder_when_at_least_five(self, mock_which, mock_run):
        barrier = threading.Barrier(6, timeout=2.0)

        def _concurrent_urlopen(req, timeout=10):
            url = req.full_url
            if "crt.sh" in url:
                raise AssertionError("crt.sh should not be called when primary sources return >= 5 hosts")
            barrier.wait()
            if "certspotter.com" in url:
                return _MockResponse([{"dns_names": ["p1.acme.example"]}])
            if "anubisdb.com" in url:
                return _MockResponse(["p2.acme.example"])
            if "otx.alienvault.com" in url:
                return _MockResponse({"passive_dns": [{"hostname": "p3.acme.example"}]})
            if "web.archive.org" in url:
                return _MockResponse([["original"], ["https://p4.acme.example/"]])
            if "api.hackertarget.com" in url:
                return _MockResponse("p5.acme.example,1.2.3.4\n")
            if "rapiddns.io" in url:
                return _MockResponse("<td>p6.acme.example</td>")
            return _MockResponse("", status=404)

        subs = discover_multi_source_subdomains(
            "acme.example",
            use_crtsh=False,
            use_subfinder=True,
            urlopen_fn=_concurrent_urlopen,
        )
        self.assertEqual(
            subs,
            {f"p{i}.acme.example" for i in range(1, 7)},
        )
        mock_which.assert_not_called()
        mock_run.assert_not_called()

    def test_response_reads_are_bounded_and_support_zero_arg_mock_read(self):
        seen_read_args = []

        class _BoundedResp:
            status = 200

            def __init__(self, raw: bytes):
                self._raw = raw

            def read(self, size: int = -1) -> bytes:
                seen_read_args.append(size)
                return self._raw if size < 0 else self._raw[:size]

        class _ZeroArgReadResp:
            status = 200

            def __init__(self, raw: bytes):
                self._raw = raw

            def read(self) -> bytes:
                return self._raw

        padding = "x" * 600000
        huge_html = f"<td>early.acme.example</td><!-- {padding} --><td>late.acme.example</td>"

        def _fake_urlopen(req, timeout=10):
            url = req.full_url
            if "rapiddns.io" in url:
                return _BoundedResp(huge_html.encode("utf-8"))
            if "anubisdb.com" in url:
                return _ZeroArgReadResp(json.dumps(["zeroarg.acme.example"]).encode("utf-8"))
            return _MockResponse("", status=404)

        subs = discover_multi_source_subdomains(
            "acme.example",
            use_crtsh=False,
            use_subfinder=False,
            urlopen_fn=_fake_urlopen,
        )
        self.assertEqual(subs, {"early.acme.example", "zeroarg.acme.example"})
        self.assertEqual(seen_read_args, [524288])


class TestExtractExplicitScopeHosts(unittest.TestCase):
    def test_extracts_url_domain_wildcard_apex_and_excludes_out_of_scope(self):
        scopes = [
            {
                "id": "1",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "https://portal.acme.example/login?next=/home",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "2",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "API.Acme.Example.",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "3",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.acme.example",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "4",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "https://portal.acme.example/logout",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "5",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "https://blocked.acme.example/admin",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "6",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "blocked.acme.example",
                    "eligible_for_submission": False,
                },
            },
            {
                "id": "7",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "https://app.staging.acme.example/",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "8",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.staging.acme.example",
                    "eligible_for_submission": False,
                },
            },
            {
                "id": "9",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "dev-*.acme.example",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "10",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "11",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "http://127.0.0.1:8080/internal",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "12",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "http://metadata.google.internal/",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "13",
                "attributes": {
                    "asset_type": "APPLE_STORE_APP_ID",
                    "asset_identifier": "id987654321",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "14",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "custom-excluded.acme.example",
                    "eligible_for_submission": True,
                },
            },
        ]

        hosts = extract_explicit_scope_hosts(
            scopes,
            out_of_scope_matcher=lambda h: h == "custom-excluded.acme.example",
        )
        self.assertEqual(
            hosts,
            ["portal.acme.example", "api.acme.example", "acme.example"],
        )

    @patch("orbit_security.vdp_recon_sources.is_safe_host")
    def test_respects_is_safe_host_guard(self, mock_is_safe):
        mock_is_safe.side_effect = lambda h: h != "ssrf-target.acme.example"
        scopes = [
            {
                "id": "1",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "ssrf-target.acme.example",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "2",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "safe.acme.example",
                    "eligible_for_submission": True,
                },
            },
        ]
        self.assertEqual(extract_explicit_scope_hosts(scopes), ["safe.acme.example"])


class TestSignalGatePreFilter(unittest.TestCase):
    def test_is_program_signal_eligible_cases(self):
        ok_low, reason_low = is_program_signal_eligible(1.0, 0.0)
        self.assertFalse(ok_low)
        self.assertIn("<", reason_low)

        ok_frac, _ = is_program_signal_eligible(0.5, 0.0)
        self.assertFalse(ok_frac)

        ok_eq, _ = is_program_signal_eligible(0.0, 0.0)
        self.assertTrue(ok_eq)

        ok_neg, _ = is_program_signal_eligible(-1.0, 0.0)
        self.assertTrue(ok_neg)

        ok_none_target, _ = is_program_signal_eligible(None, 0.0)
        self.assertTrue(ok_none_target)

        ok_none_researcher, _ = is_program_signal_eligible(1.0, None)
        self.assertTrue(ok_none_researcher)

        ok_both_none, _ = is_program_signal_eligible(None, None)
        self.assertTrue(ok_both_none)


if __name__ == "__main__":
    unittest.main()
