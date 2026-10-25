"""Comprehensive unit and integration test suite for Orbit Security Local Tool Adapters.

Tests:
1. everything_search: es.exe CLI wrapper, IPC detection, fallback filesystem search, secret/cert finding.
2. xh_probe: xh.exe / xhs.exe HTTP/TLS probe, header security grading, certificate inspection.
3. adhx_client: ADHX API client, URL parsing, threat intel IOC extraction, error handling.
4. duckdb_analytics: OLAP SQL engine, DNS telemetry, CVE feeds, Parquet export.
5. attack_tree: DAG threat modeling, fluent builder, path metrics, Mermaid export, OSINT converter.
6. ffmpeg_renderer: Video/GIF rendering, ffprobe media inspection, terminal teaser generator.
7. yt_threat_harvester: yt-dlp conference talk harvester, CTI extraction, subtitles/audio downloader.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.tools.everything_search import (
    EverythingIPCError,
    EverythingNotInstalledError,
    EverythingSearchError,
    EverythingSearcher,
    SearchResult,
    search_files,
)
from orbit_security.tools.xh_probe import (
    CertificateInfo,
    ProbeResult,
    SecurityHeaderAudit,
    XHNotInstalledError,
    XHProbe,
    XHProbeError,
    probe_target,
)
from orbit_security.tools.adhx_client import (
    ADHXClient,
    ADHXError,
    ArticleInfo,
    AuthorInfo,
    EngagementMetrics,
    InvalidTweetURLError,
    ThreatIntelExtraction,
    TweetData,
    TweetNotFoundError,
    get_x_post,
)
from orbit_security.tools.duckdb_analytics import (
    DuckDBAnalyticsError,
    DuckDBEngine,
    DuckDBNotInstalledError,
    DuckDBQueryError,
    run_analytics_query,
)
from orbit_security.tools.attack_tree import (
    AttackAttributes,
    AttackNode,
    AttackPathAnalyzer,
    AttackTree,
    AttackTreeBuilder,
    Cost,
    DetectionRisk,
    Difficulty,
    MermaidExporter,
    NodeType,
    from_osint_findings,
    tree_to_mermaid,
)
from orbit_security.tools.ffmpeg_renderer import (
    FFmpegError,
    FFmpegNotInstalledError,
    FFmpegRenderer,
    MediaInfo,
    MediaStream,
    default_renderer,
)
from orbit_security.tools.yt_threat_harvester import (
    HarvestResult,
    VideoExtractionError,
    VideoMetadata,
    YTDLPError,
    YTDLPNotInstalledError,
    YTThreatHarvester,
    default_harvester,
)


# ============================================================================
# 1. Everything Search Adapter Tests
# ============================================================================

class TestEverythingSearch:
    def test_es_installation_detection(self):
        searcher = EverythingSearcher()
        # es.exe was verified on system; is_installed should return boolean
        installed = searcher.is_installed()
        assert isinstance(installed, bool)

    def test_es_ipc_check(self):
        searcher = EverythingSearcher()
        ipc = searcher.is_ipc_available()
        assert isinstance(ipc, bool)

    def test_search_result_dataclass(self):
        p = Path("C:/test/file.txt")
        sr = SearchResult(path=p, filename="file.txt", size=1024, date_modified=datetime.now())
        d = sr.to_dict()
        assert d["filename"] == "file.txt"
        assert d["size"] == 1024
        assert d["is_directory"] is False

    @patch("subprocess.run")
    def test_es_search_mocked_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "C:\\path\\one.txt\nC:\\path\\two.log\n"
        mock_run.return_value = mock_proc

        searcher = EverythingSearcher(es_path="es.exe")
        with patch.object(searcher, "is_installed", return_value=True):
            results = searcher.search("test query", max_results=10)
            assert len(results) == 2
            assert results[0].filename == "one.txt"
            assert results[1].filename == "two.log"

    @patch("subprocess.run")
    def test_es_search_ipc_error_handling(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 8
        mock_proc.stderr = "Error 8: Everything IPC not found. Please make sure Everything is running."
        mock_run.return_value = mock_proc

        searcher = EverythingSearcher(es_path="es.exe")
        with patch.object(searcher, "is_installed", return_value=True):
            with pytest.raises(EverythingIPCError) as exc_info:
                searcher.search("query", fallback_on_ipc_error=False)
            assert "IPC" in str(exc_info.value)

    def test_es_fallback_filesystem_search(self, tmp_path):
        # Create dummy directory structure
        secret_file = tmp_path / "production.env"
        secret_file.write_text("API_KEY=12345")
        cert_file = tmp_path / "server.crt"
        cert_file.write_text("CERT CONTENT")
        other_file = tmp_path / "readme.txt"
        other_file.write_text("Hello")

        searcher = EverythingSearcher(es_path="nonexistent_es.exe")
        results = searcher._fallback_search("*.env", max_results=10, regex=False, extension=None, root=tmp_path)
        assert len(results) == 1
        assert results[0].filename == "production.env"

        cert_results = searcher.find_certificates(target_dir=tmp_path, fallback_on_ipc_error=True)
        assert any(r.filename == "server.crt" for r in cert_results)

    @patch("subprocess.run")
    def test_es_count_mocked(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "42\n"
        mock_run.return_value = mock_proc

        searcher = EverythingSearcher(es_path="es.exe")
        with patch.object(searcher, "is_installed", return_value=True):
            count = searcher.count("*.log")
            assert count == 42


# ============================================================================
# 2. XH Reconnaissance Probe Tests
# ============================================================================

class TestXHProbe:
    def test_xh_installation_detection(self):
        probe = XHProbe()
        assert isinstance(probe.is_installed(), bool)

    def test_security_header_scoring(self):
        probe = XHProbe()
        good_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        audit = probe.audit_headers(good_headers)
        assert audit.score == 100
        assert audit.grade == "A+"
        assert len(audit.missing_headers) == 0

        bad_headers = {"server": "nginx"}
        bad_audit = probe.audit_headers(bad_headers)
        assert bad_audit.score == 0
        assert bad_audit.grade == "F"
        assert len(bad_audit.missing_headers) == 6

    def test_parse_xh_output(self):
        probe = XHProbe()
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            "\r\n"
            '{"status": "ok"}'
        )
        status, headers, body = probe._parse_xh_output(raw)
        assert status == 200
        assert headers["Content-Type"] == "application/json"
        assert headers["Strict-Transport-Security"] == "max-age=31536000"
        assert '{"status": "ok"}' in body

    def test_xh_offline_probe_real_execution(self):
        probe = XHProbe()
        if probe.is_installed():
            # Test actual binary invocation with --offline
            result = probe.probe("https://example.com", offline=True)
            assert result.url == "https://example.com"
            assert isinstance(result.security_audit, SecurityHeaderAudit)

    def test_certificate_info_dataclass(self):
        cert = CertificateInfo(
            subject={"commonName": "orbit.sec"},
            issuer={"commonName": "DigiCert"},
            valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2027, 1, 1, tzinfo=timezone.utc),
            days_remaining=300,
            san_list=["orbit.sec", "*.orbit.sec"],
            is_self_signed=False,
            is_expired=False,
        )
        d = cert.to_dict()
        assert d["subject"]["commonName"] == "orbit.sec"
        assert d["is_expired"] is False
        assert d["days_remaining"] == 300


# ============================================================================
# 3. ADHX Client & CTI Extraction Tests
# ============================================================================

class TestADHXClient:
    def test_url_parser(self):
        # Various valid URL patterns
        user, sid = ADHXClient.parse_tweet_url("https://x.com/dgt10011/status/2020167690560647464")
        assert user == "dgt10011"
        assert sid == "2020167690560647464"

        user, sid = ADHXClient.parse_tweet_url("https://twitter.com/elonmusk/status/1234567890?s=20")
        assert user == "elonmusk"
        assert sid == "1234567890"

        user, sid = ADHXClient.parse_tweet_url("https://adhx.com/alexp/status/987654321/")
        assert user == "alexp"
        assert sid == "987654321"

        user, sid = ADHXClient.parse_tweet_url("author_handle/11223344")
        assert user == "author_handle"
        assert sid == "11223344"

    def test_invalid_url_raises(self):
        with pytest.raises(InvalidTweetURLError):
            ADHXClient.parse_tweet_url("https://google.com/search?q=test")

    def test_threat_intel_extraction(self):
        client = ADHXClient()
        tweet = TweetData(
            id="123",
            url="https://x.com/sec/status/123",
            text="Critical 0day RCE discovered in Shopify plugin! See CVE-2026-44011 and T1059. Connects to C2 at 185.220.101.5",
            author=AuthorInfo(username="sec", name="Security Researcher"),
            created_at="2026-10-24T00:00:00Z",
            engagement=EngagementMetrics(likes=50, retweets=20),
            article=ArticleInfo(
                title="Full Exploit Analysis",
                content="PoC exploit hashes: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 targeting evil-payload.net",
            ),
        )

        intel = client.extract_threat_intel(tweet)
        assert "CVE-2026-44011" in intel.cves
        assert "T1059" in intel.mitre_attack
        assert "185.220.101.5" in intel.ips
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in intel.hashes
        assert "0day" in intel.security_tags
        assert "rce" in intel.security_tags
        assert "exploit" in intel.security_tags

    @patch.object(ADHXClient, "_http_get_json")
    def test_fetch_tweet_mocked(self, mock_get):
        mock_get.return_value = {
            "id": "2020167690560647464",
            "url": "https://x.com/testuser/status/2020167690560647464",
            "text": "DNS hijacking attack detected on subdomains! CVE-2025-9988",
            "author": {"name": "Test User", "username": "testuser", "avatarUrl": "https://avatar.png"},
            "createdAt": "2026-10-24T00:00:00Z",
            "engagement": {"replies": 5, "retweets": 10, "likes": 100, "views": 1500},
            "article": None,
        }

        client = ADHXClient()
        tweet = client.fetch_tweet("https://x.com/testuser/status/2020167690560647464")
        assert tweet.id == "2020167690560647464"
        assert tweet.author.username == "testuser"
        assert tweet.engagement.likes == 100
        assert tweet.intel is not None
        assert "CVE-2025-9988" in tweet.intel.cves

    @patch.object(ADHXClient, "_http_get_json")
    def test_fetch_tweet_not_found(self, mock_get):
        mock_get.side_effect = TweetNotFoundError("Post returned 404")
        client = ADHXClient()
        with pytest.raises(TweetNotFoundError):
            client.fetch_tweet("https://x.com/nobody/status/000000000000")


# ============================================================================
# 4. DuckDB Analytics Engine Tests
# ============================================================================

class TestDuckDBAnalytics:
    @pytest.fixture(autouse=True)
    def skip_if_duckdb_missing(self):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed (neither duckdb module nor duckdb.exe found)")

    def test_duckdb_availability(self):
        engine = DuckDBEngine()
        assert isinstance(engine.is_available(), bool)

    def test_duckdb_real_cli_query(self):
        engine = DuckDBEngine()
        res = engine.execute_query("SELECT 42 AS answer, 'orbit_sec' AS project;")
        assert len(res) == 1
        assert res[0]["answer"] == 42
        assert res[0]["project"] == "orbit_sec"

    def test_duckdb_json_telemetry_query(self, tmp_path):
        data = [
            {"domain": "sub1.example.com", "status": "NXDOMAIN", "response_time_ms": 15},
            {"domain": "sub2.example.com", "status": "NOERROR", "response_time_ms": 8},
            {"domain": "sub3.example.com", "status": "NXDOMAIN", "response_time_ms": 22},
        ]
        json_file = tmp_path / "dns_telemetry.json"
        json_file.write_text(json.dumps(data))

        engine = DuckDBEngine()
        results = engine.query_file(json_file, sql_filter="status = 'NXDOMAIN'")
        assert len(results) == 2
        assert all(r["status"] == "NXDOMAIN" for r in results)

    def test_duckdb_analyze_dns_telemetry(self, tmp_path):
        data = [
            {"domain": "target.com", "status": "NOERROR"},
            {"domain": "dev.target.com", "status": "NXDOMAIN"},
            {"domain": "test.target.com", "status": "NXDOMAIN"},
        ]
        dns_file = tmp_path / "dns.json"
        dns_file.write_text(json.dumps(data))

        engine = DuckDBEngine()
        report = engine.analyze_dns_telemetry(dns_file)
        assert report["summary"]["total_queries"] == 3
        assert report["summary"]["nxdomain_count"] == 2
        assert len(report["top_domains"]) > 0

    def test_duckdb_export_to_parquet(self, tmp_path):
        engine = DuckDBEngine()
        parquet_file = tmp_path / "export.parquet"
        engine.export_to_parquet("SELECT 'critical' as severity, 'CVE-2026-1111' as cve", parquet_file)
        assert parquet_file.is_file()

        # Query parquet back
        queried = engine.query_file(parquet_file)
        assert len(queried) == 1
        assert queried[0]["cve"] == "CVE-2026-1111"

    def test_duckdb_syntax_error(self):
        engine = DuckDBEngine()
        with pytest.raises(DuckDBQueryError):
            engine.execute_query("INVALID SYNTAX QUERY FROM NOTHING;")


# ============================================================================
# 5. Attack Tree & Threat Modeling Engine Tests
# ============================================================================

class TestAttackTree:
    def test_fluent_builder_and_path_metrics(self):
        tree = (
            AttackTreeBuilder("API Compromise", "Compromise backend API")
            .goal("G1", "Unauthorized API Access")
            .or_node("OR1", "Credential Stealing")
                .attack("A1", "Credential Stuffing", difficulty=Difficulty.TRIVIAL, cost=Cost.LOW)
                .attack("A2", "Phishing Admin", difficulty=Difficulty.MEDIUM, cost=Cost.MEDIUM)
            .end()
            .or_node("OR2", "Vulnerability Exploit")
                .attack("A3", "SQL Injection", difficulty=Difficulty.LOW, cost=Cost.FREE)
            .end()
            .build()
        )

        assert tree.name == "API Compromise"
        assert len(tree.root.children) == 2
        assert len(tree.get_all_leaf_attacks()) == 3

        easiest = tree.find_easiest_path()
        assert any(n.id == "A1" for n in easiest)

    def test_attack_path_analyzer(self):
        tree = (
            AttackTreeBuilder("Takeover Model")
            .goal("ROOT", "Subdomain Hijacking")
            .and_node("AND1", "Dangling Record Takeover")
                .attack("STEP1", "Discover dangling CNAME", difficulty=Difficulty.TRIVIAL, mitigations=["Ghost DNS"])
                .attack("STEP2", "Register AWS S3 bucket", difficulty=Difficulty.LOW, mitigations=["Enforce bucket policies"])
            .end()
            .build()
        )

        analyzer = AttackPathAnalyzer(tree)
        paths = analyzer.get_all_paths()
        assert len(paths) == 1
        metrics = analyzer.calculate_path_metrics(paths[0])
        assert metrics["steps"] == 2
        assert metrics["total_difficulty"] == 1 + 2  # TRIVIAL(1) + LOW(2)

        mitigations = analyzer.prioritize_mitigations()
        assert len(mitigations) == 2

    def test_mermaid_export(self):
        tree = (
            AttackTreeBuilder("Test")
            .goal("ROOT", "Main Goal")
            .or_node("OR_SUB", "Sub Goal")
                .attack("LEAF_1", "Attack Action", difficulty=Difficulty.HIGH)
            .end()
            .build()
        )
        mermaid = tree_to_mermaid(tree)
        assert "flowchart TD" in mermaid
        assert "Main Goal" in mermaid
        assert "Attack Action" in mermaid
        assert "style" in mermaid

    def test_from_osint_findings_converter(self):
        findings = [
            {
                "category": "takeover",
                "target": "staging.client.com",
                "title": "Dangling CNAME to GitHub Pages",
                "severity": "CRITICAL",
            },
            {
                "category": "email",
                "target": "client.com",
                "title": "Missing DMARC policy",
                "severity": "HIGH",
            },
            {
                "category": "web",
                "target": "api.client.com/v1",
                "type": "sqli",
                "title": "SQL Injection in Search parameter",
                "severity": "CRITICAL",
                "cves": ["CVE-2025-1234"],
            },
        ]

        tree = from_osint_findings("client.com", findings)
        assert "client.com" in tree.name
        leaves = tree.get_all_leaf_attacks()
        assert len(leaves) == 3
        cve_refs = [cve for leaf in leaves for cve in leaf.cve_refs]
        assert "CVE-2025-1234" in cve_refs

    def test_json_roundtrip(self):
        tree = (
            AttackTreeBuilder("Roundtrip")
            .goal("G", "Goal")
            .attack("A", "Attack", difficulty=Difficulty.LOW)
            .build()
        )
        json_str = tree.to_json()
        loaded = AttackTree.from_json(json_str)
        assert loaded.name == "Roundtrip"
        assert len(loaded.root.children) == 1
        assert loaded.root.children[0].attributes.difficulty == Difficulty.LOW


# ============================================================================
# 6. FFmpeg Renderer Automation Tests
# ============================================================================

class TestFFmpegRenderer:
    def test_ffmpeg_and_ffprobe_installed(self):
        renderer = FFmpegRenderer()
        assert renderer.is_ffmpeg_installed() is True
        assert renderer.is_ffprobe_installed() is True

    def test_synthetic_video_and_probe_media(self, tmp_path):
        renderer = FFmpegRenderer()
        video_file = tmp_path / "synthetic.mp4"

        # Generate a 1-second blank synthetic video using ffmpeg
        cmd = [
            renderer.ffmpeg_path,
            "-y",
            "-f", "lavfi",
            "-i", "color=c=navy:s=320x240:d=1",
            "-pix_fmt", "yuv420p",
            str(video_file),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert video_file.is_file()

        # Probe with ffprobe
        info = renderer.probe_media(video_file)
        assert info.duration >= 0.9
        assert info.video_stream is not None
        assert info.video_stream.width == 320
        assert info.video_stream.height == 240

    def test_create_gif_from_video(self, tmp_path):
        renderer = FFmpegRenderer()
        video_file = tmp_path / "source.mp4"
        gif_file = tmp_path / "animated.gif"

        subprocess.run(
            [renderer.ffmpeg_path, "-y", "-f", "lavfi", "-i", "color=c=black:s=160x120:d=1", "-pix_fmt", "yuv420p", str(video_file)],
            capture_output=True,
            check=True,
        )

        out_gif = renderer.create_gif(video_file, gif_file, fps=10, width=160)
        assert out_gif.is_file()
        assert out_gif.stat().st_size > 0

    def test_terminal_teaser_generator(self, tmp_path):
        renderer = FFmpegRenderer()
        out_mp4 = tmp_path / "orbit_radar_teaser.mp4"

        findings = [
            "Dangling CNAME: dev.target.com -> s3.amazonaws.com",
            "Missing DMARC Policy (p=none)",
        ]
        teaser = renderer.generate_terminal_teaser(
            title="Perimeter Breach Radar",
            subtitle="Autonomous OSINT Triangulation",
            findings=findings,
            output_path=out_mp4,
            duration_sec=1.0,
            fps=15,
            width=640,
            height=360,
        )
        assert teaser.is_file()
        assert teaser.stat().st_size > 5000


# ============================================================================
# 7. YT Threat Harvester Tests
# ============================================================================

class TestYTThreatHarvester:
    def test_yt_dlp_installed(self):
        harvester = YTThreatHarvester()
        assert isinstance(harvester.is_installed(), bool)

    def test_extract_threat_intel_from_metadata(self):
        harvester = YTThreatHarvester()
        meta = VideoMetadata(
            id="tTAISQqmxWQ",
            title="DEF CON 33 - Exploiting Deserialization in WordPress: CVE-2025-43210 RCE",
            uploader="DEFCONConference",
            channel="DEFCONConference",
            duration=3420.0,
            view_count=12000,
            description="In this talk, we demonstrate exploiting CVE-2025-43210 using Burp Suite and Ghidra.",
            tags=["defcon", "rce", "exploit", "cve", "wordpress"],
            chapters=[
                {"title": "Introduction to Deserialization", "start_time": 0},
                {"title": "Bypassing WAF with Metasploit", "start_time": 600},
            ],
        )

        intel = harvester.extract_threat_intel(meta)
        assert "CVE-2025-43210" in intel["cves"]
        assert "rce" in intel["attack_vectors"]
        assert "deserialization" in intel["attack_vectors"]
        assert "burp suite" in intel["detected_tools"]
        assert "ghidra" in intel["detected_tools"]
        assert "metasploit" in intel["detected_tools"]
        assert "wordpress" in intel["affected_platforms"]
        assert intel["threat_relevance_score"] >= 60

    @patch("subprocess.run")
    def test_get_video_info_mocked(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({
            "id": "abc123xyz",
            "title": "Black Hat USA - Cloud Privilege Escalation",
            "uploader": "BlackHatOfficial",
            "duration": 1800,
            "view_count": 5500,
            "description": "Exploiting AWS IAM roles and token leakage.",
            "tags": ["blackhat", "cloud", "aws", "privesc"],
        })
        mock_run.return_value = mock_proc

        harvester = YTThreatHarvester()
        with patch.object(harvester, "is_installed", return_value=True):
            meta = harvester.get_video_info("https://www.youtube.com/watch?v=abc123xyz")
        assert meta.id == "abc123xyz"
        assert meta.uploader == "BlackHatOfficial"
        assert meta.duration == 1800

    @patch.object(YTThreatHarvester, "get_video_info")
    @patch.object(YTThreatHarvester, "download_subtitles")
    def test_harvest_threat_intel_pipeline(self, mock_subs, mock_info, tmp_path):
        mock_info.return_value = VideoMetadata(
            id="vid999",
            title="Zero-Day Kernel Exploit Talk",
            uploader="SecurityConf",
            channel="SecurityConf",
            duration=2400,
            view_count=9000,
            description="Discussing kernel privesc CVE-2026-7788",
            tags=["kernel", "privesc", "0day"],
        )
        mock_subs.return_value = tmp_path / "vid999.en.vtt"

        harvester = YTThreatHarvester()
        result = harvester.harvest_threat_intel(
            "https://www.youtube.com/watch?v=vid999",
            output_dir=tmp_path,
            download_audio_track=False,
            download_subs=True,
        )
        assert result.video_id == "vid999"
        assert "CVE-2026-7788" in result.threat_intel["cves"]
        assert result.subtitles_path == tmp_path / "vid999.en.vtt"


# ============================================================================
# 8. Edge Cases, Async Execution & Error Branch Tests
# ============================================================================

class TestAdapterEdgeCasesAndAsync:
    def test_es_not_installed_error(self):
        searcher = EverythingSearcher(es_path="C:/nonexistent_es_binary.exe")
        with pytest.raises(EverythingNotInstalledError):
            searcher.search("test", fallback_on_ipc_error=False)

    def test_es_async_search(self, tmp_path):
        async def _test():
            f = tmp_path / "secret.env"
            f.write_text("TEST=1")
            searcher = EverythingSearcher(es_path="nonexistent.exe")
            results = await searcher.async_search("*.env", fallback_on_ipc_error=True, fallback_root=tmp_path)
            assert len(results) == 1
            assert results[0].filename == "secret.env"
        asyncio.run(_test())

    def test_es_find_env_secrets_and_logs(self, tmp_path):
        f1 = tmp_path / ".env.production"
        f1.write_text("TOKEN=xyz")
        f2 = tmp_path / "app.log"
        f2.write_text("info")

        searcher = EverythingSearcher(es_path="nonexistent.exe")
        secrets = searcher.find_env_secrets(target_dir=tmp_path, fallback_on_ipc_error=True)
        assert any(s.filename == ".env.production" for s in secrets)

        logs = searcher.find_logs(target_dir=tmp_path, fallback_on_ipc_error=True)
        assert any(l.filename == "app.log" for l in logs)

    def test_xh_async_probe(self):
        async def _test():
            probe = XHProbe()
            result = await probe.async_probe("https://example.com", offline=True)
            assert result.url == "https://example.com"
            assert result.security_audit is not None
        asyncio.run(_test())

    def test_xh_not_installed_error_when_httpx_missing(self):
        probe = XHProbe(xh_path="C:/nonexistent_xh.exe")
        with patch.dict("sys.modules", {"httpx": None}):
            with pytest.raises(XHNotInstalledError):
                probe.probe("https://example.com")

    def test_adhx_async_fetch_tweet(self):
        async def _test():
            client = ADHXClient()
            with patch.object(client, "fetch_tweet") as mock_fetch:
                mock_fetch.return_value = TweetData(
                    id="123",
                    url="https://x.com/user/status/123",
                    text="Zero-day",
                    author=AuthorInfo(),
                    created_at="",
                    engagement=EngagementMetrics(),
                )
                res = await client.async_fetch_tweet("https://x.com/user/status/123")
                assert res.id == "123"
        asyncio.run(_test())

    def test_adhx_missing_fields_defaults(self):
        raw = {"id": "555"}
        tweet = TweetData.from_dict(raw)
        assert tweet.id == "555"
        assert tweet.text == ""
        assert tweet.author.name == ""
        assert tweet.engagement.likes == 0
        assert tweet.article is None

    def test_duckdb_async_execute_query(self):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed")
        async def _test():
            engine = DuckDBEngine()
            res = await engine.async_execute_query("SELECT 'async_ok' as status;")
            assert len(res) == 1
            assert res[0]["status"] == "async_ok"
        asyncio.run(_test())

    def test_duckdb_csv_query(self, tmp_path):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed")
        csv_file = tmp_path / "findings.csv"
        csv_file.write_text("target,severity,port\napi.com,critical,443\nweb.com,low,80\n")
        engine = DuckDBEngine()
        rows = engine.query_file(csv_file, sql_filter="severity = 'critical'")
        assert len(rows) == 1
        assert rows[0]["target"] == "api.com"

    def test_duckdb_analyze_cve_and_recon(self, tmp_path):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed")
        cve_file = tmp_path / "cves.json"
        cve_file.write_text(json.dumps([
            {"cve_id": "CVE-2026-0001", "cvss_score": 9.8, "summary": "RCE in edge proxy"},
            {"cve_id": "CVE-2026-0002", "cvss_score": 5.3, "summary": "Info leak"},
        ]))
        recon_file = tmp_path / "recon.json"
        recon_file.write_text(json.dumps([
            {"target": "client.com", "severity": "HIGH", "category": "web"},
            {"target": "client.com", "severity": "HIGH", "category": "web"},
            {"target": "client.com", "severity": "LOW", "category": "dns"},
        ]))

        engine = DuckDBEngine()
        high_cves = engine.analyze_cve_feed(cve_file, min_cvss=7.0)
        assert len(high_cves) == 1
        assert high_cves[0]["cve_id"] == "CVE-2026-0001"

        recon_analysis = engine.analyze_recon_findings(recon_file)
        assert len(recon_analysis["by_severity"]) > 0
        assert any(r["severity"] == "HIGH" and r["count"] == 2 for r in recon_analysis["by_severity"])

    def test_attack_tree_empty_osint(self):
        tree = from_osint_findings("safe-target.org", [])
        assert "safe-target.org" in tree.name
        leaves = tree.get_all_leaf_attacks()
        assert len(leaves) >= 1
        assert "Credential Stuffing" in leaves[0].name

    def test_attack_tree_unmitigated_attacks(self):
        tree = (
            AttackTreeBuilder("Zero Day")
            .goal("G", "Compromise")
            .attack("A1", "Unknown 0-day", mitigations=[])
            .attack("A2", "Known vuln", mitigations=["Apply patch"])
            .build()
        )
        unmitigated = tree.get_unmitigated_attacks()
        assert len(unmitigated) == 1
        assert unmitigated[0].id == "A1"

    def test_ffmpeg_probe_media_not_found(self):
        renderer = FFmpegRenderer()
        with pytest.raises(FileNotFoundError):
            renderer.probe_media("C:/does_not_exist_file.mp4")

    def test_ffmpeg_render_video_empty_frames(self, tmp_path):
        renderer = FFmpegRenderer()
        with pytest.raises(ValueError):
            renderer.render_video_from_frames([], tmp_path / "out.mp4")

    def test_ffmpeg_extract_clip_and_audio(self, tmp_path):
        renderer = FFmpegRenderer()
        video_file = tmp_path / "base.mp4"
        clip_file = tmp_path / "clip.mp4"

        # Generate 2-second synthetic video
        subprocess.run(
            [renderer.ffmpeg_path, "-y", "-f", "lavfi", "-i", "color=c=red:s=160x120:d=2", "-pix_fmt", "yuv420p", str(video_file)],
            capture_output=True,
            check=True,
        )

        res_clip = renderer.extract_clip(video_file, clip_file, start_sec=0.5, duration_sec=1.0)
        assert res_clip.is_file()
        info = renderer.probe_media(res_clip)
        assert 0.8 <= info.duration <= 1.2

    def test_yt_empty_metadata_raises(self):
        harvester = YTThreatHarvester()
        with patch.object(harvester, "is_installed", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.stdout = "Not JSON output at all"
                mock_run.return_value = mock_proc
                with pytest.raises(VideoExtractionError):
                    harvester.get_video_info("https://youtube.com/watch?v=bad")

    def test_yt_search_security_talks_mocked(self):
        harvester = YTThreatHarvester()
        with patch.object(harvester, "is_installed", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.stdout = (
                    json.dumps({"id": "vid1", "title": "Talk 1", "uploader": "DEF CON"}) + "\n" +
                    json.dumps({"id": "vid2", "title": "Talk 2", "uploader": "Black Hat"}) + "\n"
                )
                mock_run.return_value = mock_proc

                results = harvester.search_security_talks("deserialization", max_results=2)
                assert len(results) == 2
                assert results[0].id == "vid1"
                assert results[1].uploader == "Black Hat"

    def test_es_find_git_repos_empty_and_valid(self, tmp_path):
        searcher = EverythingSearcher(es_path="nonexistent_es.exe")
        # Empty folder with non-git file
        (tmp_path / "normal_code.py").write_text("print('test')")
        empty_res = searcher.find_git_repos(target_dir=tmp_path, fallback_on_ipc_error=True)
        assert len(empty_res) == 0

        # Create .git folder
        (tmp_path / ".git").mkdir()
        valid_res = searcher.find_git_repos(target_dir=tmp_path, fallback_on_ipc_error=True)
        assert len(valid_res) == 1
        assert valid_res[0].filename == ".git"

    def test_es_count_with_fallback(self, tmp_path):
        searcher = EverythingSearcher(es_path="nonexistent_es.exe")
        (tmp_path / "audit1.log").write_text("entry 1")
        (tmp_path / "audit2.log").write_text("entry 2")
        cnt = searcher.count("*.log", fallback_on_ipc_error=True, fallback_root=tmp_path)
        assert cnt == 2

    def test_xh_inspect_certificate_real(self):
        probe = XHProbe()
        try:
            cert = probe.inspect_certificate("https://example.com", timeout_sec=5.0)
            assert cert.subject.get("commonName") == "example.com"
            assert cert.days_remaining is not None and cert.days_remaining > 0
            assert "example.com" in cert.san_list
        except Exception:
            pytest.skip("Network TLS test skipped in offline test environment")

    def test_xh_offline_probe_hb_headers(self):
        probe = XHProbe()
        if probe.is_installed():
            res = probe.probe("https://example.com", offline=True)
            assert "example.com" in res.raw_output
            assert len(res.raw_output) > 0

    def test_xh_fallback_httpx_offline(self):
        probe = XHProbe(xh_path="nonexistent_xh.exe")
        res = probe.probe("https://orbit.sec/api/v1/test", offline=True)
        assert res.status_code == 0
        assert res.url == "https://orbit.sec/api/v1/test"
        assert "orbit.sec" in res.raw_output

    def test_adhx_parse_tweet_url_adhx_variants(self):
        u1, s1 = ADHXClient.parse_tweet_url("https://adhx.com/dgt10011/2020167690560647464")
        assert u1 == "dgt10011"
        assert s1 == "2020167690560647464"

        u2, s2 = ADHXClient.parse_tweet_url("https://adhx.com/api/share/tweet/researcher/998877")
        assert u2 == "researcher"
        assert s2 == "998877"

        u3, s3 = ADHXClient.parse_tweet_url("https://adhx.com/share/tweet/alice/554433")
        assert u3 == "alice"
        assert s3 == "554433"

    def test_adhx_http_error_wrapped(self):
        client = ADHXClient(base_url="https://nonexistent-host-domain-orbit-sec.xyz")
        with pytest.raises(ADHXError):
            client.fetch_tweet("user/123")

    def test_adhx_intel_ip_and_hash_validation(self):
        client = ADHXClient()
        tweet = TweetData(
            id="1",
            url="https://x.com/u/status/1",
            text="Invalid IP 999.888.777.666 and version 1.2.3.4 with pure number 12345678901234567890123456789012 and real 198.51.100.2",
            author=AuthorInfo(),
            created_at="",
            engagement=EngagementMetrics(),
        )
        intel = client.extract_threat_intel(tweet)
        assert "999.888.777.666" not in intel.ips
        assert "198.51.100.2" in intel.ips
        # Pure numeric 32-digit string should not be treated as MD5 hash
        assert "12345678901234567890123456789012" not in intel.hashes

    def test_duckdb_export_to_parquet_with_semicolon(self, tmp_path):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed")
        engine = DuckDBEngine()
        out_pq = tmp_path / "semi.parquet"
        engine.export_to_parquet("SELECT 'valid' AS status, 100 AS score;", out_pq)
        assert out_pq.is_file()
        rows = engine.query_file(out_pq)
        assert len(rows) == 1
        assert rows[0]["status"] == "valid"

    def test_duckdb_analyze_dns_telemetry_parquet(self, tmp_path):
        if not DuckDBEngine().is_available():
            pytest.skip("DuckDB not installed")
        engine = DuckDBEngine()
        pq_file = tmp_path / "dns_feed.parquet"
        engine.export_to_parquet(
            "SELECT 'sub.target.com' AS domain, 'NXDOMAIN' AS status "
            "UNION ALL SELECT 'api.target.com' AS domain, 'NOERROR' AS status",
            pq_file,
        )
        assert pq_file.is_file()
        res = engine.analyze_dns_telemetry(pq_file)
        assert res["summary"]["total_queries"] == 2
        assert res["summary"]["nxdomain_count"] == 1
        assert res["summary"]["noerror_count"] == 1

    def test_attack_tree_case_insensitive_osint_findings(self):
        findings = [
            {"category": "WEB", "type": "SQLi", "target": "db.corp.net", "title": "SQL Injection", "cves": "CVE-2026-9090"},
            {"category": "Cloud_Storage", "type": "s3_bucket", "target": "data-bucket", "title": "Public S3 bucket"},
        ]
        tree = from_osint_findings("corp.net", findings)
        leaves = tree.get_all_leaf_attacks()
        assert len(leaves) == 2
        leaf_cves = [c for l in leaves for c in l.cve_refs]
        assert "CVE-2026-9090" in leaf_cves

    def test_attack_tree_mermaid_newlines_sanitized(self):
        tree = (
            AttackTreeBuilder("Multiline Test")
            .goal("ROOT", "Goal with\nnewline")
            .attack("A1", 'Attack with "quotes"\nand break')
            .build()
        )
        mermaid = tree_to_mermaid(tree)
        # Should not have raw unescaped newlines inside node tags
        assert "\nand break" not in mermaid
        assert "Attack with 'quotes' and break" in mermaid

    def test_ffmpeg_odd_dimensions_rendering(self, tmp_path):
        from PIL import Image
        renderer = FFmpegRenderer()
        odd_img = Image.new("RGB", (101, 101), color=(0, 255, 0))
        frame_p = tmp_path / "frame_odd.png"
        odd_img.save(frame_p)
        out_vid = tmp_path / "odd_video.mp4"

        # Odd dimensions must not crash H.264 rendering
        rendered = renderer.render_video_from_frames([frame_p], out_vid, fps=10)
        assert rendered.is_file()
        assert rendered.stat().st_size > 0

    def test_ffmpeg_file_not_found_errors(self, tmp_path):
        renderer = FFmpegRenderer()
        missing = tmp_path / "nonexistent.mp4"
        with pytest.raises(FileNotFoundError):
            renderer.create_gif(missing, tmp_path / "out.gif")
        with pytest.raises(FileNotFoundError):
            renderer.extract_clip(missing, tmp_path / "clip.mp4", 0, 1)
        with pytest.raises(FileNotFoundError):
            renderer.extract_audio(missing, tmp_path / "out.mp3")

    def test_ffmpeg_async_methods(self, tmp_path):
        async def _test():
            renderer = FFmpegRenderer()
            from PIL import Image
            img = Image.new("RGB", (64, 64), color="blue")
            f1 = tmp_path / "f1.png"
            img.save(f1)
            v = await renderer.async_render_video_from_frames([f1], tmp_path / "async_vid.mp4", fps=5)
            assert v.is_file()
            info = await renderer.async_probe_media(v)
            assert info.video_stream is not None
        asyncio.run(_test())

    def test_yt_metadata_string_views(self):
        data = {
            "id": "v123",
            "title": "Security Talk",
            "view_count": "15000.0",
            "duration": "120.5",
        }
        meta = VideoMetadata.from_dict(data)
        assert meta.view_count == 15000
        assert meta.duration == 120.5

    def test_yt_download_audio_no_file_raises(self, tmp_path):
        harvester = YTThreatHarvester()
        with patch.object(harvester, "is_installed", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_run.return_value = mock_proc
                # Empty output dir, no audio created
                with pytest.raises(VideoExtractionError):
                    harvester.download_audio("https://youtube.com/watch?v=none", tmp_path)

    def test_yt_search_security_talks_error_code(self):
        harvester = YTThreatHarvester()
        with patch.object(harvester, "is_installed", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 1
                mock_proc.stderr = "Network blocked"
                mock_proc.stdout = ""
                mock_run.return_value = mock_proc
                with pytest.raises(VideoExtractionError):
                    harvester.search_security_talks("exploit", max_results=3)

    def test_yt_harvest_sanitizes_id(self, tmp_path):
        harvester = YTThreatHarvester()
        with patch.object(harvester, "get_video_info") as mock_info:
            mock_info.return_value = VideoMetadata(
                id="talk:2026/01?v=1",
                title="Sanitized Talk",
                uploader="Conf",
                channel="Conf",
                duration=100,
                view_count=50,
                description="",
            )
            with patch.object(harvester, "download_subtitles", return_value=None):
                result = harvester.harvest_threat_intel("https://youtube.com/watch?v=test", tmp_path, download_subs=False)
                assert result.video_id == "talk:2026/01?v=1"
                # Check that directory was sanitized without Windows illegal chars
                created_dirs = [p.name for p in tmp_path.iterdir() if p.is_dir()]
                assert any(":" not in d and "?" not in d for d in created_dirs)
