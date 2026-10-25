"""TDD Test Suite for Orbit Security Tier 2 Roadmap (Projects #11 - #20).

Covers:
- Wave 2A:
  - Project #11: Autonomous Dangling Cloud Resource Sweeper (cloud_sentinels.py)
  - Project #15: Passive TLS / SSL Cipher Suite & Expiry Sentinel (cloud_sentinels.py)
  - Project #18: Self-Contained SQLite Blackboard Replication via Litestream (blackboard.py & infra/litestream.yml)
- Wave 2B:
  - Project #13: GraphRAG Codebase AST Security Vulnerability Matrix (ast_sentinel.py)
  - Project #16: Headless Browser-Free DOM Error Signature Extractor (bounty_active_prober.py)
  - Project #17: One-Click Verification Sandbox Signed Receipts (exploit_sandbox.py)
  - Project #20: Local Vectorized / GPU-Ready Log Analysis & Anomaly Detection (threat_radar.py)
- Wave 2C:
  - Project #12: EPSS Probability Horizon Visualizer Widget (landing/index.html & orbit_radar.js)
  - Project #14: Automated Co-Branded Portal Provisioner for Agencies (agency_retainer.py)
  - Project #19: Public Bug Bounty Radar Statuspage on GitHub Pages (bounty_radar.py, landing/index.html, orbit_radar.js)
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from orbit_security.blackboard import Blackboard


# ==============================================================================
# Wave 2A: Cloud Autonomy & Perimeter Sentinels (#11, #15, #18)
# ==============================================================================

def test_project_11_dangling_cloud_resource_sweeper(tmp_path):
    from orbit_security.cloud_sentinels import CloudBucketTakeoverSentinel

    bb = Blackboard(db_path=tmp_path / "sweeper_bb.db")
    fleet_targets = [
        {
            "domain": "cdn-assets.brand.com",
            "cname_target": "orphaned-brand-assets.s3.amazonaws.com",
            "mock_body": "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        },
        {
            "domain": "media.enterprise.io",
            "cname_target": "unclaimedblob.blob.core.windows.net",
            "mock_body": "BlobNotFound: The specified blob does not exist.",
        },
        {
            "domain": "safe.brand.com",
            "cname_target": "active-bucket.s3.amazonaws.com",
            "mock_body": "<html>Active storefront</html>",
        },
    ]

    report = CloudBucketTakeoverSentinel.sweep_cloud_fleet(fleet_targets, blackboard=bb)
    assert report["total_swept"] == 3
    assert report["vulnerable_count"] == 2
    providers = {f["provider"] for f in report["findings"]}
    assert "AWS S3" in providers
    assert "Azure Blob Storage" in providers

    events = bb.get_recent(limit=10, event_type="DANGLING_CLOUD_RESOURCE_DETECTED")
    assert len(events) == 2


def test_project_15_passive_tls_cipher_and_expiry_sentinel(tmp_path):
    from orbit_security.cloud_sentinels import PassiveTlsCipherSentinel

    bb = Blackboard(db_path=tmp_path / "tls_bb.db")

    # 1. Deprecated protocol + weak cipher + imminent expiry + SAN mismatch
    vuln_res = PassiveTlsCipherSentinel.evaluate_tls_posture(
        domain="legacy-pay.client.com",
        tls_version="TLSv1.0",
        cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
        days_remaining=5,
        san_domains=["other.client.com"],
        blackboard=bb,
    )
    assert vuln_res["vulnerable"] is True
    assert vuln_res["severity"] in ("CRITICAL", "HIGH")
    issue_codes = {i["code"] for i in vuln_res["issues"]}
    assert "DEPRECATED_TLS_PROTOCOL" in issue_codes
    assert "WEAK_CIPHER_SUITE" in issue_codes
    assert "CERTIFICATE_EXPIRING_CRITICAL" in issue_codes
    assert "SAN_HOSTNAME_MISMATCH" in issue_codes

    events = bb.get_recent(limit=10, event_type="TLS_POSTURE_ANOMALY")
    assert len(events) == 1

    # 2. Healthy TLS 1.3 posture
    safe_res = PassiveTlsCipherSentinel.evaluate_tls_posture(
        domain="checkout.client.com",
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        days_remaining=75,
        san_domains=["*.client.com", "client.com"],
        blackboard=bb,
    )
    assert safe_res["vulnerable"] is False
    assert safe_res["issues"] == []


def test_project_18_litestream_sqlite_wal_replication(tmp_path):
    root = Path(__file__).resolve().parent.parent
    litestream_cfg = root / "infra" / "litestream.yml"
    assert litestream_cfg.exists()
    cfg_text = litestream_cfg.read_text(encoding="utf-8")
    assert "dbs:" in cfg_text
    assert "blackboard.db" in cfg_text
    assert "orbit_events.db" in cfg_text

    bb = Blackboard(db_path=tmp_path / "live_blackboard.db")
    bb.publish("REPL_TEST_EVENT", {"seq": 1}, source="unit_test")
    bb.publish("REPL_TEST_EVENT", {"seq": 2}, source="unit_test")

    snap_dir = tmp_path / "snapshots"
    manifest = bb.create_litestream_snapshot(snapshot_dir=snap_dir)
    assert manifest["ok"] is True
    assert manifest["total_events"] == 2
    assert len(manifest["sha256"]) == 64
    snap_path = Path(manifest["snapshot_path"])
    assert snap_path.exists()

    # Verify replicated SQLite snapshot is readable and contains both events
    replica_bb = Blackboard(db_path=snap_path)
    assert len(replica_bb.get_recent(limit=10, event_type="REPL_TEST_EVENT")) == 2


# ==============================================================================
# Wave 2B: Local PC Leverage, AST Matrix & Verification Sandbox (#13, #16, #17, #20)
# ==============================================================================

def test_project_13_graphrag_ast_security_vulnerability_matrix(tmp_path):
    from orbit_security.ast_sentinel import ASTCodeSentinel

    sample_py = tmp_path / "vulnerable_service.py"
    sample_py.write_text(
        "import subprocess\n"
        "import pickle\n"
        "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLEKEY999999'\n"
        "def run_unsafe(user_cmd, raw_blob):\n"
        "    eval(user_cmd)\n"
        "    subprocess.run(user_cmd, shell=True)\n"
        "    return pickle.loads(raw_blob)\n",
        encoding="utf-8",
    )

    sentinel = ASTCodeSentinel(workspace_root=tmp_path)
    matrix = sentinel.build_security_vulnerability_matrix(tmp_path)

    assert matrix["files_scanned"] == 1
    assert matrix["total_vulnerabilities"] >= 3
    sink_types = {f["sink_type"] for f in matrix["findings"]}
    assert "dangerous_eval_exec" in sink_types
    assert "subprocess_shell_true" in sink_types
    assert "unsafe_deserialization" in sink_types
    assert len(matrix["nodes"]) >= 2
    assert len(matrix["edges"]) >= 1


def test_project_16_headless_browser_free_dom_error_extractor():
    from orbit_security.bounty_active_prober import BountyActiveProber

    prober = BountyActiveProber()
    leaked_html = """
    <html>
    <head><title>500 Internal Error</title></head>
    <body>
      <pre>Traceback (most recent call last):
        File "/srv/app/views.py", line 42, in checkout
      sqlalchemy.exc.ProgrammingError: (psycopg2.errors.SyntaxError) SELECT * FROM users</pre>
      <script id="__NEXT_DATA__" type="application/json">{"buildId":"dev","runtimeConfig":{"STRIPE_SECRET":"sk_live_123"}}</script>
      <script src="/static/chunks/main.js"></script>
      <!--# sourceMappingURL=main.js.map -->
    </body>
    </html>
    """
    res = prober.extract_dom_error_signatures("checkout.target.com", leaked_html)
    assert res["vulnerable"] is True
    assert res["browser_spawned"] is False
    categories = {s["category"] for s in res["signatures"]}
    assert "stack_trace_leak" in categories
    assert "sql_database_error" in categories
    assert "sourcemap_exposure" in categories
    assert "ssr_hydration_leak" in categories


def test_project_17_one_click_verification_sandbox_receipt():
    from orbit_security.exploit_sandbox import OperatorExploitSandbox

    finding = {
        "target_domain": "cdn.victim-corp.com",
        "flaw_type": "cloud_storage_takeover",
        "evidence": "NoSuchBucket: The specified bucket does not exist",
        "mock_execution": {
            "exit_code": 0,
            "stdout": "STATUS: 404\nBODY_PREVIEW: <Code>NoSuchBucket</Code>",
            "stderr": "",
            "duration_ms": 42.5,
            "status_code": 404,
            "response_body_preview": "<Code>NoSuchBucket</Code>",
        },
    }

    receipt = OperatorExploitSandbox.generate_signed_verification_receipt(
        finding, secret_key="orbit-test-signing-key"
    )
    assert receipt["is_confirmed"] is True
    assert receipt["confidence_score"] >= 0.85
    assert len(receipt["hmac_sha256"]) == 64
    assert receipt["receipt_id"].startswith("ORBIT-VERIFY-")
    assert OperatorExploitSandbox.verify_receipt_signature(
        receipt, secret_key="orbit-test-signing-key"
    ) is True

    # Adversarial / Tampered Receipt Verification Tests (Agent 3 Audit)
    tampered = dict(receipt)
    tampered["is_confirmed"] = False
    assert OperatorExploitSandbox.verify_receipt_signature(
        tampered, secret_key="orbit-test-signing-key"
    ) is False
    assert OperatorExploitSandbox.verify_receipt_signature(
        receipt, secret_key="wrong-signing-key"
    ) is False
    malformed = dict(receipt)
    malformed["confidence_score"] = "not-a-float"
    assert OperatorExploitSandbox.verify_receipt_signature(
        malformed, secret_key="orbit-test-signing-key"
    ) is False


def test_project_20_local_gpu_accelerated_log_anomaly_detector(tmp_path):
    from orbit_security.threat_radar import LogAnomalyDetector

    bb = Blackboard(db_path=tmp_path / "log_anom_bb.db")
    detector = LogAnomalyDetector(blackboard=bb)

    # Normal baseline IPs + one brute-force / scanner IP spiking 401/403 and request volume
    log_entries = []
    for i in range(10):
        log_entries.append({"ip": f"198.51.100.{i + 1}", "status": 200, "path": "/index.html", "ua": "Mozilla/5.0"})
    for _ in range(60):
        log_entries.append({"ip": "203.0.113.99", "status": 401, "path": "/wp-login.php", "ua": "sqlmap/1.8"})

    result = detector.analyze_access_logs(log_entries, z_threshold=1.8)
    assert result["total_logs"] == 70
    assert result["anomalous_ip_count"] >= 1
    flagged_ips = {a["ip"] for a in result["anomalies"]}
    assert "203.0.113.99" in flagged_ips

    events = bb.get_recent(limit=10, event_type="LOG_ANOMALY_DETECTED")
    assert len(events) >= 1


# ==============================================================================
# Wave 2C: GitHub Pages Showcase & Agency Business Automation (#12, #14, #19)
# ==============================================================================

def test_project_14_automated_cobranded_portal_provisioner(tmp_path):
    from orbit_security.agency_retainer import AgencyPortalRenderer, AgencyRetainerManager

    mgr = AgencyRetainerManager(data_path=tmp_path / "retainers.json")
    docs_portals = tmp_path / "docs" / "portals"
    landing_portals = tmp_path / "landing" / "portals"

    summary = AgencyPortalRenderer.provision_all_enrolled_portals(
        manager=mgr,
        docs_dir=docs_portals,
        landing_dir=landing_portals,
    )
    assert summary["provisioned_count"] >= 4
    assert (docs_portals / "eastside-co.html").exists()
    assert (landing_portals / "eastside-co.html").exists()
    assert (docs_portals / "index.html").exists()
    assert (landing_portals / "index.html").exists()
    assert (docs_portals / "eastside-co.html").read_text(encoding="utf-8") == (
        landing_portals / "eastside-co.html"
    ).read_text(encoding="utf-8")


def test_projects_12_and_19_epss_horizon_and_bounty_statuspage_ui(tmp_path):
    from orbit_security.bounty_radar import BountyScopeIngester

    ingester = BountyScopeIngester(data_path=tmp_path / "bounty_programs.json")
    snapshot = ingester.export_public_statuspage_snapshot()
    assert snapshot["total_programs"] >= 1
    assert snapshot["safe_harbor_enforced"] is True
    assert snapshot["commercial_outreach_frozen"] is True
    assert len(snapshot["programs"]) >= 1

    root = Path(__file__).resolve().parent.parent
    landing_html = (root / "landing" / "index.html").read_text(encoding="utf-8")
    docs_html = (root / "docs" / "index.html").read_text(encoding="utf-8")
    landing_js = (root / "landing" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")
    docs_js = (root / "docs" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")

    # Project #12: EPSS Probability Horizon Visualizer Widget
    assert 'id="epss-horizon-visualizer"' in landing_html
    assert "function renderEpssHorizonChart" in landing_js

    # Project #19: Public Bug Bounty Radar Statuspage on GitHub Pages
    assert 'id="bounty-radar-statuspage"' in landing_html
    assert "function initBountyRadarStatuspage" in landing_js

    assert landing_html == docs_html
    assert landing_js == docs_js
