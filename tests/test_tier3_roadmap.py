"""TDD Test Suite for Orbit Security Tier 3 Roadmap (Projects #21 - #30).

Covers:
- Wave 3A:
  - Project #22: Autonomous Email Security SPF/DKIM/DMARC Policy Analyzer (cloud_sentinels.py)
  - Project #25: Dynamic Bandwidth & Network Failure Resiliency Engine (network_bonding.py)
  - Project #26: Multi-Cloud Cloud-Init Matrix (AWS / GCP / DigitalOcean / Oracle) (deploy_oracle_sentinel.py & infra/cloud_init_multi_cloud_matrix.yaml)
  - Project #27: Autonomous Bug Bounty Program Scope Parser (HackerOne / Bugcrowd) (bounty_radar.py)
- Wave 3B:
  - Project #23: Interactive Executive Triage Modal in Cockpit HUD (bounty_triage_copilot.py)
  - Project #24: Automated CISA KEV Pull Request Security Reviewer (github_sentinel.py)
  - Project #28: Local Audio DSP Threat Telegraphs for Workstation (threat_radar.py)
  - Project #29: Retro TUI Cockpit Terminal Mode for SSH / Termux (blackboard.py)
  - Project #30: Automated Release Packager & GitHub Showcase DevOps Sentinel (github_sentinel.py)
- Wave 3C:
  - Project #21: 32-bit Cyber Arcade CRT Shader Canvas for Public Web (landing/index.html & orbit_radar.js)
"""

from __future__ import annotations

from pathlib import Path
import pytest

from orbit_security.blackboard import Blackboard


# ==============================================================================
# Wave 3A: Cloud Autonomy, Email Policy, Resiliency & Multi-Cloud Matrix (#22, #25, #26, #27)
# ==============================================================================

def test_project_22_email_security_spf_dkim_dmarc_analyzer(tmp_path):
    from orbit_security.cloud_sentinels import EmailAuthPolicyAnalyzer

    bb = Blackboard(db_path=tmp_path / "email_bb.db")

    # 1. Vulnerable domain: SPF +all, >10 lookups, DMARC p=none without rua, no DKIM
    vuln = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="spoofable-brand.com",
        spf_record="v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com +all",
        dmarc_record="v=DMARC1; p=none; pct=50",
        dkim_selectors={},
        mta_sts_record=None,
        bimi_record=None,
        blackboard=bb,
    )
    assert vuln["spoofable"] is True
    assert vuln["severity"] == "CRITICAL"
    codes = {f["code"] for f in vuln["findings"]}
    assert "SPF_PERMISSIVE_PLUS_ALL" in codes
    assert "SPF_LOOKUP_LIMIT_EXCEEDED" in codes
    assert "DMARC_POLICY_NONE" in codes
    assert "DKIM_NO_VALID_SELECTORS" in codes

    events = bb.get_recent(limit=10, event_type="EMAIL_AUTH_POSTURE_EVALUATED")
    assert len(events) == 1

    # 2. Hardened domain: SPF -all, DMARC p=reject, valid 2048-bit DKIM
    hardened = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="hardened-bank.com",
        spf_record="v=spf1 include:_spf.google.com -all",
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@hardened-bank.com; pct=100",
        dkim_selectors={"google": "v=DKIM1; k=rsa; p=" + ("A" * 360)},
        mta_sts_record="v=STSv1; id=20261025",
        bimi_record="v=BIMI1; l=https://hardened-bank.com/logo.svg",
    )
    assert hardened["spoofable"] is False
    assert hardened["severity"] == "SAFE"


def test_project_25_dynamic_bandwidth_and_network_resiliency_engine():
    from orbit_security.network_bonding import NetworkResiliencyGovernor

    gov = NetworkResiliencyGovernor(base_concurrency=32, min_concurrency=4, max_concurrency=64)
    # Record healthy low-latency probes on adapter eth0
    for _ in range(5):
        gov.record_probe_outcome("eth0", success=True, latency_ms=25.0)

    # Record degraded / failing probes on adapter wlan1
    for _ in range(5):
        gov.record_probe_outcome("wlan1", success=False, latency_ms=2500.0)

    health = gov.evaluate_transport_health()
    assert health["recommended_adapter"] == "eth0"
    assert "wlan1" in health["quarantined_adapters"]
    assert 4 <= health["recommended_concurrency"] <= 64


def test_project_26_multi_cloud_init_matrix():
    from orbit_security.tools.deploy_oracle_sentinel import export_multi_cloud_init_matrix

    root = Path(__file__).resolve().parent.parent
    matrix_yaml = root / "infra" / "cloud_init_multi_cloud_matrix.yaml"
    assert matrix_yaml.exists()

    matrix = export_multi_cloud_init_matrix(tailscale_hostname="orbit-multi-sentinel")
    assert set(matrix["providers"].keys()) >= {"oracle_arm64", "aws_graviton", "gcp_e2_micro", "digitalocean_droplet"}
    for prov, spec in matrix["providers"].items():
        assert "orbit-multi-sentinel" in spec["user_data"]
        assert "41641/udp" in spec["user_data"]



def test_project_24_automated_cisa_kev_pr_security_reviewer():
    from orbit_security.github_sentinel import GitHubPRAuditor

    auditor = GitHubPRAuditor()
    diff_with_kev = (
        "+ # Temporary debug bypass referencing CVE-2024-21887 and CVE-2021-44228\n"
        "+ log4j-core==2.14.1\n"
    )
    res = auditor.audit_pr_against_cisa_kev(diff_content=diff_with_kev)
    assert res["passed"] is False
    assert res["verdict"] == "BLOCK_CISA_KEV_EXPLOITED"
    assert "CVE-2024-21887" in res["matched_kev_cves"]


def test_project_28_local_audio_dsp_threat_telegraphs():
    from orbit_security.threat_radar import AudioDspThreatTelegraph

    telegraph = AudioDspThreatTelegraph.synthesize_threat_telegraph(
        severity="CRITICAL",
        event_type="SUBDOMAIN_TAKEOVER_DETECTED",
    )
    assert telegraph["severity"] == "CRITICAL"
    assert telegraph["base_freq_hz"] >= 600
    assert telegraph["wav_bytes"].startswith(b"RIFF")
    assert len(telegraph["wav_bytes"]) > 200


def test_project_29_retro_tui_cockpit_terminal_mode(tmp_path):
    bb = Blackboard(db_path=tmp_path / "tui_bb.db")
    bb.publish("SUBDOMAIN_TAKEOVER_DETECTED", {"domain": "promo.client.com", "service": "AWS S3"}, source="cname_sentinel")

    tui_frame = bb.render_retro_tui_dashboard(width=84)
    assert "ORBIT SECURITY // RETRO TUI COCKPIT" in tui_frame
    assert "SUBDOMAIN_TAKEOVER_DETECTED" in tui_frame
    assert "OUTREACH FREEZE: LOCKED" in tui_frame


def test_project_30_automated_release_packager_and_showcase_sentinel(tmp_path):
    from orbit_security.github_sentinel import GitHubDevOpsSwarm

    swarm = GitHubDevOpsSwarm()
    commits = [
        "feat(tier1): deploy CISA KEV radar and Tailscale shuttle",
        "feat(tier2): add Litestream WAL replication and AST security matrix",
        "fix(tier3): harden CISA KEV PR reviewer",
    ]
    bundle = swarm.package_verified_release_bundle(
        version="2.0.0",
        commits=commits,
        test_count=88,
        output_dir=tmp_path,
    )
    assert bundle["ok"] is True
    assert bundle["version"] == "2.0.0"
    assert Path(bundle["manifest_path"]).exists()
    assert Path(bundle["changelog_path"]).exists()
    assert Path(bundle["badge_svg_path"]).exists()
    assert len(bundle["sha256_digest"]) == 64


# ==============================================================================
# Wave 3C: 32-Bit Cyber Arcade CRT Shader Canvas for Public Web (#21)
# ==============================================================================

def test_project_21_crt_arcade_shader_canvas_web_ui_parity():
    root = Path(__file__).resolve().parent.parent
    landing_html = (root / "landing" / "index.html").read_text(encoding="utf-8")
    docs_html = (root / "docs" / "index.html").read_text(encoding="utf-8")
    landing_labs = (root / "landing" / "labs.html").read_text(encoding="utf-8")
    docs_labs = (root / "docs" / "labs.html").read_text(encoding="utf-8")
    landing_cat_js = (root / "landing" / "assets" / "simple_cat.js").read_text(encoding="utf-8")
    docs_cat_js = (root / "docs" / "assets" / "simple_cat.js").read_text(encoding="utf-8")
    landing_js = (root / "landing" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")
    docs_js = (root / "docs" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")

    assert 'id="crt-arcade-shader-canvas"' in landing_cat_js
    assert "function initCrtArcadeShaderCanvas" in landing_js
    assert "function toggleCrtArcadeShader" in landing_js
    assert landing_html == docs_html
    assert landing_labs == docs_labs
    assert landing_cat_js == docs_cat_js
    assert landing_js == docs_js


def test_swarm_audit_adversarial_edge_cases(tmp_path):
    """Verify negative/adversarial edge-cases identified by the 5-Agent Audit Swarm."""
    from orbit_security.cloud_sentinels import EmailAuthPolicyAnalyzer
    from orbit_security.threat_radar import AudioDspThreatTelegraph

    # 1. Revoked DKIM key with trailing comment must be flagged as revoked, not valid
    revoked_posture = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="revoked-dkim.example",
        spf_record="v=spf1 include:_spf.google.com -all",
        dmarc_record="v=DMARC1; p=reject",
        dkim_selectors={
            "default": "v=DKIM1; k=rsa; p=; n=revoked_key_with_very_long_comment_exceeding_sixty_four_bytes_total_length_1234567890"
        },
    )
    assert revoked_posture["valid_dkim_selectors"] == []
    assert "DKIM_NO_VALID_SELECTORS" in {f["code"] for f in revoked_posture["findings"]}

    # 3. AudioDspThreatTelegraph MUTED profile & extreme sample_rate clamping
    muted = AudioDspThreatTelegraph.synthesize_threat_telegraph(
        severity="MUTED", sample_rate=999999
    )
    assert muted["severity"] == "MUTED"
    assert muted["sample_rate"] == 48000
    assert muted["wav_bytes"].startswith(b"RIFF")

    # 4. Retro TUI width clamping
    bb = Blackboard(db_path=tmp_path / "clamp_bb.db")
    narrow_frame = bb.render_retro_tui_dashboard(width=10)
    assert "ORBIT SECURITY // RETRO TUI COCKPIT" in narrow_frame

