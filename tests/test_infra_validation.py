"""Unit and syntax tests for Orbit Zero-Trust Infrastructure Provisioning Kit (TDD).

Validates:
1. Cloud-Init YAML formatting and mandatory directives.
2. Zero public ingress enforcement (UFW default deny incoming, tailscale0 only).
3. Linux systemd service sandbox directives (ProtectSystem, NoNewPrivileges, etc.).
4. Shell provisioner safety standards (set -euo pipefail, non-root user creation).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

INFRA_DIR = Path(__file__).resolve().parent.parent / "infra"
CLOUD_INIT_FILE = INFRA_DIR / "cloud_init_oracle_free.yaml"
PROVISION_SCRIPT = INFRA_DIR / "provision_zero_trust_node.sh"


def test_cloud_init_file_exists():
    assert CLOUD_INIT_FILE.exists(), f"Missing cloud-init template at {CLOUD_INIT_FILE}"
    assert PROVISION_SCRIPT.exists(), f"Missing provision script at {PROVISION_SCRIPT}"


def test_cloud_init_content_structure():
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    assert content.startswith("#cloud-config"), "Cloud-Init must start with #cloud-config header"

    data = yaml.safe_load(content)
    assert isinstance(data, dict), "Cloud-init must parse to a valid YAML dictionary"
    assert "packages" in data
    assert "users" in data
    assert "write_files" in data
    assert "runcmd" in data

    users = [u["name"] for u in data["users"] if isinstance(u, dict) and "name" in u]
    assert "orbit" in users


def test_zero_ingress_firewall_rules():
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    # Ingress must be default deny
    assert "ufw default deny incoming" in content
    assert "ufw default deny incoming" in script

    # Only tailscale0 should be allowed in
    assert "ufw allow in on tailscale0" in content
    assert "ufw allow in on tailscale0" in script

    # Public ports 22, 80, 443 must NOT have open incoming rules
    assert "ufw allow 22" not in content
    assert "ufw allow 80" not in content
    assert "ufw allow 443" not in content
    assert "ufw allow 22" not in script
    assert "ufw allow 80" not in script
    assert "ufw allow 443" not in script


def test_systemd_hardening_directives():
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    required_directives = [
        "ProtectSystem=strict",
        "ProtectHome=true",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectKernelTunables=true",
        "ProtectControlGroups=true",
        "ProtectKernelModules=true",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "RestrictRealtime=true",
        "CapabilityBoundingSet=",
        "LockPersonality=true",
        "User=orbit",
        "Group=orbit",
    ]

    for directive in required_directives:
        assert directive in content, f"Missing systemd directive in cloud-init: {directive}"
        assert directive in script, f"Missing systemd directive in shell script: {directive}"


def test_shuttle_service_unit():
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "orbit-shuttle.service" in content
    assert "orbit-shuttle.service" in script
    assert "orbit_security.event_shuttle --daemon" in content
    assert "orbit_security.event_shuttle --daemon" in script
    assert "Environment=PYTHONPATH=/opt/orbit-security/src" in content
    assert "Environment=PYTHONPATH=/opt/orbit-security/src" in script
    assert "pip install -e /opt/orbit-security" in content or "pip install -e \"${ORBIT_INSTALL_DIR}\"" in script


def test_shell_script_defensive_flags():
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "ARCH=$(uname -m)" in script


def test_environment_file_and_deploy_oracle_sentinel_renderer(tmp_path):
    """Verifies EnvironmentFile wiring and Oracle ARM64 cloud-init bundle rendering."""
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "EnvironmentFile=-/etc/default/orbit-security" in content
    assert "EnvironmentFile=-/etc/default/orbit-security" in script

    from orbit_security.tools.deploy_oracle_sentinel import render_oracle_cloud_init

    out_yaml = tmp_path / "rendered_cloud_init.yaml"
    meta = render_oracle_cloud_init(
        cockpit_host="100.88.42.10",
        cockpit_port=9090,
        shuttle_secret="custom-hmac-secret-999",
        node_id="oracle-arm64-prod-1",
        tailscale_authkey="tskey-auth-test12345",
        output_path=out_yaml,
    )

    assert out_yaml.exists()
    assert meta["target_url"] == "http://100.88.42.10:9090/api/orbit/blackboard/shuttle"
    assert meta["shape"] == "VM.Standard.A1.Flex"
    assert meta["ocpus"] == 4
    assert meta["memory_gb"] == 24

    rendered_text = out_yaml.read_text(encoding="utf-8")
    parsed = yaml.safe_load(rendered_text)
    assert isinstance(parsed, dict)
    assert "http://100.88.42.10:9090/api/orbit/blackboard/shuttle" in rendered_text
    assert "oracle-arm64-prod-1" in rendered_text

