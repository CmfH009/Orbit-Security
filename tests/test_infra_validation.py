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

INFRA_DIR = Path(__file__).resolve().parent.parent / "infra"
CLOUD_INIT_FILE = INFRA_DIR / "cloud_init_oracle_free.yaml"
PROVISION_SCRIPT = INFRA_DIR / "provision_zero_trust_node.sh"


def test_cloud_init_file_exists():
    assert CLOUD_INIT_FILE.exists(), f"Missing cloud-init template at {CLOUD_INIT_FILE}"
    assert PROVISION_SCRIPT.exists(), f"Missing provision script at {PROVISION_SCRIPT}"


def test_cloud_init_content_structure():
    content = CLOUD_INIT_FILE.read_text(encoding="utf-8")
    assert content.startswith("#cloud-config"), "Cloud-Init must start with #cloud-config header"
    assert "packages:" in content
    assert "ufw" in content
    assert "tailscale" in content
    assert "users:" in content
    assert "orbit" in content


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
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "User=orbit",
        "Group=orbit",
    ]

    for directive in required_directives:
        assert directive in content, f"Missing systemd directive in cloud-init: {directive}"
        assert directive in script, f"Missing systemd directive in shell script: {directive}"


def test_shell_script_defensive_flags():
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "ARCH=$(uname -m)" in script
