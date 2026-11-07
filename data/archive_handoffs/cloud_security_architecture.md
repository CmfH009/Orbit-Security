# 🛡️ Orbit Security: 24/7 Autonomous Cloud Security Architecture

## Executive Summary
In light of modern AI agent CVE attacks, supply chain exploits, and automated internet-wide port scans, **Project Orbit** adopts a **Zero-Trust, Zero-Listening-Port, Ephemeral-First** cloud architecture for 24/7 autonomous security operations.

This document details the threat model, mitigation controls, and operational configurations that guarantee autonomous operation in the cloud with zero risk of remote code execution (RCE), credential exfiltration, or lateral movement.

---

## 🥷 2026 Threat Modeling: AI Agent CVE Vectors & Defenses

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ORBIT DEFENSE-IN-DEPTH MATRIX                      │
├───────────────────────────────┬─────────────────────────────────────────────┤
│ 2026 Threat / Attack Vector   │ Orbit Architectural Defense                 │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 1. Port Probing / Shodan RCE  │ ZERO Public Listening Ports (Pull-Only &    │
│    (Open Webhook/FastAPI Vuln)│ Ephemeral GitHub Actions / Tailscale VPN)   │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 2. Indirect Prompt Injection  │ Deterministic Input Sanitizer               │
│    (Malicious security.txt)   │ (Regex validation, prompt injection filter) │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 3. Container Escapes & Shell  │ Distroless Non-Root Runtime                 │
│    Command Injection          │ (No /bin/sh, no package managers, UID 65532)│
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 4. Supply Chain / PyPI CVEs   │ Automated pip-audit & Frozen uv.lock        │
│                               │ (Build blocks on any known CVE vulnerability)│
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 5. Credential Exfiltration    │ Ephemeral Workload Identity Federation (WIF)│
│                               │ (No long-lived API keys on disk)            │
└───────────────────────────────┴─────────────────────────────────────────────┘
```

---

## ☁️ Tier 1: Ephemeral 24/7 Cloud Sentinel (GitHub Actions)
* **Configuration**: [`.github/workflows/orbit-247-autonomous-sentinel.yml`](../.github/workflows/orbit-247-autonomous-sentinel.yml)
* **Schedule**: Runs every 4 hours (`cron: '0 */4 * * *'`) on GitHub's hardened Microsoft Azure hypervisors.
* **Cost**: **$0.00 / month** (within GitHub Free 2,000 CI minutes).
* **Attack Surface**: **Literally Zero.**
  - The container boots, pulls tasks, runs audits, publishes findings, and destroys itself.
  - Zero persistent IP addresses, zero open ports for Shodan or botnets to probe.

### Execution Stages:
1. **Supply Chain Gate**: Runs `pip-audit` against installed packages to detect any newly disclosed CVEs.
2. **Invariant Testing**: Validates AST parsers and regex sanitizers via `pytest`.
3. **Perimeter Recon**: Scans tracked domains in `.orbit-targets.txt` for dangling CNAME takeovers, SPF/DMARC hygiene, and exposed sensitive files (`.git`, `.env`).
4. **Step Summary Reporting**: Directly renders the audit matrix into GitHub's UI and preserves encrypted audit logs.

---

## 🔒 Tier 2: Continuous 24/7 Cloud Daemons (Oracle Cloud Always Free / Cloud Run)

For continuous listener daemons (e.g. real-time IMAP email monitoring or webhook receivers), deployment adheres to strict zero-trust standards:

### 1. Network Boundary: Tailscale Zero Trust (No Public IP)
Never assign a public IPv4 address to the cloud VM. Access the machine and services strictly through a private **Tailscale Mesh VPN**:
* All inbound connections from the public internet are blocked (`ufw default deny incoming`).
* Only authorized devices in your Tailnet can reach the agent or blackboard endpoints (`100.x.y.z`).

### 2. Distroless Non-Root Container Sandbox
As codified in [`Dockerfile`](../Dockerfile):
```dockerfile
FROM gcr.io/distroless/python3-debian12:nonroot
USER 65532:65532
# Zero shell (/bin/sh does not exist)
# Zero package manager (no apt, no yum)
# Read-only root filesystem
```
If an adversary somehow exploits a Python vulnerability, there is **no shell binary to spawn**, no `curl`/`wget` to download malware, and no root permissions to escalate.

### 3. Hardened Linux Systemd Service (Defense in Depth)
When running directly on an Ubuntu/Debian host, the service unit enforces Linux kernel sandboxing:
```ini
[Unit]
Description=Orbit Security 24/7 Daemon
After=network.target

[Service]
Type=simple
User=orbit
Group=orbit
WorkingDirectory=/opt/orbit-security
ExecStart=/opt/orbit-security/.venv/bin/python src/orbit_security/bounty_rolling_daemon.py
Restart=always
RestartSec=10

# Hardened Linux Security Directives
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

---

## 🛡️ Input Sanitization & Indirect Injection Neutralization

External data fetched from the internet (e.g. DNS TXT records, RFC 9116 `security.txt` fields, email headers) passes through [`input_sanitizer.py`](../src/orbit_security/input_sanitizer.py):

* **RFC 1123 Hostname Enforcement**: Rejects shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`).
* **Prompt Injection Neutralizer**: Identifies and filters override instructions (`ignore all previous instructions`, `system prompt:`, `[INST]`).
* **CRLF Response Splitting Prevention**: Normalizes HTTP headers and strips control codes (`\x00` - `\x1F`).
