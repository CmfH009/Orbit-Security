# Orbit Sprint 1: Foundation & High-ROI Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 1 Sprint 1 high-ROI automation for Project ORBIT, comprising a hardened Cloud Run zero-tunnel telemetry receiver, a 1-command remediation CLI (`orbit remediate <domain>`), 1-click Discord alert triggers, and an interactive subdomain takeover proof-of-concept playground.

**Architecture:** Enhances `radar_telemetry.py` to auto-detect read-only container runtimes (Cloud Run) and serve interactive action webhooks alongside permanent HTTPS fallbacks; expands `remediation.py` and `cli.py` to compile full DNS/Terraform/BIND/PDF fix packages from the terminal; upgrades Discord webhook alerts with rich Action Row link buttons and HMAC-validated execution hooks; and deploys an interactive 35-provider subdomain takeover verification playground in both CLI and GhostDNS web terminal.

**Tech Stack:** Python 3.13, dnspython, reportlab, httpx, pytest, vanilla JS (RFC-8484 DoH), Docker / Google Cloud Run, Tailwind CSS.

**Spec:** [ORBIT_30_OBJECTIVE_MASTER_ROADMAP.md](file:///A:/knowledge/specs/ORBIT_30_OBJECTIVE_MASTER_ROADMAP.md) (Objectives #1, #6, #10, #12).

## Global Constraints

- Zero regression against the 21 existing tests in `tests/test_radar_telemetry.py`.
- Strict preservation of `COMMERCIAL_OUTREACH_FROZEN = True` invariant (no automated external email delivery).
- Strict byte-identical parity between `landing/` and `docs/` verified by `python scripts/sync_landing_to_docs.py --check`.
- Distroless read-only filesystem compatibility (Cloud Run runs with `readOnlyRootFilesystem: true`, non-root user 65532).
- Zero reliance on external paid API keys for primary flows; all DNS resolution routes through RFC 8484 DoH or local dnspython resolvers.

---

### Task 1: Cloud Run Telemetry Receiver Hardening & Read-Only /tmp Safe Mode

**Files:**
- Modify: `src/orbit_security/radar_telemetry.py`
- Modify: `landing/assets/orbit_radar.js`
- Test: `tests/test_cloudrun_telemetry.py`

**Interfaces:**
- Consumes: `os.environ.get("PORT")`, `os.environ.get("ORBIT_DATA_DIR")`, `os.environ.get("K_SERVICE")`.
- Produces: `get_effective_data_dir() -> Path`, `/api/health` (zero-disk fast probe), `/api/orbit/radar/config` (JSON health + environment descriptors).

- [ ] **Step 1: Write the failing test**

Create `tests/test_cloudrun_telemetry.py`:
```python
import os
import tempfile
from pathlib import Path
import pytest
from orbit_security.radar_telemetry import (
    get_effective_data_dir,
    RadarTelemetryService,
    RadarTelemetryHandler,
)


def test_get_effective_data_dir_respects_env_var(monkeypatch, tmp_path):
    custom_dir = tmp_path / "custom_data"
    custom_dir.mkdir()
    monkeypatch.setenv("ORBIT_DATA_DIR", str(custom_dir))
    effective = get_effective_data_dir()
    assert effective == custom_dir
    assert effective.exists()


def test_get_effective_data_dir_fallback_on_readonly(monkeypatch, tmp_path):
    # Simulate read-only path by setting an unwriteable directory
    readonly_dir = tmp_path / "readonly_mock"
    readonly_dir.mkdir()
    # Remove write permissions
    os.chmod(readonly_dir, 0o444)
    monkeypatch.setattr("orbit_security.radar_telemetry.DATA_DIR", readonly_dir)
    monkeypatch.delenv("ORBIT_DATA_DIR", raising=False)

    try:
        effective = get_effective_data_dir()
        assert effective != readonly_dir
        assert effective.exists()
        test_file = effective / "write_test.tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
    finally:
        os.chmod(readonly_dir, 0o777)


def test_radar_config_endpoint_returns_json():
    handler = RadarTelemetryHandler.__new__(RadarTelemetryHandler)
    config = handler._build_server_config()
    assert config["service"] == "orbit-radar-telemetry"
    assert "version" in config
    assert "env" in config
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloudrun_telemetry.py -v`
Expected: FAIL with `ImportError: cannot import name 'get_effective_data_dir'` or `AttributeError: type object 'RadarTelemetryHandler' has no attribute '_build_server_config'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/radar_telemetry.py`:
```python
def get_effective_data_dir() -> Path:
    """Returns the writable data directory for radar telemetry logs.

    Detects read-only filesystems (such as Google Cloud Run containers with
    readOnlyRootFilesystem=true) and automatically falls back to /tmp/orbit_data.
    """
    env_dir = os.environ.get("ORBIT_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Test default DATA_DIR writability
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        test_file = DATA_DIR / f".write_test_{os.getpid()}.tmp"
        test_file.write_text("test", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return DATA_DIR
    except (OSError, PermissionError):
        fallback = Path("/tmp/orbit_data") if os.name != "nt" else Path(tempfile.gettempdir()) / "orbit_data"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback
```

Update `DEFAULT_QUERIES_FILE` and initialization in `RadarTelemetryService` to use `get_effective_data_dir()`.
In `RadarTelemetryHandler`:
Add `_build_server_config(self)`:
```python
    @classmethod
    def _build_server_config(cls) -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": "orbit-radar-telemetry",
            "version": "2.4.0",
            "env": "cloudrun" if os.environ.get("K_SERVICE") else "standalone",
            "zero_tunnel": True,
            "data_dir": str(get_effective_data_dir()),
        }
```
And handle `GET /api/orbit/radar/config` in `do_GET`.

In `landing/assets/orbit_radar.js` (lines 858-860), prepend the permanent Cloud Run endpoint before the ephemeral tunnel:
```javascript
            // 3. Permanent Zero-Tunnel Cloud Edge & Live HTTPS Tunnel
            if (window.ORBIT_LIVE_CLOUD_ENDPOINT) addEp(window.ORBIT_LIVE_CLOUD_ENDPOINT);
            addEp('https://orbit-security-api-911438991206.us-central1.run.app/api/orbit/radar/telemetry');
            if (window.ORBIT_LIVE_TUNNEL_ENDPOINT) addEp(window.ORBIT_LIVE_TUNNEL_ENDPOINT);
            addEp('https://fc1acb6485846d.lhr.life/api/orbit/radar/telemetry');
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cloudrun_telemetry.py -v`
Expected: PASS with 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/radar_telemetry.py landing/assets/orbit_radar.js tests/test_cloudrun_telemetry.py
git commit -m "feat(telemetry): harden Cloud Run receiver with read-only fallback and permanent endpoint"
```

---

### Task 2: Automated Discord Alert Embed with 1-Click "Generate Client Retainer" Trigger

**Files:**
- Modify: `src/orbit_security/radar_telemetry.py`
- Test: `tests/test_discord_action_trigger.py`

**Interfaces:**
- Consumes: `format_discord_radar_embed(record, enrichment, proposal, base_url)`, `RadarRetainerProposalStager.stage_campaign(domain)`.
- Produces: Discord Action Row components (`type: 1`) with Link Buttons (`type: 2`, `style: 5`), and `/api/orbit/radar/action` endpoint handling `stage_retainer`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_discord_action_trigger.py`:
```python
import json
import pytest
from orbit_security.radar_telemetry import (
    format_discord_radar_embed,
    generate_action_token,
    verify_action_token,
    RadarTelemetryHandler,
)


def test_format_discord_radar_embed_contains_action_components():
    record = {"domain": "smartmouseco.com", "score": 85, "grade": "B", "trigger_source": "radar_submit"}
    enrichment = {"registrar": "GoDaddy", "tech_stack": ["Shopify"]}
    base_url = "https://orbit-security-api.run.app"
    
    payload = format_discord_radar_embed(record, enrichment=enrichment, base_url=base_url)
    
    assert "components" in payload
    assert len(payload["components"]) > 0
    action_row = payload["components"][0]
    assert action_row["type"] == 1
    buttons = action_row["components"]
    assert len(buttons) >= 2
    assert any("Generate Retainer" in b["label"] or "Stage Retainer" in b["label"] for b in buttons)
    retainer_btn = next(b for b in buttons if "Retainer" in b["label"])
    assert "action=stage_retainer" in retainer_btn["url"]
    assert "domain=smartmouseco.com" in retainer_btn["url"]


def test_action_token_generation_and_verification():
    domain = "testbrand.com"
    token = generate_action_token(domain, action="stage_retainer")
    assert isinstance(token, str)
    assert len(token) > 0
    assert verify_action_token(domain, action="stage_retainer", token=token) is True
    assert verify_action_token(domain, action="stage_retainer", token="invalid") is False
    assert verify_action_token("otherdomain.com", action="stage_retainer", token=token) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_discord_action_trigger.py -v`
Expected: FAIL with `ImportError: cannot import name 'generate_action_token'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/radar_telemetry.py`:
```python
ACTION_SIGNING_SALT = os.environ.get("ORBIT_ACTION_SALT", "orbit-action-secret-v1")


def generate_action_token(domain: str, action: str = "stage_retainer") -> str:
    """Generates a keyed HMAC-SHA256 signature for 1-click webhook action triggers."""
    msg = f"{action}:{domain.lower().strip()}"
    return hmac.new(ACTION_SIGNING_SALT.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def verify_action_token(domain: str, action: str, token: str) -> bool:
    """Validates an action token in constant time."""
    if not token or not domain:
        return False
    expected = generate_action_token(domain, action)
    return hmac.compare_digest(expected, token)
```

In `format_discord_radar_embed()`:
Add parameter `base_url: Optional[str] = None` (defaults to `https://orbit-security-api-911438991206.us-central1.run.app`).
Compute action token:
```python
    target_base = base_url or os.environ.get("ORBIT_LIVE_CLOUD_ENDPOINT", "https://orbit-security-api-911438991206.us-central1.run.app")
    action_token = generate_action_token(domain, "stage_retainer")
    stage_action_url = f"{target_base}/api/orbit/radar/action?action=stage_retainer&domain={domain}&token={action_token}"
    radar_url = f"https://cmfh009.github.io/Orbit-Security/?target={domain}"
    fleet_url = f"https://cmfh009.github.io/Orbit-Security/fleet.html?domain={domain}"

    # Also add clickable markdown link into embed description
    embed["description"] = (
        f"⚡ **[1-Click Stage Retainer Proposal]({stage_action_url})** • "
        f"🛡️ **[Open Terminal Radar]({radar_url})** • "
        f"🌐 **[Fleet Command]({fleet_url})**"
    )

    components = [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 5,  # Link button
                    "label": "⚡ Generate Client Retainer",
                    "url": stage_action_url,
                },
                {
                    "type": 2,
                    "style": 5,
                    "label": "🛡️ Open Terminal Radar",
                    "url": radar_url,
                },
                {
                    "type": 2,
                    "style": 5,
                    "label": "🌐 Fleet Command",
                    "url": fleet_url,
                },
            ],
        }
    ]
    payload["components"] = components
```

In `RadarTelemetryHandler.do_GET`:
Add routing for `/api/orbit/radar/action`:
```python
        if parsed.path in ("/api/orbit/radar/action", "/api/radar/action"):
            params = urllib.parse.parse_qs(parsed.query)
            action = params.get("action", [""])[0]
            domain = params.get("domain", [""])[0]
            token = params.get("token", [""])[0]

            if not verify_action_token(domain, action, token):
                self._send_json_error(403, "Invalid or expired action token")
                return

            if action == "stage_retainer":
                stager = RadarRetainerProposalStager()
                result = stager.stage_campaign(domain=domain)
                enricher = RadarLeadEnricher()
                enrichment = enricher.enrich_domain(domain=domain)
                response = {
                    "status": "ok",
                    "action": "stage_retainer",
                    "domain": domain,
                    "deliverables": result,
                    "message": f"Retainer campaign successfully staged for {domain}",
                }
                body = json.dumps(response, indent=2).encode("utf-8")
                self.send_cors_headers(200, "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_discord_action_trigger.py -v`
Expected: PASS with 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/radar_telemetry.py tests/test_discord_action_trigger.py
git commit -m "feat(discord): add 1-click client retainer action buttons and signed action endpoint"
```

---

### Task 3: Terminal CLI & TUI Instant Remediation (`orbit-security remediate <domain>`)

**Files:**
- Modify: `src/orbit_security/remediation.py`
- Modify: `src/orbit_security/cli.py`
- Modify: `A:\bin\orbit-security.cmd`
- Modify: `A:\system\bin\orbit.cmd`
- Test: `tests/test_cli_remediation.py`

**Interfaces:**
- Consumes: `DnsRemediationGenerator`, `ReportGenerator.generate_pdf(audit_result, ...)`
- Produces: `DnsRemediationGenerator.generate_full_package(domain, ...) -> Dict[str, Any]`, `cli.py remediate` subcommand.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_remediation.py`:
```python
from pathlib import Path
import pytest
from orbit_security.remediation import DnsRemediationGenerator


def test_generate_full_package_creates_all_files(tmp_path):
    domain = "testremediate.com"
    out_dir = tmp_path / "campaign_out"
    
    pkg = DnsRemediationGenerator.generate_full_package(
        domain=domain,
        output_dir=out_dir,
        policy="quarantine",
        report_email="security@testremediate.com",
        generate_pdf=False,
    )
    
    assert pkg["domain"] == domain
    assert (out_dir / "remediation.zone").exists()
    assert (out_dir / "remediation.tf").exists()
    assert (out_dir / "security.txt").exists()
    assert (out_dir / "remediation_summary.txt").exists()
    
    zone_content = (out_dir / "remediation.zone").read_text(encoding="utf-8")
    assert "v=DMARC1" in zone_content
    assert "v=spf1" in zone_content
    
    tf_content = (out_dir / "remediation.tf").read_text(encoding="utf-8")
    assert 'resource "cloudflare_record"' in tf_content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_remediation.py -v`
Expected: FAIL with `AttributeError: type object 'DnsRemediationGenerator' has no attribute 'generate_full_package'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/remediation.py`:
Add `generate_bind_zone_file(domain, dmarc_val, spf_val, caa_vals)` and `generate_full_package()`:
```python
    @classmethod
    def generate_full_package(
        cls,
        domain: str,
        output_dir: Optional[Path] = None,
        policy: str = "quarantine",
        report_email: Optional[str] = None,
        generate_pdf: bool = False,
    ) -> Dict[str, Any]:
        """Generates all 5 remediation deliverables: .zone, .tf, security.txt, summary.txt, and PDF."""
        out = output_dir or (Path("outbound_campaigns") / domain.replace(".", "_"))
        out.mkdir(parents=True, exist_ok=True)

        dmarc_snippets = cls.generate_dmarc_fix(domain, policy=policy, report_email=report_email)
        spf_snippets = cls.generate_spf_fix(domain, hard_fail=True)
        caa_snippets = cls.generate_caa_fix(domain, alert_email=report_email)
        sec_txt = cls.generate_security_txt(domain, contact_email=report_email)

        # 1. BIND Zone File (Cloudflare DNS 1-click importable)
        zone_lines = [
            f"; Orbit Security RFC 1035 BIND Zone Remediation File for {domain}",
            f"; Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            "$ORIGIN " + domain + ".",
            "$TTL 300",
            f'_dmarc\tIN\tTXT\t{dmarc_snippets[0].record_value}',
            f'@\tIN\tTXT\t{spf_snippets[0].record_value}',
            f'@\tIN\tCAA\t0 issue "letsencrypt.org"',
            f'@\tIN\tCAA\t0 issue "digicert.com"',
        ]
        zone_path = out / "remediation.zone"
        zone_path.write_text("\n".join(zone_lines) + "\n", encoding="utf-8")

        # 2. Terraform HCL
        tf_blocks = [
            "# Orbit Security: Terraform DNS Remediation Blueprint",
            dmarc_snippets[0].terraform_hcl,
            spf_snippets[0].terraform_hcl,
            caa_snippets[0].terraform_hcl,
        ]
        tf_path = out / "remediation.tf"
        tf_path.write_text("\n\n".join(tf_blocks) + "\n", encoding="utf-8")

        # 3. security.txt
        sec_path = out / "security.txt"
        sec_path.write_text(sec_txt, encoding="utf-8")

        # 4. remediation_summary.txt
        summary_lines = [
            f"=== ORBIT SECURITY REMEDIATION BLUEPRINT: {domain} ===",
            f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            "",
            "1. DMARC POLICY ENFORCEMENT:",
            f"   Record: _dmarc.{domain} TXT {dmarc_snippets[0].record_value}",
            f"   Action: {dmarc_snippets[0].instructions}",
            "",
            "2. SPF STRICT HARD-FAIL:",
            f"   Record: {domain} TXT {spf_snippets[0].record_value}",
            f"   Action: {spf_snippets[0].instructions}",
            "",
            "3. CAA RESTRICTION:",
            f"   Record: {domain} CAA 0 issue \"letsencrypt.org\"",
            "",
            "Files Generated:",
            f" - {zone_path.name} (BIND zone file importable in Cloudflare DNS)",
            f" - {tf_path.name} (Terraform HCL infrastructure-as-code)",
            f" - {sec_path.name} (RFC 9116 security policy)",
        ]
        summary_path = out / "remediation_summary.txt"
        summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

        # 5. Optional PDF report
        pdf_path = None
        if generate_pdf:
            try:
                from orbit_security.reporter import ReportGenerator
                from orbit_security.models import DomainAuditResult, VulnerabilityFinding, Severity
                pdf_file = out / f"{domain.replace('.', '_')}_dns_remediation.pdf"
                dummy_audit = DomainAuditResult(
                    domain=domain,
                    score=75,
                    grade="C",
                    findings=[
                        VulnerabilityFinding(
                            title="Missing DMARC Policy Enforcement",
                            severity=Severity.HIGH,
                            description=f"Domain {domain} lacks strict DMARC quarantine/reject policy.",
                            remediation=dmarc_snippets[0].instructions,
                            evidence="p=none or missing",
                        )
                    ],
                )
                ReportGenerator.generate_pdf(dummy_audit, output_path=pdf_file)
                pdf_path = pdf_file
            except Exception as e:
                logger.warning(f"Failed to generate remediation PDF: {e}")

        return {
            "domain": domain,
            "output_dir": str(out),
            "zone_file": str(zone_path),
            "terraform_file": str(tf_path),
            "security_txt": str(sec_path),
            "summary_file": str(summary_path),
            "pdf_file": str(pdf_path) if pdf_path else None,
        }
```

In `src/orbit_security/cli.py`:
Add `remediate` subparser:
```python
    rem_parser = subparsers.add_parser("remediate", help="Generate instant 1-click DNS remediation package & PDF")
    rem_parser.add_argument("domain", help="Target domain to remediate")
    rem_parser.add_argument("--output-dir", help="Directory to save generated remediation artifacts")
    rem_parser.add_argument("--policy", choices=["quarantine", "reject"], default="quarantine", help="DMARC policy")
    rem_parser.add_argument("--email", help="DMARC/security.txt reporting email")
    rem_parser.add_argument("--pdf", action="store_true", default=True, help="Generate executive remediation PDF")
```
And dispatch in `main()`:
```python
    elif args.command == "remediate":
        from orbit_security.remediation import DnsRemediationGenerator
        out_dir = Path(args.output_dir) if args.output_dir else None
        res = DnsRemediationGenerator.generate_full_package(
            domain=args.domain,
            output_dir=out_dir,
            policy=args.policy,
            report_email=args.email,
            generate_pdf=args.pdf,
        )
        print(f"[+] Remediation package generated for {args.domain} in {res['output_dir']}:")
        print(f"    - BIND Zone:      {res['zone_file']}")
        print(f"    - Terraform:      {res['terraform_file']}")
        print(f"    - security.txt:   {res['security_txt']}")
        if res.get("pdf_file"):
            print(f"    - Executive PDF:  {res['pdf_file']}")
```

In `A:\bin\orbit-security.cmd`:
Add `if /i "%~1"=="remediate" goto :do_cli`.
In `A:\system\bin\orbit.cmd`:
Add `if /i "%ARG1%"=="remediate" goto :do_remediate`, delegating to `orbit-security remediate %*`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_remediation.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/remediation.py src/orbit_security/cli.py tests/test_cli_remediation.py
git commit -m "feat(cli): add orbit-security remediate command with BIND, Terraform, security.txt and PDF exports"
```

---

### Task 4: Subdomain Takeover Exploit Proof-of-Concept Playground

**Files:**
- Modify: `src/orbit_security/cli.py`
- Modify: `landing/ghostdns/index.html`
- Modify: `docs/ghostdns/index.html`
- Test: `tests/test_takeover_playground.py`

**Interfaces:**
- Consumes: `SAAS_TAKEOVER_SIGNATURES`, `SaasSignature.detect_fingerprint(html)`
- Produces: `orbit-security takeover-poc <subdomain>` and interactive GhostDNS playground with multi-subdomain scanning & safe non-destructive curl verification proofs.

- [ ] **Step 1: Write the failing test**

Create `tests/test_takeover_playground.py`:
```python
import pytest
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES


def test_takeover_signatures_contain_key_providers():
    providers = {sig.saas_provider.lower(): sig for sig in SAAS_TAKEOVER_SIGNATURES}
    assert "github pages" in providers or "github" in providers
    assert "aws s3" in providers or "amazon s3" in providers
    assert "shopify" in providers
    assert "webflow" in providers


def test_simulate_takeover_poc_generation():
    from orbit_security.cli import generate_takeover_poc_proof
    
    subdomain = "shop.acmebrand.com"
    cname_target = "shops.myshopify.com"
    poc = generate_takeover_poc_proof(subdomain, cname_target=cname_target, provider="Shopify")
    
    assert poc["subdomain"] == subdomain
    assert poc["cname_target"] == cname_target
    assert "curl -sI" in poc["curl_command"]
    assert "Host: shop.acmebrand.com" in poc["curl_command"]
    assert "remediation" in poc
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_takeover_playground.py -v`
Expected: FAIL with `ImportError: cannot import name 'generate_takeover_poc_proof' from 'orbit_security.cli'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/cli.py`:
```python
def generate_takeover_poc_proof(subdomain: str, cname_target: str, provider: str = "Unknown") -> Dict[str, Any]:
    """Generates a harmless, non-destructive proof-of-concept verification script and remediation block."""
    from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES
    matched_sig = next(
        (s for s in SAAS_TAKEOVER_SIGNATURES if s.saas_provider.lower() in provider.lower() or any(c in cname_target for c in s.cname_fingerprints)),
        None,
    )
    expected_status = matched_sig.status_code if matched_sig else 404
    pattern = matched_sig.response_fingerprints[0] if (matched_sig and matched_sig.response_fingerprints) else "Not Found"

    curl_cmd = f'curl -sI -k -H "Host: {subdomain}" "https://{cname_target}"'
    return {
        "subdomain": subdomain,
        "cname_target": cname_target,
        "provider": matched_sig.saas_provider if matched_sig else provider,
        "expected_status": expected_status,
        "signature_pattern": pattern,
        "curl_command": curl_cmd,
        "remediation": f"Delete DNS record '{subdomain} CNAME {cname_target}' immediately or claim in {provider}.",
        "safe_harbor_notice": "Non-destructive passive audit verification only. Do not claim unauthorized resources.",
    }
```
Add `takeover-poc` subparser to `cli.py` calling `generate_takeover_poc_proof()`.

In `landing/ghostdns/index.html`:
Enhance the interactive script (lines 400-500) to:
1. Support scanning 10 common subdomains (`shop`, `store`, `blog`, `promo`, `app`, `dev`, `status`, `help`, `billing`, `staging`) in parallel via RFC 8484 DoH.
2. Render an interactive **"Subdomain Takeover Exploit Proof-of-Concept Playground"** table with:
   - Subdomain name & CNAME destination.
   - Matched SaaS provider & risk indicator (`● SECURE` or `⚠️ DANGLING // UNCLAIMED`).
   - Copyable safe verification command: `curl -sI -H "Host: {subdomain}" https://{target}`.
   - 1-click BIND `.zone` / Terraform removal snippet.
Sync `landing/ghostdns/index.html` to `docs/ghostdns/index.html` via `python scripts/sync_landing_to_docs.py --apply`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_takeover_playground.py -v`
Expected: PASS.
Run: `python scripts/sync_landing_to_docs.py --check`
Expected: Parity OK (89/89 identical).

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/cli.py landing/ghostdns/index.html docs/ghostdns/index.html tests/test_takeover_playground.py
git commit -m "feat(playground): add subdomain takeover exploit POC playground to CLI and GhostDNS web terminal"
```

---

### Task 5: End-to-End Regression & Parity Verification

**Files:**
- Test: All suites across `orbit_security`

- [ ] **Step 1: Run complete test suite**

Run: `pytest tests/ -v -k "telemetry or remediation or takeover or cloudrun or discord"`
Expected: 100% PASS across all 5 test files.

- [ ] **Step 2: Run AST code sentinel check**

Run: `python src/orbit_security/ast_sentinel.py --check src`
Expected: 0 syntax or security violations.

- [ ] **Step 3: Run landing/docs parity guard**

Run: `python scripts/sync_landing_to_docs.py --check`
Expected: 89 shared files identical, 0 drift.

- [ ] **Step 4: Final verification commit & status log**

```bash
git status
```
