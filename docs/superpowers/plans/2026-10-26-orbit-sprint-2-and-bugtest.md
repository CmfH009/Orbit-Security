# Orbit Sprint 2 & Sprint 1 Adversarial Bugtest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conduct an adversarial bugtest and hardening sweep of Sprint 1 deliverables, then implement Sprint 2 high-ROI objectives from the 30-Objective Master Roadmap: Historical Score Delta Buying-Signal Tracker (Roadmap #4), Recursive RFC 7208 SPF 10-Lookup Tree Counter & Flattening Simulator (Roadmap #5), and Downloadable Browser DNS Fix Pack Exporter (Roadmap #6).

**Architecture:** Fixes minor edge cases and token handling in Sprint 1; upgrades `radar_lead_enricher.py` with rolling 12-snapshot history and score delta detection for repeat scans; adds recursive SPF lookup tree expansion in both backend (`cloud_sentinels.py`) and frontend (`orbit_radar.js`) with an RFC 7208 fuel gauge; and deploys an in-browser `RemediationBundleBuilder` for 1-click downloads of `.tf`, BIND `.zone`, and `security.txt` bundles directly from the Radar Terminal HUD.

**Tech Stack:** Python 3.13, dnspython, reportlab, vanilla JavaScript (RFC 8484 DoH), Tailwind CSS, pytest.

**Spec:** [ORBIT_30_OBJECTIVE_MASTER_ROADMAP.md](file:///A:/knowledge/specs/ORBIT_30_OBJECTIVE_MASTER_ROADMAP.md) (Objectives #4, #5, #6).

## Global Constraints

- Strict preservation of `COMMERCIAL_OUTREACH_FROZEN = True` invariant (no automated external email delivery).
- Strict byte-identical parity between `landing/` and `docs/` verified by `python scripts/sync_landing_to_docs.py --check`.
- Zero regression against the 32 existing unit tests across `tests/test_*.py`.
- Adhere strictly to RFC 7208 SPF lookup counting (10 include/redirect/a/mx/ptr/exists limit + 2 void lookups limit).
- Non-destructive passive audit verification only (CFAA safe harbor compliance).

---

### Task 1: Adversarial Bug Testing & Hardening of Sprint 1

**Files:**
- Modify: `src/orbit_security/radar_telemetry.py`
- Modify: `src/orbit_security/remediation.py`
- Modify: `src/orbit_security/cli.py`
- Test: `tests/test_sprint1_adversarial_bugtest.py`

**Interfaces:**
- Consumes: `/api/orbit/radar/action`, `DnsRemediationGenerator.generate_full_package()`, `generate_takeover_poc_proof()`.
- Produces: Inverted enrich-then-stage execution order in `/action`, PDF inclusion in `remediation_summary.txt`, and clear CNAME fallback notices in `takeover-poc`.

- [ ] **Step 1: Write the failing adversarial test**

Create `tests/test_sprint1_adversarial_bugtest.py`:
```python
import json
import os
from pathlib import Path
import pytest
from orbit_security.radar_telemetry import (
    generate_action_token,
    verify_action_token,
    RadarTelemetryHTTPHandler,
)
from orbit_security.remediation import DnsRemediationGenerator
from orbit_security.cli import generate_takeover_poc_proof


def test_remediation_summary_lists_pdf_when_generated(tmp_path):
    domain = "fuzzbrand.com"
    out_dir = tmp_path / "fuzz_out"
    
    pkg = DnsRemediationGenerator.generate_full_package(
        domain=domain,
        output_dir=out_dir,
        generate_pdf=True,
    )
    
    summary_text = (out_dir / "remediation_summary.txt").read_text(encoding="utf-8")
    assert "remediation.zone" in summary_text
    assert "remediation.tf" in summary_text
    assert "security.txt" in summary_text
    assert ".pdf" in summary_text
    assert pkg["pdf_file"] is not None


def test_takeover_poc_handles_unresolved_cname_notice():
    subdomain = "ghost.unresolvedtarget123.com"
    poc = generate_takeover_poc_proof(subdomain, cname_target="target.unresolved.local")
    assert "safe_harbor_notice" in poc
    assert "target.unresolved.local" in poc["curl_command"]


def test_action_endpoint_tampered_token_rejection(tmp_path):
    domain = "attackertarget.com"
    valid_token = generate_action_token(domain, "stage_retainer")
    
    # Tampered domain with valid token
    assert verify_action_token("otherdomain.com", "stage_retainer", valid_token) is False
    # Tampered action with valid token
    assert verify_action_token(domain, "unauthorized_action", valid_token) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sprint1_adversarial_bugtest.py -v`
Expected: FAIL on `assert ".pdf" in summary_text`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/radar_telemetry.py` (lines 1248-1254):
Invert the call order so `enricher.enrich_domain(domain=domain)` is called before `stager.stage_campaign(domain=domain, enrichment=enrichment)`:
```python
            if action == "stage_retainer":
                enricher = RadarLeadEnricher()
                enrichment = enricher.enrich_domain(domain=domain)
                stager = RadarRetainerProposalStager()
                result = stager.stage_campaign(domain=domain, enrichment=enrichment)
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

In `src/orbit_security/remediation.py`:
Move the `remediation_summary.txt` generation after PDF compilation, and append the PDF filename to the summary files list when `pdf_path` is present:
```python
        # 4. Optional PDF report
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
                import logging
                logging.getLogger("orbit_security.remediation").warning(f"Failed to generate remediation PDF: {e}")

        # 5. remediation_summary.txt
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
        if pdf_path:
            summary_lines.append(f" - {pdf_path.name} (Executive PDF remediation audit)")

        summary_path = out / "remediation_summary.txt"
        summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
```

In `src/orbit_security/cli.py`:
In `generate_takeover_poc_proof`, when falling back to placeholder CNAME targets, include `fallback_assigned: True` and print a notice.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_sprint1_adversarial_bugtest.py -v`
Expected: PASS with 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/radar_telemetry.py src/orbit_security/remediation.py src/orbit_security/cli.py tests/test_sprint1_adversarial_bugtest.py
git commit -m "fix(sprint1): resolve deferred minors for enrich ordering, summary PDF listing, and CNAME fallback notices"
```

---

### Task 2: Historical Score Delta & Prospect Re-Scan Buying-Signal Tracker (Roadmap #4)

**Files:**
- Modify: `src/orbit_security/radar_lead_enricher.py`
- Modify: `src/orbit_security/radar_telemetry.py`
- Modify: `src/orbit_security/radar_proposal_stager.py`
- Test: `tests/test_radar_score_delta.py`

**Interfaces:**
- Consumes: `RadarLeadEnricher._save_enriched_lead(domain, profile)`
- Produces: `enrichment_history` array (up to 12 snapshots), `score_delta`, `is_buying_signal: bool`, `probe_count`, and tailored Discord buying-signal alert.

- [ ] **Step 1: Write the failing test**

Create `tests/test_radar_score_delta.py`:
```python
import json
from pathlib import Path
import pytest
from orbit_security.radar_lead_enricher import RadarLeadEnricher


def test_enricher_maintains_rolling_history_and_computes_delta(tmp_path):
    leads_file = tmp_path / "leads.json"
    enricher = RadarLeadEnricher(enriched_leads_file=leads_file)
    domain = "acmesignal.com"
    
    # First scan: score 65
    profile_1 = {"computed_score": 65, "computed_grade": "D", "dmarc_status": "none"}
    enricher._save_enriched_lead(domain, profile_1)
    
    data = json.loads(leads_file.read_text(encoding="utf-8"))
    assert domain in data
    assert len(data[domain].get("enrichment_history", [])) == 1
    assert data[domain]["enrichment_history"][0]["score"] == 65
    assert data[domain]["score_delta"] == 0
    
    # Second scan: prospect fixed DMARC, score improves to 92 (+27)
    profile_2 = {"computed_score": 92, "computed_grade": "A", "dmarc_status": "enforced"}
    enricher._save_enriched_lead(domain, profile_2)
    
    data2 = json.loads(leads_file.read_text(encoding="utf-8"))
    record = data2[domain]
    assert len(record["enrichment_history"]) == 2
    assert record["score_delta"] == 27
    assert record["previous_score"] == 65
    assert record["is_buying_signal"] is True
    assert record["probe_count"] == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_radar_score_delta.py -v`
Expected: FAIL with `KeyError: 'enrichment_history'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/radar_lead_enricher.py`:
In `_save_enriched_lead(self, domain: str, profile: Dict[str, Any])`:
```python
        existing = data.get(domain, {})
        history = list(existing.get("enrichment_history", []))

        current_score = profile.get("computed_score", 0)
        previous_score = history[-1].get("score") if history else current_score
        score_delta = current_score - (previous_score if previous_score is not None else current_score)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        snapshot = {
            "timestamp": now_iso,
            "score": current_score,
            "grade": profile.get("computed_grade", "U"),
            "dmarc_status": profile.get("dmarc_status", "unknown"),
            "spf_status": profile.get("spf_status", "unknown"),
        }
        history.append(snapshot)
        # Keep maximum 12 rolling snapshots
        history = history[-12:]

        probe_count = len(history)
        is_buying_signal = probe_count >= 2 and (score_delta > 0 or profile.get("dmarc_status") == "enforced")

        profile["enrichment_history"] = history
        profile["previous_score"] = previous_score
        profile["score_delta"] = score_delta
        profile["probe_count"] = probe_count
        profile["is_buying_signal"] = is_buying_signal

        data[domain] = profile
```

In `src/orbit_security/radar_telemetry.py` (`format_discord_radar_embed`):
When `enrich.get("is_buying_signal")` is True:
Prepend a prominent highlight to the embed title / fields:
```python
    if enrich.get("is_buying_signal"):
        delta = enrich.get("score_delta", 0)
        prev = enrich.get("previous_score", score)
        probe_n = enrich.get("probe_count", 2)
        fields.insert(0, {
            "name": "🔥 BUYING SIGNAL DETECTED",
            "value": f"**Repeat Probe #{probe_n}** • Delta: `+{delta} pts` ({prev} → {score}) | DMARC Posture Modified!",
            "inline": False,
        })
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_radar_score_delta.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/radar_lead_enricher.py src/orbit_security/radar_telemetry.py tests/test_radar_score_delta.py
git commit -m "feat(telemetry): add historical score delta and repeat-scan buying signal tracker"
```

---

### Task 3: Recursive RFC 7208 SPF 10-Lookup Tree Counter & 1-Click Flattening Simulator (Roadmap #5)

**Files:**
- Modify: `src/orbit_security/cloud_sentinels.py`
- Modify: `landing/assets/orbit_radar.js`
- Test: `tests/test_spf_tree_counter.py`

**Interfaces:**
- Consumes: `EmailAuthPolicyAnalyzer._count_spf_lookups(record, resolver)`
- Produces: Recursive lookup counter expanding `include:` and `redirect=`, detecting loops, RFC 7208 10-lookup fuel gauge, and flattened CIDR generation.

- [ ] **Step 1: Write the failing test**

Create `tests/test_spf_tree_counter.py`:
```python
import pytest
from orbit_security.cloud_sentinels import EmailAuthPolicyAnalyzer


def test_recursive_spf_tree_expansion_counts_nested_includes():
    mock_records = {
        "example.com": "v=spf1 include:_spf.nested1.com include:_spf.nested2.com -all",
        "_spf.nested1.com": "v=spf1 include:_spf.child.com -all",
        "_spf.nested2.com": "v=spf1 ip4:198.51.100.1 ~all",
        "_spf.child.com": "v=spf1 ip4:203.0.113.5 ~all",
    }
    
    def mock_resolver(domain):
        return mock_records.get(domain)

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="example.com",
        spf_record=mock_records["example.com"],
        lookup_fn=mock_resolver,
    )
    
    assert result["total_lookups"] == 3  # nested1, nested2, child
    assert result["exceeds_limit"] is False
    assert "198.51.100.1" in result["flattened_ips"]
    assert "203.0.113.5" in result["flattened_ips"]


def test_recursive_spf_tree_detects_infinite_loop():
    mock_records = {
        "loop.com": "v=spf1 include:loop2.com -all",
        "loop2.com": "v=spf1 include:loop.com -all",
    }
    
    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="loop.com",
        spf_record=mock_records["loop.com"],
        lookup_fn=lambda d: mock_records.get(d),
    )
    
    assert result["has_loop"] is True
    assert result["total_lookups"] >= 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_spf_tree_counter.py -v`
Expected: FAIL with `AttributeError: type object 'EmailAuthPolicyAnalyzer' has no attribute 'expand_spf_tree'`.

- [ ] **Step 3: Write minimal implementation**

In `src/orbit_security/cloud_sentinels.py`:
Add `expand_spf_tree(domain, spf_record, lookup_fn=None)`:
```python
    @classmethod
    def expand_spf_tree(
        cls,
        domain: str,
        spf_record: str,
        lookup_fn: Optional[Any] = None,
        max_lookups: int = 10,
    ) -> Dict[str, Any]:
        """Recursively walks RFC 7208 SPF lookup tree, counting lookups and collecting CIDRs."""
        visited: Set[str] = {domain.lower()}
        total_lookups = 0
        void_lookups = 0
        flattened_ips: List[str] = []
        has_loop = False

        def walk(rec: str):
            nonlocal total_lookups, void_lookups, has_loop
            if not rec or total_lookups >= 20:
                return
            tokens = rec.split()
            for token in tokens:
                t_lower = token.lower()
                if t_lower.startswith("ip4:") or t_lower.startswith("ip6:"):
                    flattened_ips.append(token.split(":", 1)[1])
                elif t_lower.startswith("include:") or t_lower.startswith("redirect="):
                    target = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
                    target_clean = target.lower().strip()
                    total_lookups += 1
                    if target_clean in visited:
                        has_loop = True
                        continue
                    visited.add(target_clean)
                    if lookup_fn:
                        nested_txt = lookup_fn(target_clean)
                        if nested_txt:
                            walk(nested_txt)
                        else:
                            void_lookups += 1

        walk(spf_record)
        return {
            "domain": domain,
            "total_lookups": total_lookups,
            "void_lookups": void_lookups,
            "exceeds_limit": total_lookups > max_lookups,
            "has_loop": has_loop,
            "flattened_ips": sorted(list(set(flattened_ips))),
            "flattened_record": f"v=spf1 {' '.join([f'ip4:{ip}' if ':' not in ip else f'ip6:{ip}' for ip in sorted(list(set(flattened_ips)))])} -all" if flattened_ips else spf_record,
        }
```

In `landing/assets/orbit_radar.js`:
Add `walkSpfLookupTree(domain, spfRecord)` using `DoHService.query()` to recursively count lookups, render an RFC 7208 lookup fuel gauge (`x / 10 lookups`) in Tab 2, and add a **"Simulate Flattened Record"** button copying the synthesized `v=spf1 ip4:... -all` record.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_spf_tree_counter.py -v`
Expected: PASS with 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/orbit_security/cloud_sentinels.py landing/assets/orbit_radar.js tests/test_spf_tree_counter.py
git commit -m "feat(spf): add recursive RFC 7208 lookup tree counter and flattening simulator"
```

---

### Task 4: Downloadable 1-Click DNS Fix Pack Exporter in Browser (`.tf` + BIND `.zone` + `security.txt`) (Roadmap #6)

**Files:**
- Modify: `landing/assets/orbit_radar.js`
- Modify: `landing/index.html`
- Modify: `docs/assets/orbit_radar.js`
- Modify: `docs/index.html`
- Test: `tests/test_radar_bundle_exporter.py`

**Interfaces:**
- Consumes: Radar DoH audit findings (`dmarc`, `spf`, `caa`, `cname`).
- Produces: In-browser `RemediationBundleBuilder` generating ready-to-import `remediation.zone`, `remediation.tf`, `security.txt`, and triggering `remediation_bundle_download` telemetry beacons.

- [ ] **Step 1: Write the failing test**

Create `tests/test_radar_bundle_exporter.py`:
```python
from pathlib import Path
import pytest


def test_landing_contains_remediation_bundle_builder():
    radar_js = (Path("landing/assets/orbit_radar.js")).read_text(encoding="utf-8")
    assert "RemediationBundleBuilder" in radar_js or "downloadDnsFixPack" in radar_js
    assert "cloudflare_bind_import.zone" in radar_js or "remediation.zone" in radar_js
    assert "security.txt" in radar_js


def test_landing_and_docs_html_have_fixpack_button():
    landing_html = (Path("landing/index.html")).read_text(encoding="utf-8")
    assert "btnDownloadFixPack" in landing_html or "download-fix-pack" in landing_html or "Fix Pack" in landing_html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_radar_bundle_exporter.py -v`
Expected: FAIL with `assert "RemediationBundleBuilder" in radar_js`.

- [ ] **Step 3: Write minimal implementation**

In `landing/assets/orbit_radar.js`:
Add `RemediationBundleBuilder` class:
```javascript
    const RemediationBundleBuilder = {
        buildZoneFile(domain, dmarcVal, spfVal) {
            return [
                `; Orbit Security BIND Zone Fix Pack for ${domain}`,
                `$ORIGIN ${domain}.`,
                `$TTL 300`,
                `_dmarc\tIN\tTXT\t"${dmarcVal || 'v=DMARC1; p=quarantine; sp=quarantine; adkim=r; aspf=r;'}"`,
                `@\tIN\tTXT\t"${spfVal || 'v=spf1 include:_spf.google.com -all'}"`,
                `@\tIN\tCAA\t0 issue "letsencrypt.org"`,
                `@\tIN\tCAA\t0 issue "digicert.com"`,
            ].join('\n');
        },
        buildTerraform(domain, dmarcVal, spfVal) {
            return [
                `# Orbit Security Terraform Fix Pack for ${domain}`,
                `resource "cloudflare_record" "dmarc" {`,
                `  zone_id = var.cloudflare_zone_id`,
                `  name    = "_dmarc"`,
                `  content = "${dmarcVal || 'v=DMARC1; p=quarantine; sp=quarantine;'}"`,
                `  type    = "TXT"`,
                `  ttl     = 1`,
                `}`,
            ].join('\n');
        },
        buildSecurityTxt(domain) {
            return `Contact: mailto:security@${domain}\nCanonical: https://${domain}/.well-known/security.txt\n`;
        },
        downloadBundle(domain, dmarcVal, spfVal) {
            const zone = this.buildZoneFile(domain, dmarcVal, spfVal);
            const blob = new Blob([zone], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${domain}_dns_fix_pack.zone`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            dispatchRadarTelemetry(domain, 'remediation_bundle_download', { domain, format: 'zone' });
        }
    };
```
Bind `RemediationBundleBuilder.downloadBundle` to the `⚡ Download DNS Fix Pack (.zone)` button in the Radar HUD.
Sync `landing/` to `docs/` using `python scripts/sync_landing_to_docs.py --apply`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_radar_bundle_exporter.py -v`
Expected: PASS.
Run: `python scripts/sync_landing_to_docs.py --check`
Expected: 89/89 identical files.

- [ ] **Step 5: Commit**

```bash
git add landing/assets/orbit_radar.js landing/index.html docs/assets/orbit_radar.js docs/index.html tests/test_radar_bundle_exporter.py
git commit -m "feat(export): add browser 1-click DNS fix pack zone exporter and download beacon"
```

---

### Task 5: End-to-End Regression, AST Sentinel & Parity Verification

**Files:**
- Test: Full repository test suites

- [ ] **Step 1: Run complete test suite**

Run: `pytest tests/ -v`
Expected: 100% pass rate across all test suites.

- [ ] **Step 2: Run AST code sentinel**

Run: `python A:\projects\orbit-security\src\orbit_security\ast_sentinel.py --check A:\projects\orbit-security\src`
Expected: 0 errors across all source files.

- [ ] **Step 3: Run landing/docs parity guard**

Run: `python A:\projects\orbit-security\scripts\sync_landing_to_docs.py --check`
Expected: 89 shared files compared, 89 identical, 0 drift.

- [ ] **Step 4: Smoke test CLI tools**

Run: `orbit-security remediate smartmouseco.com --no-pdf` and `orbit-security takeover-poc shop.smartmouseco.com --provider Shopify`
Expected: Pristine execution with valid outputs.
