"""Tests for the browser 1-click DNS Fix Pack exporter (Roadmap #6).

The pure builder is extracted between two marker comments and executed with
Node.js so the exact `.zone`, `.tf`, and `security.txt` payloads are asserted
against real output rather than string presence in the source file.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
JS_PATH = REPO_ROOT / "landing" / "assets" / "orbit_radar.js"
LANDING_HTML = REPO_ROOT / "landing" / "index.html"
DOCS_HTML = REPO_ROOT / "docs" / "index.html"

START_MARKER = "// REMEDIATION_BUNDLE_BUILDER_START"
END_MARKER = "// REMEDIATION_BUNDLE_BUILDER_END"
NODE = shutil.which("node")


def _js_source() -> str:
    return JS_PATH.read_text(encoding="utf-8")


def _builder_source() -> str:
    js = _js_source()
    assert START_MARKER in js, "RemediationBundleBuilder start marker missing"
    assert END_MARKER in js, "RemediationBundleBuilder end marker missing"
    return js[js.index(START_MARKER) : js.index(END_MARKER)]


def _eval_in_node(tmp_path: Path, expression: str):
    if not NODE:
        pytest.skip("Node.js is required to execute the browser bundle builder")
    script = tmp_path / "fixpack_harness.js"
    script.write_text(
        _builder_source() + f"\nprocess.stdout.write(JSON.stringify({expression}));\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [NODE, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_landing_contains_remediation_bundle_builder():
    js = _js_source()
    assert "RemediationBundleBuilder" in js
    assert "remediation.zone" in js
    assert "remediation.tf" in js
    assert "security.txt" in js
    assert "remediation_bundle_download" in js
    assert "downloadBundle" in js


def test_zone_file_exact_output(tmp_path):
    zone = _eval_in_node(
        tmp_path,
        "RemediationBundleBuilder.buildZoneFile("
        "'acmebrand.com', 'v=DMARC1; p=reject;', 'v=spf1 include:_spf.google.com -all')",
    )

    assert zone == (
        "; Orbit Security BIND Zone Fix Pack for acmebrand.com\n"
        "$ORIGIN acmebrand.com.\n"
        "$TTL 300\n"
        '_dmarc\tIN\tTXT\t"v=DMARC1; p=reject;"\n'
        '@\tIN\tTXT\t"v=spf1 include:_spf.google.com -all"\n'
        '@\tIN\tCAA\t0 issue "letsencrypt.org"\n'
        '@\tIN\tCAA\t0 issue "digicert.com"'
    )


def test_terraform_exact_output(tmp_path):
    terraform = _eval_in_node(
        tmp_path,
        "RemediationBundleBuilder.buildTerraform("
        "'acmebrand.com', 'v=DMARC1; p=reject;', 'v=spf1 include:_spf.google.com -all')",
    )

    assert terraform == (
        "# Orbit Security Terraform Fix Pack for acmebrand.com\n"
        '# Apply with: terraform apply -var="cloudflare_zone_id=<zone_id>"\n'
        'resource "cloudflare_record" "dmarc" {\n'
        "  zone_id = var.cloudflare_zone_id\n"
        '  name    = "_dmarc"\n'
        '  content = "v=DMARC1; p=reject;"\n'
        '  type    = "TXT"\n'
        "  ttl     = 1\n"
        "}\n"
        "\n"
        'resource "cloudflare_record" "spf" {\n'
        "  zone_id = var.cloudflare_zone_id\n"
        '  name    = "@"\n'
        '  content = "v=spf1 include:_spf.google.com -all"\n'
        '  type    = "TXT"\n'
        "  ttl     = 1\n"
        "}\n"
        "\n"
        'resource "cloudflare_record" "caa" {\n'
        "  zone_id = var.cloudflare_zone_id\n"
        '  name    = "@"\n'
        '  type    = "CAA"\n'
        "  ttl     = 1\n"
        "  data {\n"
        '    flags = "0"\n'
        '    tag   = "issue"\n'
        '    value = "letsencrypt.org"\n'
        "  }\n"
        "}"
    )


def test_security_txt_exact_output(tmp_path):
    security_txt = _eval_in_node(
        tmp_path,
        "RemediationBundleBuilder.buildSecurityTxt("
        "'acmebrand.com', 'security@acmebrand.com', '2027-10-26T00:00:00Z')",
    )

    assert security_txt == (
        "Contact: mailto:security@acmebrand.com\n"
        "Expires: 2027-10-26T00:00:00Z\n"
        "Canonical: https://acmebrand.com/.well-known/security.txt\n"
        "Policy: https://acmebrand.com/security\n"
        "Preferred-Languages: en\n"
    )


def test_bundle_contains_all_three_artifacts(tmp_path):
    bundle = _eval_in_node(
        tmp_path,
        "RemediationBundleBuilder.buildBundle("
        "'acmebrand.com', 'v=DMARC1; p=quarantine;', 'v=spf1 -all')",
    )

    assert set(bundle) == {"zone", "terraform", "securityTxt"}
    assert "$ORIGIN acmebrand.com." in bundle["zone"]
    assert 'resource "cloudflare_record" "dmarc"' in bundle["terraform"]
    assert "Canonical: https://acmebrand.com/.well-known/security.txt" in bundle["securityTxt"]


def test_build_from_audit_uses_doh_findings(tmp_path):
    audit = {
        "domain": "clientbrand.com",
        "dmarcParsed": {"raw": "v=DMARC1; p=none;"},
        "spfResult": {"raw": "v=spf1 include:mail.zendesk.com ~all"},
    }
    bundle = _eval_in_node(
        tmp_path,
        f"RemediationBundleBuilder.buildFromAudit({json.dumps(audit)})",
    )

    assert '"v=DMARC1; p=none;"' in bundle["zone"]
    assert '"v=spf1 include:mail.zendesk.com ~all"' in bundle["zone"]
    assert 'content = "v=DMARC1; p=none;"' in bundle["terraform"]


def test_bundle_uses_safe_defaults_for_missing_values(tmp_path):
    zone = _eval_in_node(tmp_path, "RemediationBundleBuilder.buildZoneFile('fallback.com')")

    assert '"v=DMARC1; p=quarantine; sp=quarantine; adkim=r; aspf=r;"' in zone
    assert '"v=spf1 include:_spf.google.com -all"' in zone


def test_domain_sanitization_strips_url_and_trailing_dot(tmp_path):
    zone = _eval_in_node(
        tmp_path,
        "RemediationBundleBuilder.buildZoneFile(' HTTPS://Evil.Example.COM/path?q=1. ')",
    )

    assert "$ORIGIN evil.example.com." in zone
    assert "path" not in zone
    assert "q=1" not in zone


def test_download_bundle_dispatches_telemetry_and_triggers_zone_download():
    js = _js_source()

    assert "dispatchRadarTelemetry(domain, 'remediation_bundle_download'" in js
    assert "['remediation.zone', bundle.zone]" in js
    assert "['remediation.tf', bundle.terraform]" in js
    assert "['security.txt', bundle.securityTxt]" in js
    assert "anchor.download = filename" in js


def test_landing_and_docs_html_have_fixpack_button():
    for path in (LANDING_HTML, DOCS_HTML):
        html = path.read_text(encoding="utf-8")
        assert "btnDownloadFixPack" in html, path
        assert "downloadDnsFixPack" in html, path
        assert "Download DNS Fix Pack" in html, path


def test_fixpack_function_is_exposed_on_window():
    js = _js_source()
    assert "window.RemediationBundleBuilder = RemediationBundleBuilder;" in js
    assert "window.downloadDnsFixPack = downloadDnsFixPack;" in js
