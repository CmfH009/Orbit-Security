"""
Empirical Challenger Test Suite for Milestone M3 & M4 (Orbit Security)
Adversarial stress-testing of client scanner, PDF generation, parity, and legal compliance.
"""

import hashlib
import json
import os
import re
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LANDING_DIR = REPO_ROOT / "landing"
DOCS_DIR = REPO_ROOT / "docs"


class TestRouteAbsenceAndClientScanner:
    """Task 1: Verify route absence & DoH in client JS."""

    def test_no_scan_endpoint_anywhere_in_public_trees(self):
        """Confirm /api/orbit-security/scan does not exist in any file in landing/ or docs/."""
        prohibited = "/api/orbit-security/scan"
        violations = []
        for base in [LANDING_DIR, DOCS_DIR]:
            for p in base.rglob("*"):
                if p.is_file() and p.suffix in (".html", ".js", ".json", ".md"):
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    if prohibited in content:
                        violations.append(str(p.relative_to(REPO_ROOT)))

        assert not violations, f"Found prohibited route '{prohibited}' in: {violations}"

    def test_no_unhandled_fetch_api_routes_in_orbit_radar_js(self):
        """Confirm orbit_radar.js does not fetch non-existent dynamic backend APIs."""
        for js_path in [LANDING_DIR / "assets" / "orbit_radar.js", DOCS_DIR / "assets" / "orbit_radar.js"]:
            text = js_path.read_text(encoding="utf-8")
            fetch_matches = re.findall(r"fetch\s*\(\s*['\"`](/api/[^'\"`]+)['\"`]", text)
            assert not fetch_matches, f"Found unhandled dynamic API fetch in {js_path}: {fetch_matches}"

    def test_doh_endpoints_are_valid_rfc8484(self):
        """Ensure client DoH implementation targets recognized DoH providers."""
        for js_path in [LANDING_DIR / "assets" / "orbit_radar.js", DOCS_DIR / "assets" / "orbit_radar.js"]:
            text = js_path.read_text(encoding="utf-8")
            assert "dns.google/resolve" in text, f"Missing Google DoH in {js_path}"
            assert "cloudflare-dns.com/dns-query" in text, f"Missing Cloudflare DoH in {js_path}"


class TestPdfGeneratorIntegrity:
    """Task 2: Empirically inspect PDF generator code in orbit_radar.js."""

    def test_sensitive_exposure_sentinel_never_asserts_pass(self):
        """Assert that SENSITIVE EXPOSURE SENTINEL badge does NOT assert PASS for .env/.git probes."""
        for js_path in [LANDING_DIR / "assets" / "orbit_radar.js", DOCS_DIR / "assets" / "orbit_radar.js"]:
            text = js_path.read_text(encoding="utf-8")

            # Check default findings configuration
            match = re.search(
                r'category:\s*["\']SENSITIVE EXPOSURE SENTINEL["\'],\s*desc:\s*["\']([^"\']+)["\'],\s*status:\s*["\']([^"\']+)["\']',
                text,
            )
            assert match, f"Could not find SENSITIVE EXPOSURE SENTINEL entry in {js_path}"
            desc, status = match.group(1), match.group(2)
            assert status != "PASS", f"SENSITIVE EXPOSURE SENTINEL must not be PASS (found: {status})"
            assert status == "N/A", f"Expected N/A status, got: {status}"
            assert "Passive DoH reconnaissance only" in desc

            # Check dynamic convertRealFindingsToPdfFormat fallback
            conv_match = re.search(
                r"cat\.key === ['\"]SENSITIVE EXPOSURE SENTINEL['\"]\s*&&\s*catFindings\.length === 0",
                text,
            )
            assert conv_match, f"Missing zero-finding handling for SENSITIVE EXPOSURE SENTINEL in {js_path}"

            # Ensure that within that block, status is 'N/A'
            block_start = conv_match.start()
            block_code = text[block_start : block_start + 400]
            assert "status: 'N/A'" in block_code or 'status: "N/A"' in block_code, (
                f"SENSITIVE EXPOSURE SENTINEL zero-findings block must set status: 'N/A' in {js_path}"
            )

    def test_pdf_demo_watermark_is_removed(self):
        """Assert that DEMO watermark is completely absent from PDF generator code in orbit_radar.js."""
        for js_path in [LANDING_DIR / "assets" / "orbit_radar.js", DOCS_DIR / "assets" / "orbit_radar.js"]:
            text = js_path.read_text(encoding="utf-8")
            assert "DEMO PREVIEW - NOT A REAL SCAN" not in text
            assert "DEMO PREVIEW" not in text
            assert "NOT A REAL SCAN" not in text


class TestFleetCertifierStewardship:
    """Task 3: Empirically inspect fleet.html certifier fallback."""

    def test_certifier_fallback_rejects_scanned_domain(self):
        """Assert fallback client certifier does not default to scanned domain."""
        for html_path in [LANDING_DIR / "fleet.html", DOCS_DIR / "fleet.html"]:
            text = html_path.read_text(encoding="utf-8")

            # Check handleAddDomain fallback
            add_match = re.search(
                r'const client =\s*nameInput\.value\.trim\(\)\s*\|\|\s*["\']([^"\']+)["\'];',
                text,
            )
            assert add_match, f"Could not find client assignment in handleAddDomain in {html_path}"
            fallback_val = add_match.group(1)
            assert fallback_val != "domain", f"Fallback client certifier must not default to domain in {html_path}"
            assert fallback_val == "Orbit Security Certified Client"

            # Check downloadSinglePDF anti-self-certification logic
            assert "const safeClient = (rawClient && rawClient !== safeDomain) ? rawClient : 'Orbit Security Certified Client';" in text, (
                f"Missing strict self-certification prevention guard in {html_path}"
            )

    def simulate_fleet_client_resolution(self, raw_client, safe_domain):
        """Python oracle mirroring JavaScript logic in fleet.html."""
        raw_client_sanitized = re.sub(r"[^\x20-\x7E]", "", raw_client.strip())
        safe_client = (
            raw_client_sanitized
            if (raw_client_sanitized and raw_client_sanitized != safe_domain)
            else "Orbit Security Certified Client"
        )
        return safe_client

    @pytest.mark.parametrize(
        "client_input,domain_input,expected_client",
        [
            ("", "target.com", "Orbit Security Certified Client"),
            ("   ", "target.com", "Orbit Security Certified Client"),
            ("target.com", "target.com", "Orbit Security Certified Client"),  # self-cert attempt blocked
            ("Acme Web Agency", "target.com", "Acme Web Agency"),
            ("SecOps Pro Inc.", "target.com", "SecOps Pro Inc."),
        ],
    )
    def test_oracle_fleet_client_resolution(self, client_input, domain_input, expected_client):
        res = self.simulate_fleet_client_resolution(client_input, domain_input)
        assert res == expected_client


class TestLegalComplianceAndDisclaimers:
    """Task 4: Empirically inspect disclaimer.html and terms.html."""

    def test_disclaimer_no_streaming_or_exfiltration_claim(self):
        """Assert 256 KB streaming claim is absent from disclaimer.html."""
        for html_path in [LANDING_DIR / "disclaimer.html", DOCS_DIR / "disclaimer.html"]:
            text = html_path.read_text(encoding="utf-8")
            assert "256 KB" not in text, f"Found '256 KB' streaming claim in {html_path}"
            assert "stream a maximum" not in text, f"Found 'stream a maximum' in {html_path}"
            assert "We never download, stream, exfiltrate, or harvest internal server files" in text

    def test_terms_montana_governing_law_and_venue(self):
        """Assert Montana governing law and Flathead County venue are present in terms.html."""
        for html_path in [LANDING_DIR / "terms.html", DOCS_DIR / "terms.html"]:
            text = html_path.read_text(encoding="utf-8")
            assert "State of Montana" in text, f"Missing State of Montana governing law in {html_path}"
            assert "Flathead County, Montana" in text, f"Missing Flathead County venue in {html_path}"

    def test_terms_binding_arbitration(self):
        """Assert binding arbitration and AAA rules are present in terms.html."""
        for html_path in [LANDING_DIR / "terms.html", DOCS_DIR / "terms.html"]:
            text = html_path.read_text(encoding="utf-8")
            assert "mandatory binding arbitration" in text.lower()
            assert "American Arbitration Association" in text or "AAA" in text
            assert "CLASS ACTION WAIVER" in text.upper()

    def test_terms_authorization_section_and_anchor(self):
        """Assert <section id="authorization"> is present in terms.html and targeted by index.html."""
        for html_path in [LANDING_DIR / "terms.html", DOCS_DIR / "terms.html"]:
            text = html_path.read_text(encoding="utf-8")
            assert '<section id="authorization"' in text, f"Missing <section id='authorization'> in {html_path}"

        for index_path in [LANDING_DIR / "index.html", DOCS_DIR / "index.html"]:
            text = index_path.read_text(encoding="utf-8")
            assert 'terms.html#authorization' in text, f"Missing link to terms.html#authorization in {index_path}"


class TestParityAndReleaseIntegrity:
    """Task 5 & Gate Integrity: Full parity oracle between landing and docs."""

    def test_landing_and_docs_shared_files_byte_for_byte_parity(self):
        """Oracle comparing all shared files between landing/ and docs/."""
        mismatches = []
        compared_count = 0

        for landing_file in LANDING_DIR.rglob("*"):
            if not landing_file.is_file():
                continue
            rel = landing_file.relative_to(LANDING_DIR)

            # Ignore files that are landing-only by design (e.g. input.css) or moved to assets
            if rel.name in ("input.css",):
                continue

            docs_file = DOCS_DIR / rel
            if not docs_file.exists():
                # Check if it was placed under assets/ in docs
                assets_candidate = DOCS_DIR / "assets" / rel.name
                if assets_candidate.exists():
                    docs_file = assets_candidate
                else:
                    continue

            compared_count += 1
            h_landing = hashlib.sha256(landing_file.read_bytes()).hexdigest()
            h_docs = hashlib.sha256(docs_file.read_bytes()).hexdigest()
            if h_landing != h_docs:
                mismatches.append(f"{rel}: landing={h_landing[:8]} vs docs={h_docs[:8]}")

        assert compared_count >= 70, f"Expected at least 70 compared files, got {compared_count}"
        assert not mismatches, f"Parity drift detected: {mismatches}"
