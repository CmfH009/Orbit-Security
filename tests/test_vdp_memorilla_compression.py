"""
test_vdp_memorilla_compression.py — Unit tests for Memorilla compression and loop prevention in Orbit Security
=============================================================================================================
Verifies:
1. Response payload compression: 50KB+ minified JS and multi-page HTML compressed into 16 high-signal
   endpoint and CORS anchors before analysis.
2. LoopPreventionSentinel hooked into HTTP redirect handling to break circular 302 redirect loops (A -> B -> A -> B).
3. LoopPreventionSentinel hooked into recursive CNAME DNS probing to eliminate redundant circular hops.
"""

import pytest
import sys
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path("A:/projects/orbit-security") if Path("A:/projects/orbit-security").exists() else Path("C:/AgyHut/projects/orbit-security")
SRC_DIR = PROJECT_ROOT / "src"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for p in (str(SRC_DIR), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from orbit_security.vdp_high_signal_detectors import compress_vdp_payload_anchors
from hunt_hackerone_vdps import _SafeVdpRedirectHandler, resolve_dns_cname_chain_guarded


def test_compress_vdp_payload_anchors_minified_js():
    """Verify 50KB+ minified JS is compressed into 16 high-signal endpoint/CORS anchors."""
    # Synthesize 50KB+ of minified JS containing high-value endpoint candidates, CORS tokens, and cloud buckets
    js_chunks = [
        "const apiGateway='/api/v2/payments/charge';fetch(apiGateway,{credentials:'include'});",
        "const corsEndpoint='/oauth/v2/token';headers['Access-Control-Allow-Origin']='https://evil.com';",
        "const s3Bucket='https://internal-backups-2026.s3.amazonaws.com/prod/export.sql';",
        "const adminPortal='/admin/dashboard/config.json';",
        "const actuatorUrl='/actuator/health';",
        "const userProfile='/api/v1/internal/users/export';",
        "const graphQlEndpoint='/v1/graphql/query';",
        "const debugEndpoint='/debug/pprof/heap';",
    ]
    # Pad out to >60KB with minified variable declarations
    padding = "var _0x12a=function(a,b){return a+b};" * 1500
    large_js = ";\n".join(js_chunks) + ";\n" + padding
    assert len(large_js.encode("utf-8")) > 50000, f"Payload size: {len(large_js.encode('utf-8'))} bytes"

    anchors = compress_vdp_payload_anchors(large_js, content_type="application/javascript", url="https://target.corp/app.min.js")
    assert isinstance(anchors, list)
    assert len(anchors) <= 16
    assert len(anchors) > 0

    # Ensure representations match Stanford Memorilla anchor token format <Concept:Summary>
    for a in anchors:
        rep = a.token_representation()
        assert rep.startswith("<")
        assert ":" in rep
        assert rep.endswith(">")

    # High-signal tokens should be preserved in anchors
    summaries = " ".join(a.summary.lower() for a in anchors)
    concepts = " ".join(a.concept.lower() for a in anchors)
    combined = f"{summaries} {concepts}"
    assert any(k in combined for k in ("api", "endpoint", "cors", "token", "payment", "internal", "s3"))


def test_compress_vdp_payload_anchors_html():
    """Verify multi-page large HTML (>50KB) is compressed into 16 anchors."""
    html_lines = ["<!doctype html><html><head><title>Portal</title></head><body>"]
    for i in range(100):
        html_lines.append(f"<div class='section-{i}'>")
        html_lines.append(f"  <a href='/api/v1/service-{i}/status'>Endpoint {i}</a>")
        html_lines.append(f"  <script src='/static/js/bundle-{i}.js'></script>")
        html_lines.append("  <p>" + ("Lorem ipsum dolor sit amet " * 15) + "</p>")
        html_lines.append("</div>")
    html_lines.append("</body></html>")
    large_html = "\n".join(html_lines)
    assert len(large_html.encode("utf-8")) > 50000

    anchors = compress_vdp_payload_anchors(large_html, content_type="text/html", url="https://target.corp/")
    assert len(anchors) <= 16
    assert len(anchors) > 0


def test_safe_vdp_redirect_handler_breaks_circular_302_loop():
    """Verify _SafeVdpRedirectHandler halts cyclical 302 redirects (A -> B -> A -> B)."""
    handler = _SafeVdpRedirectHandler()
    assert hasattr(handler, "sentinel")

    mock_req = urllib.request.Request("https://target.corp/login")
    mock_fp = MagicMock()
    mock_headers = {}

    url_a = "https://target.corp/login"
    url_b = "https://target.corp/auth/redirect"

    # Step 1: Redirect to B
    res_1 = handler.redirect_request(mock_req, mock_fp, 302, "Found", mock_headers, url_b)
    assert res_1 is not None

    # Step 2: Redirect back to A
    res_2 = handler.redirect_request(mock_req, mock_fp, 302, "Found", mock_headers, url_a)
    assert res_2 is not None

    # Step 3: Redirect to B again
    res_3 = handler.redirect_request(mock_req, mock_fp, 302, "Found", mock_headers, url_b)
    assert res_3 is not None

    # Step 4: Redirect to A again completes cycle A -> B -> A -> B: Sentinel MUST break loop
    res_4 = handler.redirect_request(mock_req, mock_fp, 302, "Found", mock_headers, url_a)
    assert res_4 is None, "Circular 302 redirect cycle must be broken by LoopPreventionSentinel returning None"


def test_resolve_dns_cname_chain_breaks_circular_cname_loop():
    """Verify recursive CNAME probing eliminates circular CNAME loops."""
    # Mock lookup returning cyclical answers:
    # sub1.corp -> cname1.corp
    # cname1.corp -> cname2.corp
    # cname2.corp -> cname1.corp (cyclical oscillation)
    mock_responses = {
        "sub1.corp": [{"data": "cname1.corp."}],
        "cname1.corp": [{"data": "cname2.corp."}],
        "cname2.corp": [{"data": "cname1.corp."}],
    }

    def mock_lookup(host, record_type="CNAME", timeout=5):
        clean_host = host.rstrip(".").lower()
        ans = mock_responses.get(clean_host, [])
        return {"Status": 0 if ans else 3, "Answer": ans}

    chain, loop_detected = resolve_dns_cname_chain_guarded(
        "sub1.corp",
        doh_lookup_fn=mock_lookup,
        max_hops=10,
    )

    assert loop_detected is True, "Expected circular CNAME loop to be detected"
    # Chain must stop once oscillation is detected rather than burning 10 hops
    assert len(chain) <= 4
