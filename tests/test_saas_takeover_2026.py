"""Tests for 2026 Modern SaaS Subdomain Takeover Fingerprints.

Validates the expanded curated signatures in orbit_security.signatures for
developer cloud platforms: Vercel, Render, Fly.io, Netlify, Webflow, Readme.io, Zendesk.
"""

import pytest
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature


EXPECTED_2026_SIGNATURES = {
    "Vercel": {
        "cname_patterns": ["cname.vercel-dns.com", "vercel.app", "vercel-dns.com"],
        "fingerprints": ["404: NOT_FOUND", "The deployment could not be found"],
        "remediation": "Remove the dangling CNAME record or configure the domain in a verified Vercel project.",
        "positives": [
            "<html><body><h1>404: NOT_FOUND</h1></body></html>",
            "<div>The deployment could not be found</div>",
            "<p>404: not_found</p>",
        ],
        "negatives": [
            "<html><body><h1>Welcome to Vercel Next.js</h1></body></html>",
            "",
            "404 Page Not Found",
        ],
    },
    "Render": {
        "cname_patterns": ["onrender.com", "render.com"],
        "fingerprints": ["Not Found", "Render 404"],
        "remediation": "Remove the CNAME record or bind the domain to an active Render web service.",
        "positives": [
            "<html><body>Not Found</body></html>",
            "<h1>Render 404</h1>",
            "<span>render 404 error</span>",
        ],
        "negatives": [
            "<html><body>Welcome to Render Web App</body></html>",
            "",
            "200 OK Success",
        ],
    },
    "Fly.io": {
        "cname_patterns": ["fly.dev", "edge.fly.io"],
        "fingerprints": ["404 Not Found"],
        "remediation": "Remove the CNAME record or attach the custom domain to a registered Fly.io application.",
        "positives": [
            "<html><head><title>404 Not Found</title></head></html>",
            "<body>404 not found on edge.fly.io</body>",
        ],
        "negatives": [
            "<html><body>Fly.io service running</body></html>",
            "",
            "502 Bad Gateway",
        ],
    },
    "Netlify": {
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID", "Netlify site not found"],
        "remediation": "Remove the dangling CNAME or configure the custom domain on an active Netlify site.",
        "positives": [
            "<div>Not Found - Request ID: 01HZY4A8...</div>",
            "<h1>Netlify site not found</h1>",
            "<p>netlify site not found</p>",
        ],
        "negatives": [
            "<html><body>Netlify Production Deployed</body></html>",
            "",
            "Site under construction",
        ],
    },
    "Webflow": {
        "cname_patterns": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "remediation": "Remove the CNAME or register the custom domain in Webflow site hosting settings.",
        "positives": [
            "<div>The page you are looking for doesn't exist or has been moved</div>",
            "<p>the page you are looking for doesn't exist or has been moved</p>",
        ],
        "negatives": [
            "<html><body>Webflow Showcase Site</body></html>",
            "",
            "Page not found",
        ],
    },
    "Readme.io": {
        "cname_patterns": ["readme.io"],
        "fingerprints": ["Project doesn't exist", "Project not found"],
        "remediation": "Remove the CNAME or claim the project subdomain in Readme.io.",
        "positives": [
            "<h1>Project doesn't exist</h1>",
            "<div>Project not found</div>",
            "<p>project doesn't exist</p>",
        ],
        "negatives": [
            "<html><body>Readme Documentation Hub</body></html>",
            "",
            "Docs home",
        ],
    },
    "Zendesk": {
        "cname_patterns": ["zendesk.com"],
        "fingerprints": ["Help Center Closed"],
        "remediation": "Remove the host mapping in DNS or update the Zendesk Guide custom domain setting.",
        "positives": [
            "<h2>Help Center Closed</h2>",
            "<p>help center closed</p>",
        ],
        "negatives": [
            "<html><body>Welcome to Help Center Support</body></html>",
            "",
            "Ticket submitted",
        ],
    },
}


def _get_signature_by_name(name: str) -> SaasSignature:
    matches = [s for s in SAAS_TAKEOVER_SIGNATURES if s.name == name]
    assert len(matches) == 1, f"Expected exactly one signature for {name}, found {len(matches)}"
    return matches[0]


@pytest.mark.parametrize("name,spec", EXPECTED_2026_SIGNATURES.items())
def test_saas_takeover_signature_metadata(name, spec):
    """Verify name, cname_patterns, fingerprints, and remediation match 2026 requirements."""
    sig = _get_signature_by_name(name)
    assert sig.name == name
    assert sig.cname_patterns == spec["cname_patterns"]
    assert sig.fingerprints == spec["fingerprints"]
    assert sig.remediation == spec["remediation"]


@pytest.mark.parametrize("name,spec", EXPECTED_2026_SIGNATURES.items())
def test_saas_takeover_signature_positive_fingerprints(name, spec):
    """Verify detect_fingerprint correctly identifies positive response snippets."""
    sig = _get_signature_by_name(name)
    for pos_html in spec["positives"]:
        assert sig.detect_fingerprint(pos_html), f"Expected {name} to detect fingerprint in: {pos_html!r}"


@pytest.mark.parametrize("name,spec", EXPECTED_2026_SIGNATURES.items())
def test_saas_takeover_signature_negative_fingerprints(name, spec):
    """Verify detect_fingerprint rejects non-vulnerable/unrelated response snippets."""
    sig = _get_signature_by_name(name)
    for neg_html in spec["negatives"]:
        assert not sig.detect_fingerprint(neg_html), f"Expected {name} NOT to detect fingerprint in: {neg_html!r}"


def test_saas_takeover_detect_fingerprint_edge_cases():
    """Verify edge case handling for detect_fingerprint (None, empty string)."""
    for name in EXPECTED_2026_SIGNATURES:
        sig = _get_signature_by_name(name)
        assert not sig.detect_fingerprint("")
        assert not sig.detect_fingerprint(None)  # type: ignore[arg-type]
