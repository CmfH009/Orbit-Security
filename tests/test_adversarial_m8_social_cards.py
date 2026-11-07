"""Adversarial stress test suite for Milestone M8: Per-Page Social Preview Cards & Footnotes.

Author: Challenger 1 (teamwork_challenger_m8_1)
Roles: critic, specialist

Stress-tests:
1. Exact canonical tag uniqueness (rejects duplicate rel=canonical per RFC 6596 / Google Search Central).
2. OpenGraph and Twitter tag completeness and uniqueness (no duplicate or contradictory tags).
3. Canonical, og:url, and twitter:url exact alignment.
4. Placement: meta tags inside <head>, before <body>, and before any executable scripts.
5. Escaping and XSS safety in meta content attributes.
6. Social crawler parsing simulations (Facebook, Twitterbot, LinkedInBot, Slackbot).
7. Physical preview image asset validation: PIL integrity, size < 5MB, high-resolution dimensions.
8. Dated claim methodology footnotes and hyperlink reachability.
9. Dual-tree landing/docs byte parity.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse
import pytest
from bs4 import BeautifulSoup
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
LANDING_DIR = REPO_ROOT / "landing"
DOCS_DIR = REPO_ROOT / "docs"

PAGES = [
    "index.html",
    "fleet.html",
    "about.html",
    "signup.html",
    "ghostdns/index.html",
    "portals/index.html",
    "benchmark/index.html",
]

EXPECTED_METADATA = {
    "index.html": {
        "title": "Orbit Security | White-Label Perimeter Defense for Agencies",
        "desc_prefix": "Automate client perimeter security",
        "url": "https://cmfh009.github.io/Orbit-Security/",
        "img_file": "og-image.png",
    },
    "fleet.html": {
        "title": "Fleet Command Center | Orbit Security",
        "desc_prefix": "Real-time multi-client attack surface sentinel",
        "url": "https://cmfh009.github.io/Orbit-Security/fleet.html",
        "img_file": "fleet_command_center_live.png",
    },
    "about.html": {
        "title": "About Orbit Security | Autonomous Perimeter Intelligence for Web Agencies",
        "desc_prefix": "Orbit Security continuously maps agency client perimeters",
        "url": "https://cmfh009.github.io/Orbit-Security/about.html",
        "img_file": "orbit_cyber_command_deck.jpg",
    },
    "signup.html": {
        "title": "Agency Retainer Onboarding | Orbit Security",
        "desc_prefix": "Initialize your white-label security retainer portal",
        "url": "https://cmfh009.github.io/Orbit-Security/signup.html",
        "img_file": "orbit_agency_retainer_vault.jpg",
    },
    "ghostdns/index.html": {
        "title": "GhostDNS | Dangling CNAME & DNS Drift Sentinel",
        "desc_prefix": "Dedicated 24/7 dangling CNAME sentinel",
        "url": "https://cmfh009.github.io/Orbit-Security/ghostdns/index.html",
        "img_file": "orbit_cname_blackhole.jpg",
    },
    "portals/index.html": {
        "title": "White-Label Client Threat Portals | Orbit Security",
        "desc_prefix": "Custom-branded, real-time perimeter defense",
        "url": "https://cmfh009.github.io/Orbit-Security/portals/index.html",
        "img_file": "orbit_agency_retainer_vault.jpg",
    },
    "benchmark/index.html": {
        "title": "Orbit Security Audit Benchmark | Reproducible Perimeter Data",
        "desc_prefix": "Measured audit latency, takeover signature coverage",
        "url": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html",
        "img_file": "og-image.png",
    },
}


def _get_page_trees(rel_path: str):
    """Return (soup, raw_text, path) for both landing and docs variants."""
    results = []
    for base in [LANDING_DIR, DOCS_DIR]:
        path = base / rel_path
        assert path.exists(), f"File does not exist: {path}"
        raw = path.read_text(encoding="utf-8")
        soup = BeautifulSoup(raw, "html.parser")
        results.append((soup, raw, path))
    return results


# ==============================================================================
# 1. CANONICAL UNIQUENESS & INTEGRITY
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_canonical_tag_uniqueness(rel_path: str):
    """Stress test: RFC 6596 / Google Search Central mandates EXACTLY ONE rel=canonical.

    Having multiple canonical tags causes search engines and social scrapers
    to ignore canonical directives entirely.
    """
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        assert head is not None, f"Missing <head> in {path}"
        canonicals = head.find_all("link", rel=lambda r: r and "canonical" in r)

        canonical_hrefs = [c.get("href") for c in canonicals]
        assert len(canonicals) == 1, (
            f"VIOLATION: Multiple canonical tags found in {path.name}: {canonical_hrefs}. "
            f"Search engines treat multiple canonical tags as contradictory and ignore them."
        )

        expected_url = EXPECTED_METADATA[rel_path]["url"]
        assert canonical_hrefs[0] == expected_url, (
            f"Canonical URL mismatch in {path.name}: got {canonical_hrefs[0]}, expected {expected_url}"
        )


# ==============================================================================
# 2. METADATA UNIQUENESS (NO DUPLICATE OR CONTRADICTORY META TAGS)
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_meta_tag_uniqueness(rel_path: str):
    """Stress test: verify no duplicate og:* or twitter:* properties exist in <head>."""
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        og_props = [m.get("property") for m in head.find_all("meta") if m.get("property", "").startswith("og:")]
        tw_names = [m.get("name") for m in head.find_all("meta") if m.get("name", "").startswith("twitter:")]

        og_counts = Counter(og_props)
        tw_counts = Counter(tw_names)

        dup_og = {k: v for k, v in og_counts.items() if v > 1}
        dup_tw = {k: v for k, v in tw_counts.items() if v > 1}

        assert not dup_og, f"Duplicate OpenGraph tags in {path}: {dup_og}"
        assert not dup_tw, f"Duplicate Twitter card tags in {path}: {dup_tw}"


# ==============================================================================
# 3. CANONICAL, OG:URL, AND TWITTER:URL THREE-WAY ALIGNMENT
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_url_alignment(rel_path: str):
    """Stress test: canonical URL, og:url, and twitter:url must be identical absolute HTTPS URLs."""
    expected_url = EXPECTED_METADATA[rel_path]["url"]
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        canonical_tags = head.find_all("link", rel=lambda r: r and "canonical" in r)
        assert canonical_tags, f"Missing canonical in {path}"
        canonical_href = canonical_tags[0].get("href")

        og_url_tag = head.find("meta", property="og:url")
        assert og_url_tag is not None, f"Missing og:url in {path}"
        og_url = og_url_tag.get("content")

        tw_url_tag = head.find("meta", attrs={"name": "twitter:url"})
        assert tw_url_tag is not None, f"Missing twitter:url in {path}"
        tw_url = tw_url_tag.get("content")

        assert canonical_href == expected_url, f"Canonical href drift in {path}: {canonical_href} != {expected_url}"
        assert og_url == expected_url, f"og:url drift in {path}: {og_url} != {expected_url}"
        assert tw_url == expected_url, f"twitter:url drift in {path}: {tw_url} != {expected_url}"


# ==============================================================================
# 4. TAG PLACEMENT: INSIDE <head>, BEFORE <body>, BEFORE EXECUTABLE SCRIPTS
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_tag_placement(rel_path: str):
    """Stress test: All social preview tags and canonical links must be inside <head>,

    before <body>, and before any executable JavaScript tags.
    """
    for soup, raw, path in _get_page_trees(rel_path):
        head = soup.find("head")
        body = soup.find("body")
        assert head is not None and body is not None, f"Malformed HTML structure in {path}"

        # Ensure no og:* or twitter:* leaked into body
        body_og = body.find_all("meta", property=lambda p: p and p.startswith("og:"))
        body_tw = body.find_all("meta", attrs={"name": lambda n: n and n.startswith("twitter:")})
        body_canon = body.find_all("link", rel=lambda r: r and "canonical" in r)

        assert not body_og, f"OpenGraph tags leaked into <body> in {path}: {body_og}"
        assert not body_tw, f"Twitter tags leaked into <body> in {path}: {body_tw}"
        assert not body_canon, f"Canonical tag leaked into <body> in {path}: {body_canon}"

        # Inspect head element order: executable scripts must come AFTER preview tags
        head_elements = [el for el in head.children if getattr(el, "name", None)]
        first_og = next((i for i, el in enumerate(head_elements) if el.name == "meta" and el.get("property", "").startswith("og:")), None)
        first_tw = next((i for i, el in enumerate(head_elements) if el.name == "meta" and el.get("name", "").startswith("twitter:")), None)
        first_exec_script = next(
            (i for i, el in enumerate(head_elements) if el.name == "script" and el.get("type") != "application/ld+json"),
            None,
        )

        assert first_og is not None, f"No OpenGraph tags in {path}"
        assert first_tw is not None, f"No Twitter tags in {path}"
        if first_exec_script is not None:
            assert first_og < first_exec_script, (
                f"Executable <script> at index {first_exec_script} appears BEFORE OpenGraph tag at index {first_og} in {path}"
            )
            assert first_tw < first_exec_script, (
                f"Executable <script> at index {first_exec_script} appears BEFORE Twitter tag at index {first_tw} in {path}"
            )


# ==============================================================================
# 5. ESCAPING & XSS SAFETY IN META CONTENT
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_meta_escaping_and_xss_safety(rel_path: str):
    """Stress test: Meta content attributes must not contain raw HTML tags or unescaped injection vectors."""
    dangerous_patterns = [
        re.compile(r"<script\b", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
        re.compile(r"<iframe\b", re.IGNORECASE),
    ]

    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        meta_tags = head.find_all("meta")

        for meta in meta_tags:
            content = meta.get("content", "")
            for pattern in dangerous_patterns:
                assert not pattern.search(content), (
                    f"POTENTIAL XSS/INJECTION in {path} meta tag {meta}: matches {pattern.pattern}"
                )


# ==============================================================================
# 6. SOCIAL CRAWLER PARSING SIMULATION
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_crawler_simulation_facebook(rel_path: str):
    """Simulate Facebook Crawler (facebookexternalhit/1.1).

    Expects: og:type, og:site_name, og:url, og:title, og:description, og:image,
    og:image:width, og:image:height, og:image:alt, unique canonical URL.
    """
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        meta_dict = {
            m["property"]: m.get("content", "")
            for m in head.find_all("meta")
            if m.has_attr("property") and m["property"].startswith("og:")
        }

        required_og = ["og:type", "og:site_name", "og:url", "og:title", "og:description", "og:image"]
        for prop in required_og:
            assert prop in meta_dict and meta_dict[prop], f"Facebook Crawler missing {prop} in {path}"

        # Image must be absolute HTTPS
        img_url = meta_dict["og:image"]
        parsed = urlparse(img_url)
        assert parsed.scheme == "https" and parsed.netloc == "cmfh009.github.io", (
            f"Facebook Crawler requires absolute HTTPS image URL, got {img_url} in {path}"
        )


@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_crawler_simulation_twitterbot(rel_path: str):
    """Simulate Twitterbot/1.0.

    Expects: twitter:card='summary_large_image', twitter:site, twitter:creator,
    twitter:title, twitter:description, twitter:image, image exists and < 5MB.
    """
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        tw_dict = {
            m["name"]: m.get("content", "")
            for m in head.find_all("meta")
            if m.has_attr("name") and m["name"].startswith("twitter:")
        }

        assert tw_dict.get("twitter:card") == "summary_large_image", (
            f"Twitterbot expects twitter:card='summary_large_image' in {path}, got {tw_dict.get('twitter:card')}"
        )
        assert tw_dict.get("twitter:site") == "@_arsoncode", f"Twitterbot invalid site in {path}"
        assert tw_dict.get("twitter:creator") == "@_arsoncode", f"Twitterbot invalid creator in {path}"
        assert tw_dict.get("twitter:title"), f"Twitterbot missing twitter:title in {path}"
        assert tw_dict.get("twitter:description"), f"Twitterbot missing twitter:description in {path}"
        assert tw_dict.get("twitter:image"), f"Twitterbot missing twitter:image in {path}"


@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_crawler_simulation_linkedin(rel_path: str):
    """Simulate LinkedInBot/1.0.

    Expects: og:title (<= 100 chars), og:description (<= 256 chars), og:image, og:url.
    """
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        og_title = head.find("meta", property="og:title")
        og_desc = head.find("meta", property="og:description")
        assert og_title and og_title.get("content"), f"LinkedInBot missing og:title in {path}"
        assert og_desc and og_desc.get("content"), f"LinkedInBot missing og:description in {path}"

        title_text = og_title.get("content")
        desc_text = og_desc.get("content")

        assert len(title_text) <= 100, f"LinkedInBot: og:title too long (>100 chars) in {path}: {len(title_text)}"
        assert len(desc_text) <= 256, f"LinkedInBot: og:description too long (>256 chars) in {path}: {len(desc_text)}"


@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_crawler_simulation_slackbot(rel_path: str):
    """Simulate Slackbot-LinkExpanding.

    Expects: og:site_name == 'Orbit Security', non-empty og:title, valid image URL.
    """
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        site_name = head.find("meta", property="og:site_name")
        assert site_name is not None and site_name.get("content") == "Orbit Security", (
            f"Slackbot missing or invalid og:site_name in {path}"
        )


# ==============================================================================
# 7. PHYSICAL IMAGE ASSET INTEGRITY & RESOLUTION
# ==============================================================================
@pytest.mark.parametrize("rel_path", PAGES)
def test_adversarial_image_physical_assets_and_pillow_integrity(rel_path: str):
    """Verify preview images physically exist, are non-empty, openable via PIL,

    and have dimensions >= 1200x630 or valid social resolution.
    """
    expected_img_file = EXPECTED_METADATA[rel_path]["img_file"]
    for soup, _, path in _get_page_trees(rel_path):
        head = soup.find("head")
        og_img = head.find("meta", property="og:image").get("content")
        tw_img = head.find("meta", attrs={"name": "twitter:image"}).get("content")

        assert expected_img_file in og_img, f"og:image does not contain {expected_img_file} in {path}"
        assert expected_img_file in tw_img, f"twitter:image does not contain {expected_img_file} in {path}"

        # Resolve to disk in landing/assets/
        asset_file = LANDING_DIR / "assets" / expected_img_file
        assert asset_file.is_file(), f"Asset missing on disk: {asset_file}"
        file_size = asset_file.stat().st_size
        assert file_size > 10_000, f"Asset suspiciously small: {file_size} bytes at {asset_file}"
        assert file_size < 5_000_000, f"Asset exceeds 5MB social crawler limit: {file_size} bytes at {asset_file}"

        # Test PIL image decoding
        with Image.open(asset_file) as im:
            width, height = im.size
            assert width >= 1200, f"Image width {width} < 1200 minimum standard for {asset_file}"
            assert height >= 630, f"Image height {height} < 630 minimum standard for {asset_file}"
            assert im.format in ("PNG", "JPEG", "WEBP"), f"Invalid image format {im.format} for {asset_file}"


# ==============================================================================
# 8. CLAIM METHODOLOGY FOOTNOTES EMPIRICAL CHECK
# ==============================================================================
def test_adversarial_claim_methodology_footnotes_rigor():
    """Verify that all pages making published empirical claims (about.html, index.html, fleet.html)

    ground each claim with dated methodology notes, valid benchmark hyperlinks,
    and exact arithmetic.
    """
    claim_pages = ["about.html", "index.html", "fleet.html"]
    for rel_path in claim_pages:
        for soup, content, path in _get_page_trees(rel_path):
            # 1. Date anchor check
            assert "2026-10-22" in content, f"Missing date anchor 2026-10-22 in {path}"

            # 2. Footnote section check
            assert "Methodology Footnotes Section" in content or "Methodology Note" in content, (
                f"Missing explicit methodology footnote section in {path}"
            )

            # 3. Grounding of latency claim
            assert "4.1s" in content and "4,063 ms" in content and "5,907 ms" in content, (
                f"Missing exact latency metrics (4.1s, 4,063 ms, 5,907 ms) in {path}"
            )

            # 4. Grounding of signature coverage claim
            assert "52 provider signatures" in content and "76 distinct" in content and "NXDOMAIN" in content, (
                f"Missing signature methodology grounding in {path}"
            )

            # 5. Grounding of retainer ROI claim with exact arithmetic
            assert "10,493%" in content and "$75,000/yr" in content and "$708/yr" in content and "$74,292/yr" in content, (
                f"Missing ROI methodology metrics (10,493%, $75,000/yr, $708/yr, $74,292/yr) in {path}"
            )

            # 6. Benchmark hyperlink reachability check
            benchmark_links = [
                a["href"] for a in soup.find_all("a", href=True)
                if "benchmark" in a["href"]
            ]
            assert benchmark_links, f"No benchmark hyperlink in {path}"


# ==============================================================================
# 9. DUAL-TREE PARITY CHECK
# ==============================================================================
def test_adversarial_dual_tree_byte_identity():
    """Verify landing/ and docs/ remain 100% byte-identical across all 7 pages."""
    import hashlib

    for page in PAGES:
        l_path = LANDING_DIR / page
        d_path = DOCS_DIR / page
        assert l_path.exists() and d_path.exists(), f"Path missing: {page}"
        l_hash = hashlib.sha256(l_path.read_bytes()).hexdigest()
        d_hash = hashlib.sha256(d_path.read_bytes()).hexdigest()
        assert l_hash == d_hash, f"Parity mismatch in {page}: landing={l_hash[:8]} vs docs={d_hash[:8]}"
