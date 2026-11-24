"""Unit and regression tests for per-page social preview cards and claim methodology footnotes.

Milestone M8 / Track 4 (Roadmap W3.5 & W4.5)
Validates OpenGraph and Twitter card metadata across all 7 landing pages,
verifies physical existence of preview card image assets, validates dated
methodology footnotes on about.html, index.html, and fleet.html, and asserts
landing/docs parity integrity.
"""

from __future__ import annotations

import os
from pathlib import Path
from bs4 import BeautifulSoup

REPO_ROOT = Path(__file__).resolve().parent.parent
LANDING_DIR = REPO_ROOT / "landing"
DOCS_DIR = REPO_ROOT / "docs"

# 7 landing pages with their expected metadata
EXPECTED_PAGES = [
    {
        "rel_path": "index.html",
        "og_title": "Orbit Security | White-Label Perimeter Defense for Agencies",
        "og_desc": "Automate client perimeter security, catch subdomain takeovers, and export co-branded monthly audit PDFs to justify $250/mo agency retainers.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/",
        "image_name": "og-image.png",
    },
    {
        "rel_path": "fleet.html",
        "og_title": "Fleet Command Center | Orbit Security",
        "og_desc": "Real-time multi-client attack surface sentinel, DNS drift telemetry, and perimeter hygiene dashboard for web and Shopify agencies.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/fleet.html",
        "image_name": "fleet_command_center_live.png",
    },
    {
        "rel_path": "about.html",
        "og_title": "About Orbit Security | Autonomous Perimeter Intelligence for Web Agencies",
        "og_desc": "Orbit Security continuously maps agency client perimeters, prevents subdomain takeovers, neutralizes DMARC spoofing, and generates white-label security retainers.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/about.html",
        "image_name": "orbit_cyber_command_deck.jpg",
    },
    {
        "rel_path": "signup.html",
        "og_title": "Agency Retainer Onboarding | Orbit Security",
        "og_desc": "Initialize your white-label security retainer portal, configure agency branding, and activate continuous perimeter sentinels.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/signup.html",
        "image_name": "orbit_agency_retainer_vault.jpg",
    },
    {
        "rel_path": "ghostdns/index.html",
        "og_title": "GhostDNS | Dangling CNAME & DNS Drift Sentinel",
        "og_desc": "Dedicated 24/7 dangling CNAME sentinel and silent DNS drift protection for high-growth DTC brands and web agencies.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/ghostdns/index.html",
        "image_name": "orbit_cname_blackhole.jpg",
    },
    {
        "rel_path": "portals/index.html",
        "og_title": "White-Label Client Threat Portals | Orbit Security",
        "og_desc": "Custom-branded, real-time perimeter defense and attack surface monitoring portals for agency client rosters.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/portals/index.html",
        "image_name": "orbit_agency_retainer_vault.jpg",
    },
    {
        "rel_path": "benchmark/index.html",
        "og_title": "Orbit Security Audit Benchmark | Reproducible Perimeter Data",
        "og_desc": "Measured audit latency, takeover signature coverage, and grading stability published as open reproducible benchmark data.",
        "og_url": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html",
        "image_name": "og-image.png",
    },
]

PUBLIC_PAGES = [item["rel_path"] for item in EXPECTED_PAGES]


def _parse_page(rel_path: str) -> tuple[BeautifulSoup, str]:
    file_path = LANDING_DIR / rel_path
    assert file_path.exists(), f"Page does not exist: {file_path}"
    content = file_path.read_text(encoding="utf-8")
    soup = BeautifulSoup(content, "html.parser")
    return soup, content


def _resolve_image_to_disk(page_rel_path: str, img_url: str) -> Path:
    """Resolve an og:image or twitter:image string to a physical Path in landing/assets/."""
    site_origin = "https://cmfh009.github.io/Orbit-Security/"
    if img_url.startswith(site_origin):
        rel_from_root = img_url[len(site_origin):]
        return (LANDING_DIR / rel_from_root).resolve()

    # Resolve relative to the HTML file location
    page_dir = (LANDING_DIR / page_rel_path).parent
    disk_path = (page_dir / img_url).resolve()
    return disk_path


def test_seven_landing_pages_have_opengraph_tags():
    """Verify all 7 landing pages contain dedicated OpenGraph tags: og:title, og:description, og:image, og:url, og:type."""
    for item in EXPECTED_PAGES:
        soup, _ = _parse_page(item["rel_path"])
        head = soup.find("head")
        assert head is not None, f"Missing <head> in {item['rel_path']}"

        og_title = head.find("meta", property="og:title")
        assert og_title is not None, f"Missing meta og:title in {item['rel_path']}"
        assert og_title.get("content") == item["og_title"], (
            f"Unexpected og:title in {item['rel_path']}: {og_title.get('content')} != {item['og_title']}"
        )

        og_desc = head.find("meta", property="og:description")
        assert og_desc is not None, f"Missing meta og:description in {item['rel_path']}"
        assert og_desc.get("content") == item["og_desc"], (
            f"Unexpected og:description in {item['rel_path']}: {og_desc.get('content')} != {item['og_desc']}"
        )

        og_url = head.find("meta", property="og:url")
        assert og_url is not None, f"Missing meta og:url in {item['rel_path']}"
        assert og_url.get("content") == item["og_url"], (
            f"Unexpected og:url in {item['rel_path']}: {og_url.get('content')} != {item['og_url']}"
        )

        og_type = head.find("meta", property="og:type")
        assert og_type is not None, f"Missing meta og:type in {item['rel_path']}"
        assert og_type.get("content") in ("website", "article"), (
            f"Invalid og:type in {item['rel_path']}: {og_type.get('content')}"
        )

        og_image = head.find("meta", property="og:image")
        assert og_image is not None, f"Missing meta og:image in {item['rel_path']}"
        assert item["image_name"] in og_image.get("content", ""), (
            f"og:image in {item['rel_path']} does not reference {item['image_name']}: {og_image.get('content')}"
        )


def test_seven_landing_pages_have_twitter_tags():
    """Verify all 7 landing pages contain dedicated Twitter card tags."""
    for item in EXPECTED_PAGES:
        soup, _ = _parse_page(item["rel_path"])
        head = soup.find("head")
        assert head is not None, f"Missing <head> in {item['rel_path']}"

        tw_card = head.find("meta", attrs={"name": "twitter:card"})
        assert tw_card is not None, f"Missing meta twitter:card in {item['rel_path']}"
        assert tw_card.get("content") == "summary_large_image", (
            f"twitter:card in {item['rel_path']} must be summary_large_image, got {tw_card.get('content')}"
        )

        tw_title = head.find("meta", attrs={"name": "twitter:title"})
        assert tw_title is not None, f"Missing meta twitter:title in {item['rel_path']}"
        assert tw_title.get("content") == item["og_title"], (
            f"Unexpected twitter:title in {item['rel_path']}: {tw_title.get('content')} != {item['og_title']}"
        )

        tw_desc = head.find("meta", attrs={"name": "twitter:description"})
        assert tw_desc is not None, f"Missing meta twitter:description in {item['rel_path']}"
        assert tw_desc.get("content") == item["og_desc"], (
            f"Unexpected twitter:description in {item['rel_path']}: {tw_desc.get('content')} != {item['og_desc']}"
        )

        tw_image = head.find("meta", attrs={"name": "twitter:image"})
        assert tw_image is not None, f"Missing meta twitter:image in {item['rel_path']}"
        assert item["image_name"] in tw_image.get("content", ""), (
            f"twitter:image in {item['rel_path']} does not reference {item['image_name']}: {tw_image.get('content')}"
        )


def test_social_card_image_assets_exist():
    """Verify that images referenced by og:image and twitter:image physically exist on disk in landing/assets/."""
    for item in EXPECTED_PAGES:
        soup, _ = _parse_page(item["rel_path"])
        head = soup.find("head")
        assert head is not None

        og_image = head.find("meta", property="og:image")
        assert og_image is not None
        og_img_url = og_image.get("content", "")
        og_path = _resolve_image_to_disk(item["rel_path"], og_img_url)
        assert og_path.is_file(), f"og:image {og_img_url} for {item['rel_path']} does not exist at {og_path}"
        assert og_path.stat().st_size > 0, f"og:image at {og_path} is empty"

        tw_image = head.find("meta", attrs={"name": "twitter:image"})
        assert tw_image is not None
        tw_img_url = tw_image.get("content", "")
        tw_path = _resolve_image_to_disk(item["rel_path"], tw_img_url)
        assert tw_path.is_file(), f"twitter:image {tw_img_url} for {item['rel_path']} does not exist at {tw_path}"
        assert tw_path.stat().st_size > 0, f"twitter:image at {tw_path} is empty"


def test_dated_methodology_footnotes_present():
    """Verify that about.html, index.html, and fleet.html have dated methodology footnotes."""
    footnote_pages = ["about.html", "index.html", "fleet.html"]
    for rel_path in footnote_pages:
        soup, content = _parse_page(rel_path)

        # Date anchor
        assert "2026-10-22" in content, f"Missing methodology date 2026-10-22 in {rel_path}"

        # Benchmark reference
        assert "benchmark/" in content or "/benchmark/" in content, (
            f"Missing reference to /benchmark/ in {rel_path}"
        )

        # Latency claim grounding (4.1s / 4,063 ms / 12s)
        assert ("4.1s" in content or "4,063 ms" in content or "12s" in content), (
            f"Missing latency methodology grounding in {rel_path}"
        )

        # Signature coverage grounding (52 provider signatures)
        assert "52 provider signatures" in content or "52 signatures" in content or "52 provider" in content, (
            f"Missing 52 provider signature coverage grounding in {rel_path}"
        )

        # Retainer unit-economics grounding (illustrative projection, not measured customer ROI)
        assert (
            "$75,000/yr" in content
            and "$708/yr" in content
            and "$74,292/yr" in content
            and "Projection only" in content
        ), f"Missing illustrative retainer economics methodology grounding in {rel_path}"


def test_docs_parity_intact():
    """Verify landing/ and docs/ are 95/95 byte-identical with zero drift."""
    import hashlib

    shared_extensions = {
        ".html", ".htm", ".css", ".js", ".mjs", ".cjs", ".json", ".xml",
        ".txt", ".webmanifest", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".webp", ".avif", ".ico", ".bmp", ".tif", ".tiff",
        ".ttf", ".otf", ".woff", ".woff2", ".eot", ".mp4", ".webm", ".mov"
    }

    landing_files = {
        p.relative_to(LANDING_DIR): p
        for p in LANDING_DIR.rglob("*")
        if p.is_file() and p.suffix.lower() in shared_extensions
    }
    docs_files = {
        p.relative_to(DOCS_DIR): p
        for p in DOCS_DIR.rglob("*")
        if p.is_file() and p.suffix.lower() in shared_extensions
    }

    shared_keys = set(landing_files.keys()) & set(docs_files.keys())
    assert len(shared_keys) >= 87, f"Expected at least 87 shared files, found {len(shared_keys)}"

    mismatches = []
    for rel in sorted(shared_keys):
        l_bytes = landing_files[rel].read_bytes()
        d_bytes = docs_files[rel].read_bytes()
        l_hash = hashlib.sha256(l_bytes).hexdigest()
        d_hash = hashlib.sha256(d_bytes).hexdigest()
        if l_hash != d_hash:
            mismatches.append(f"{rel}: landing={l_hash[:8]} vs docs={d_hash[:8]}")

    assert not mismatches, f"Parity drift detected in {len(mismatches)} files:\n" + "\n".join(mismatches)


def test_all_public_pages_have_exactly_one_canonical_tag():
    """Verify that every public page in PUBLIC_PAGES has exactly 1 canonical tag."""
    for rel_path in PUBLIC_PAGES:
        soup, _ = _parse_page(rel_path)
        canonical_links = soup.find_all("link", rel=lambda r: r and "canonical" in r)
        assert len(canonical_links) == 1, (
            f"Expected exactly 1 canonical tag in {rel_path}, found {len(canonical_links)}: "
            f"{[c.get('href') for c in canonical_links]}"
        )


def test_public_pages_avoid_inflated_traction_and_roi_claims():
    """Verify public landing and docs pages avoid inflated traction or ROI claims."""
    forbidden_tokens = (
        "10,493%",
        "Orbit Security is used by",
        "premier digital agencies",
        ">Active SLA<",
    )
    for base_dir in (LANDING_DIR, DOCS_DIR):
        for rel_path in ("about.html", "index.html", "fleet.html", "portals/index.html"):
            content = (base_dir / rel_path).read_text(encoding="utf-8")
            for token in forbidden_tokens:
                assert token not in content, (
                    f"Inflated claim token {token!r} found in {base_dir.name}/{rel_path}"
                )


def test_top_level_pages_have_no_broken_links_or_hash_anchors():
    """Verify every relative href and #anchor across all 13 top-level pages resolves cleanly."""
    top_pages = (
        "index.html",
        "audit.html",
        "fleet.html",
        "labs.html",
        "about.html",
        "signup.html",
        "portals/index.html",
        "ghostdns/index.html",
        "stealthbridge/index.html",
        "benchmark/index.html",
        "terms.html",
        "privacy.html",
        "refunds.html",
        "disclaimer.html",
    )
    for base_dir in (LANDING_DIR, DOCS_DIR):
        ids_by_page = {}
        soups_by_page = {}
        for rel_path in top_pages:
            page_path = base_dir / rel_path
            assert page_path.is_file(), f"Missing top-level page: {page_path}"
            soup = BeautifulSoup(page_path.read_text(encoding="utf-8"), "html.parser")
            soups_by_page[rel_path] = soup
            ids_by_page[rel_path] = {el.get("id") for el in soup.find_all(id=True)}

        for rel_path, soup in soups_by_page.items():
            page_dir = (base_dir / rel_path).parent
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("http://", "https://", "mailto:", "javascript:", "tel:", "data:")):
                    continue
                if href.startswith("#"):
                    anchor = href[1:]
                    if anchor:
                        assert anchor in ids_by_page[rel_path], (
                            f"Broken anchor {href} in {base_dir.name}/{rel_path}"
                        )
                    continue
                path_part, _, anchor = href.partition("#")
                path_part = path_part.split("?")[0]
                target = (page_dir / path_part).resolve()
                if target.is_dir():
                    target = target / "index.html"
                assert target.exists(), f"Broken relative link {href} in {base_dir.name}/{rel_path}"
                if anchor:
                    target_rel = target.relative_to(base_dir.resolve()).as_posix()
                    if target_rel in ids_by_page:
                        assert anchor in ids_by_page[target_rel], (
                            f"Broken cross-page anchor {href} in {base_dir.name}/{rel_path}"
                        )


def test_slice1_defensive_and_copy_hygiene():
    """Verify Slice 1 typo/fact-check fixes, defensive stealthbridge copy, and persistent simple_cat.js."""
    top_pages = (
        "index.html",
        "audit.html",
        "fleet.html",
        "labs.html",
        "about.html",
        "signup.html",
        "portals/index.html",
        "ghostdns/index.html",
        "stealthbridge/index.html",
        "benchmark/index.html",
        "terms.html",
        "privacy.html",
        "refunds.html",
        "disclaimer.html",
    )
    for base_dir in (LANDING_DIR, DOCS_DIR):
        sb_text = (base_dir / "stealthbridge/index.html").read_text(encoding="utf-8")
        for bad in ("Turnstile", "DataDome", "PerimeterX", "$49", "Orbit Security Inc"):
            assert bad not in sb_text, f"Offensive/inaccurate token {bad!r} in {base_dir.name}/stealthbridge/index.html"

        idx_text = (base_dir / "index.html").read_text(encoding="utf-8")
        for bad in ("`dns.google`", 'href="#flipbook"', "ORBIT-SENTINEL v2.4", "pure profit"):
            assert bad not in idx_text, f"Unfixed token {bad!r} in {base_dir.name}/index.html"

        fleet_text = (base_dir / "fleet.html").read_text(encoding="utf-8")
        for bad in ("`@_arsoncode`", "1P: CARSON"):
            assert bad not in fleet_text, f"Unfixed token {bad!r} in {base_dir.name}/fleet.html"

        audit_text = (base_dir / "audit.html").read_text(encoding="utf-8")
        assert "orbit-security.io" not in audit_text, f"Unowned sample domain in {base_dir.name}/audit.html"

        for rel_path in top_pages:
            page_text = (base_dir / rel_path).read_text(encoding="utf-8")
            assert "simple_cat.js" in page_text, f"Missing simple_cat.js in {base_dir.name}/{rel_path}"


def test_slice2_labs_split_open_source_proof_and_command_deck():
    """Verify Slice 2: labs.html split, #security-labs previews, #open-source-proof, slim #legal, and Command Deck."""
    for base_dir in (LANDING_DIR, DOCS_DIR):
        idx_text = (base_dir / "index.html").read_text(encoding="utf-8")
        labs_text = (base_dir / "labs.html").read_text(encoding="utf-8")
        cat_js = (base_dir / "assets/simple_cat.js").read_text(encoding="utf-8")

        for lab_id in (
            'id="kev-epss-radar"',
            'id="takeover-poc-playground"',
            'id="fleet-sentinel-cockpit"',
            'id="zk-agency-scorecard"',
            'id="bounty-radar-statuspage"',
            'id="epss-horizon-visualizer"',
            'id="visualAttackTreeContainer"',
        ):
            assert lab_id in labs_text, f"Missing {lab_id} in {base_dir.name}/labs.html"

        for moved_id in (
            'id="kev-epss-radar"',
            'id="takeover-poc-playground"',
            'id="fleet-sentinel-cockpit"',
        ):
            assert moved_id not in idx_text, f"Moved section {moved_id} still on {base_dir.name}/index.html"

        assert 'id="security-labs"' in idx_text
        assert 'href="labs.html#kev-epss-radar"' in idx_text
        assert 'href="labs.html#takeover-poc-playground"' in idx_text
        assert 'href="labs.html#fleet-sentinel-cockpit"' in idx_text

        assert 'id="open-source-proof"' in idx_text
        for token in ("CmfH009/Orbit-Security@v1", "SARIF 2.1.0", "1,900+", "benchmark/index.html"):
            assert token in idx_text, f"Missing {token!r} in {base_dir.name}/index.html #open-source-proof"

        assert 'id="legal"' in idx_text
        assert 'id="copy-rider-btn"' in idx_text
        assert 'id="legal-tab-terms"' not in idx_text
        for legal_href in ('href="terms.html"', 'href="privacy.html"', 'href="disclaimer.html"', 'href="refunds.html"'):
            assert legal_href in idx_text

        assert 'onclick="showKeyboardHud()"' not in idx_text
        for deck_id in ('id="dock-deck-btn"', 'id="crtShaderToggleBtn"', 'id="crt-arcade-shader-canvas"', 'id="cmd-shortcuts-btn"'):
            assert deck_id in cat_js, f"Missing {deck_id} in {base_dir.name}/assets/simple_cat.js"


def test_astro_cat_guided_tour_and_scan_reactor():
    """Verify Astro-Cat tactical spotlight tour, page-aware routes, visor moods, and scan reactor."""
    for base_dir in (LANDING_DIR, DOCS_DIR):
        cat_js = (base_dir / "assets/simple_cat.js").read_text(encoding="utf-8")
        radar_js = (base_dir / "assets/orbit_radar.js").read_text(encoding="utf-8")

        for token in (
            "astro-tour-spotlight",
            "TOUR_ROUTES",
            "labs.html?tour=1",
            'id="tour-prev-btn"',
            'id="tour-step-pips"',
            'id="tour-action-btn"',
            'id="bubble-decode-finding-btn"',
            "function reactToScan(",
            "function setVisorMood(",
            "PAGE_QUIPS",
            "SECTION_QUIPS",
        ):
            assert token in cat_js, f"Missing {token!r} in {base_dir.name}/assets/simple_cat.js"

        assert "Instant MRR boost!" not in cat_js, f"Stale hype copy found in {base_dir.name}/assets/simple_cat.js"
        assert "SimpleCat.reactToScan(audit)" in radar_js, f"Missing reactToScan hook in {base_dir.name}/assets/orbit_radar.js"
        assert "SimpleCat.setVisorMood('radar'" in radar_js, f"Missing visor mood hook in {base_dir.name}/assets/orbit_radar.js"


def test_explainer_v4_and_retired_legacy_videos():
    """Verify orbit_security_explainer_v4.mp4 + poster exist in landing/ and docs/ and legacy videos are retired."""
    retired = (
        "orbit_security_ad_video.mp4",
        "orbit_security_ad_video.webm",
        "orbit_security_ad_video_web.mp4",
        "orbit_astro_cat_gameplay_x.mp4",
        "orbit_montage_master.mp4",
        "orbit_teardown_master.mp4",
        "orbit_boast_roast_2026.mp4",
        "orbit_cat_ad_final.mp4",
        "orbit_cat_continuous_32s.mp4",
        "orbit_cat_continuous_32s_final.mp4",
        "orbit_cat_humor_ad.mp4",
    )
    for base_dir in (LANDING_DIR, DOCS_DIR):
        assets_dir = base_dir / "assets"
        assert (assets_dir / "orbit_security_explainer_v4.mp4").is_file()
        assert (assets_dir / "orbit_security_explainer_v4_poster.jpg").is_file()
        for legacy in retired:
            assert not (assets_dir / legacy).exists(), f"Retired video {legacy} still exists in {assets_dir}"

        idx_html = (base_dir / "index.html").read_text(encoding="utf-8")
        assert 'id="orbit-explainer-video"' in idx_html
        assert "assets/orbit_security_explainer_v4.mp4" in idx_html
        assert "assets/orbit_security_explainer_v4_poster.jpg" in idx_html
        for legacy in retired:
            assert legacy not in idx_html, f"Retired video reference {legacy} found in {base_dir.name}/index.html"

