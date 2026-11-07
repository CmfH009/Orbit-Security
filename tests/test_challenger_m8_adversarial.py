"""Adversarial stress test suite for Milestone M8 Gate.

Author: Challenger 2 (teamwork_challenger_m8_2)
Archetype: critic, specialist
Target: Landing/Docs Parity, Image Asset Integrity, Claim Methodology Footnotes
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from bs4 import BeautifulSoup
from PIL import Image

REPO_ROOT = Path("A:/projects/orbit-security")
LANDING_DIR = REPO_ROOT / "landing"
DOCS_DIR = REPO_ROOT / "docs"

PUBLIC_PAGES = [
    "index.html",
    "fleet.html",
    "about.html",
    "signup.html",
    "ghostdns/index.html",
    "portals/index.html",
    "benchmark/index.html",
]

FOOTNOTE_PAGES = [
    "about.html",
    "index.html",
    "fleet.html",
]

DESIGNATED_IMAGES = {
    "og-image.png": {"min_w": 1200, "min_h": 630, "formats": {"PNG"}},
    "fleet_command_center_live.png": {"min_w": 1200, "min_h": 630, "formats": {"PNG"}},
    "orbit_cyber_command_deck.jpg": {"min_w": 1200, "min_h": 630, "formats": {"JPEG"}},
    "orbit_agency_retainer_vault.jpg": {"min_w": 1200, "min_h": 630, "formats": {"JPEG"}},
    "orbit_cname_blackhole.jpg": {"min_w": 1200, "min_h": 630, "formats": {"JPEG"}},
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_dual_tree_byte_parity_exhaustive():
    """Adversarially verify SHA-256 byte parity between landing/ and docs/."""
    assert LANDING_DIR.is_dir(), f"Missing landing dir at {LANDING_DIR}"
    assert DOCS_DIR.is_dir(), f"Missing docs dir at {DOCS_DIR}"

    # Collect all files in landing/
    import scripts.sync_landing_to_docs as sync_module
    shared_landing = sync_module.collect(LANDING_DIR)
    shared_docs = sync_module.collect(DOCS_DIR)

    # Exactly 95 shared assets according to sync_landing_to_docs specification
    assert len(shared_landing) == 95, f"Expected 95 shared files in landing, got {len(shared_landing)}"
    assert len(shared_docs) == 95, f"Expected 95 shared files in docs, got {len(shared_docs)}"
    assert set(shared_landing.keys()) == set(shared_docs.keys()), "Shared key mismatch between landing and docs"

    landing_files = {p.relative_to(LANDING_DIR): p for p in LANDING_DIR.rglob("*") if p.is_file()}
    docs_files = {p.relative_to(DOCS_DIR): p for p in DOCS_DIR.rglob("*") if p.is_file()}

    # Every single landing file must exist in docs/
    missing_in_docs = set(landing_files.keys()) - set(docs_files.keys())
    assert not missing_in_docs, f"Files in landing/ missing from docs/: {missing_in_docs}"

    # Check SHA-256 byte-by-byte hash of all 95 shared files
    mismatches = []
    for rel_str in sorted(shared_landing.keys()):
        lp = shared_landing[rel_str]
        dp = shared_docs[rel_str]
        l_hash = _sha256(lp)
        d_hash = _sha256(dp)
        if l_hash != d_hash:
            mismatches.append(f"{rel_str}: landing={l_hash} != docs={d_hash}")

    assert not mismatches, f"Parity mismatch in {len(mismatches)} shared files:\n" + "\n".join(mismatches)

    # In addition, check ALL 97 files in landing/ have identical hashes in docs/
    all_landing_mismatches = []
    for rel_path in sorted(landing_files.keys()):
        lp = landing_files[rel_path]
        dp = docs_files[rel_path]
        l_hash = _sha256(lp)
        d_hash = _sha256(dp)
        if l_hash != d_hash:
            all_landing_mismatches.append(f"{rel_path}: landing={l_hash} != docs={d_hash}")
    assert not all_landing_mismatches, f"Mismatch in landing files:\n" + "\n".join(all_landing_mismatches)




def test_designated_image_asset_integrity_and_dimensions():
    """Verify designated preview card images are valid, loadable, and meet minimum dimensions."""
    assets_dir = LANDING_DIR / "assets"
    docs_assets_dir = DOCS_DIR / "assets"

    for img_name, spec in DESIGNATED_IMAGES.items():
        for adir, label in [(assets_dir, "landing/assets"), (docs_assets_dir, "docs/assets")]:
            img_path = adir / img_name
            assert img_path.is_file(), f"Missing {img_name} in {label}"
            size = img_path.stat().st_size
            assert size > 0, f"Zero-byte image {img_name} in {label}"

            # Open and verify format and integrity with Pillow
            with Image.open(img_path) as im:
                im.verify()  # detects corruption
            
            # Reopen to read dimensions and load pixels
            with Image.open(img_path) as im:
                assert im.format in spec["formats"], (
                    f"Unexpected format {im.format} for {img_name} in {label}, expected {spec['formats']}"
                )
                w, h = im.size
                assert w >= spec["min_w"], f"{img_name} width {w} < {spec['min_w']} in {label}"
                assert h >= spec["min_h"], f"{img_name} height {h} < {spec['min_h']} in {label}"
                aspect_ratio = w / h
                # Rich preview standard aspect ratio is 1.91:1 (or 16:9 ~ 1.77:1)
                assert 1.2 <= aspect_ratio <= 2.2, f"{img_name} aspect ratio {aspect_ratio:.2f} unusual for preview card"
                # Ensure pixel data can actually be loaded without decoding error
                im.load()


def test_individual_image_specifications():
    """Verify each image meets or exceeds exact 1200x630 resolution."""
    expected_details = {
        "og-image.png": (1200, 630, "PNG"),
        "fleet_command_center_live.png": (1200, 630, "PNG"),
        "orbit_cyber_command_deck.jpg": (1200, 630, "JPEG"),
        "orbit_agency_retainer_vault.jpg": (1200, 630, "JPEG"),
        "orbit_cname_blackhole.jpg": (1200, 630, "JPEG"),
    }
    for img_name, (min_w, min_h, fmt) in expected_details.items():
        img_path = LANDING_DIR / "assets" / img_name
        assert img_path.exists()
        with Image.open(img_path) as im:
            assert im.format == fmt
            assert im.width >= min_w, f"{img_name} width {im.width} < {min_w}"
            assert im.height >= min_h, f"{img_name} height {im.height} < {min_h}"
            print(f"IMAGE SPEC: {img_name} -> {im.format} {im.size[0]}x{im.size[1]} ({img_path.stat().st_size:,} bytes)")



def test_per_page_social_metadata_strictly_configured():
    """Adversarially verify all 7 pages in both landing/ and docs/ have valid social metadata."""
    for base_dir, base_label in [(LANDING_DIR, "landing"), (DOCS_DIR, "docs")]:
        for rel_page in PUBLIC_PAGES:
            page_path = base_dir / rel_page
            assert page_path.is_file(), f"Missing {rel_page} in {base_label}"

            soup = BeautifulSoup(page_path.read_text(encoding="utf-8"), "html.parser")
            head = soup.find("head")
            assert head is not None, f"Missing <head> in {base_label}/{rel_page}"

            # OpenGraph tags
            og_title = head.find_all("meta", property="og:title")
            assert len(og_title) == 1, f"Expected exactly 1 og:title in {base_label}/{rel_page}, got {len(og_title)}"
            assert og_title[0].get("content") and len(og_title[0].get("content").strip()) > 10

            og_desc = head.find_all("meta", property="og:description")
            assert len(og_desc) == 1, f"Expected exactly 1 og:description in {base_label}/{rel_page}, got {len(og_desc)}"
            assert og_desc[0].get("content") and len(og_desc[0].get("content").strip()) > 20

            og_image = head.find_all("meta", property="og:image")
            assert len(og_image) == 1, f"Expected exactly 1 og:image in {base_label}/{rel_page}, got {len(og_image)}"
            og_img_url = og_image[0].get("content", "").strip()
            assert og_img_url, f"Empty og:image in {base_label}/{rel_page}"

            og_url = head.find_all("meta", property="og:url")
            assert len(og_url) == 1, f"Expected exactly 1 og:url in {base_label}/{rel_page}, got {len(og_url)}"
            url_val = og_url[0].get("content", "").strip()
            assert url_val.startswith("https://cmfh009.github.io/Orbit-Security/"), f"Invalid og:url '{url_val}' in {base_label}/{rel_page}"

            og_type = head.find_all("meta", property="og:type")
            assert len(og_type) == 1, f"Expected exactly 1 og:type in {base_label}/{rel_page}, got {len(og_type)}"
            assert og_type[0].get("content") in ("website", "article")

            # Twitter Card tags
            tw_card = head.find_all("meta", attrs={"name": "twitter:card"})
            assert len(tw_card) == 1, f"Expected exactly 1 twitter:card in {base_label}/{rel_page}, got {len(tw_card)}"
            assert tw_card[0].get("content") == "summary_large_image"

            tw_title = head.find_all("meta", attrs={"name": "twitter:title"})
            assert len(tw_title) == 1, f"Expected exactly 1 twitter:title in {base_label}/{rel_page}, got {len(tw_title)}"
            assert tw_title[0].get("content") == og_title[0].get("content"), (
                f"twitter:title does not match og:title in {base_label}/{rel_page}"
            )

            tw_desc = head.find_all("meta", attrs={"name": "twitter:description"})
            assert len(tw_desc) == 1, f"Expected exactly 1 twitter:description in {base_label}/{rel_page}, got {len(tw_desc)}"
            assert tw_desc[0].get("content") == og_desc[0].get("content"), (
                f"twitter:description does not match og:description in {base_label}/{rel_page}"
            )

            tw_image = head.find_all("meta", attrs={"name": "twitter:image"})
            assert len(tw_image) == 1, f"Expected exactly 1 twitter:image in {base_label}/{rel_page}, got {len(tw_image)}"
            assert tw_image[0].get("content") == og_image[0].get("content"), (
                f"twitter:image does not match og:image in {base_label}/{rel_page}"
            )

            # Canonical link tag
            canonical = head.find_all("link", rel=lambda r: r and "canonical" in r)
            assert len(canonical) >= 1, f"Missing canonical link in {base_label}/{rel_page}"
            assert canonical[0].get("href") == url_val, (
                f"Canonical href {canonical[0].get('href')} != og:url {url_val} in {base_label}/{rel_page}"
            )


def test_claim_methodology_footnotes_rigor():
    """Adversarially verify exact claim methodology citations across about.html, index.html, and fleet.html."""
    for base_dir, base_label in [(LANDING_DIR, "landing"), (DOCS_DIR, "docs")]:
        for rel_page in FOOTNOTE_PAGES:
            page_path = base_dir / rel_page
            content = page_path.read_text(encoding="utf-8")
            soup = BeautifulSoup(content, "html.parser")

            # 1. Exact measurement date anchor 2026-10-22
            assert "2026-10-22" in content, f"Missing exact date '2026-10-22' in {base_label}/{rel_page}"

            # 2. Link to /benchmark/
            benchmark_links = [
                a for a in soup.find_all("a", href=True)
                if "benchmark" in a["href"]
            ]
            assert len(benchmark_links) >= 1, f"Missing functional link to benchmark in {base_label}/{rel_page}"
            assert any(
                a["href"] in ("/benchmark/", "benchmark/", "benchmark/index.html", "./benchmark/", "../benchmark/")
                or "/benchmark/" in a["href"]
                for a in benchmark_links
            ), f"No valid benchmark hyperlink target found in {base_label}/{rel_page}: {[a['href'] for a in benchmark_links]}"

            # 3. Latency claim grounding (4.1s median latency, verifying < 12s)
            has_4_1s = "4.1s" in content or "4,063 ms" in content
            assert has_4_1s, f"Missing '4.1s' (4,063 ms) median latency claim grounding in {base_label}/{rel_page}"
            # Extract latency value and verify strictly < 12s
            import re
            m = re.search(r"(\d+\.?\d*)\s*s\s*\(4,063\s*ms\)\s*median", content)
            if m:
                val = float(m.group(1))
                assert val < 12.0, f"Latency {val}s is not < 12s in {base_label}/{rel_page}"

            # 4. Signature coverage claim grounding (52 provider signatures across 76 fingerprints)
            has_52_sigs = "52" in content and ("signature" in content.lower() or "provider" in content.lower())
            assert has_52_sigs, f"Missing '52 signatures' coverage claim grounding in {base_label}/{rel_page}"

            # 5. Retainer ROI claim grounding (10,493% ROI)
            assert "10,493%" in content, f"Missing '10,493%' ROI benchmark citation in {base_label}/{rel_page}"

