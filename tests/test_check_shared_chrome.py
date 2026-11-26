"""Unit tests for scripts/check_shared_chrome.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_shared_chrome.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("check_shared_chrome", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_real_landing_and_docs_pass():
    mod = _load_mod()
    assert mod.main() == 0


def test_detects_missing_header_wrong_order_and_version_drift(tmp_path, monkeypatch):
    mod = _load_mod()
    landing = tmp_path / "landing"
    (landing / "benchmark").mkdir(parents=True)
    (landing / "portals").mkdir(parents=True)

    valid_html = (
        '<header><nav class="lg:flex"><button id="header-tour-btn"></button>'
        '<button id="mobile-header-tour-btn"></button><button id="audio-toggle-btn"></button></nav></header>'
        '<link rel="stylesheet" href="assets/styles.min.css?v=v1">'
        '<script src="assets/simple_cat_data.js?v=v1" defer></script>'
        '<script src="assets/simple_cat.js?v=v1" defer></script>'
        '<script src="assets/orbit_radar.js?v=v1" defer></script>'
        '<script src="assets/landing_ui.js?v=v1" defer></script>'
        '<script src="assets/orbit_labs.js?v=v1" defer></script>'
        '<footer><a href="privacy.html"></a><a href="terms.html"></a>'
        '<a href="disclaimer.html"></a><a href="refunds.html"></a></footer>'
    )
    for rel in mod.SHARED_PAGES:
        (landing / rel).write_text(valid_html, encoding="utf-8")

    assert mod.check_tree("landing") == [] if mod.REPO_ROOT == tmp_path else True
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    assert mod.check_tree("landing") == []

    # Break index.html: remove #header-tour-btn, swap simple_cat order, and drift styles.min.css ?v=
    broken_html = (
        '<header><nav class="lg:flex">'
        '<button id="mobile-header-tour-btn"></button><button id="audio-toggle-btn"></button></nav></header>'
        '<link rel="stylesheet" href="assets/styles.min.css?v=v2">'
        '<script src="assets/simple_cat.js?v=v1" defer></script>'
        '<script src="assets/simple_cat_data.js?v=v1" defer></script>'
        '<script src="assets/orbit_radar.js?v=v1" defer></script>'
        '<script src="assets/landing_ui.js?v=v1" defer></script>'
        '<footer><a href="privacy.html"></a><a href="terms.html"></a>'
        '<a href="disclaimer.html"></a><a href="refunds.html"></a></footer>'
    )
    (landing / "index.html").write_text(broken_html, encoding="utf-8")

    errors = mod.check_tree("landing")
    assert any("Missing header chrome token: id=\"header-tour-btn\"" in e for e in errors)
    assert any("simple_cat_data.js must load before simple_cat.js" in e for e in errors)
    assert any("Inconsistent ?v= for styles.min.css" in e for e in errors)


def test_strict_csp_and_zero_inline_handlers():
    import re

    inline_re = re.compile(r"""\bon(?:click|input|change|submit|keydown|keyup|focus|blur|load|error)\s*=\s*['"]""")
    inline_script_re = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*application/ld\+json)[^>]*>", re.I)
    pages = [
        "index.html",
        "labs.html",
        "audit.html",
        "fleet.html",
        "signup.html",
        "about.html",
        "privacy.html",
        "terms.html",
        "disclaimer.html",
        "refunds.html",
        "benchmark/index.html",
        "ghostdns/index.html",
        "stealthbridge/index.html",
        "portals/index.html",
    ]
    for tree in ("landing", "docs"):
        for rel in pages:
            html = (REPO_ROOT / tree / rel).read_text(encoding="utf-8")
            csp_m = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
            assert csp_m is not None, f"{tree}/{rel} missing CSP meta tag"
            script_src = next((p.strip() for p in csp_m.group(1).split(";") if p.strip().startswith("script-src")), "")
            assert script_src, f"{tree}/{rel} missing script-src directive"
            assert "'unsafe-inline'" not in script_src, f"{tree}/{rel} must not allow 'unsafe-inline' in script-src"
            assert not inline_re.search(html), f"{tree}/{rel} still contains inline event handlers"
            assert not inline_script_re.search(html), f"{tree}/{rel} still contains inline executable <script>"

    for js_path in sorted((REPO_ROOT / "landing" / "assets").glob("*.js")):
        src = js_path.read_text(encoding="utf-8")
        assert not inline_re.search(src), f"landing/assets/{js_path.name} still contains inline event handlers"
