"""Build Orbit Security "trust assets" for the GitHub Pages site.

Generates, deterministically and re-runnably:

  * assets/og-image.png   1200x630 social card (Pillow)
  * assets/logo.png       512x512 transparent logo mark (Pillow)
  * favicon.ico           multi-resolution icon 16/32/48 (Pillow)
  * robots.txt            crawler + AI-crawler policy
  * sitemap.xml           7 URLs, lastmod 2026-10-22
  * .well-known/security.txt  RFC 9116 disclosure contact
  * llms.txt              plain-markdown convenience summary

Every artefact is written to BOTH ``docs/`` (deployed copy) and ``landing/``
(source copy) so the two trees stay byte-identical for shared files.

Usage::

    python scripts/build_trust_assets.py              # build + verify
    python scripts/build_trust_assets.py --verify-only # verify only
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

# --------------------------------------------------------------------------
# Paths & constants
# --------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[1]
SITE_ROOT = "https://cmfh009.github.io/Orbit-Security"
TREES = (REPO / "docs", REPO / "landing")

FONT_DIR = REPO / "docs" / "assets"
FONT_PIXEL = FONT_DIR / "PressStart2P-Regular.ttf"  # display / headings
FONT_MONO_B = FONT_DIR / "Silkscreen-Bold.ttf"  # tagline
FONT_MONO = FONT_DIR / "Silkscreen-Regular.ttf"  # body / HUD

# Brand palette (matches docs/index.html)
BG_TOP = (2, 6, 23)  # slate-950
BG_BOT = (10, 20, 33)  # deep navy
GRID = (18, 32, 52)
EMERALD = (16, 185, 129)  # #10b981
EMERALD_LT = (110, 231, 183)  # #6ee7b7
EMERALD_DK = (6, 78, 59)  # #064e3b
CYAN = (34, 211, 238)  # #22d3ee
SLATE_300 = (203, 213, 225)  # #cbd5e1
SLATE_400 = (148, 163, 184)  # #94a3b8
WHITE = (248, 250, 252)  # #f8fafc
AMBER = (245, 158, 11)  # #f59e0b

OG_SIZE = (1200, 630)
LOGO_SIZE = (512, 512)
OG_MAX_BYTES = 600 * 1024
LOGO_MAX_BYTES = 200 * 1024
SS = 4  # supersampling factor for vector-ish drawing

# --------------------------------------------------------------------------
# Text assets (exact bytes, written verbatim to both trees)
# --------------------------------------------------------------------------

ROBOTS_TXT = """User-agent: *
Allow: /
Sitemap: https://cmfh009.github.io/Orbit-Security/sitemap.xml

User-agent: GPTBot
Allow: /
User-agent: OAI-SearchBot
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: PerplexityBot
Allow: /
User-agent: Google-Extended
Allow: /
User-agent: CCBot
Allow: /
User-agent: Bytespider
Allow: /
"""

_SITEMAP_URLS = (
    ("https://cmfh009.github.io/Orbit-Security/", "weekly", "1.0"),
    ("https://cmfh009.github.io/Orbit-Security/about.html", "weekly", "0.9"),
    ("https://cmfh009.github.io/Orbit-Security/fleet.html", "weekly", "0.8"),
    ("https://cmfh009.github.io/Orbit-Security/signup.html", "monthly", "0.8"),
    ("https://cmfh009.github.io/Orbit-Security/ghostdns/index.html", "weekly", "0.7"),
    ("https://cmfh009.github.io/Orbit-Security/portals/index.html", "monthly", "0.7"),
    ("https://cmfh009.github.io/Orbit-Security/sample_audit.pdf", "monthly", "0.6"),
)


def build_sitemap_xml() -> str:
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for loc, freq, priority in _SITEMAP_URLS:
        parts += [
            "  <url>",
            f"    <loc>{loc}</loc>",
            "    <lastmod>2026-10-22</lastmod>",
            f"    <changefreq>{freq}</changefreq>",
            f"    <priority>{priority}</priority>",
            "  </url>",
        ]
    parts.append("</urlset>")
    return "\n".join(parts) + "\n"


SECURITY_TXT = """# Orbit Security - vulnerability disclosure contact
# Scope: passive perimeter hygiene disclosures affecting this site only.
# No funded bug bounty program is currently operating.

Canonical: https://cmfh009.github.io/Orbit-Security/.well-known/security.txt
Contact: mailto:carsonmail009@gmail.com
Expires: 2027-10-22T00:00:00.000Z
Policy: https://cmfh009.github.io/Orbit-Security/disclaimer.html
Preferred-Languages: en
Description: Reports are accepted for perimeter hygiene issues affecting this site only - missing or misconfigured security headers, exposed configuration or backup files, leaked credentials in public responses, dangling DNS records, and other publicly observable weaknesses. This is a best-effort channel for defensive research, not a bug bounty. No funded bug bounty program is currently operating, no financial reward is offered, and the presence of this file does not authorise active testing, exploitation, denial of service, or access to any data beyond what is already publicly served. Reports are acknowledged on a best-effort basis and handled in line with the RFC Passive Reconnaissance and Safe Harbor policy linked above.
"""

LLMS_TXT = """# Orbit Security

Orbit Security is an autonomous perimeter intelligence and attack surface management platform for web development agencies. It continuously monitors client digital estates for dangling DNS records, subdomain takeover exposure, email spoofing (DMARC/SPF) gaps, and publicly observable application weaknesses, then converts findings into client-ready work: white-label audit PDFs, DNS and Nginx remediation scripts, and priority-ordered findings for technical directors. Collection is passive. It reads public DNS, Certificate Transparency logs, and HTTP response headers; it never registers a dangling target, never claims an asset, and never attempts exploitation.

## Capabilities

- Continuous attack surface discovery across subdomains, CNAME targets, and certificate transparency logs
- Dangling DNS and subdomain takeover detection with remediation guidance
- DMARC, SPF, and email authentication policy auditing (RFC 7489 / RFC 7208)
- Exposure checks for configuration files, backup archives, and secrets in public responses
- Per-domain and per-client reporting, white-labelable for agency delivery
- Ongoing monitoring scopes for Shopify Plus, WordPress VIP, and Laravel client estates

## Key facts

- Name: Orbit Security (Orbit Security Operations)
- Tagline: Autonomous Perimeter Intelligence
- Founded: 2026, United States
- Founder: Carson Haynes, Founder and Lead Systems Engineer (https://x.com/_arsoncode)
- Type: Defensive, passive perimeter reconnaissance and attack surface hygiene
- Scope: External client perimeter only; not a replacement for internal vulnerability scanning
- Safe harbor and disclosure policy: https://cmfh009.github.io/Orbit-Security/disclaimer.html

## About

https://cmfh009.github.io/Orbit-Security/about.html

## Contact

- Security disclosures and general enquiries: carsonmail009@gmail.com
- Disclosure policy and channel: https://cmfh009.github.io/Orbit-Security/.well-known/security.txt
- Site: https://cmfh009.github.io/Orbit-Security/
"""


# --------------------------------------------------------------------------
# Drawing helpers
# --------------------------------------------------------------------------


def font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(path), size)


def fit_font(path: Path, text: str, max_w: float, start: int, minimum: int = 8) -> ImageFont.FreeTypeFont:
    """Largest size <= start whose rendered width fits max_w."""
    size = start
    while size > minimum:
        f = font(path, size)
        if f.getlength(text) <= max_w:
            return f
        size -= 1
    return font(path, minimum)


def text_w(f: ImageFont.FreeTypeFont, s: str) -> float:
    return f.getlength(s)


def hexagon(cx: float, cy: float, r: float, rotation: float = 0.0) -> list[tuple[float, float]]:
    pts = []
    for i in range(6):
        a = rotation + i * math.pi / 3.0
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


def radial_glow(
    size: tuple[int, int],
    center: tuple[float, float],
    radius: float,
    color: tuple[int, int, int],
    max_alpha: int,
) -> Image.Image:
    """Soft radial light bloom as an RGBA layer."""
    w, h = size
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    steps = 26
    for i in range(steps, 0, -1):
        t = i / steps
        r = radius * t
        alpha = int(max_alpha * (1.0 - t) ** 2.0)
        if alpha <= 0:
            continue
        d.ellipse(
            [center[0] - r, center[1] - r, center[0] + r, center[1] + r],
            fill=(*color, alpha),
        )
    return layer.filter(ImageFilter.GaussianBlur(radius=18))


# --------------------------------------------------------------------------
# OG image (1200x630)
# --------------------------------------------------------------------------


def build_og_image() -> Image.Image:
    w, h = OG_SIZE
    img = Image.new("RGB", OG_SIZE, BG_TOP)
    d = ImageDraw.Draw(img)

    # --- banded vertical gradient (posterised so PNG palette compression wins)
    bands = 48
    for i in range(bands):
        t = i / (bands - 1)
        c = tuple(
            int(BG_TOP[k] + (BG_BOT[k] - BG_TOP[k]) * t) for k in range(3)
        )
        y0 = int(h * i / bands)
        y1 = int(h * (i + 1) / bands) + 1
        d.rectangle([0, y0, w, y1], fill=c)

    # --- faint technical grid
    step = 48
    for x in range(0, w + 1, step):
        d.line([(x, 0), (x, h)], fill=GRID, width=1)
    for y in range(0, h + 1, step):
        d.line([(0, y), (w, y)], fill=GRID, width=1)

    # --- emerald bloom behind the glyph
    img = img.convert("RGBA")
    img.alpha_composite(radial_glow(OG_SIZE, (930, 280), 470, EMERALD, 92))

    # --- horizon sweep line
    sweep = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    ds = ImageDraw.Draw(sweep)
    ds.rectangle([0, 0, w, 2], fill=(*EMERALD, 40))
    sweep = sweep.filter(ImageFilter.GaussianBlur(1.2))
    img.alpha_composite(sweep)

    # ---------------- right-hand emblem: hexagon shield + orbit ring -----
    gx, gy, gr = 930.0, 282.0, 168.0
    glyph = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    gd = ImageDraw.Draw(glyph)

    hexpts = hexagon(gx, gy, gr, rotation=math.pi / 2)
    gd.polygon(hexpts, outline=(*EMERALD_DK, 255), width=2)
    gd.line(hexpts + [hexpts[0]], fill=(*EMERALD, 255), width=7, joint="curve")

    # inner "O" ring
    r_out, r_in = 84.0, 56.0
    gd.ellipse(
        [gx - r_out, gy - r_out, gx + r_out, gy + r_out],
        outline=(*EMERALD, 255),
        width=int(r_out - r_in),
    )

    # tilted orbit ellipse
    orb = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    od = ImageDraw.Draw(orb)
    od.ellipse(
        [gx - 205, gy - 76, gx + 205, gy + 76],
        outline=(*EMERALD_LT, 255),
        width=9,
    )
    orb = orb.rotate(-18, center=(gx, gy), resample=Image.Resampling.BICUBIC)
    gd = ImageDraw.Draw(glyph)
    glyph.alpha_composite(orb)

    # satellite on the orbit
    sat_a = math.radians(-18)
    sat = (gx + 205 * math.cos(sat_a) * 0.985, gy + 205 * math.sin(sat_a) * 0.985)
    gd = ImageDraw.Draw(glyph)
    gd.ellipse([sat[0] - 15, sat[1] - 15, sat[0] + 15, sat[1] + 15], fill=(*EMERALD_LT, 255))
    gd.ellipse(
        [sat[0] - 24, sat[1] - 24, sat[0] + 24, sat[1] + 24],
        outline=(*EMERALD, 140),
        width=3,
    )

    # crosshair ticks
    for ang in (0, 90, 180, 270):
        a = math.radians(ang)
        x0, y0 = gx + 108 * math.cos(a), gy + 108 * math.sin(a)
        x1, y1 = gx + 126 * math.cos(a), gy + 126 * math.sin(a)
        gd.line([(x0, y0), (x1, y1)], fill=(*EMERALD, 190), width=3)

    # glow pass
    glow = glyph.filter(ImageFilter.GaussianBlur(14))
    glow.putalpha(glow.getchannel("A").point(lambda v: int(v * 0.75)))
    img.alpha_composite(glow)
    img.alpha_composite(glyph)

    # ---------------- corner brackets -------------------------------------
    brackets = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    bd = ImageDraw.Draw(brackets)
    bl, off, th = 40, 26, 4
    for (cx, cy, dx, dy) in (
        (off, off, 1, 1),
        (w - off, off, -1, 1),
        (off, h - off, 1, -1),
        (w - off, h - off, -1, -1),
    ):
        bd.line([(cx, cy), (cx + dx * bl, cy)], fill=(*EMERALD, 210), width=th)
        bd.line([(cx, cy), (cx, cy + dy * bl)], fill=(*EMERALD, 210), width=th)
    img.alpha_composite(brackets)

    # ---------------- left-hand copy --------------------------------------
    L = 88
    d = ImageDraw.Draw(img)

    f_eyebrow = font(FONT_MONO_B, 19)
    d.text(
        (L, 118),
        "PERIMETER INTELLIGENCE // EST. 2026",
        font=f_eyebrow,
        fill=EMERALD,
    )

    f_title = font(FONT_PIXEL, 60)
    # hard emerald drop shadow, drawn underneath the glyphs
    d.text((L - 4, 165), "ORBIT", font=f_title, fill=EMERALD)
    d.text((L - 4, 158), "ORBIT", font=f_title, fill=WHITE)
    d.text((L - 4, 245), "SECURITY", font=f_title, fill=EMERALD)
    d.text((L - 4, 238), "SECURITY", font=f_title, fill=WHITE)

    # rule
    d.rectangle([L, 328, L + 428, 333], fill=EMERALD)

    f_tag = fit_font(FONT_MONO_B, "AUTONOMOUS PERIMETER INTELLIGENCE", 560, 27, 14)
    d.text((L, 356), "AUTONOMOUS PERIMETER INTELLIGENCE", font=f_tag, fill=EMERALD_LT)

    f_body = font(FONT_MONO, 19)
    d.text((L, 404), "Continuous attack surface monitoring.", font=f_body, fill=SLATE_300)
    d.text((L, 434), "Subdomain takeover defense. DMARC enforcement.", font=f_body, fill=SLATE_400)

    # ---------------- terminal strip ---------------------------------------
    strip = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    sd = ImageDraw.Draw(strip)
    sd.rectangle([L, 500, 1112, 564], fill=(*(4, 10, 20), 235), outline=(*EMERALD, 190), width=2)
    sd.rectangle([L, 500, L + 6, 564], fill=(*EMERALD, 255))
    img.alpha_composite(strip)
    d = ImageDraw.Draw(img)

    f_term = font(FONT_MONO, 19)
    tx = L + 26
    d.text((tx, 517), ">", font=f_term, fill=EMERALD)
    tx += text_w(f_term, ">") + 24
    for label, colour in (
        ("STATUS: NOMINAL", WHITE),
        ("CNAME_TAKEOVER: 0", EMERALD),
        ("DMARC: ENFORCING", EMERALD),
        ("DRIFT: 0", AMBER),
    ):
        d.text((tx, 517), label, font=f_term, fill=colour)
        tx += text_w(f_term, label) + 40

    # ---------------- CRT scanlines ---------------------------------------
    lines = Image.new("RGBA", OG_SIZE, (0, 0, 0, 0))
    ld = ImageDraw.Draw(lines)
    for y in range(0, h, 4):
        ld.rectangle([0, y, w, y], fill=(0, 0, 0, 26))
    img.alpha_composite(lines)

    # ---------------- bottom-right site tag -------------------------------
    d = ImageDraw.Draw(img)
    f_url = font(FONT_MONO, 16)
    d.text(
        (1112 - text_w(f_url, "cmfh009.github.io/Orbit-Security"), 582),
        "cmfh009.github.io/Orbit-Security",
        font=f_url,
        fill=SLATE_400,
    )

    return img.convert("RGB")


# --------------------------------------------------------------------------
# Logo (512x512 RGBA, transparent)
# --------------------------------------------------------------------------


def build_logo() -> Image.Image:
    S = LOGO_SIZE[0] * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = S / 2.0

    # hexagon shield
    hexpts = hexagon(c, c, S * 0.40, rotation=math.pi / 2)
    d.polygon(hexpts, fill=(*EMERALD_DK, 48))
    d.line(hexpts + [hexpts[0]], fill=(*EMERALD, 255), width=int(S * 0.028), joint="curve")

    # orbit ellipse (drawn on its own layer so it can be rotated)
    orb = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    od = ImageDraw.Draw(orb)
    rx, ry = S * 0.455, S * 0.175
    od.ellipse([c - rx, c - ry, c + rx, c + ry], outline=(*EMERALD_LT, 255), width=int(S * 0.030))
    orb = orb.rotate(-20, center=(c, c), resample=Image.Resampling.BICUBIC)
    img.alpha_composite(orb)

    d = ImageDraw.Draw(img)

    # the "O"
    r_out = S * 0.245
    width = int(S * 0.085)
    d.ellipse(
        [c - r_out, c - r_out, c + r_out, c + r_out],
        outline=(*EMERALD, 255),
        width=width,
    )
    # inner core dot
    r_core = S * 0.055
    d.ellipse([c - r_core, c - r_core, c + r_core, c + r_core], fill=(*EMERALD_LT, 255))

    # satellite on the orbit
    a = math.radians(-20)
    sx, sy = c + rx * math.cos(a), c + rx * math.sin(a)
    d = ImageDraw.Draw(img)
    d.ellipse([sx - S * 0.045, sy - S * 0.045, sx + S * 0.045, sy + S * 0.045], fill=(*EMERALD_LT, 255))
    d.ellipse(
        [sx - S * 0.075, sy - S * 0.075, sx + S * 0.075, sy + S * 0.075],
        outline=(*EMERALD, 200),
        width=int(S * 0.012),
    )

    # soft glow
    glow = img.filter(ImageFilter.GaussianBlur(S * 0.020))
    glow.putalpha(glow.getchannel("A").point(lambda v: int(v * 0.45)))
    out = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    out.alpha_composite(glow)
    out.alpha_composite(img)

    return out.resize(LOGO_SIZE, Image.Resampling.LANCZOS)


# --------------------------------------------------------------------------
# Favicon glyphs (rendered per size for crispness)
# --------------------------------------------------------------------------


def build_favicon_frame(size: int) -> Image.Image:
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = S / 2.0

    # dark tile
    d.rectangle([0, 0, S - 1, S - 1], fill=(*BG_TOP, 255))

    # emerald ring
    r_out = S * 0.38
    width = max(int(S * 0.13), 2)
    d.ellipse(
        [c - r_out, c - r_out, c + r_out, c + r_out],
        outline=(*EMERALD, 255),
        width=width,
    )

    # carve a notch in the ring, then seat a satellite bead in it
    r_mid = r_out - width / 2.0
    ang = math.radians(-52)
    gx, gy = c + r_mid * math.cos(ang), c + r_mid * math.sin(ang)
    gr = S * 0.115

    notch = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(notch).ellipse([gx - gr, gy - gr, gx + gr, gy + gr], fill=(*BG_TOP, 255))
    img.alpha_composite(notch)

    d = ImageDraw.Draw(img)
    dr = S * 0.105
    d.ellipse([gx - dr, gy - dr, gx + dr, gy + dr], fill=(*EMERALD_LT, 255))

    return img.resize((size, size), Image.Resampling.LANCZOS)


# --------------------------------------------------------------------------
# PNG saving with a hard byte budget
# --------------------------------------------------------------------------


def save_png_bounded(img: Image.Image, path: Path, max_bytes: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if img.mode == "RGBA":
        img.save(path, "PNG", optimize=True, compress_level=9)
        if path.stat().st_size <= max_bytes:
            return path.stat().st_size
        # palette fallback keeps per-index alpha via PNG tRNS
        for colors in (200, 128, 96, 64, 48):
            try:
                q = img.quantize(colors=colors, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
            except ValueError:
                break
            q.save(path, "PNG", optimize=True, compress_level=9)
            if path.stat().st_size <= max_bytes:
                break
        return path.stat().st_size

    img.save(path, "PNG", optimize=True, compress_level=9)
    if path.stat().st_size <= max_bytes:
        return path.stat().st_size
    for colors in (160, 128, 96, 64, 48, 32):
        q = img.quantize(colors=colors, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
        q.save(path, "PNG", optimize=True, compress_level=9)
        if path.stat().st_size <= max_bytes:
            break
    return path.stat().st_size


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def write_text(rel: str, content: str) -> list[Path]:
    written = []
    for tree in TREES:
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8")
        p.write_bytes(data)
        written.append(p)
    return written


def build() -> None:
    print("== building trust assets ==")

    og = build_og_image()
    logo = build_logo()
    frames = {s: build_favicon_frame(s) for s in (16, 32, 48)}

    for tree in TREES:
        (tree / "assets").mkdir(parents=True, exist_ok=True)
        (tree / ".well-known").mkdir(parents=True, exist_ok=True)

        og_bytes = save_png_bounded(og, tree / "assets" / "og-image.png", OG_MAX_BYTES)
        logo_bytes = save_png_bounded(logo, tree / "assets" / "logo.png", LOGO_MAX_BYTES)
        print(f"  {tree.name}/assets/og-image.png  {og_bytes:,} bytes")
        print(f"  {tree.name}/assets/logo.png      {logo_bytes:,} bytes")

        ico_path = tree / "favicon.ico"
        frames[48].save(
            ico_path,
            "ICO",
            sizes=[(16, 16), (32, 32), (48, 48)],
            append_images=[frames[16], frames[32]],
        )
        print(f"  {tree.name}/favicon.ico           {ico_path.stat().st_size:,} bytes")

    write_text("robots.txt", ROBOTS_TXT)
    write_text("sitemap.xml", build_sitemap_xml())
    write_text(".well-known/security.txt", SECURITY_TXT)
    write_text("llms.txt", LLMS_TXT)
    print("  robots.txt / sitemap.xml / .well-known/security.txt / llms.txt written")


# --------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def verify() -> int:
    failures: list[str] = []

    print("\n== A. generated images ==")
    print(f"{'file':<62} {'bytes':>10}  dims")
    for tree in TREES:
        for rel in ("assets/og-image.png", "assets/logo.png"):
            p = tree / rel
            if not p.exists():
                failures.append(f"missing {p}")
                continue
            with Image.open(p) as im:
                im.verify()
            with Image.open(p) as im:
                dims = f"{im.width}x{im.height} {im.mode}"
            print(f"{str(p):<62} {p.stat().st_size:>10,}  {dims}")

    for tree in TREES:
        p = tree / "favicon.ico"
        with Image.open(p) as im:
            sizes = sorted(im.ico.sizes())
            im.verify()
        print(f"{str(p):<62} {p.stat().st_size:>10,}  ICO frames {sizes}")

    print("\n== B. size budgets ==")
    for tree in TREES:
        og = tree / "assets" / "og-image.png"
        lg = tree / "assets" / "logo.png"
        for p, budget in ((og, OG_MAX_BYTES), (lg, LOGO_MAX_BYTES)):
            ok = p.stat().st_size <= budget
            print(f"  {str(p):<62} {p.stat().st_size:>10,} <= {budget:,}  {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"over budget: {p}")

    print("\n== C. docs/ vs landing/ byte-identity ==")
    for rel in (
        "robots.txt",
        "sitemap.xml",
        "llms.txt",
        ".well-known/security.txt",
        "assets/og-image.png",
        "assets/logo.png",
        "favicon.ico",
    ):
        a, b = TREES[0] / rel, TREES[1] / rel
        ha, hb = sha256(a), sha256(b)
        ok = ha == hb
        print(f"  {rel:<26} {'IDENTICAL' if ok else 'DIFFERENT'}  sha256={ha[:16]}...")
        if not ok:
            failures.append(f"docs/landing mismatch: {rel}")

    print("\n== D. parse checks ==")
    for tree in TREES:
        root = ET.parse(tree / "sitemap.xml").getroot()
        ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
        urls = root.findall(f"{ns}url")
        locs = [u.find(f"{ns}loc").text for u in urls]
        lastmods = {u.find(f"{ns}lastmod").text for u in urls}
        print(f"  {tree.name}/sitemap.xml  well-formed XML, {len(urls)} urls, lastmod={lastmods}")
        if len(urls) != 7 or lastmods != {"2026-10-22"}:
            failures.append(f"bad sitemap: {tree}")

        for rel in ("robots.txt", ".well-known/security.txt", "llms.txt"):
            txt = (tree / rel).read_text(encoding="utf-8")
            lines = txt.splitlines()
            print(f"  {tree.name}/{rel:<22} {len(lines):>3} lines, {len(txt):>5} chars, utf-8 OK")
            if not txt.endswith("\n"):
                failures.append(f"{tree}/{rel} missing trailing newline")

        llms_lines = (tree / "llms.txt").read_text(encoding="utf-8").splitlines()
        if not llms_lines[0].startswith("# "):
            failures.append(f"{tree}/llms.txt missing H1")
        if len(llms_lines) >= 60:
            failures.append(f"{tree}/llms.txt exceeds 60 lines")
        print(f"  {tree.name}/llms.txt  H1 ok, {len(llms_lines)} lines (<60)")

    print("\n== E. security.txt RFC 9116 field check ==")
    for tree in TREES:
        raw = (tree / ".well-known" / "security.txt").read_text(encoding="utf-8")
        fields: dict[str, list[str]] = {}
        for line in raw.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            k, _, v = line.partition(":")
            fields.setdefault(k.strip().lower(), []).append(v.strip())
        required = {"contact", "expires"}
        missing = required - set(fields)
        dupes = [k for k, v in fields.items() if len(v) > 1 and k in {"expires", "preferred-languages"}]
        print(f"  {tree.name}: fields={sorted(fields)}")
        if missing:
            failures.append(f"{tree} security.txt missing {missing}")
        if dupes:
            failures.append(f"{tree} security.txt duplicate single-occurrence fields {dupes}")
        if fields.get("expires", [""])[0] != "2027-10-22T00:00:00.000Z":
            failures.append(f"{tree} security.txt Expires mismatch")

    print("\n== RESULT ==")
    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        return 1
    print("  ALL CHECKS PASSED")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()

    if not args.verify_only:
        build()
    return verify()


if __name__ == "__main__":
    sys.exit(main())
