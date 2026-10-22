"""
Upgrades `orbit_boast_roast_2026.mp4` to Version 2 after visual critique:
1. Removes duplicate URL badge from Slide 1.
2. Crops out the grey right-hand Chrome scrollbar (x=1902..1920) and bookmarks bar residue (y=108..112).
3. Tightly zooms into the UI cards on Slides 2, 3, and 4 so text is 2x larger and legible on mobile X feeds without clicking fullscreen.
"""

import os
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, r"A:\projects\orbit-security\src")
from orbit_security.voice_model import CatVoiceEngine, VoiceProfile

ARTIFACT_DIR = Path(r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9")
DOCS_ASSETS = Path(r"A:\projects\orbit-security\docs\assets")
LANDING_ASSETS = Path(r"A:\projects\orbit-security\landing\assets")

def get_font(size: int, bold: bool = True) -> ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\consolab.ttf" if bold else r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
    ]
    for c in candidates:
        if os.path.exists(c):
            try:
                return ImageFont.truetype(c, size)
            except Exception:
                pass
    return ImageFont.load_default()

def build_zoomed_frame(
    src_path: Path,
    crop_box: tuple | None,
    step_badge: str,
    headline: str,
    subline: str,
    accent_rgb: tuple,
    out_path: Path,
):
    """Creates a crisp 1920x1080 broadcast slide with tight UI focus for mobile X legibility."""
    canvas = Image.new("RGB", (1920, 1080), (4, 8, 18))
    draw = ImageDraw.Draw(canvas)

    im = Image.open(src_path).convert("RGB")
    if crop_box is not None:
        im = im.crop(crop_box)

    target_w, target_h = 1760, 840
    im_resized = im.resize((target_w, target_h), Image.Resampling.LANCZOS)

    vx, vy = (1920 - target_w) // 2, 42
    draw.rounded_rectangle(
        [(vx - 4, vy - 4), (vx + target_w + 4, vy + target_h + 4)],
        radius=16,
        fill=(8, 14, 28),
        outline=accent_rgb,
        width=3,
    )
    canvas.paste(im_resized, (vx, vy))

    # Bottom broadcast HUD bar
    bar_x1, bar_y1, bar_x2, bar_y2 = 80, 902, 1840, 1048
    draw.rounded_rectangle(
        [(bar_x1, bar_y1), (bar_x2, bar_y2)],
        radius=16,
        fill=(9, 15, 30),
        outline=accent_rgb,
        width=3,
    )

    font_step = get_font(18, bold=True)
    font_head = get_font(30, bold=True)
    font_sub = get_font(20, bold=False)
    font_url = get_font(20, bold=True)

    sb_bbox = draw.textbbox((0, 0), step_badge, font=font_step)
    sb_w = (sb_bbox[2] - sb_bbox[0]) + 32
    draw.rounded_rectangle(
        [(bar_x1 + 28, bar_y1 + 20), (bar_x1 + 28 + sb_w, bar_y1 + 54)],
        radius=8,
        fill=accent_rgb,
    )
    draw.text((bar_x1 + 44, bar_y1 + 27), step_badge, fill=(4, 8, 18), font=font_step)
    draw.text((bar_x1 + 48 + sb_w, bar_y1 + 19), headline, fill=(255, 255, 255), font=font_head)
    draw.text((bar_x1 + 28, bar_y1 + 78), subline, fill=(148, 163, 184), font=font_sub)

    url_str = "cmfh009.github.io/Orbit-Security"
    ub = draw.textbbox((0, 0), url_str, font=font_url)
    uw = (ub[2] - ub[0]) + 40
    ux1 = bar_x2 - uw - 28
    draw.rounded_rectangle(
        [(ux1, bar_y1 + 44), (bar_x2 - 28, bar_y1 + 102)],
        radius=10,
        fill=(4, 8, 18),
        outline=accent_rgb,
        width=2,
    )
    draw.text((ux1 + 20, bar_y1 + 61), url_str, fill=accent_rgb, font=font_url)

    canvas.save(out_path, quality=95)
    return out_path

def main():
    slides_dir = ARTIFACT_DIR / "video_slides"
    slides_dir.mkdir(parents=True, exist_ok=True)

    # Clean Slide 1 source without duplicate bottom-right URL pill (only ERR: 404 fix)
    raw_card = Image.open(ARTIFACT_DIR / "orbit_x_boast_roast_card_png_1792655756601.jpg").convert("RGB")
    draw_rc = ImageDraw.Draw(raw_card)
    panel_bg = raw_card.getpixel((285, 352))
    draw_rc.rectangle([(205, 342), (275, 366)], fill=panel_bg)
    draw_rc.text((210, 346), "ERR: 404", fill=(239, 68, 68), font=get_font(14, bold=True))
    clean_card_path = slides_dir / "clean_card_no_pill.jpg"
    raw_card.save(clean_card_path, quality=95)

    s1 = build_zoomed_frame(
        src_path=clean_card_path,
        crop_box=None,
        step_badge="01 // THE ROAST",
        headline="404 Dangling CNAMEs vs. Active Perimeter Defense",
        subline="Agencies charge $50k for a build, then leave promo.client.com dangling on Unbounce & DMARC on p=none.",
        accent_rgb=(239, 68, 68),
        out_path=slides_dir / "slide_01_roast.jpg",
    )

    # Slide 2: Zoom into the Attack Simulator Terminal (16:9 crop: 1488x709 centered at x=216..1704, y=220..929)
    s2 = build_zoomed_frame(
        src_path=ARTIFACT_DIR / "audit_02_attack_simulator.png",
        crop_box=(216, 210, 1704, 919),
        step_badge="02 // ATTACK SIMULATOR",
        headline="1-Click Live Subdomain Hijack Packet Trace",
        subline="Watch how an attacker claims an abandoned CNAME in 60 seconds—or neutralize it before they do.",
        accent_rgb=(245, 158, 11),
        out_path=slides_dir / "slide_02_simulator.jpg",
    )

    # Slide 3: Zoom directly into the White-Label PDF Flipbook Modal with full bottom padding (x=350..1570, y=235..816 -> 1220x581)
    s3 = build_zoomed_frame(
        src_path=ARTIFACT_DIR / "audit_05_pdf_flipbook_modal.png",
        crop_box=(350, 235, 1570, 816),
        step_badge="03 // WHITE-LABEL PDF",
        headline="100% Co-Branded Executive Audit Deliverables",
        subline="Compiled in browser RAM with your agency logo, brand palette, and zero Orbit Security watermarks.",
        accent_rgb=(16, 185, 129),
        out_path=slides_dir / "slide_03_flipbook.jpg",
    )

    # Slide 4: Zoom into the Retainer ROI Calculator + 3 Pricing Cards including Deploy CTAs (x=136..1784, y=180..965 -> 1648x785)
    s4 = build_zoomed_frame(
        src_path=ARTIFACT_DIR / "audit_06_pricing_roi_vault.png",
        crop_box=(136, 180, 1784, 965),
        step_badge="04 // RETAINER ROI VAULT",
        headline="Turn $59/mo Into +$74,292/yr Net Agency Profit",
        subline="Just 1 client on a $250/mo security care plan pays for your entire Orbit stack 4x over.",
        accent_rgb=(6, 182, 212),
        out_path=slides_dir / "slide_04_roi.jpg",
    )

    # Reuse synthesized voiceover track
    audio_path = slides_dir / "vo_helmet.wav"
    if not audio_path.exists():
        audio_path = slides_dir / "vo_raw.mp3"

    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", str(audio_path)],
        capture_output=True,
        text=True,
    )
    total_dur = float(probe.stdout.strip() or "29.87")
    seg_dur = total_dur / 4.0

    concat_txt = slides_dir / "concat.txt"
    with open(concat_txt, "w", encoding="utf-8") as f:
        for sl in [s1, s2, s3, s4]:
            f.write(f"file '{sl.as_posix()}'\n")
            f.write(f"duration {seg_dur:.3f}\n")
        f.write(f"file '{s4.as_posix()}'\n")

    out_mp4 = ARTIFACT_DIR / "orbit_boast_roast_2026.mp4"
    cmd = [
        "ffmpeg", "-y",
        "-f", "concat", "-safe", "0", "-i", str(concat_txt),
        "-i", str(audio_path),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", "30", "-preset", "fast", "-crf", "20",
        "-c:a", "aac", "-b:a", "192k",
        "-shortest",
        str(out_mp4),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"ffmpeg failed:\n{res.stderr}")

    for dest in [DOCS_ASSETS / "orbit_boast_roast_2026.mp4", LANDING_ASSETS / "orbit_boast_roast_2026.mp4"]:
        dest.write_bytes(out_mp4.read_bytes())

    print(f"[+] Re-rendered V2 MP4: {out_mp4} ({out_mp4.stat().st_size:,} bytes)")

if __name__ == "__main__":
    main()
