"""Perfectly fixes the X Header Banner (1500x500 3:1), Avatar copy, and Boast & Roast Card."""
import os
import shutil
from PIL import Image, ImageDraw, ImageFont

ARTIFACT_DIR = r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9"
ASSETS_DIR = r"A:\projects\orbit-security\docs\assets"
LANDING_ASSETS_DIR = r"A:\projects\orbit-security\landing\assets"

def get_mono_font(size, bold=True):
    candidates = [
        r"C:\Windows\Fonts\consolab.ttf" if bold else r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ]
    for c in candidates:
        if os.path.exists(c):
            try:
                return ImageFont.truetype(c, size)
            except Exception:
                pass
    return ImageFont.load_default()

# 1. Copy fixed Avatar to assets
avatar_fixed_src = os.path.join(ARTIFACT_DIR, "orbit_x_avatar_fixed_jpg_1792655947621.jpg")
avatar_out = os.path.join(ARTIFACT_DIR, "orbit_x_avatar_fixed.jpg")
shutil.copyfile(avatar_fixed_src, avatar_out)
shutil.copyfile(avatar_fixed_src, os.path.join(ASSETS_DIR, "orbit_x_avatar_2026.jpg"))
shutil.copyfile(avatar_fixed_src, os.path.join(LANDING_ASSETS_DIR, "orbit_x_avatar_2026.jpg"))

# 2. Fix X Header Banner -> 1500x500 (3:1 X Header aspect ratio)
header_src = os.path.join(ARTIFACT_DIR, "orbit_x_header_2026_png_1792655709309.jpg")
img_h = Image.open(header_src).convert("RGB")
w, h = img_h.size  # 1408 x 792

canvas_w = 1860
canvas_h = 620
padded = Image.new("RGB", (canvas_w, h), (3, 7, 17))
padded.paste(img_h, (canvas_w - w, 0))
# Smoothly blend the seam at x = canvas_w - w (452) over 60 pixels so there is zero visible line
seam_x = canvas_w - w
for y in range(h):
    right_col = img_h.getpixel((0, y))
    for dx in range(-40, 20):
        x = seam_x + dx
        alpha = (dx + 40) / 60.0
        orig = padded.getpixel((x, y))
        blended = tuple(int((1 - alpha) * right_col[i] + alpha * orig[i]) for i in range(3))
        padded.putpixel((x, y), right_col if dx < 0 else blended)
# Fill left extension with exact leftmost column pixels of img_h so gradient is 100% seamless
for y in range(h):
    left_px = img_h.getpixel((0, y))
    for x in range(seam_x):
        padded.putpixel((x, y), left_px)
cropped_h = padded.crop((0, 130, canvas_w, 130 + canvas_h))
final_header = cropped_h.resize((1500, 500), Image.Resampling.LANCZOS)

draw_h = ImageDraw.Draw(final_header)
font_badge = get_mono_font(17, bold=True)
font_sub = get_mono_font(13, bold=False)

t1 = "ORBIT SECURITY // PERIMETER SENTINELS"
t2 = "RFC-8484 DoH RADAR  •  SUBDOMAIN TAKEOVER DEFENSE"
b1 = draw_h.textbbox((0, 0), t1, font=font_badge)
b2 = draw_h.textbbox((0, 0), t2, font=font_sub)
box_w = max(b1[2] - b1[0], b2[2] - b2[0]) + 44
box_h = 70

draw_h.rounded_rectangle([(36, 28), (36 + box_w, 28 + box_h)], radius=10, fill=(8, 13, 26), outline=(16, 185, 129), width=2)
draw_h.text((58, 40), t1, fill=(16, 185, 129), font=font_badge)
draw_h.text((58, 66), t2, fill=(148, 163, 184), font=font_sub)

header_out = os.path.join(ARTIFACT_DIR, "orbit_x_header_fixed.jpg")
final_header.save(header_out, quality=95)
final_header.save(os.path.join(ASSETS_DIR, "orbit_x_header_2026.jpg"), quality=95)
final_header.save(os.path.join(LANDING_ASSETS_DIR, "orbit_x_header_2026.jpg"), quality=95)

# 3. Fix Boast & Roast Split-Screen Post Card
card_src = os.path.join(ARTIFACT_DIR, "orbit_x_boast_roast_card_png_1792655756601.jpg")
img_c = Image.open(card_src).convert("RGB")
cw, ch = img_c.size  # 1408 x 792
draw_c = ImageDraw.Draw(img_c)

# The tiny "▲ ΔIC!" on the server rack is right below the big warning triangle at x=205..272, y=342..365
panel_bg = img_c.getpixel((285, 352))
draw_c.rectangle([(205, 342), (275, 366)], fill=panel_bg)
font_mini = get_mono_font(14, bold=True)
draw_c.text((210, 346), "ERR: 404", fill=(239, 68, 68), font=font_mini)

# Bottom-right URL pill using dynamic textbbox so it NEVER clips
url_text = "LIVE SIMULATOR: cmfh009.github.io/Orbit-Security"
font_url = get_mono_font(15, bold=True)
ub = draw_c.textbbox((0, 0), url_text, font=font_url)
tw = ub[2] - ub[0]
th = ub[3] - ub[1]
pill_w = tw + 44
pill_h = 42
px1 = cw - pill_w - 24
py1 = ch - pill_h - 20
draw_c.rounded_rectangle([(px1, py1), (px1 + pill_w, py1 + pill_h)], radius=10, fill=(6, 10, 22), outline=(16, 185, 129), width=2)
draw_c.text((px1 + 22, py1 + 12), url_text, fill=(52, 211, 153), font=font_url)

card_out = os.path.join(ARTIFACT_DIR, "orbit_x_boast_roast_card_fixed.jpg")
img_c.save(card_out, quality=95)
img_c.save(os.path.join(ASSETS_DIR, "orbit_x_boast_roast_card.jpg"), quality=95)
img_c.save(os.path.join(LANDING_ASSETS_DIR, "orbit_x_boast_roast_card.jpg"), quality=95)
print("[+] Perfected Header, Avatar, and Boast & Roast Card!")
