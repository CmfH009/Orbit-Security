import os
import sys
import time
import random
from pathlib import Path
from PIL import Image
import numpy as np

sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

SCRATCH_DIR = Path(r"C:\Users\purav\.gemini\antigravity-cli\brain\03e0bb90-5770-41f8-bb48-334123c6654b\scratch")
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)

WINDOW_LEFT = 946
WINDOW_TOP = 0

def navigate_url(url: str, wait_sec: float = 3.5, label: str = "nav"):
    da.focus_window("chrome")
    time.sleep(0.3)
    da.send_shortcut("ctrl+l")
    time.sleep(0.2)
    da.paste_text(url)
    time.sleep(0.2)
    da.send_key("enter")
    time.sleep(wait_sec)
    shot_path = SCRATCH_DIR / f"{label}.png"
    da.capture_window("chrome", str(shot_path))
    return shot_path

def detect_follow_buttons(img_path: str):
    img = Image.open(img_path)
    arr = np.array(img)
    # The Follow button has off-white background (#eff3f4) around col 530 in the window
    matches = (arr[:, 530, 0] > 230) & (arr[:, 530, 1] > 235)
    ys = np.where(matches)[0]
    clusters = []
    if len(ys) > 0:
        curr = [ys[0]]
        for y in ys[1:]:
            if y - curr[-1] <= 4:
                curr.append(y)
            else:
                if len(curr) >= 12:
                    clusters.append(int(np.mean(curr)))
                curr = [y]
        if len(curr) >= 12:
            clusters.append(int(np.mean(curr)))
    return clusters

def run_follow_batch(query: str, target_count: int = 6, label: str = "batch"):
    url = f"https://x.com/search?q={query}&src=typed_query&f=user"
    print(f"\n[+] Navigating to search: {query} (People)")
    shot_path = navigate_url(url, wait_sec=4.0, label=f"{label}_search")
    
    followed = 0
    attempts = 0
    while followed < target_count and attempts < 3:
        attempts += 1
        centers = detect_follow_buttons(str(shot_path))
        print(f"    Found {len(centers)} Follow buttons on screen.")
        if not centers:
            # Try scrolling down to load more
            print("    Scrolling down...")
            da.scroll(-5, 1400, 500)
            time.sleep(2.5)
            shot_path = SCRATCH_DIR / f"{label}_scroll_{attempts}.png"
            da.capture_window("chrome", str(shot_path))
            continue
            
        da.focus_window("chrome")
        time.sleep(0.2)
        for y in centers:
            if followed >= target_count:
                break
            screen_x = WINDOW_LEFT + 550
            screen_y = WINDOW_TOP + y
            print(f"    -> Clicking Follow at ({screen_x}, {screen_y})")
            da.click_at(screen_x, screen_y)
            followed += 1
            time.sleep(random.uniform(0.7, 1.2))
            
        if followed < target_count:
            print("    Scrolling for next page...")
            da.scroll(-6, 1400, 500)
            time.sleep(2.5)
            shot_path = SCRATCH_DIR / f"{label}_scroll_{attempts}.png"
            da.capture_window("chrome", str(shot_path))

    # Final verification shot
    verify_shot = SCRATCH_DIR / f"{label}_done.png"
    da.capture_window("chrome", str(verify_shot))
    print(f"[✓] Followed {followed} accounts for '{query}'. Verification saved to {verify_shot.name}")
    return followed

if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "infosec"
    cnt = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    lbl = sys.argv[3] if len(sys.argv) > 3 else "test"
    run_follow_batch(q, cnt, lbl)
