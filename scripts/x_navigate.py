import time
import sys
from pathlib import Path

# Add system tools to path
sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da

def navigate(url: str, wait_sec: float = 3.5, shot_name: str = "x_nav.png"):
    print(f"Navigating Chrome to {url}...")
    da.focus_window("chrome")
    time.sleep(0.3)
    da.send_shortcut("ctrl+l")
    time.sleep(0.3)
    da.paste_text(url)
    time.sleep(0.2)
    da.send_key("enter")
    print(f"Waiting {wait_sec}s for page render...")
    time.sleep(wait_sec)
    
    out_path = Path(r"C:\Users\purav\.gemini\antigravity-cli\brain\03e0bb90-5770-41f8-bb48-334123c6654b\scratch") / shot_name
    ok, msg = da.capture_window("chrome", str(out_path))
    print(f"Capture result: {ok}, {msg}")
    return ok, str(out_path)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://x.com/search?q=web%20security%20agency&src=typed_query&f=user"
    name = sys.argv[2] if len(sys.argv) > 2 else "x_search_users.png"
    navigate(url, 4.0, name)
