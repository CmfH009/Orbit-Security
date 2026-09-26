import win32service, win32gui, win32con, win32ui, ctypes, threading, time, traceback
from PIL import Image
import pyautogui, pyperclip

LINKEDIN_LAUNCH_COPY = """Most web agencies build extraordinary digital experiences.

They spend months perfecting the UX, tuning Core Web Vitals, and writing clean code.

Then comes launch day. Champagne bottles pop. Everyone celebrates. 🥂

And then... 6 months pass.

A developer forgets an old staging subdomain.
A third-party DNS record gets left pointing to an abandoned cloud bucket.
DMARC email security silently drifts to p=none.

Nobody notices until a malicious actor claims the dangling DNS or a client's deliverability tanks. And when that happens, the client doesn't blame the hosting vendor.

They call the agency.

I spent the past several months architecting a solution to this exact problem: Orbit Security.

Orbit Security is an autonomous perimeter hygiene and white-label reporting sentinel built exclusively for digital web and eCommerce agencies.

Here is how we built it differently:
1. 100% Non-Intrusive: Zero code to install, zero access tokens required, strictly RFC-compliant passive surveillance.
2. Human Craftsmanship + Autonomous AI: I personally review and tune our security heuristics and reporting standards, while our autonomous sentinel engine, Nova, handles 24/7 background telemetry.
3. Built to Drive Agency Revenue: Our partners package our automated white-label PDF audits directly into their monthly care plans, turning passive security into an extra $200–$500/mo retainer per client.

We just pushed our live platform and released our agency tier:
👉 https://cmfh009.github.io/Orbit-Security/

If you run a web or Shopify agency and want me to run a complimentary, zero-obligation perimeter audit on one of your flagship client builds, drop a comment below or send me a DM.

#WebDevelopment #ShopifyPlus #CyberSecurity #AgencyGrowth #B2BSaaS #SystemsArchitecture"""

BANNER_PATH = r"A:\projects\orbit-security\landing\assets\orbit_ad_banner.jpg"

def run():
    try:
        hDesk = win32service.OpenDesktop('Default', 0, False, win32con.GENERIC_ALL)
        hDesk.SetThreadDesktop()
        
        hwnd = None
        def cb(h, extra):
            nonlocal hwnd
            t = win32gui.GetWindowText(h)
            if 'Chrome' in t:
                hwnd = h
            return True
        win32gui.EnumWindows(cb, None)
        
        if not hwnd:
            print("Chrome window not found!")
            return
            
        ctypes.windll.user32.AllowSetForegroundWindow(-1)
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.3)
        
        rect = win32gui.GetWindowRect(hwnd)
        
        # Navigate to feed
        print("Navigating to LinkedIn feed...")
        pyautogui.hotkey('ctrl', 'l')
        time.sleep(0.3)
        pyperclip.copy('https://www.linkedin.com/feed/')
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(0.2)
        pyautogui.press('enter')
        time.sleep(4.0)
        
        # Click "Start a post" (approx x=rect[0] + 250, y=rect[1] + 200 depending on resolution)
        print("Clicking Start a post...")
        pyautogui.click(rect[0] + 250, rect[1] + 215)
        time.sleep(2.0)
        
        # Focus post modal and paste
        print("Pasting launch post copy...")
        pyperclip.copy(LINKEDIN_LAUNCH_COPY)
        time.sleep(0.2)
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(1.5)
        
        # Capture screenshot
        w = rect[2] - rect[0]
        h = rect[3] - rect[1]
        hwndDC = win32gui.GetWindowDC(hwnd)
        mfcDC  = win32ui.CreateDCFromHandle(hwndDC)
        saveDC = mfcDC.CreateCompatibleDC()
        saveBitMap = win32ui.CreateBitmap()
        saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
        saveDC.SelectObject(saveBitMap)
        
        ctypes.windll.user32.PrintWindow(hwnd, saveDC.GetSafeHdc(), 2)
        bmpinfo = saveBitMap.GetInfo()
        bmpstr = saveBitMap.GetBitmapBits(True)
        im = Image.frombuffer('RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']), bmpstr, 'raw', 'BGRX', 0, 1)
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\linkedin_post_state.png')
        print("Saved LinkedIn post modal to scratch/linkedin_post_state.png")
        
        win32gui.DeleteObject(saveBitMap.GetHandle())
        saveDC.DeleteDC()
        mfcDC.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwndDC)

    except Exception as e:
        traceback.print_exc()

if __name__ == '__main__':
    t = threading.Thread(target=run)
    t.start()
    t.join()
