import win32service, win32gui, win32con, win32ui, ctypes, threading, time, traceback
from PIL import Image
import pyautogui, pyperclip

FB_POST_COPY = """Turn post-launch security into a recurring retainer. Deliver automated white-label perimeter audits under your agency's brand.

Most web agencies build brilliant sites, hand over the keys, and leave money on the table.

With Orbit Security, you protect up to 40 client domains, monitor DNS decay and subdomain takeover risks 24/7, and automatically generate branded security health audits with your logo and colors.

Our agency partners package this into a $200–$500/month continuous care plan—while our autonomous engine does 100% of the heavy lifting.

Plans start at just $29/mo. 14-day zero-risk trial:
https://cmfh009.github.io/Orbit-Security/#pricing"""

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
            print("No Chrome window found!")
            return
            
        ctypes.windll.user32.AllowSetForegroundWindow(-1)
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.5)
        
        rect = win32gui.GetWindowRect(hwnd)
        print(f"Window rect: {rect}")
        
        # 1. Click text area inside post modal
        text_x = rect[0] + 250
        text_y = rect[1] + 330
        print(f"Clicking text input area at ({text_x}, {text_y})...")
        pyautogui.moveTo(text_x, text_y)
        time.sleep(0.2)
        ctypes.windll.user32.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.05)
        ctypes.windll.user32.mouse_event(4, 0, 0, 0, 0)
        time.sleep(0.5)
        
        # 2. Paste text
        print("Pasting Facebook post copy...")
        pyperclip.copy(FB_POST_COPY)
        time.sleep(0.2)
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(1.5)
        
        # 3. Take screenshot before clicking Post
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
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\facebook_post_filled.png')
        print("Saved filled post to facebook_post_filled.png")
        
        win32gui.DeleteObject(saveBitMap.GetHandle())
        saveDC.DeleteDC()
        mfcDC.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwndDC)
        
        # 4. Click Post button (rect[0] + 450, rect[1] + 960)
        post_btn_x = rect[0] + 450
        post_btn_y = rect[1] + 960
        print(f"Clicking Post button at ({post_btn_x}, {post_btn_y})...")
        pyautogui.moveTo(post_btn_x, post_btn_y)
        time.sleep(0.3)
        ctypes.windll.user32.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.05)
        ctypes.windll.user32.mouse_event(4, 0, 0, 0, 0)
        time.sleep(4.5)
        
        # 5. Capture final confirmation screenshot
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
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\facebook_post_published.png')
        print("Saved published post to facebook_post_published.png")
        
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
