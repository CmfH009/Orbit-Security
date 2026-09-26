import win32service, win32gui, win32con, win32ui, ctypes, threading, time, traceback
from PIL import Image
import pyautogui, pyperclip

FB_POST_COPY = """Zero-drift attack surface monitoring doesn't have to be complicated.

We built Orbit Security to act as an autonomous 24/7 background sentinel for digital web and Shopify Plus agencies—catching dangling DNS, abandoned staging servers, and email spoofing risks before anyone else notices.

Built with developer craftsmanship and non-intrusive, RFC-compliant passive surveillance.

See how our agency partners package automated white-label security audits into recurring care plans:
👉 https://cmfh009.github.io/Orbit-Security/"""

IMAGE_PATH = r"A:\projects\orbit-security\landing\assets\orbit_cats_pounce.jpg"

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
        
        ctypes.windll.user32.AllowSetForegroundWindow(-1)
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.3)
        
        rect = win32gui.GetWindowRect(hwnd)
        
        # 1. Navigate to facebook.com
        print("Navigating to facebook.com...")
        pyautogui.hotkey('ctrl', 'l')
        time.sleep(0.3)
        pyperclip.copy('https://www.facebook.com/')
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(0.2)
        pyautogui.press('enter')
        time.sleep(4.0)
        
        # 2. Click the green Photo/Video icon at (rect[0] + 565, rect[1] + 215)
        print("Clicking Photo/Video icon...")
        pyautogui.click(rect[0] + 565, rect[1] + 215)
        time.sleep(2.5)
        
        # 3. Handle Open dialog
        dlg = None
        for _ in range(10):
            def find_dlg(h, extra):
                if win32gui.GetWindowText(h) == 'Open':
                    extra.append(h)
                return True
            dlgs = []
            win32gui.EnumWindows(find_dlg, dlgs)
            if dlgs:
                dlg = dlgs[0]
                break
            time.sleep(0.5)
            
        if dlg:
            print(f"Found Open dialog HWND: {dlg}")
            edit_hwnd = None
            open_btn_hwnd = None
            def find_ctrls(h, extra):
                nonlocal edit_hwnd, open_btn_hwnd
                cls = win32gui.GetClassName(h)
                txt = win32gui.GetWindowText(h)
                if cls == 'Edit' and not edit_hwnd:
                    edit_hwnd = h
                if cls == 'Button' and '&Open' in txt:
                    open_btn_hwnd = h
                return True
            win32gui.EnumChildWindows(dlg, find_ctrls, None)
            
            print(f"Setting image path in Open dialog: {IMAGE_PATH}")
            win32gui.SendMessage(edit_hwnd, win32con.WM_SETTEXT, 0, IMAGE_PATH)
            time.sleep(0.4)
            win32gui.SendMessage(open_btn_hwnd, win32con.BM_CLICK, 0, 0)
            time.sleep(3.0)
            
        # 4. Click text area in Create Post modal
        text_x = rect[0] + 250
        text_y = rect[1] + 330
        print(f"Clicking text input area at ({text_x}, {text_y})...")
        pyautogui.click(text_x, text_y)
        time.sleep(0.5)
        
        # 5. Paste text
        print("Pasting Facebook post copy...")
        pyperclip.copy(FB_POST_COPY)
        time.sleep(0.2)
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(2.0)
        
        # 6. Click Post button center at (rect[0] + 400, rect[1] + 980)
        post_btn_x = rect[0] + 400
        post_btn_y = rect[1] + 980
        print(f"Clicking Post button at ({post_btn_x}, {post_btn_y})...")
        pyautogui.click(post_btn_x, post_btn_y)
        time.sleep(5.0)
        
        # 7. Capture verification screenshot
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
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\facebook_cats_post_published.png')
        print("Saved published post verification to scratch/facebook_cats_post_published.png")
        
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
