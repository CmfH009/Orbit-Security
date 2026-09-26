import win32service, win32gui, win32con, win32ui, ctypes, threading, time, traceback
from PIL import Image
import pyautogui, pyperclip

COVER_IMAGE_PATH = r"A:\projects\orbit-security\landing\assets\orbit_cats_banner.jpg"

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
        print(f"Window rect: {rect}")
        
        # Navigate to facebook.com/me
        print("Navigating to facebook.com/me...")
        pyautogui.hotkey('ctrl', 'l')
        time.sleep(0.3)
        pyperclip.copy('https://www.facebook.com/me')
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(0.2)
        pyautogui.press('enter')
        time.sleep(4.0)
        
        # Take screenshot of profile top
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
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\fb_profile_before_cover.png')
        print("Saved profile top to fb_profile_before_cover.png")
        
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
