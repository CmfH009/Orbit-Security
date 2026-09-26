import win32service, win32gui, win32con, win32ui, ctypes, threading, time, traceback
from PIL import Image
import pyautogui

IMAGE_PATH = r"A:\projects\orbit-security\landing\assets\orbit_cats_banner.jpg"

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
        print(f"Window rect: {rect}")
        
        # 1. Click "Upload photo" in the open menu (x ≈ 540, y ≈ 450 relative to window)
        upload_x = rect[0] + 540
        upload_y = rect[1] + 450
        print(f"Clicking 'Upload photo' at ({upload_x}, {upload_y})...")
        pyautogui.click(upload_x, upload_y)
        time.sleep(2.5)
        
        # 2. Wait for Open dialog
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
            time.sleep(4.0)
        else:
            print("Open dialog not detected!")
            
        # 3. Capture screenshot of Facebook cover crop/save state
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
        im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\fb_cover_after_upload.png')
        print("Saved to fb_cover_after_upload.png")
        
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
