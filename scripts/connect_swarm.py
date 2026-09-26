import win32service, win32gui, win32con, win32ui, ctypes, threading, time, random
from PIL import Image
import pyautogui

def run_swarm(target_count=8):
    hDesk = win32service.OpenDesktop('Default', 0, False, win32con.GENERIC_ALL)
    hDesk.SetThreadDesktop()
    
    hwnd = None
    def cb(h, extra):
        nonlocal hwnd
        t = win32gui.GetWindowText(h)
        if 'Chrome' in t and ('LinkedIn' in t or 'Grow' in t or 'Feed' in t):
            hwnd = h
        return True
    win32gui.EnumWindows(cb, None)
    
    if not hwnd:
        print('Chrome LinkedIn window not found!')
        return False
        
    ctypes.windll.user32.AllowSetForegroundWindow(-1)
    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(0.5)
    
    rect = win32gui.GetWindowRect(hwnd)
    print(f'Chrome window rect: {rect}')
    
    def click_at(x, y):
        pyautogui.moveTo(x, y)
        time.sleep(0.15)
        ctypes.windll.user32.mouse_event(2, 0, 0, 0, 0) # MOUSEEVENTF_LEFTDOWN
        time.sleep(0.06)
        ctypes.windll.user32.mouse_event(4, 0, 0, 0, 0) # MOUSEEVENTF_LEFTUP
    
    # Coordinates of visible cards on mynetwork/grow/ (relative to window)
    # We already clicked Card 1 (Row 1 Col 1)
    points_to_click = [
        ("Card 2 (Row 1 Col 2)", rect[0] + 490, rect[1] + 600),
        ("Card 3 (Row 2 Col 1)", rect[0] + 180, rect[1] + 800),
        ("Card 4 (Row 2 Col 2)", rect[0] + 490, rect[1] + 800),
        ("Card 5 (Row 3 Col 1)", rect[0] + 180, rect[1] + 1000),
        ("Card 6 (Row 3 Col 2)", rect[0] + 490, rect[1] + 1000),
    ]
    
    sent = 1 # Billy Boone already sent
    print(f'Starting connection swarm. 1 already pending (Billy Boone). Target: {target_count}')
    
    for name, cx, cy in points_to_click:
        if sent >= target_count:
            break
        jitter = random.uniform(1.4, 2.2)
        time.sleep(jitter)
        print(f'[{sent+1}/{target_count}] Clicking {name} at ({cx}, {cy})...')
        click_at(cx, cy)
        sent += 1

    # If we need more, scroll down and click more
    if sent < target_count:
        print('Scrolling down for next batch...')
        # Position mouse in center of content
        pyautogui.moveTo(rect[0] + 300, rect[1] + 500)
        time.sleep(0.5)
        # Scroll down
        pyautogui.scroll(-550)
        time.sleep(2.0)
        
        # After scrolling down by ~550px, new cards will occupy similar relative row positions
        extra_points = [
            ("Batch 2 Card 1", rect[0] + 180, rect[1] + 680),
            ("Batch 2 Card 2", rect[0] + 490, rect[1] + 680),
            ("Batch 2 Card 3", rect[0] + 180, rect[1] + 880),
            ("Batch 2 Card 4", rect[0] + 490, rect[1] + 880),
        ]
        
        for name, cx, cy in extra_points:
            if sent >= target_count:
                break
            jitter = random.uniform(1.4, 2.3)
            time.sleep(jitter)
            print(f'[{sent+1}/{target_count}] Clicking {name} at ({cx}, {cy})...')
            click_at(cx, cy)
            sent += 1

    print(f'Successfully dispatched {sent} connection requests!')
    time.sleep(2.0)
    
    # Capture verification screenshot
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
    im.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\10a850a6-c4de-444d-8721-e753d8e636c9\scratch\after_swarm_connections.png')
    print('Saved verification screenshot to scratch/after_swarm_connections.png')
    
    win32gui.DeleteObject(saveBitMap.GetHandle())
    saveDC.DeleteDC()
    mfcDC.DeleteDC()
    win32gui.ReleaseDC(hwnd, hwndDC)
    return True

if __name__ == '__main__':
    t = threading.Thread(target=run_swarm, kwargs={'target_count': 8})
    t.start()
    t.join()
