import win32service, win32con, win32gui, win32process, ctypes, time, traceback
import pyautogui, pyperclip
from PIL import Image

def run():
    try:
        hDesk = win32service.OpenDesktop('Default', 0, False, win32con.GENERIC_ALL)
        hDesk.SetThreadDesktop()

        user_chrome_hwnd = None
        def enum_cb(hwnd, extra):
            nonlocal user_chrome_hwnd
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if title:
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    if pid == 6100:
                        user_chrome_hwnd = hwnd
        win32gui.EnumWindows(enum_cb, None)

        if not user_chrome_hwnd:
            print("ERROR: User Chrome window (PID 6100) not found!")
            return

        print(f"Targeting User Chrome HWND: {user_chrome_hwnd}")
        ctypes.windll.user32.AllowSetForegroundWindow(-1)
        win32gui.ShowWindow(user_chrome_hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(user_chrome_hwnd)
        time.sleep(0.5)

        # Open a new tab
        print("Opening new tab in user's Chrome...")
        pyautogui.hotkey('ctrl', 't')
        time.sleep(0.5)

        # Navigate to Stripe Dashboard status
        stripe_url = "https://dashboard.stripe.com/account/status"
        print(f"Navigating to {stripe_url}...")
        pyperclip.copy(stripe_url)
        time.sleep(0.2)
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(0.2)
        pyautogui.press('enter')

        # Wait for Stripe page to load
        print("Waiting 8 seconds for Stripe Dashboard to load...")
        time.sleep(8.0)

        # Check window title
        current_title = win32gui.GetWindowText(user_chrome_hwnd)
        print(f"Current window title: {current_title}")

        # Capture desktop screenshot
        shot = pyautogui.screenshot()
        shot_path = r"C:\Users\purav\.gemini\antigravity-cli\brain\6ffa4a2e-a6e3-4baa-9886-9933822cc90f\scratch\stripe_account_status.png"
        shot.save(shot_path)
        print(f"Screenshot saved to: {shot_path}")

    except Exception as e:
        traceback.print_exc()

if __name__ == '__main__':
    run()
