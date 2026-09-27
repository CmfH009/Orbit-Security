import win32service, win32con, win32gui, win32clipboard, pyautogui, pyperclip, time, io, traceback
from PIL import Image

def run():
    try:
        hDesk = win32service.OpenDesktop('Default', 0, False, win32con.GENERIC_ALL)
        hDesk.SetThreadDesktop()

        hwnd = 15992538
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.5)

        # Click background to ensure not in an input box
        pyautogui.click(1000, 300)
        time.sleep(0.3)

        # Open compose modal
        print("Opening compose modal...")
        pyautogui.press('n')
        time.sleep(2.0)

        # 1. Copy image to clipboard
        print("Copying image to clipboard...")
        im = Image.open(r'A:\projects\orbit-security\docs\assets\fleet_arena_preview.png')
        output = io.BytesIO()
        im.convert('RGB').save(output, 'BMP')
        data = output.getvalue()[14:]
        output.close()

        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
        win32clipboard.CloseClipboard()
        time.sleep(0.3)

        # Paste image
        print("Pasting image into compose modal...")
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(3.0)

        # 2. Copy and paste Tweet 1 text
        TWEET_1 = """How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:

The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance catches them in 800ms. 🧵👇"""
        pyperclip.copy(TWEET_1)
        time.sleep(0.2)
        print("Pasting Tweet 1 text...")
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(1.5)

        # Screenshot compose state
        shot = pyautogui.screenshot()
        shot.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\6ffa4a2e-a6e3-4baa-9886-9933822cc90f\scratch\tweet_1_composed.png')
        print("Saved compose screenshot.")

        # Post Tweet 1
        print("Submitting Tweet 1...")
        pyautogui.hotkey('ctrl', 'enter')
        time.sleep(4.0)

        shot2 = pyautogui.screenshot()
        shot2.save(r'C:\Users\purav\.gemini\antigravity-cli\brain\6ffa4a2e-a6e3-4baa-9886-9933822cc90f\scratch\tweet_1_posted.png')
        print("Saved posted screenshot.")

    except Exception as e:
        traceback.print_exc()

if __name__ == '__main__':
    run()
