import sys
sys.path.insert(0, r"C:\AgyHut\system\tools")
import desktop_automation as da
import time, win32clipboard, win32con

da.attach_to_interactive_desktop()
da.focus_window("Carson Haynes")
time.sleep(1.0)

# Open DevTools console
da.send_shortcut("ctrl+shift+j")
time.sleep(2.0)

script = "copy(document.querySelector('article time').closest('a').href);"
da.paste_text(script)
time.sleep(0.5)
da.send_key("enter")
time.sleep(1.0)

# Close devtools
da.send_shortcut("ctrl+shift+j")
time.sleep(0.8)

win32clipboard.OpenClipboard()
url = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
win32clipboard.CloseClipboard()
print("Top Tweet URL:", url)
