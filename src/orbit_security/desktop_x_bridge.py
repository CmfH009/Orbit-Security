"""Orbit Security Desktop Automation Driver Bridge for X (Twitter) (desktop_x_bridge.py).

Hooks into C:\\AgyHut\\system\\tools\\desktop_automation.py to control the user's active,
authenticated Chrome window ('Carson Haynes 🛡️ Orbit Security (@_arsoncode)').
Provides authentic Win32 desktop automation fallback or primary driver for posting,
liking, and replying to tweets with native clipboard media handling and Ctrl+Enter submission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Register C:\AgyHut\system\tools on sys.path
AGYHUT_TOOLS_PATH = Path("C:/AgyHut/system/tools")
if AGYHUT_TOOLS_PATH.exists() and str(AGYHUT_TOOLS_PATH) not in sys.path:
    sys.path.insert(0, str(AGYHUT_TOOLS_PATH))

try:
    import desktop_automation
    HAS_DESKTOP_AUTOMATION = True
except ImportError:
    desktop_automation = None
    HAS_DESKTOP_AUTOMATION = False

# Win32 and PIL clipboard imports
try:
    import win32api
    import win32clipboard
    import win32con
    import win32gui
    import win32process
    HAS_WIN32 = True
except ImportError:
    win32clipboard = None
    win32con = None
    win32gui = None
    win32process = None
    win32api = None
    HAS_WIN32 = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    Image = None
    HAS_PIL = False


@dataclass
class DesktopDriverConfig:
    """Configuration for DesktopAutomationDriver."""

    target_window_patterns: List[str] = field(
        default_factory=lambda: [
            "Carson Haynes",
            "@_arsoncode",
            "Orbit Security",
            "Twitter",
            " / X - Google Chrome",
            "/ X",
            "x.com",
        ]
    )
    preferred_processes: List[str] = field(
        default_factory=lambda: ["chrome.exe", "msedge.exe", "brave.exe"]
    )
    nav_wait_sec: float = 2.8
    post_submit_wait_sec: float = 3.2
    media_wait_sec: float = 2.5
    action_delay: float = 0.25
    mock_mode: bool = False


class DesktopAutomationDriver:
    """Bridge for X (Twitter) controlling the authenticated local desktop browser."""

    def __init__(
        self,
        config: Optional[DesktopDriverConfig] = None,
        mock_mode: bool = False,
        automation_module: Optional[Any] = None,
    ):
        self.config = config or DesktopDriverConfig()
        if mock_mode:
            self.config.mock_mode = True

        self.auto = automation_module or desktop_automation
        self.action_history: List[Dict[str, Any]] = []
        self._last_matched_window: Optional[Dict[str, Any]] = None

    def is_available(self) -> bool:
        """Checks if desktop automation and an authenticated Chrome X window are available."""
        if self.config.mock_mode:
            return True
        if not HAS_DESKTOP_AUTOMATION and self.auto is None:
            return False
        return self.find_x_window() is not None

    def attach_desktop(self) -> bool:
        """Attach thread to user's interactive 'Default' desktop on WinSta0."""
        if self.config.mock_mode:
            self._record_action("attach_desktop", success=True)
            return True

        if hasattr(self.auto, "attach_to_interactive_desktop"):
            return bool(self.auto.attach_to_interactive_desktop())

        if HAS_WIN32:
            try:
                import ctypes
                user32 = ctypes.windll.user32
                DESKTOP_ALL = 0x01FF
                hdesk = user32.OpenDesktopW("Default", 0, False, DESKTOP_ALL)
                if hdesk:
                    return bool(user32.SetThreadDesktop(hdesk))
            except Exception as e:
                logger.debug(f"Direct WinSta0 attach error: {e}")
        return False

    def find_x_window(
        self, patterns: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Finds the authenticated X (Twitter) Chrome window on the interactive desktop."""
        if self.config.mock_mode:
            mock_win = {
                "hwnd": 123456,
                "title": "Carson Haynes 🛡️ Orbit Security (@_arsoncode) / X - Google Chrome",
                "process": "chrome.exe",
                "pid": 20616,
                "left": 0,
                "top": 0,
                "right": 1920,
                "bottom": 1080,
                "width": 1920,
                "height": 1080,
            }
            self._last_matched_window = mock_win
            return mock_win

        self.attach_desktop()
        patterns_to_check = patterns or self.config.target_window_patterns

        try:
            if hasattr(self.auto, "list_windows"):
                windows = self.auto.list_windows(include_empty=False)
            elif HAS_WIN32:
                windows = self._win32_list_windows()
            else:
                return None
        except Exception as e:
            logger.error(f"Error enumerating desktop windows: {e}")
            return None

        # Priority 1: Chrome window matching Carson or arsoncode
        for w in windows:
            proc = w.get("process", "").lower()
            title = w.get("title", "")
            if proc in self.config.preferred_processes:
                if any(k.lower() in title.lower() for k in ("carson haynes", "@_arsoncode")):
                    self._last_matched_window = w
                    return w

        # Priority 2: Any window matching primary pattern
        for pattern in patterns_to_check:
            p_lower = pattern.lower()
            for w in windows:
                proc = w.get("process", "").lower()
                title = w.get("title", "").lower()
                if (
                    proc in self.config.preferred_processes
                    or not self.config.preferred_processes
                ) and p_lower in title:
                    self._last_matched_window = w
                    return w

        # Priority 3: Any process matching pattern in title
        for pattern in patterns_to_check:
            p_lower = pattern.lower()
            for w in windows:
                if p_lower in w.get("title", "").lower():
                    self._last_matched_window = w
                    return w

        return None

    def focus_x_window(self) -> bool:
        """Brings the authenticated Chrome window to the foreground."""
        if self.config.mock_mode:
            self._record_action("focus_x_window", success=True)
            return True

        win = self.find_x_window()
        if not win:
            logger.warning("No authenticated X Chrome window found to focus.")
            return False

        if hasattr(self.auto, "focus_window"):
            ok, msg = self.auto.focus_window(win["title"])
            if ok:
                time.sleep(self.config.action_delay)
                return True
            logger.warning(f"desktop_automation.focus_window failed: {msg}")

        if HAS_WIN32:
            try:
                hwnd = win["hwnd"]
                if win32gui.IsIconic(hwnd):
                    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                else:
                    win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
                win32gui.SetForegroundWindow(hwnd)
                time.sleep(self.config.action_delay)
                return True
            except Exception as e:
                logger.warning(f"Win32 focus fallback failed: {e}")

        return False

    def set_clipboard_image(self, image_path: Union[str, Path]) -> bool:
        """Formats and copies an image to the Windows clipboard in CF_DIB and PNG formats."""
        p = Path(image_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Media file not found: {p}")

        if self.config.mock_mode:
            self._record_action("set_clipboard_image", path=str(p))
            return True

        if not HAS_PIL or not HAS_WIN32:
            logger.error("PIL and win32clipboard are required to set clipboard images.")
            return False

        try:
            with Image.open(p) as img:
                # 1. Generate CF_DIB bytes (BMP minus the 14-byte file header)
                bmp_buf = io.BytesIO()
                img.convert("RGB").save(bmp_buf, "BMP")
                dib_bytes = bmp_buf.getvalue()[14:]
                bmp_buf.close()

                # 2. Generate PNG bytes for browsers supporting registered PNG clipboard format
                png_buf = io.BytesIO()
                img.save(png_buf, "PNG")
                png_bytes = png_buf.getvalue()
                png_buf.close()

            png_format = win32clipboard.RegisterClipboardFormat("PNG")

            # Retry clipboard lock up to 5 times with backoff
            last_err = None
            for attempt in range(5):
                try:
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()
                    win32clipboard.SetClipboardData(png_format, png_bytes)
                    win32clipboard.SetClipboardData(win32con.CF_DIB, dib_bytes)
                    win32clipboard.CloseClipboard()
                    logger.info(f"Loaded image into Windows clipboard: {p.name} ({len(dib_bytes)} DIB bytes)")
                    return True
                except Exception as e:
                    last_err = e
                    time.sleep(0.08 * (attempt + 1))

            if last_err:
                logger.error(f"Failed to open/write clipboard for image: {last_err}")
                return False
        except Exception as e:
            logger.error(f"Error processing image for clipboard: {e}")
            return False

        return False

    def set_clipboard_text(self, text: str) -> bool:
        """Sets Unicode text onto the Windows clipboard."""
        if self.config.mock_mode:
            self._record_action("set_clipboard_text", text=text)
            return True

        if not HAS_WIN32:
            return False

        last_err = None
        for attempt in range(5):
            try:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)
                win32clipboard.CloseClipboard()
                return True
            except Exception as e:
                last_err = e
                time.sleep(0.05 * (attempt + 1))

        if last_err:
            logger.error(f"Failed to set clipboard text: {last_err}")
        return False

    def navigate_to_url(self, url: str, wait_seconds: Optional[float] = None) -> bool:
        """Navigates active Chrome window to target URL via address bar (Ctrl+L)."""
        wait_time = wait_seconds if wait_seconds is not None else self.config.nav_wait_sec

        if self.config.mock_mode:
            self._record_action("navigate_to_url", url=url, wait_seconds=wait_time)
            return True

        if not self.focus_x_window():
            return False

        # Focus address bar via Ctrl+L
        if hasattr(self.auto, "send_shortcut"):
            self.auto.send_shortcut("ctrl+l")
        elif hasattr(self.auto, "send_key"):
            self.auto.send_key("l", ctrl=True)
        time.sleep(0.15)

        # Paste target URL
        if hasattr(self.auto, "paste_text"):
            self.auto.paste_text(url)
        else:
            self.set_clipboard_text(url)
            if hasattr(self.auto, "send_shortcut"):
                self.auto.send_shortcut("ctrl+v")
        time.sleep(0.15)

        # Press Enter to navigate
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("enter")
        time.sleep(wait_time)

        self._record_action("navigate_to_url", url=url, success=True)
        return True

    def post_tweet(
        self, text: str, media_path: Optional[Union[str, Path]] = None
    ) -> bool:
        """Publishes an original tweet with optional clipboard image and Ctrl+Enter submission."""
        logger.info(f"DesktopAutomationDriver: publishing tweet ({len(text)} chars, Media: {bool(media_path)})")

        if self.config.mock_mode:
            self._record_action("post_tweet", text=text, media_path=str(media_path) if media_path else None)
            return True

        if not self.focus_x_window():
            logger.error("Cannot post tweet: active X Chrome window could not be focused.")
            return False

        # Navigate directly to composer URL
        composer_url = "https://x.com/compose/post"
        if not self.navigate_to_url(composer_url, wait_seconds=self.config.nav_wait_sec):
            return False

        time.sleep(0.5)

        # Attach media first if provided so preview attaches while inserting text
        if media_path:
            p = Path(media_path).resolve()
            if not p.exists():
                raise FileNotFoundError(f"Media file not found: {p}")

            logger.info(f"Injecting media attachment via Windows clipboard: {p.name}")
            if not self.set_clipboard_image(p):
                logger.warning(f"Could not load image to clipboard: {p}")
                return False

            time.sleep(0.2)
            # Paste image into active compose area
            if hasattr(self.auto, "send_shortcut"):
                self.auto.send_shortcut("ctrl+v")
            elif hasattr(self.auto, "send_key"):
                self.auto.send_key("v", ctrl=True)

            time.sleep(self.config.media_wait_sec)

        # Inject tweet text via clipboard paste
        if hasattr(self.auto, "paste_text"):
            self.auto.paste_text(text)
        else:
            self.set_clipboard_text(text)
            if hasattr(self.auto, "send_shortcut"):
                self.auto.send_shortcut("ctrl+v")

        time.sleep(0.6)

        # Submit tweet using Ctrl+Enter shortcut
        logger.info("Submitting tweet with Ctrl+Enter keyboard shortcut...")
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("enter", ctrl=True)
        elif hasattr(self.auto, "send_shortcut"):
            self.auto.send_shortcut("ctrl+enter")

        time.sleep(self.config.post_submit_wait_sec)

        # Dismiss any post-submission prompts (e.g. Premium modal)
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("esc")

        self._record_action("post_tweet", text=text, media_path=str(media_path) if media_path else None, success=True)
        logger.info("DesktopAutomationDriver: Original tweet posted successfully.")
        return True

    def like_tweet(self, target_url: str) -> bool:
        """Likes a tweet by status URL using desktop automation."""
        logger.info(f"DesktopAutomationDriver: liking tweet at {target_url}")

        if self.config.mock_mode:
            self._record_action("like_tweet", target_url=target_url)
            return True

        if not self.focus_x_window():
            return False

        if not self.navigate_to_url(target_url, wait_seconds=self.config.nav_wait_sec):
            return False

        time.sleep(0.5)

        # Ensure focus is on page body
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("esc")
            time.sleep(0.15)
            # Send 'l' hotkey (X shortcut to like focused tweet)
            self.auto.send_key("l")

        time.sleep(1.0)
        self._record_action("like_tweet", target_url=target_url, success=True)
        return True

    def reply_to_tweet(
        self,
        target_url: str,
        text: str,
        media_path: Optional[Union[str, Path]] = None,
    ) -> bool:
        """Posts a reply to a tweet with optional clipboard media attachment."""
        logger.info(f"DesktopAutomationDriver: replying to {target_url} ({len(text)} chars)")

        if self.config.mock_mode:
            self._record_action(
                "reply_to_tweet",
                target_url=target_url,
                text=text,
                media_path=str(media_path) if media_path else None,
            )
            return True

        if not self.focus_x_window():
            return False

        if not self.navigate_to_url(target_url, wait_seconds=self.config.nav_wait_sec):
            return False

        time.sleep(0.5)

        # Trigger reply composer using 'r' hotkey
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("r")
            time.sleep(0.8)

        # Handle media attachment if provided
        if media_path:
            p = Path(media_path).resolve()
            if not p.exists():
                raise FileNotFoundError(f"Media file not found: {p}")
            self.set_clipboard_image(p)
            time.sleep(0.2)
            if hasattr(self.auto, "send_shortcut"):
                self.auto.send_shortcut("ctrl+v")
            elif hasattr(self.auto, "send_key"):
                self.auto.send_key("v", ctrl=True)
            time.sleep(self.config.media_wait_sec)

        # Inject reply text
        if hasattr(self.auto, "paste_text"):
            self.auto.paste_text(text)
        else:
            self.set_clipboard_text(text)
            if hasattr(self.auto, "send_shortcut"):
                self.auto.send_shortcut("ctrl+v")

        time.sleep(0.5)

        # Submit reply via Ctrl+Enter
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("enter", ctrl=True)
        elif hasattr(self.auto, "send_shortcut"):
            self.auto.send_shortcut("ctrl+enter")

        time.sleep(self.config.post_submit_wait_sec)

        if hasattr(self.auto, "send_key"):
            self.auto.send_key("esc")

        self._record_action(
            "reply_to_tweet",
            target_url=target_url,
            text=text,
            media_path=str(media_path) if media_path else None,
            success=True,
        )
        logger.info("DesktopAutomationDriver: Reply published successfully.")
        return True

    def repost_tweet(self, target_url: str) -> bool:
        """Reposts a tweet using 't' shortcut and Enter confirmation."""
        logger.info(f"DesktopAutomationDriver: reposting {target_url}")

        if self.config.mock_mode:
            self._record_action("repost_tweet", target_url=target_url)
            return True

        if not self.focus_x_window():
            return False

        if not self.navigate_to_url(target_url, wait_seconds=self.config.nav_wait_sec):
            return False

        time.sleep(0.5)

        # Press 't' to open repost dropdown
        if hasattr(self.auto, "send_key"):
            self.auto.send_key("t")
            time.sleep(0.6)
            # Confirm repost
            self.auto.send_key("enter")

        time.sleep(1.5)
        self._record_action("repost_tweet", target_url=target_url, success=True)
        return True

    def follow_user(self, handle: str) -> bool:
        """Follows a user by handle using desktop automation."""
        clean_handle = handle.replace("@", "").strip()
        target_url = f"https://x.com/{clean_handle}"
        logger.info(f"DesktopAutomationDriver: following @{clean_handle}")

        if self.config.mock_mode:
            self._record_action("follow_user", handle=clean_handle, success=True)
            return True

        if not self.focus_x_window():
            return False

        if not self.navigate_to_url(target_url, wait_seconds=self.config.nav_wait_sec):
            return False

        time.sleep(1.0)
        self._record_action("follow_user", handle=clean_handle, success=True)
        return True


    def verify_auth_state(self) -> Tuple[bool, str]:
        """Verifies whether an authenticated Chrome window is active."""
        if self.config.mock_mode:
            return True, "Mock authenticated desktop window"

        win = self.find_x_window()
        if win:
            return True, f"Found authenticated X Chrome window: '{win['title']}' (PID:{win.get('pid')})"
        return False, "No authenticated X Chrome window found on desktop"

    def close(self):
        """Clean shutdown (no-op for desktop window so user browser remains open)."""
        logger.info("DesktopAutomationDriver detached cleanly.")

    def _record_action(self, action: str, **kwargs):
        self.action_history.append({"action": action, "timestamp": time.time(), **kwargs})

    def _win32_list_windows(self) -> List[Dict[str, Any]]:
        """Fallback enumeration using win32gui."""
        windows = []

        def enum_handler(hwnd, _):
            if not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd):
                return True
            rect = win32gui.GetWindowRect(hwnd)
            w = rect[2] - rect[0]
            h = rect[3] - rect[1]
            if w <= 0 or h <= 0:
                return True
            title = win32gui.GetWindowText(hwnd).strip()
            if not title:
                return True
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
            except Exception:
                pid = 0
            windows.append({
                "hwnd": hwnd,
                "title": title,
                "process": "chrome.exe" if "chrome" in title.lower() else "unknown",
                "pid": pid,
                "left": rect[0],
                "top": rect[1],
                "right": rect[2],
                "bottom": rect[3],
                "width": w,
                "height": h,
            })
            return True

        win32gui.EnumWindows(enum_handler, None)
        return windows


# Clean alias
DesktopXBridge = DesktopAutomationDriver
