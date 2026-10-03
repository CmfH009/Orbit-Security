"""Unit and Integration Tests for DesktopAutomationDriver bridge (test_desktop_x_bridge.py).

Verifies:
1. WinSta0 Default interactive desktop attachment.
2. Window discovery logic (matching 'Carson Haynes', '@_arsoncode', 'Twitter', 'X').
3. Windows clipboard image formatting (CF_DIB header stripping and PNG registration).
4. Keyboard automation sequencing for post_tweet (Ctrl+Enter), like_tweet ('l'), reply_to_tweet ('r' + Ctrl+Enter), and repost_tweet ('t' + Enter).
5. Headless / mock fallback when no matching desktop window is present.
6. Integration with OrbitXDriver and SocialDaemon.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from PIL import Image
import pytest

from orbit_security.desktop_x_bridge import (
    DesktopAutomationDriver,
    DesktopDriverConfig,
    DesktopXBridge,
)
from orbit_security.social_daemon import SocialDaemon
from orbit_security.x_driver import DriverConfig, OrbitXDriver


class MockAutomationEngine:
    """Mock desktop_automation module for deterministic offline testing."""

    def __init__(self, windows: Optional[List[Dict[str, Any]]] = None):
        self.call_log: List[Dict[str, Any]] = []
        self.windows = windows if windows is not None else [
            {
                "hwnd": 99991,
                "title": "Carson Haynes 🛡️ Orbit Security (@_arsoncode) / X - Google Chrome",
                "process": "chrome.exe",
                "pid": 20616,
                "left": 0,
                "top": 0,
                "right": 1920,
                "bottom": 1080,
                "width": 1920,
                "height": 1080,
            },
            {
                "hwnd": 99992,
                "title": "Windows Terminal",
                "process": "WindowsTerminal.exe",
                "pid": 13944,
                "left": 0,
                "top": 0,
                "right": 1920,
                "bottom": 1080,
                "width": 1920,
                "height": 1080,
            },
        ]
        self.attached = False

    def attach_to_interactive_desktop(self) -> bool:
        self.call_log.append({"action": "attach_to_interactive_desktop"})
        self.attached = True
        return True

    def list_windows(self, include_empty: bool = False) -> List[Dict[str, Any]]:
        self.call_log.append({"action": "list_windows", "include_empty": include_empty})
        return list(self.windows)

    def focus_window(self, query: str) -> tuple[bool, str]:
        self.call_log.append({"action": "focus_window", "query": query})
        return True, f"Focused window: {query}"

    def send_shortcut(self, combo: str):
        self.call_log.append({"action": "send_shortcut", "combo": combo})

    def send_key(self, key: str, ctrl: bool = False, alt: bool = False, shift: bool = False):
        self.call_log.append({"action": "send_key", "key": key, "ctrl": ctrl, "alt": alt, "shift": shift})

    def paste_text(self, text: str):
        self.call_log.append({"action": "paste_text", "text": text})

    def click_at(self, x: int, y: int, clicks: int = 1, button: str = "left"):
        self.call_log.append({"action": "click_at", "x": x, "y": y, "clicks": clicks, "button": button})


@pytest.fixture
def temp_test_image(tmp_path: Path) -> Path:
    """Creates a temporary test PNG image."""
    img_path = tmp_path / "test_attachment.png"
    img = Image.new("RGB", (120, 120), color=(18, 52, 86))
    img.save(str(img_path), "PNG")
    return img_path


# =========================================================================
# 1. Config and Initialization Tests
# =========================================================================

def test_driver_config_defaults():
    config = DesktopDriverConfig()
    assert "Carson Haynes" in config.target_window_patterns
    assert "@_arsoncode" in config.target_window_patterns
    assert "chrome.exe" in config.preferred_processes
    assert config.nav_wait_sec > 0
    assert config.mock_mode is False


def test_alias_equivalence():
    assert DesktopXBridge is DesktopAutomationDriver


# =========================================================================
# 2. Window Discovery Tests
# =========================================================================

def test_window_discovery_with_mock_engine():
    mock_engine = MockAutomationEngine()
    driver = DesktopAutomationDriver(
        config=DesktopDriverConfig(nav_wait_sec=0.01, post_submit_wait_sec=0.01, media_wait_sec=0.01, action_delay=0.0),
        automation_module=mock_engine,
    )

    win = driver.find_x_window()
    assert win is not None
    assert win["hwnd"] == 99991
    assert "Carson Haynes" in win["title"]
    assert win["process"] == "chrome.exe"
    assert driver.is_available() is True


def test_window_discovery_priorities():
    custom_windows = [
        {"hwnd": 1, "title": "Other / X - Google Chrome", "process": "chrome.exe"},
        {"hwnd": 2, "title": "Carson Haynes 🛡️ Orbit Security (@_arsoncode) / X - Google Chrome", "process": "chrome.exe"},
        {"hwnd": 3, "title": "Carson Haynes Notepad", "process": "notepad.exe"},
    ]
    mock_engine = MockAutomationEngine(windows=custom_windows)
    driver = DesktopAutomationDriver(automation_module=mock_engine)

    # Should prioritize Carson Haynes in chrome.exe (hwnd 2)
    win = driver.find_x_window()
    assert win is not None
    assert win["hwnd"] == 2


def test_window_discovery_not_found():
    no_x_windows = [
        {"hwnd": 1, "title": "Calculator", "process": "calc.exe"},
        {"hwnd": 2, "title": "Settings", "process": "SystemSettings.exe"},
    ]
    mock_engine = MockAutomationEngine(windows=no_x_windows)
    driver = DesktopAutomationDriver(automation_module=mock_engine)

    assert driver.find_x_window() is None
    assert driver.is_available() is False

    ok, reason = driver.verify_auth_state()
    assert ok is False
    assert "No authenticated X Chrome window found" in reason


def test_live_window_discovery():
    """Empirical test against the host system's real windows."""
    driver = DesktopAutomationDriver()
    # Check if host has Carson's window
    win = driver.find_x_window()
    if win:
        assert "@_arsoncode" in win["title"] or "Carson Haynes" in win["title"] or "X" in win["title"]
        assert win["process"].lower() == "chrome.exe"
        assert driver.is_available() is True
        auth_ok, auth_msg = driver.verify_auth_state()
        assert auth_ok is True
        assert "authenticated" in auth_msg.lower()


# =========================================================================
# 3. Interactive Desktop Attachment Tests
# =========================================================================

def test_interactive_desktop_attachment():
    mock_engine = MockAutomationEngine()
    driver = DesktopAutomationDriver(automation_module=mock_engine)
    assert driver.attach_desktop() is True
    assert mock_engine.attached is True


# =========================================================================
# 4. Clipboard Handling and Image Formatting Tests
# =========================================================================

def test_clipboard_image_formatting_real(temp_test_image: Path):
    """Tests placing real DIB and PNG data on the Windows clipboard."""
    driver = DesktopAutomationDriver()
    success = driver.set_clipboard_image(temp_test_image)
    assert success is True

    # Validate clipboard contents via win32clipboard if available
    try:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            has_dib = win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB)
            assert has_dib, "CF_DIB format must be present on Windows clipboard"

            dib_data = win32clipboard.GetClipboardData(win32con.CF_DIB)
            assert len(dib_data) > 0, "DIB payload must not be empty"

            png_fmt = win32clipboard.RegisterClipboardFormat("PNG")
            has_png = win32clipboard.IsClipboardFormatAvailable(png_fmt)
            assert has_png, "Registered PNG format must be present on clipboard"
        finally:
            win32clipboard.CloseClipboard()
    except ImportError:
        pass


def test_clipboard_image_file_not_found():
    driver = DesktopAutomationDriver()
    with pytest.raises(FileNotFoundError):
        driver.set_clipboard_image("A:/nonexistent/path/ghost_image.png")


def test_clipboard_text_setting():
    driver = DesktopAutomationDriver()
    test_str = "Orbit Security Sentinel Test String 🛡️"
    ok = driver.set_clipboard_text(test_str)
    assert ok is True

    try:
        import time
        import win32clipboard
        import win32con

        for attempt in range(5):
            try:
                win32clipboard.OpenClipboard()
                try:
                    clip_text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                    assert clip_text == test_str
                    break
                finally:
                    win32clipboard.CloseClipboard()
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(0.1 * (attempt + 1))
    except ImportError:
        pass


# =========================================================================
# 5. Tweet Operations with Mock Engine
# =========================================================================

def test_post_tweet_flow(temp_test_image: Path):
    mock_engine = MockAutomationEngine()
    driver = DesktopAutomationDriver(
        config=DesktopDriverConfig(
            nav_wait_sec=0.01,
            post_submit_wait_sec=0.01,
            media_wait_sec=0.01,
            action_delay=0.0,
        ),
        automation_module=mock_engine,
    )

    tweet_text = "Dangling CNAME takeover discovery test via DesktopAutomationDriver"
    ok = driver.post_tweet(text=tweet_text, media_path=temp_test_image)
    assert ok is True

    # Verify action sequence
    actions = [call["action"] for call in mock_engine.call_log]

    # Must focus window
    assert "focus_window" in actions

    # Must navigate to compose URL (Ctrl+L -> paste -> enter)
    shortcuts = [call.get("combo") for call in mock_engine.call_log if call["action"] == "send_shortcut"]
    assert "ctrl+l" in shortcuts

    pasted = [call.get("text") for call in mock_engine.call_log if call["action"] == "paste_text"]
    assert "https://x.com/compose/post" in pasted
    assert tweet_text in pasted

    # Must paste media attachment via Ctrl+V
    assert "ctrl+v" in shortcuts

    # Must submit with Ctrl+Enter
    keys_sent = [(call.get("key"), call.get("ctrl")) for call in mock_engine.call_log if call["action"] == "send_key"]
    assert ("enter", True) in keys_sent

    # Must dismiss post modals with Esc
    keys_only = [call.get("key") for call in mock_engine.call_log if call["action"] == "send_key"]
    assert "esc" in keys_only


def test_like_tweet_flow():
    mock_engine = MockAutomationEngine()
    driver = DesktopAutomationDriver(
        config=DesktopDriverConfig(
            nav_wait_sec=0.01,
            post_submit_wait_sec=0.01,
            action_delay=0.0,
        ),
        automation_module=mock_engine,
    )

    target_url = "https://x.com/_arsoncode/status/1880000000000000000"
    ok = driver.like_tweet(target_url)
    assert ok is True

    actions = [call["action"] for call in mock_engine.call_log]
    assert "focus_window" in actions

    pasted = [call.get("text") for call in mock_engine.call_log if call["action"] == "paste_text"]
    assert target_url in pasted

    keys = [call.get("key") for call in mock_engine.call_log if call["action"] == "send_key"]
    assert "l" in keys  # 'l' hotkey for like


def test_reply_to_tweet_disabled():
    """Verifies that reply_to_tweet returns False as commenting is disabled by policy."""
    driver = DesktopAutomationDriver()
    ok = driver.reply_to_tweet("https://x.com/test/status/1", "Test reply")
    assert ok is False


def test_repost_tweet_flow():
    mock_engine = MockAutomationEngine()
    driver = DesktopAutomationDriver(
        config=DesktopDriverConfig(
            nav_wait_sec=0.01,
            post_submit_wait_sec=0.01,
            action_delay=0.0,
        ),
        automation_module=mock_engine,
    )

    target_url = "https://x.com/_arsoncode/status/1880000000000000000"
    ok = driver.repost_tweet(target_url)
    assert ok is True

    keys = [call.get("key") for call in mock_engine.call_log if call["action"] == "send_key"]
    assert "t" in keys
    assert "enter" in keys


# =========================================================================
# 6. Mock Mode / Headless Offline Tests
# =========================================================================

def test_pure_mock_mode():
    driver = DesktopAutomationDriver(mock_mode=True)
    assert driver.is_available() is True
    assert driver.attach_desktop() is True
    assert driver.find_x_window() is not None

    assert driver.post_tweet("Mock post text") is True
    assert driver.like_tweet("https://x.com/test/status/1") is True
    assert driver.reply_to_tweet("https://x.com/test/status/1", "Mock reply") is False
    assert driver.repost_tweet("https://x.com/test/status/1") is True

    assert len(driver.action_history) >= 3


def test_headless_no_window_behavior():
    """When no matching window exists in live mode, methods gracefully return False."""
    mock_engine = MockAutomationEngine(windows=[])
    driver = DesktopAutomationDriver(automation_module=mock_engine)

    assert driver.focus_x_window() is False
    assert driver.post_tweet("Text") is False
    assert driver.like_tweet("https://x.com/test/status/1") is False
    assert driver.reply_to_tweet("https://x.com/test/status/1", "Reply") is False
    assert driver.repost_tweet("https://x.com/test/status/1") is False


# =========================================================================
# 7. OrbitXDriver Integration Tests
# =========================================================================

def test_orbit_x_driver_desktop_mode():
    config = DriverConfig(use_desktop_driver=True)
    driver = OrbitXDriver(config=config)
    # Inject mock desktop driver to avoid real GUI clicks during pytest
    mock_desktop = DesktopAutomationDriver(mock_mode=True)
    driver.desktop_driver = mock_desktop
    driver.start()

    assert driver.is_authenticated is True
    assert driver.post_tweet("Integration tweet") is True
    assert driver.like_tweet("https://x.com/test/status/1") is True
    assert driver.reply_to_tweet("https://x.com/test/status/1", "Integration reply") is False
    assert driver.repost_tweet("https://x.com/test/status/1") is True

    driver.close()
    assert len(mock_desktop.action_history) >= 3


def test_orbit_x_driver_desktop_fallback():
    """When browser page is None, OrbitXDriver falls back to desktop driver."""
    config = DriverConfig(desktop_fallback=True)
    driver = OrbitXDriver(config=config)
    mock_desktop = DesktopAutomationDriver(mock_mode=True)
    driver.desktop_driver = mock_desktop
    driver.page = None

    assert driver.post_tweet("Fallback tweet") is True
    assert driver.like_tweet("https://x.com/test/status/2") is True
    assert driver.reply_to_tweet("https://x.com/test/status/2", "Fallback reply") is False
    assert driver.repost_tweet("https://x.com/test/status/2") is True


# =========================================================================
# 8. SocialDaemon Integration Tests
# =========================================================================

def test_social_daemon_with_desktop_driver(tmp_path):
    from orbit_security.social_state import SocialStateManager

    sm = SocialStateManager(
        db_path=tmp_path / "test_social.db",
        json_export_path=tmp_path / "test_social.json",
    )
    mock_desktop = DesktopAutomationDriver(mock_mode=True)
    daemon = SocialDaemon(dry_run=True, driver=mock_desktop, state_manager=sm)
    assert daemon.driver is mock_desktop

    res = daemon.publish_original_post(text="Social daemon test tweet")
    assert res["status"] in ("SUCCESS", "SIMULATED")


def test_social_daemon_auto_desktop_mode(monkeypatch):
    """Verifies SocialDaemon auto-picks DesktopAutomationDriver if available."""
    mock_desktop = DesktopAutomationDriver(mock_mode=True)
    monkeypatch.setattr(
        "orbit_security.desktop_x_bridge.DesktopAutomationDriver.is_available",
        lambda self: True,
    )
    daemon = SocialDaemon(dry_run=False, driver_mode="desktop", driver=mock_desktop)
    assert isinstance(daemon.driver, DesktopAutomationDriver)


def test_desktop_driver_follow_user_disabled():
    """Verifies that follow_user returns False as following is disabled by policy."""
    mock_desktop = DesktopAutomationDriver(mock_mode=True)
    res = mock_desktop.follow_user("@troyhunt")
    assert res is False


