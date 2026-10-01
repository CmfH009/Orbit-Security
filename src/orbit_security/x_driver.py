"""Orbit Security Autonomous X (Twitter) Driver (x_driver.py).

Production-grade, anti-bot resilient browser automation driver for X (Twitter).
Built on Patchright with persistent browser context, human behavioral dynamics,
React synthetic event compatibility, direct media streaming, and circuit-breaker integration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import datetime
import json
import logging
import math
import os
from pathlib import Path
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Fallback imports: support patchright (stealth) or playwright
try:
    from patchright.sync_api import sync_playwright, Playwright, BrowserContext, Page, Locator, TimeoutError as PwTimeoutError
    DRIVER_FLAVOR = "patchright"
except ImportError:
    try:
        from playwright.sync_api import sync_playwright, Playwright, BrowserContext, Page, Locator, TimeoutError as PwTimeoutError
        DRIVER_FLAVOR = "playwright"
    except ImportError:
        DRIVER_FLAVOR = "none"

try:
    import rookiepy
    HAS_ROOKIE = True
except ImportError:
    HAS_ROOKIE = False

try:
    from orbit_security.desktop_x_bridge import DesktopAutomationDriver
    HAS_DESKTOP_BRIDGE = True
except ImportError:
    DesktopAutomationDriver = None
    HAS_DESKTOP_BRIDGE = False


@dataclass
class TweetData:
    tweet_id: str
    handle: str
    display_name: str
    timestamp: str
    text: str
    status_url: str
    has_media: bool = False
    metrics: Dict[str, str] = field(default_factory=dict)


@dataclass
class DriverConfig:
    user_data_dir: Path = field(default_factory=lambda: Path("data/x_browser_profile"))
    headless: bool = False  # Headless mode: False or True (stealth new headless)
    slow_mo_ms: int = 50
    viewport_width: int = 1440
    viewport_height: int = 900
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    timeout_ms: int = 25000
    cdp_endpoint: Optional[str] = None  # e.g., "http://127.0.0.1:9222" if attaching to running Chrome
    use_desktop_driver: bool = False
    desktop_fallback: bool = True


class HumanKinematics:
    """Generates natural, non-linear mouse Bezier curves and human typing dynamics."""

    @staticmethod
    def bezier_point(p0: Tuple[float, float], p1: Tuple[float, float], 
                     p2: Tuple[float, float], p3: Tuple[float, float], t: float) -> Tuple[float, float]:
        """Cubic Bezier curve point evaluation."""
        u = 1.0 - t
        tt = t * t
        uu = u * u
        uuu = uu * u
        ttt = tt * t

        x = uuu * p0[0] + 3 * uu * t * p1[0] + 3 * u * tt * p2[0] + ttt * p3[0]
        y = uuu * p0[1] + 3 * uu * t * p1[1] + 3 * u * tt * p2[1] + ttt * p3[1]
        return x, y

    @classmethod
    def move_mouse_humanlike(cls, page: Page, target_x: float, target_y: float, steps: int = 25):
        """Moves mouse using a randomized cubic Bezier curve to mimic human arm kinematics."""
        # Random initial perturbation or approximate current position
        start_x = target_x + random.uniform(-300, 300)
        start_y = target_y + random.uniform(-200, 200)

        # Control points with organic perpendicular displacement
        dx = target_x - start_x
        dy = target_y - start_y
        dist = math.hypot(dx, dy)

        ctrl1_x = start_x + dx * 0.25 + random.uniform(-dist * 0.2, dist * 0.2)
        ctrl1_y = start_y + dy * 0.25 + random.uniform(-dist * 0.2, dist * 0.2)

        ctrl2_x = start_x + dx * 0.75 + random.uniform(-dist * 0.15, dist * 0.15)
        ctrl2_y = start_y + dy * 0.75 + random.uniform(-dist * 0.15, dist * 0.15)

        for i in range(1, steps + 1):
            t = i / steps
            # Smooth ease-in-out easing
            t_eased = t * t * (3.0 - 2.0 * t)
            px, py = cls.bezier_point((start_x, start_y), (ctrl1_x, ctrl1_y), (ctrl2_x, ctrl2_y), (target_x, target_y), t_eased)
            page.mouse.move(px, py)
            time.sleep(random.uniform(0.005, 0.015))

    @staticmethod
    def type_humanlike(page: Page, text: str, min_delay_ms: int = 40, max_delay_ms: int = 130):
        """Types string with log-normal delays and natural word-boundary pauses."""
        for char in text:
            page.keyboard.type(char)
            # Log-normal / Gaussian delay simulation
            base_delay = random.gauss(80, 20)
            delay = max(min_delay_ms, min(max_delay_ms, base_delay)) / 1000.0

            # Inter-word thinking pauses
            if char in (' ', '.', ',', '!', '?'):
                delay += random.uniform(0.12, 0.35)

            time.sleep(delay)


class OrbitXDriver:
    """Master Browser Automation Driver for Orbit Security autonomous social agents."""

    # Resilient DOM Selector Matrix
    SELECTORS = {
        "tweet_article": 'article[data-testid="tweet"]',
        "tweet_text": '[data-testid="tweetText"]',
        "user_name": '[data-testid="User-Name"]',
        "like_button": '[data-testid="like"]',
        "unlike_button": '[data-testid="unlike"]',
        "retweet_button": '[data-testid="retweet"]',
        "unretweet_button": '[data-testid="unretweet"]',
        "retweet_confirm": '[data-testid="retweetConfirm"]',
        "retweet_dropdown": '[data-testid="Dropdown"]',
        "reply_button": '[data-testid="reply"]',
        "compose_textarea": '[data-testid="tweetTextarea_0"]',
        "tweet_submit_inline": '[data-testid="tweetButtonInline"]',
        "tweet_submit_modal": '[data-testid="tweetButton"]',
        "file_input": 'input[data-testid="fileInput"]',
        "attachments": '[data-testid="attachments"]',
        "toast_message": '[data-testid="toast"]',
        "error_sheet": '[data-testid="error-detail"]',
        "login_prompt": 'a[href="/login"], a[data-testid="loginButton"]',
        "arkose_frame": 'iframe[src*="arkoselabs"], iframe[src*="arkose"]',
        "follow_button": '[data-testid$="-follow"]',
        "unfollow_button": '[data-testid$="-unfollow"]',
    }

    def __init__(self, config: Optional[DriverConfig] = None):
        self.config = config or DriverConfig()
        self.playwright: Optional[Playwright] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.desktop_driver: Optional[Any] = None
        self.is_authenticated: bool = False
        self._ensure_profile_dir()
        if self.config.use_desktop_driver and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
            self.desktop_driver = DesktopAutomationDriver()

    def _ensure_profile_dir(self):
        self.config.user_data_dir.mkdir(parents=True, exist_ok=True)

    def start(self):
        """Initializes the browser context using Patchright persistent storage, CDP, or DesktopAutomationDriver."""
        if self.config.use_desktop_driver:
            if not self.desktop_driver and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
            if self.desktop_driver:
                self.is_authenticated = self.desktop_driver.is_available()
                logger.info(f"OrbitXDriver initialized in Desktop mode (is_authenticated={self.is_authenticated})")
            return

        if DRIVER_FLAVOR == "none":
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                logger.info("Patchright/playwright unavailable. Activating DesktopAutomationDriver fallback.")
                self.desktop_driver = DesktopAutomationDriver()
                self.is_authenticated = self.desktop_driver.is_available()
                return
            raise RuntimeError("Neither patchright nor playwright is installed.")

        logger.info(f"Initializing OrbitXDriver using engine: [{DRIVER_FLAVOR}]")
        self.playwright = sync_playwright().start()

        # Mode A: Connect to running Chrome via CDP
        if self.config.cdp_endpoint:
            logger.info(f"Connecting to existing Chrome session over CDP: {self.config.cdp_endpoint}")
            self.context = self.playwright.chromium.connect_over_cdp(self.config.cdp_endpoint)
            pages = self.context.pages
            self.page = pages[0] if pages else self.context.new_page()
            return

        # Mode B: Persistent stealth browser context
        args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--window-size=1440,900",
        ]

        logger.info(f"Launching persistent stealth browser context: {self.config.user_data_dir.resolve()}")
        self.context = self.playwright.chromium.launch_persistent_context(
            user_data_dir=str(self.config.user_data_dir.resolve()),
            headless=self.config.headless,
            slow_mo=self.config.slow_mo_ms,
            viewport={"width": self.config.viewport_width, "height": self.config.viewport_height},
            user_agent=self.config.user_agent,
            args=args,
            accept_downloads=True,
            ignore_https_errors=True,
        )

        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self.page.set_default_timeout(self.config.timeout_ms)

        # Load authenticated session cookies from storage_state.json if present
        storage_file = self.config.user_data_dir / "storage_state.json"
        if not storage_file.exists():
            storage_file = Path("data/x_browser_profile/storage_state.json")
        if storage_file.exists():
            try:
                with open(storage_file, "r", encoding="utf-8") as f:
                    state_data = json.load(f)
                cookies = state_data.get("cookies", [])
                if cookies:
                    self.context.add_cookies(cookies)
                    logger.info(f"Loaded {len(cookies)} authenticated session cookies into context.")
            except Exception as e:
                logger.warning(f"Failed to load storage_state cookies: {e}")

        # Apply stealth overrides
        self._apply_stealth_shims()

        # Verify initial auth state
        try:
            auth_ok, auth_reason = self.verify_auth_state()
            self.is_authenticated = auth_ok
            logger.info(f"Driver auth verification: {auth_reason} (is_authenticated={self.is_authenticated})")
        except Exception as e:
            logger.warning(f"Could not verify initial auth state: {e}")

    def _apply_stealth_shims(self):
        """Injects deep stealth scripts into all frames to neutralize CDP/Webdriver fingerprints."""
        stealth_js = """
        // Mask navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        
        // Mock chrome runtime
        window.chrome = {
            runtime: {
                id: 'kbfnbcaeplbcioakkpcpgfkobkghlhen',
                sendMessage: () => {},
                onMessage: { addListener: () => {} }
            }
        };

        // Realistic hardware concurrency & languages
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

        // Normal permissions behavior
        const origQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (params) => (
            params.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                origQuery(params)
        );
        """
        self.page.add_init_script(stealth_js)

    def import_rookie_cookies(self, browser_name: str = "chrome"):
        """Extracts existing X authentication cookies directly from local user browser."""
        if not HAS_ROOKIE:
            logger.warning("rookiepy library not installed. Skipping local cookie import.")
            return False

        try:
            logger.info(f"Extracting X cookies from local {browser_name} using rookiepy...")
            getter = getattr(rookiepy, browser_name, None)
            if not getter:
                getter = rookiepy.chrome
            
            cookies = getter(domains=[".x.com", ".twitter.com"])
            pw_cookies = []
            for c in cookies:
                pw_c = {
                    "name": c["name"],
                    "value": c["value"],
                    "domain": c["domain"],
                    "path": c.get("path", "/"),
                    "httpOnly": bool(c.get("http_only", False)),
                    "secure": bool(c.get("secure", True)),
                    "sameSite": "Lax",
                }
                if c.get("expires"):
                    pw_c["expires"] = int(c["expires"])
                pw_cookies.append(pw_c)

            if pw_cookies:
                self.context.add_cookies(pw_cookies)
                logger.info(f"Successfully loaded {len(pw_cookies)} cookies into session.")
                return True
        except Exception as e:
            logger.error(f"Failed to import rookie cookies: {e}")
        return False

    def verify_auth_state(self) -> Tuple[bool, str]:
        """Checks if browser is currently authenticated to X.com."""
        if self.desktop_driver:
            ok, reason = self.desktop_driver.verify_auth_state()
            self.is_authenticated = ok
            return ok, reason
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                ok, reason = self.desktop_driver.verify_auth_state()
                self.is_authenticated = ok
                return ok, reason
            self.is_authenticated = False
            return False, "Browser page is not active"
        try:
            self.page.goto("https://x.com/home", wait_until="domcontentloaded")
            try:
                self.page.wait_for_selector(
                    f'{self.SELECTORS["tweet_article"]}, {self.SELECTORS["compose_textarea"]}, [data-testid="primaryColumn"], a[href="/login"]',
                    timeout=10000,
                )
            except Exception:
                pass
            time.sleep(1.5)

            # Check for redirect to login
            curr_url = self.page.url
            if "/i/flow/login" in curr_url or "/login" in curr_url:
                self.is_authenticated = False
                return False, "Redirected to login flow"

            # Check for Arkose challenge
            if self.page.locator(self.SELECTORS["arkose_frame"]).count() > 0:
                self.is_authenticated = False
                return False, "Arkose bot challenge detected"

            # Check for home feed presence
            has_feed = self.page.locator(self.SELECTORS["tweet_article"]).count() > 0
            has_compose = self.page.locator(self.SELECTORS["compose_textarea"]).count() > 0
            has_primary = self.page.locator('[data-testid="primaryColumn"]').count() > 0

            if has_feed or has_compose or (has_primary and "/home" in curr_url):
                self.is_authenticated = True
                return True, "Authenticated"
            
            self.is_authenticated = False
            return False, f"Unexpected page state (URL: {curr_url})"
        except Exception as e:
            self.is_authenticated = False
            return False, f"Auth verification error: {e}"

    def check_for_rate_limits(self) -> Tuple[bool, Optional[str]]:
        """Inspects DOM for rate limit banners, toasts, and error notices."""
        try:
            # Check toast container
            toasts = self.page.locator(self.SELECTORS["toast_message"])
            for i in range(toasts.count()):
                t_text = toasts.nth(i).inner_text().lower()
                if "rate limit" in t_text or "too many requests" in t_text or "try again later" in t_text:
                    return True, t_text

            # Check inline error detail
            errors = self.page.locator(self.SELECTORS["error_sheet"])
            if errors.count() > 0:
                err_text = errors.first.inner_text().lower()
                if "rate limit" in err_text:
                    return True, err_text
        except Exception:
            pass
        return False, None

    def harvest_feed(self, feed_url: Optional[str] = None, limit: int = 15, scroll_rounds: int = 4) -> List[TweetData]:
        """Scrapes tweets from feed (navigates to feed_url if provided)."""
        if not self.page:
            logger.warning("Cannot harvest feed: browser page is not active.")
            return []
        if feed_url:
            logger.info(f"Navigating to feed URL: {feed_url}")
            try:
                self.page.goto(feed_url, wait_until="domcontentloaded")
                try:
                    self.page.wait_for_selector(
                        f'{self.SELECTORS["tweet_article"]}, [data-testid="primaryColumn"]',
                        timeout=12000,
                    )
                except Exception:
                    pass
                time.sleep(random.uniform(2.0, 3.5))
            except Exception as e:
                logger.error(f"Navigation failed for feed {feed_url}: {e}")
                return []

        results: Dict[str, TweetData] = {}

        for round_idx in range(scroll_rounds):
            articles = self.page.locator(self.SELECTORS["tweet_article"])
            count = articles.count()

            for i in range(count):
                art = articles.nth(i)
                try:
                    # Status URL
                    links = art.locator('a[href*="/status/"]')
                    if links.count() == 0:
                        continue
                    status_url = links.first.get_attribute("href") or ""
                    if not status_url.startswith("http"):
                        status_url = f"https://x.com{status_url}"

                    tweet_id = status_url.split("/status/")[-1].split("?")[0].split("/")[0]
                    if tweet_id in results:
                        continue

                    # Author info
                    user_el = art.locator(self.SELECTORS["user_name"])
                    user_text = user_el.inner_text() if user_el.count() > 0 else ""
                    lines = [line.strip() for line in user_text.split("\n") if line.strip()]
                    display_name = lines[0] if lines else ""
                    handle = next((l for l in lines if l.startswith("@")), "")

                    # Tweet text
                    text_el = art.locator(self.SELECTORS["tweet_text"])
                    text = text_el.inner_text().strip() if text_el.count() > 0 else ""

                    # Timestamp
                    time_el = art.locator("time")
                    timestamp = time_el.get_attribute("datetime") if time_el.count() > 0 else ""

                    # Media presence
                    has_media = art.locator('[data-testid="tweetPhoto"], [data-testid="videoPlayer"]').count() > 0

                    td = TweetData(
                        tweet_id=tweet_id,
                        handle=handle,
                        display_name=display_name,
                        timestamp=timestamp or "",
                        text=text,
                        status_url=status_url,
                        has_media=has_media,
                    )
                    results[tweet_id] = td
                    if len(results) >= limit:
                        break
                except Exception:
                    continue

            if len(results) >= limit:
                break

            # Natural scroll with momentum
            scroll_delta = random.randint(600, 950)
            self.page.mouse.wheel(0, scroll_delta)
            time.sleep(random.uniform(1.2, 2.0))

        return list(results.values())

    def like_tweet(self, target_url: str) -> bool:
        """Likes a tweet by status URL. Prevents un-liking if already liked."""
        if self.desktop_driver:
            return self.desktop_driver.like_tweet(target_url)
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                return self.desktop_driver.like_tweet(target_url)
            logger.warning("Cannot like tweet: browser page is not active.")
            return False
        logger.info(f"Targeting LIKE on: {target_url}")
        self.page.goto(target_url, wait_until="domcontentloaded")

        # Explicitly wait up to 8s for status page action buttons or tweet container to hydrate
        try:
            self.page.wait_for_selector(
                f'{self.SELECTORS["like_button"]}, {self.SELECTORS["unlike_button"]}, article[data-testid="tweet"]',
                timeout=8000,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.8, 1.5))

        # Check if already liked
        if self.page.locator(self.SELECTORS["unlike_button"]).count() > 0:
            logger.info("Tweet is already liked. Skipping to prevent un-liking.")
            return True

        like_btn = self.page.locator(self.SELECTORS["like_button"]).first
        if not like_btn.is_visible():
            # Keyboard shortcut fallback: Focus tweet via 'j' and trigger 'l'
            try:
                self.page.keyboard.press("Escape")
                time.sleep(0.2)
                self.page.keyboard.press("j")
                time.sleep(0.3)
                self.page.keyboard.press("l")
                time.sleep(1.2)
                if self.page.locator(self.SELECTORS["unlike_button"]).count() > 0:
                    logger.info(f"Like outcome for {target_url} (via shortcut 'l'): SUCCESS")
                    return True
            except Exception:
                pass

        if not like_btn.is_visible():
            logger.warning("Like button not visible on target status page.")
            return False

        # Natural mouse trajectory and click
        box = like_btn.bounding_box()
        if box:
            target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
            target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
            HumanKinematics.move_mouse_humanlike(self.page, target_x, target_y)
            time.sleep(random.uniform(0.1, 0.3))
            self.page.mouse.click(target_x, target_y)
        else:
            like_btn.click()

        time.sleep(random.uniform(1.0, 1.8))
        success = self.page.locator(self.SELECTORS["unlike_button"]).count() > 0
        logger.info(f"Like outcome for {target_url}: {'SUCCESS' if success else 'FAILED'}")
        return success

    def repost_tweet(self, target_url: str) -> bool:
        """Reposts (retweets) a tweet. Handles confirmation modal and duplicate detection."""
        if self.desktop_driver:
            return self.desktop_driver.repost_tweet(target_url)
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                return self.desktop_driver.repost_tweet(target_url)
            logger.warning("Cannot repost tweet: browser page is not active.")
            return False
        logger.info(f"Targeting REPOST on: {target_url}")
        self.page.goto(target_url, wait_until="domcontentloaded")

        try:
            self.page.wait_for_selector(
                f'{self.SELECTORS["retweet_button"]}, {self.SELECTORS["unretweet_button"]}, article[data-testid="tweet"]',
                timeout=8000,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.8, 1.5))

        # Check if already retweeted
        if self.page.locator(self.SELECTORS["unretweet_button"]).count() > 0:
            logger.info("Tweet is already retweeted. Skipping.")
            return True

        rt_btn = self.page.locator(self.SELECTORS["retweet_button"]).first
        if not rt_btn.is_visible():
            # Keyboard shortcut fallback: Focus tweet via 'j' and press 't'
            try:
                self.page.keyboard.press("Escape")
                time.sleep(0.2)
                self.page.keyboard.press("j")
                time.sleep(0.3)
                self.page.keyboard.press("t")
                time.sleep(0.8)
            except Exception:
                pass

        # Check if confirm popover or menuitem appeared
        confirm_btn = self.page.locator(self.SELECTORS["retweet_confirm"]).first
        if not confirm_btn.is_visible():
            confirm_btn = self.page.locator('div[role="menuitem"]:has-text("Repost")').first

        if confirm_btn.is_visible():
            confirm_btn.click()
            time.sleep(random.uniform(1.2, 2.0))
            success = self.page.locator(self.SELECTORS["unretweet_button"]).count() > 0
            logger.info(f"Repost outcome: {'SUCCESS' if success else 'FAILED'}")
            return success

        if rt_btn.is_visible():
            # Click retweet button to open popover
            rt_btn.click()
            time.sleep(random.uniform(0.6, 1.1))

            confirm_btn = self.page.locator(self.SELECTORS["retweet_confirm"]).first
            if not confirm_btn.is_visible():
                confirm_btn = self.page.locator('div[role="menuitem"]:has-text("Repost")').first

            if confirm_btn.is_visible():
                confirm_btn.click()
                time.sleep(random.uniform(1.2, 2.0))
                success = self.page.locator(self.SELECTORS["unretweet_button"]).count() > 0
                logger.info(f"Repost outcome: {'SUCCESS' if success else 'FAILED'}")
                return success

        logger.warning("Repost confirm button did not appear.")
        self.page.keyboard.press("Escape")
        return False

    def follow_user(self, handle: str) -> bool:
        """Follows a user by handle on X. Prevents duplicate follows if already following."""
        if self.desktop_driver:
            return self.desktop_driver.follow_user(handle)
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                return self.desktop_driver.follow_user(handle)
            logger.warning("Cannot follow user: browser page is not active.")
            return False

        clean_handle = handle.replace("@", "").strip()
        target_url = f"https://x.com/{clean_handle}"
        logger.info(f"Targeting FOLLOW on: @{clean_handle} ({target_url})")

        try:
            self.page.goto(target_url, wait_until="domcontentloaded")
            try:
                self.page.wait_for_selector(
                    f'button[aria-label*="Follow @{clean_handle}" i], [data-testid$="-follow"], [data-testid$="-unfollow"]',
                    timeout=12000,
                )
            except Exception:
                pass
            time.sleep(random.uniform(1.5, 2.5))

            # Check if already following
            unfollow_sel = (
                f'button[aria-label*="Unfollow @{clean_handle}" i], '
                f'button[aria-label*="Following @{clean_handle}" i], '
                f'[data-testid$="-unfollow"]'
            )
            if self.page.locator(unfollow_sel).count() > 0:
                logger.info(f"Already following @{clean_handle}. Skipping.")
                return True

            follow_sel = (
                f'button[aria-label*="Follow @{clean_handle}" i], '
                f'[data-testid$="-follow"]'
            )
            follow_btn = self.page.locator(follow_sel).first
            if not follow_btn.is_visible():
                follow_btn = self.page.locator('button:has-text("Follow")').first

            if not follow_btn.is_visible():
                logger.warning(f"Follow button not found on profile for @{clean_handle}.")
                return False

            box = follow_btn.bounding_box()
            if box:
                target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
                target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
                HumanKinematics.move_mouse_humanlike(self.page, target_x, target_y)
                time.sleep(random.uniform(0.1, 0.3))
                self.page.mouse.click(target_x, target_y)
            else:
                follow_btn.click()

            time.sleep(random.uniform(1.8, 3.0))
            success = self.page.locator(unfollow_sel).count() > 0
            logger.info(f"Follow outcome for @{clean_handle}: {'SUCCESS' if success else 'FAILED'}")
            return success
        except Exception as e:
            logger.error(f"Error following user @{clean_handle}: {e}")
            return False


    def reply_to_tweet(self, target_url: str, text: str, media_path: Optional[Union[str, Path]] = None) -> bool:
        """Posts a comment/reply to a specific tweet with optional media attachment."""
        if self.desktop_driver:
            return self.desktop_driver.reply_to_tweet(target_url, text, media_path=media_path)
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                return self.desktop_driver.reply_to_tweet(target_url, text, media_path=media_path)
            logger.warning("Cannot reply to tweet: browser page is not active.")
            return False
        logger.info(f"Submitting REPLY to {target_url} (Media: {bool(media_path)})")
        self.page.goto(target_url, wait_until="domcontentloaded")

        time.sleep(random.uniform(2.0, 3.5))

        # Find reply textarea (inline or modal)
        reply_box = self.page.locator(self.SELECTORS["compose_textarea"]).first
        if not reply_box.is_visible():
            reply_trigger = self.page.locator(self.SELECTORS["reply_button"]).first
            if reply_trigger.is_visible():
                reply_trigger.click()
                time.sleep(random.uniform(0.8, 1.4))
                reply_box = self.page.locator(self.SELECTORS["compose_textarea"]).first

        if not reply_box.is_visible():
            logger.error("Reply textarea could not be activated.")
            return False

        # Focus and human-like typing
        reply_box.click()
        time.sleep(0.3)
        HumanKinematics.type_humanlike(self.page, text)
        time.sleep(random.uniform(0.5, 1.2))

        # Handle media attachment if provided
        if media_path:
            p = Path(media_path).resolve()
            if not p.exists():
                raise FileNotFoundError(f"Media file not found: {p}")

            logger.info(f"Uploading media file: {p.name}")
            file_input = self.page.locator(self.SELECTORS["file_input"]).first
            file_input.set_input_files(str(p))

            # Wait for attachment preview to stabilize
            time.sleep(3.0)
            self._wait_for_media_processing()

        # Submit reply via Ctrl+Enter or submit button
        submit_btn = self.page.locator(self.SELECTORS["tweet_submit_inline"])
        if not submit_btn.is_visible():
            submit_btn = self.page.locator(self.SELECTORS["tweet_submit_modal"])

        if submit_btn.is_visible() and submit_btn.get_attribute("aria-disabled") != "true":
            submit_btn.click()
        else:
            # Trusted keyboard submit fallback
            self.page.keyboard.down("Control")
            self.page.keyboard.press("Enter")
            self.page.keyboard.up("Control")

        time.sleep(random.uniform(3.5, 5.5))
        is_limited, reason = self.check_for_rate_limits()
        if is_limited:
            logger.error(f"Rate limit triggered on reply: {reason}")
            return False

        # Dismiss any post-submission modals (e.g. Premium upsell)
        self.page.keyboard.press("Escape")
        logger.info(f"Reply posted successfully to {target_url}")
        return True

    def post_tweet(self, text: str, media_path: Optional[Union[str, Path]] = None) -> bool:
        """Publishes an original tweet with optional image or video attachment."""
        if self.desktop_driver:
            return self.desktop_driver.post_tweet(text, media_path=media_path)
        if not self.page:
            if self.config.desktop_fallback and HAS_DESKTOP_BRIDGE and DesktopAutomationDriver:
                self.desktop_driver = DesktopAutomationDriver()
                return self.desktop_driver.post_tweet(text, media_path=media_path)
            logger.warning("Cannot post tweet: browser page is not active.")
            return False
        logger.info(f"Publishing original tweet ({len(text)} chars, Media: {bool(media_path)})")
        self.page.goto("https://x.com/home", wait_until="domcontentloaded")

        try:
            self.page.wait_for_selector(
                '[data-testid="SideNav_NewTweet_Button"], [data-testid="tweetTextarea_0"]',
                timeout=20000,
            )
        except Exception as e:
            logger.warning(f"Timeout waiting for compose triggers: {e}")

        side_btn = self.page.locator('[data-testid="SideNav_NewTweet_Button"]').first
        if side_btn.is_visible():
            side_btn.click()
            time.sleep(random.uniform(1.2, 2.0))

        compose_box = self.page.locator(self.SELECTORS["compose_textarea"]).first
        if not compose_box.is_visible():
            self.page.goto("https://x.com/compose/post", wait_until="domcontentloaded")
            time.sleep(3.0)
            compose_box = self.page.locator(self.SELECTORS["compose_textarea"]).first

        if not compose_box.is_visible():
            logger.error("Compose textarea not visible.")
            return False

        compose_box.click()
        time.sleep(0.3)

        # Attach media first if present so preview loads during text insertion
        if media_path:
            p = Path(media_path).resolve()
            if not p.exists():
                raise FileNotFoundError(f"Media file not found: {p}")

            logger.info(f"Streaming media file to file input: {p.name}")
            file_input = self.page.locator(self.SELECTORS["file_input"]).first
            file_input.set_input_files(str(p))
            time.sleep(2.5)

        # Type tweet text with natural cadence
        HumanKinematics.type_humanlike(self.page, text)
        time.sleep(random.uniform(0.8, 1.5))

        # Wait for media ingestion & transcoding if video
        if media_path:
            self._wait_for_media_processing()

        # Submit post
        submit_btn = self.page.locator(self.SELECTORS["tweet_submit_modal"]).first
        if not submit_btn.is_visible():
            submit_btn = self.page.locator(self.SELECTORS["tweet_submit_inline"]).first

        # Ensure button is active
        for _ in range(20):
            if submit_btn.is_visible() and submit_btn.get_attribute("aria-disabled") != "true":
                break
            time.sleep(1.0)

        if submit_btn.is_visible() and submit_btn.get_attribute("aria-disabled") != "true":
            submit_btn.click()
        else:
            logger.info("Using keyboard Ctrl+Enter submission shortcut...")
            self.page.keyboard.down("Control")
            self.page.keyboard.press("Enter")
            self.page.keyboard.up("Control")

        time.sleep(random.uniform(4.0, 6.0))

        # Check for rate limits or errors
        is_limited, reason = self.check_for_rate_limits()
        if is_limited:
            logger.error(f"Rate limit triggered on original post: {reason}")
            return False

        # Dismiss post-submission modals
        self.page.keyboard.press("Escape")
        logger.info("Original tweet published successfully.")
        return True

    def _wait_for_media_processing(self, max_wait_sec: int = 45):
        """Monitors media upload progress bar and transcoding spinners."""
        logger.info("Waiting for media transcoding & upload stabilization...")
        start = time.time()
        while time.time() - start < max_wait_sec:
            # Check if progress bar is present
            progress = self.page.locator('[role="progressbar"]')
            if progress.count() == 0:
                # Progress bar gone, preview ready
                logger.info(f"Media ingestion verified in {time.time() - start:.1f}s.")
                return True
            time.sleep(1.5)
        logger.warning(f"Media processing exceeded {max_wait_sec}s timeout. Proceeding.")
        return False

    def close(self):
        """Clean shutdown of browser context."""
        try:
            if self.desktop_driver:
                try:
                    self.desktop_driver.close()
                except Exception:
                    pass
            if self.context:
                try:
                    self.context.close()
                except Exception:
                    pass
            if self.playwright:
                try:
                    self.playwright.stop()
                except Exception:
                    pass
            logger.info("OrbitXDriver stopped cleanly.")
        except Exception as e:
            logger.debug(f"Error during driver close: {e}")

    stop = close
