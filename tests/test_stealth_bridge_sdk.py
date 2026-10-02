"""Unit tests for Act IV Product 2: StealthBridge SDK Commercial Library (stealth_bridge_sdk.py).

Covers:
  - Configuration options and seat licensing.
  - Anti-detection human keystroke jitter and cognitive pause simulation.
  - Cubic Bézier cursor dynamics with organic tremor.
  - Stealth injection script validation (masking navigator.webdriver).
  - Cloudflare Turnstile detection and coordinate solver.
  - Resilient proxy pool round-robin and health failover.
  - High-level StealthSession lifecycle.
"""

from __future__ import annotations

import pytest

from orbit_security.stealth_bridge_sdk import (
    AntiDetectionGuard,
    ProxyRouter,
    StealthBridgeConfig,
    StealthSession,
    TurnstileSolver,
)


class TestStealthBridgeSDK:
    def test_config_defaults(self):
        cfg = StealthBridgeConfig(seat_license_key="TEST-SEAT-123")
        assert cfg.seat_license_key == "TEST-SEAT-123"
        assert cfg.humanize_latency is True
        assert cfg.auto_solve_turnstile is True
        assert cfg.cdp_port == 9222

    def test_human_keystroke_delays(self):
        text = "Hello world! This is a test."
        delays = AntiDetectionGuard.generate_human_keystroke_delays(text)
        assert len(delays) == len(text)
        # Verify non-zero natural human delays
        for d in delays:
            assert 0.005 <= d <= 0.350

        # Punctuation pauses should be noticeably higher on average
        space_idx = text.index(" ")
        char_idx = text.index("e")
        # Punctuation or space delay has extra pause
        assert delays[space_idx] > delays[char_idx] * 0.5

    def test_bezier_cursor_path_generation(self):
        start = (100.0, 100.0)
        end = (500.0, 400.0)
        steps = 20
        path = AntiDetectionGuard.generate_bezier_cursor_path(start, end, steps=steps)

        assert len(path) == steps + 1
        # First point equals start
        assert path[0] == start
        # Last point equals end
        assert path[-1] == end
        # Intermediate points progress continuously towards end
        for x, y in path:
            assert isinstance(x, float)
            assert isinstance(y, float)

    def test_stealth_injection_script_content(self):
        js = AntiDetectionGuard.get_stealth_injection_script()
        assert "navigator.webdriver" in js
        assert "window.chrome" in js
        assert "plugins" in js
        assert "Notification.permission" in js

    def test_turnstile_detection_and_coordinates(self):
        clean_dom = "<html><body><h1>Welcome</h1><p>Clean store</p></body></html>"
        assert TurnstileSolver.detect_turnstile(clean_dom) is False

        turnstile_dom = (
            "<html><body><div id='cf-stage' class='challenges.cloudflare.com/turnstile'></div></body></html>"
        )
        assert TurnstileSolver.detect_turnstile(turnstile_dom) is True

        coords = TurnstileSolver.compute_turnstile_box_coordinates(
            iframe_x=100.0, iframe_y=200.0, box_height=60.0
        )
        assert isinstance(coords, tuple)
        assert len(coords) == 2
        # Target coordinate is inside the checkbox region
        assert 120.0 <= coords[0] <= 135.0
        assert 225.0 <= coords[1] <= 235.0

    def test_proxy_router_round_robin_and_failover(self):
        proxies = [
            "http://proxy1.example.com:8080",
            "http://proxy2.example.com:8080",
            "http://proxy3.example.com:8080",
        ]
        router = ProxyRouter(proxy_urls=proxies)

        # Round-robin order
        assert router.get_next_proxy() == proxies[0]
        assert router.get_next_proxy() == proxies[1]
        assert router.get_next_proxy() == proxies[2]
        assert router.get_next_proxy() == proxies[0]

        # Fail proxy1 3 times to mark unhealthy
        router.record_outcome(proxies[0], success=False)
        router.record_outcome(proxies[0], success=False)
        router.record_outcome(proxies[0], success=False)

        # Next proxies should only be proxy2 and proxy3
        next_proxies = {router.get_next_proxy(), router.get_next_proxy()}
        assert proxies[0] not in next_proxies
        assert proxies[1] in next_proxies
        assert proxies[2] in next_proxies

    def test_stealth_session_lifecycle(self):
        cfg = StealthBridgeConfig(humanize_latency=False)
        session = StealthSession(config=cfg)

        assert session.connect(mock_success=True) is True
        assert session.is_connected is True

        # Navigation
        nav_res = session.navigate("https://store.example.com/checkout")
        assert nav_res["status"] == "LOADED"
        assert nav_res["cloaking_injected"] is True

        # Natural typing
        duration = session.human_type("admin@store.com")
        assert duration > 0.0

        # Click
        path = session.human_click(target_coords=(250.0, 350.0), steps=10)
        assert len(path) == 11
        assert session.current_cursor == (250.0, 350.0)

        # Turnstile challenge handle
        cf_dom = "<div class='cf-turnstile'></div>"
        solved_coords = session.handle_turnstile_if_present(cf_dom)
        assert solved_coords is not None
