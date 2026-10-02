#!/usr/bin/env python3
r"""
Orbit Security Autonomous Social Agent Daemon CLI & Runner
==========================================================
Executes the hourly social pipeline daemon with single-instance Win32 mutex,
quota controls, circuit breaker tripwires, and supervisor integration.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time
from pathlib import Path

# Add src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from orbit_security.circuit_breaker import BreakerState, SocialCircuitBreaker
from orbit_security.quota_manager import SocialQuotaManager
from orbit_security.social_daemon import SocialDaemon
from orbit_security.social_state import SocialStateManager

_MUTEX_HANDLE = None


def acquire_process_mutex(mutex_name: str = "Global\\OrbitSecuritySocialDaemon") -> bool:
    """Enforces strict single-instance execution via named Windows mutex."""
    global _MUTEX_HANDLE
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        last_error = kernel32.GetLastError()
        ERROR_ALREADY_EXISTS = 183
        if last_error == ERROR_ALREADY_EXISTS:
            if handle:
                kernel32.CloseHandle(handle)
            return False
        _MUTEX_HANDLE = handle
        return True
    except Exception:
        return True


def apply_process_priority():
    """Enforces BELOW_NORMAL_PRIORITY_CLASS on Windows to respect desktop workloads."""
    if os.name == "nt":
        try:
            import psutil
            p = psutil.Process(os.getpid())
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        except Exception:
            pass


def print_status():
    """Renders formatted operational health, quota balances, and breaker state."""
    state_mgr = SocialStateManager()
    quota_mgr = SocialQuotaManager(state_manager=state_mgr)
    summary = quota_mgr.get_status_summary()

    print("==============================================================================")
    print(" 🛡️ ORBIT SECURITY SOCIAL DAEMON STATUS")
    print("==============================================================================")

    # Check process liveness via state file
    state_file = PROJECT_ROOT / "data" / "social_daemon_state.json"
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                st = json.load(f)
            print(f" Daemon State:     {st.get('status')} (PID: {st.get('pid')})")
            print(f" Circuit Breaker:  {st.get('circuit_state')}")
            print(f" Last Heartbeat:   {st.get('timestamp')}")
        except Exception:
            print(" Daemon State:     UNKNOWN")
    else:
        print(" Daemon State:     NOT RUNNING (No state file)")

    print("------------------------------------------------------------------------------")
    print(f" Time-of-Day Band: {summary['time_of_day_band']} (Multiplier: {summary['velocity_multiplier']}x)")
    print(f" Dedup Records:    {len(state_mgr._dedup_cache)} interacted actions cached in SQLite")
    print("------------------------------------------------------------------------------")
    print(" Quota Balances (Current Cycle & Today):")
    print(f"  • Posts:    Hourly {summary['hourly_executed'].get('POST', 0)}/{summary['hourly_limits']['posts']}  |  Daily {summary['daily_executed'].get('posts_count', 0)}/{summary['daily_caps']['posts']}")
    print(f"  • Replies:  Hourly {summary['hourly_executed'].get('REPLY', 0)}/{summary['hourly_limits']['replies']}  |  Daily {summary['daily_executed'].get('replies_count', 0)}/{summary['daily_caps']['replies']}")
    print(f"  • Likes:    Hourly {summary['hourly_executed'].get('LIKE', 0)}/{summary['hourly_limits']['likes']}  |  Daily {summary['daily_executed'].get('likes_count', 0)}/{summary['daily_caps']['likes']}")
    print(f"  • Reposts:  Hourly {summary['hourly_executed'].get('REPOST', 0)}/{summary['hourly_limits']['reposts']}  |  Daily {summary['daily_executed'].get('reposts_count', 0)}/{summary['daily_caps']['reposts']}")
    print(f"  • Follows:  Hourly {summary['hourly_executed'].get('FOLLOW', 0)}/{summary['hourly_limits']['follows']}  |  Daily {summary['daily_executed'].get('follows_count', 0)}/{summary['daily_caps']['follows']}")
    print("==============================================================================")


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security Autonomous Social Pipeline Daemon"
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuous 24/7 background execution loop",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Execute single hourly cycle and exit immediately",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Display current daemon health, quotas, and database metrics",
    )
    parser.add_argument(
        "--reset-circuit",
        action="store_true",
        help="Manually reset tripped circuit breaker to CLOSED (nominal)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without mutating external X state",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force execution even during dormant night window",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=7200,
        help="Base execution interval in seconds (default: 7200)",
    )

    args = parser.parse_args()

    if args.status or (not args.daemon and not args.once and not args.reset_circuit):
        print_status()
        return

    if args.reset_circuit:
        state_mgr = SocialStateManager()
        breaker = SocialCircuitBreaker(state_manager=state_mgr)
        breaker.reset()
        print("✓ Circuit breaker successfully reset to CLOSED.")
        return

    # Check Mutex
    if not acquire_process_mutex():
        print("[!] An Orbit Security Social Daemon is already running (mutex locked). Exiting.")
        sys.exit(0)

    apply_process_priority()

    daemon = SocialDaemon(
        nominal_interval_seconds=args.interval,
        dry_run=args.dry_run,
    )
    if args.force:
        daemon.force_cycle = True

    if args.once:
        print("[*] Executing single hourly cycle...")
        try:
            result = daemon.execute_hourly_cycle()
            print(f"[✓] Single cycle complete: {result}")
        finally:
            daemon.close()
        return

    if args.daemon:
        print("[*] Launching Orbit Security Social Daemon in continuous loop...")
        print("[*] Supervised under Project ORBIT. Press Ctrl+C to terminate.")
        try:
            daemon.run_loop()
        finally:
            daemon.close()


if __name__ == "__main__":
    main()
