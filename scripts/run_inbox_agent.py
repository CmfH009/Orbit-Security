import argparse
import ctypes
import os
import sys
import time

from orbit_security.inbox_agent import InboxAgent

_MUTEX_HANDLE = None


def acquire_process_mutex(mutex_name: str) -> bool:
    """Enforces single-instance execution via named Windows mutex."""
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


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security Autonomous Inbox & Negotiation Agent"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll inbox once and exit immediately"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Polling interval in seconds (default: 60)"
    )
    args = parser.parse_args()

    if not args.once:
        if not acquire_process_mutex("Global\\OrbitSecurityInboxDaemon"):
            print("[!] Orbit Security Inbox Agent is already running (mutex locked). Exiting.")
            sys.exit(0)

    print("[*] Starting Orbit Security Autonomous Inbox Agent...")
    print("[*] Operator Email: carsonmail009@gmail.com")
    agent = InboxAgent()

    if args.once:
        print("[*] Running single inbox poll...")
        processed = agent.poll_inbox()
        print(f"[✔] Inbox check complete. Processed {len(processed)} message(s).")
        return

    print(f"[*] Entering active daemon loop (polling every {args.interval}s)...")
    print("[*] Supervised under Project ORBIT. Press Ctrl+C to terminate.")

    try:
        while True:
            # 1. Check incoming email replies
            processed = agent.poll_inbox()
            if processed:
                for item in processed:
                    if item.get("needs_escalation"):
                        print(f"    [🔥 ESCALATION] Lead ready to pay: {item.get('sender')}! Alert dispatched to Carson.")

            # 2. Check Stripe for newly completed payments & revenue
            payments = agent.check_stripe_payments()
            if payments:
                for pay in payments:
                    c_email = pay.get("customer_details", {}).get("email")
                    print(f"    [💰 MONEY IN] New paid subscription detected from {c_email}!")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Inbox Agent terminated gracefully.")


if __name__ == "__main__":
    main()
