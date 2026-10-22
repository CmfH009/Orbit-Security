#!/usr/bin/env python3
"""Orbit Security - publishing harness for the "roast F grades" X campaign.

SAFETY MODEL (hard defaults)
-----------------------------
* Dry run is the default. Nothing is published unless ``--post`` is passed AND a
  concrete target (``--thread`` or ``--id <post_id>``) is supplied.
* Only ids that exist in the manifest's ``posts`` array are publishable. Anything in
  ``held_variants`` is refused with a DO-NOT-PUBLISH error.
* The X length validator runs before any browser interaction; a validation failure
  aborts the publish.
* The publish is refused when no authenticated Chrome window with an X tab is found.
* The publish is refused when a publish already happened inside the trailing 8h
  window (or the daily cap is reached) unless ``--force`` is passed. Policy mirrors
  ``src/orbit_security/quota_manager.py``: ``max_daily_posts = 2``,
  ``min_post_spacing_hours = 8.0``, ``max_hourly_posts = 1``.
* Every attempt (dry run or real) is appended to ``data/roast_f_grades_post_log.jsonl``
  with timestamps, mode, post ids, weighted lengths, result and evidence image paths.

Desktop automation reuses the shared library at ``C:\\AgyHut\\system\\tools`` and the
proven posting patterns from ``post_x_vulnerability_thread.py`` /
``post_x_thread_continuation.py`` / ``post_boast_and_roast_x.py``.

Usage
-----
  post_x_roast_f_grades.py                          # dry run, full preview (default)
  post_x_roast_f_grades.py --list                   # print the manifest
  post_x_roast_f_grades.py --check-session          # inspect windows only, posts nothing
  post_x_roast_f_grades.py --thread                 # dry run of the 4-post thread
  post_x_roast_f_grades.py --thread --post          # REAL publish of the thread
  post_x_roast_f_grades.py --id roast-standalone-1 --post
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = REPO_ROOT / "data" / "roast_f_grades_posts.json"
LOG_PATH = REPO_ROOT / "data" / "roast_f_grades_post_log.jsonl"
ARTIFACT_DIR = r"C:\Users\purav\.gemini\antigravity-cli\brain\9dad3157-5599-43d5-afaf-94bd85ec1bc9"
SOCIAL_DB_PATH = REPO_ROOT / "data" / "orbit_social.db"

PROFILE_URL = "https://x.com/_arsoncode"
COMPOSE_URL = "https://x.com/compose/post"

# Deliberate pacing (matches the proven scripts, and the required floors).
NAV_SETTLE_SECONDS = 8.0     # >= 8s after every page navigation
POST_GAP_SECONDS = 6.0       # >= 6s between posts
PASTE_SETTLE_SECONDS = 2.5   # draft preview stabilisation after paste
SUBMIT_SETTLE_SECONDS = 6.0  # cooldown after Ctrl+Enter

# Fallback quota policy (mirrors src/orbit_security/quota_manager.py).
FALLBACK_MAX_DAILY_POSTS = 2
FALLBACK_MIN_SPACING_HOURS = 8.0
FALLBACK_MAX_HOURLY_POSTS = 1

# Shared desktop automation library.
sys.path.insert(0, r"C:\AgyHut\system\tools")
try:  # pragma: no cover - import guard
    import desktop_automation as da
    DA_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    da = None  # type: ignore[assignment]
    DA_IMPORT_ERROR = str(exc)

# Shared validator (single source of truth for the weighting rule).
sys.path.insert(0, str(SCRIPT_DIR))
try:  # pragma: no cover - import guard
    import validate_x_post_lengths as validator
    VALIDATOR_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    validator = None  # type: ignore[assignment]
    VALIDATOR_IMPORT_ERROR = str(exc)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt: datetime.datetime) -> str:
    return dt.isoformat()


def banner(title: str, width: int = 78) -> str:
    return "\n".join(["=" * width, title, "=" * width])


def require_desktop_automation() -> Any:
    if da is None:
        raise RuntimeError(
            "desktop_automation is unavailable "
            f"({VALIDATOR_IMPORT_ERROR or DA_IMPORT_ERROR}). "
            "Run with the project venv: A:\\projects\\orbit-security\\.venv\\Scripts\\python.exe"
        )
    return da


def require_validator() -> Any:
    if validator is None:
        raise RuntimeError(
            f"validate_x_post_lengths could not be imported ({VALIDATOR_IMPORT_ERROR})."
        )
    return validator


# --------------------------------------------------------------------------- #
# Manifest + publishability guard
# --------------------------------------------------------------------------- #
def load_manifest(path: Path = MANIFEST_PATH) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def publishable_posts(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Only the ``posts`` array is publishable. ``held_variants`` never appear here."""
    return list(manifest.get("posts") or [])


def held_variants(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(manifest.get("held_variants") or [])


def publishable_ids(manifest: Dict[str, Any]) -> List[str]:
    return [str(p.get("id")) for p in publishable_posts(manifest)]


def thread_posts(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Thread posts ordered by their ``position`` field (fallback: manifest order)."""
    posts = [p for p in publishable_posts(manifest) if str(p.get("type")) == "thread"]
    return sorted(posts, key=lambda p: (p.get("position") if isinstance(p.get("position"), int) else 10_000))


def assert_publishable(post_id: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Hard guard: refuse anything that is not a publishable ``posts`` id."""
    allowed = publishable_ids(manifest)
    if post_id in allowed:
        for post in publishable_posts(manifest):
            if str(post.get("id")) == post_id:
                return post

    held_ids = [str(h.get("id")) for h in held_variants(manifest)]
    if post_id in held_ids:
        raise PermissionError(
            f"REFUSED: '{post_id}' is a HELD variant (DO-NOT-PUBLISH). "
            "Only ids present in the manifest's 'posts' array can ever be published."
        )
    raise KeyError(
        f"REFUSED: '{post_id}' is not a publishable post id. Publishable ids: {', '.join(allowed)}"
    )


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def append_log(record: Dict[str, Any], path: Path = LOG_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def read_log_records(path: Path = LOG_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:  # noqa: BLE001
            continue
    return records


# --------------------------------------------------------------------------- #
# Quota policy (mirrors src/orbit_security/quota_manager.py)
# --------------------------------------------------------------------------- #
def load_quota_policy() -> Dict[str, Any]:
    """Read the real budget from quota_manager.QuotaBudget when importable."""
    policy = {
        "max_daily_posts": FALLBACK_MAX_DAILY_POSTS,
        "min_post_spacing_hours": FALLBACK_MIN_SPACING_HOURS,
        "max_hourly_posts": FALLBACK_MAX_HOURLY_POSTS,
        "source": "fallback constants (quota_manager import failed)",
    }
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from orbit_security.quota_manager import QuotaBudget  # noqa: WPS433

        budget = QuotaBudget()
        policy.update(
            {
                "max_daily_posts": budget.max_daily_posts,
                "min_post_spacing_hours": budget.min_post_spacing_hours,
                "max_hourly_posts": budget.max_hourly_posts,
                "source": "src/orbit_security/quota_manager.py:QuotaBudget",
            }
        )
    except Exception as exc:  # noqa: BLE001
        policy["import_error"] = str(exc)
    return policy


def read_db_posts(db_path: Path = SOCIAL_DB_PATH) -> List[Dict[str, Any]]:
    """Read-only view of successful POST actions from the social state DB."""
    if not db_path.exists():
        return []
    try:
        import sqlite3

        uri = f"file:{db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT tweet_id, action_type, status, created_at_utc FROM social_actions "
                "WHERE action_type IN ('POST','ORIGINAL_POST') AND status = 'SUCCESS' "
                "ORDER BY created_at_utc DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return []


def _parse_ts(value: Any) -> Optional[datetime.datetime]:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except Exception:  # noqa: BLE001
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def collect_publish_history(
    log_path: Path = LOG_PATH, db_path: Path = SOCIAL_DB_PATH
) -> Dict[str, Any]:
    """Collect publish timestamps from the harness log (authoritative for this
    harness) and from the shared social state DB (mirrors quota_manager)."""
    harness: List[Dict[str, Any]] = []
    for record in read_log_records(log_path):
        if record.get("mode") != "post" or record.get("result") != "success":
            continue
        when = _parse_ts(record.get("timestamp_utc"))
        if when:
            harness.append(
                {
                    "when": when,
                    "source": "harness-log",
                    "label": record.get("action") or ",".join(record.get("post_ids") or []),
                    "originals": int(record.get("original_count") or 1),
                }
            )

    db_rows: List[Dict[str, Any]] = []
    for row in read_db_posts(db_path):
        when = _parse_ts(row.get("created_at_utc"))
        if when:
            db_rows.append(
                {
                    "when": when,
                    "source": "orbit_social.db",
                    "label": str(row.get("tweet_id")),
                    "originals": 1,
                }
            )

    all_publishes = sorted(harness + db_rows, key=lambda item: item["when"])
    return {"harness": harness, "db": db_rows, "all": all_publishes}


def evaluate_quota(history: Dict[str, Any], policy: Dict[str, Any], now: datetime.datetime) -> Dict[str, Any]:
    """Evaluate the quota policy for a NEW publish burst."""
    publishes = history["all"]
    spacing_hours = float(policy["min_post_spacing_hours"])
    window = datetime.timedelta(hours=spacing_hours)

    recent_window = [p for p in publishes if now - p["when"] < window]
    last = publishes[-1] if publishes else None
    elapsed_hours = (now - last["when"]).total_seconds() / 3600.0 if last else None

    hourly_window = datetime.timedelta(hours=1)
    recent_hour = [p for p in publishes if now - p["when"] < hourly_window]

    today = now.strftime("%Y-%m-%d")
    originals_today = sum(
        p["originals"]
        for p in publishes
        if p["when"].strftime("%Y-%m-%d") == today
    )

    reasons: List[str] = []
    if recent_window:
        reasons.append(
            f"{len(recent_window)} publish(es) already occurred in the trailing "
            f"{spacing_hours:g}h window (this one would make {len(recent_window) + 1}); "
            f"policy allows 1 original post per {spacing_hours:g}h"
        )
    if elapsed_hours is not None and elapsed_hours < spacing_hours:
        reasons.append(
            f"only {elapsed_hours:.2f}h since the last publish (minimum "
            f"{spacing_hours:g}h required)"
        )
    if len(recent_hour) >= int(policy["max_hourly_posts"]):
        reasons.append(
            f"{len(recent_hour)} publish(es) in the last hour "
            f"(max_hourly_posts = {policy['max_hourly_posts']})"
        )
    if originals_today >= int(policy["max_daily_posts"]):
        reasons.append(
            f"{originals_today} original post(s) already published today (UTC {today}); "
            f"max_daily_posts = {policy['max_daily_posts']}"
        )

    return {
        "ok": not reasons,
        "reasons": reasons,
        "policy": policy,
        "publishes_in_window": len(recent_window),
        "publishes_last_hour": len(recent_hour),
        "originals_today": originals_today,
        "hours_since_last_publish": round(elapsed_hours, 3) if elapsed_hours is not None else None,
        "last_publish": iso(last["when"]) if last else None,
        "last_publish_source": last["source"] if last else None,
    }


# --------------------------------------------------------------------------- #
# Session detection (read-only)
# --------------------------------------------------------------------------- #
X_TITLE_MARKERS = (
    "x.com",
    "twitter.com",
    " / x",
    "/ x -",
    "x - google chrome",
    "(x) ",
    "home / x",
    "notifications / x",
    "post / x",
    "messages / x",
)


def check_session() -> Dict[str, Any]:
    """Read-only inspection: is there a Chrome window showing X?

    Never navigates, never types, never clicks. Only enumerates top-level windows.
    """
    module = require_desktop_automation()
    module.attach_to_interactive_desktop()
    windows = module.list_windows(include_empty=False)

    chrome_windows = [
        w for w in windows if "chrome" in str(w.get("process", "")).lower() and w.get("width", 0) > 600
    ]
    x_windows = []
    for window in chrome_windows:
        title = str(window.get("title", "")).lower()
        if any(marker in title for marker in X_TITLE_MARKERS):
            x_windows.append(window)

    try:
        import psutil

        chrome_pids = sum(1 for p in psutil.process_iter(["name"]) if (p.info.get("name") or "").lower() == "chrome.exe")
    except Exception:  # noqa: BLE001
        chrome_pids = -1

    return {
        "checked_utc": iso(utc_now()),
        "chrome_window_count": len(chrome_windows),
        "chrome_process_count": chrome_pids,
        "x_tab_detected": bool(x_windows),
        "x_windows": [{"title": w.get("title"), "hwnd": w.get("hwnd")} for w in x_windows],
        "chrome_windows": [{"title": w.get("title"), "hwnd": w.get("hwnd")} for w in chrome_windows],
        "all_window_titles": [str(w.get("title", ""))[:60] for w in windows],
        "ready": bool(x_windows),
        "note": (
            "Title heuristic only - the compose modal is the real authentication check "
            "and is exercised at publish time. A window on another desktop/session "
            "is not visible to this process."
        ),
    }


def print_session_report(session: Dict[str, Any]) -> None:
    print(banner("X SESSION CHECK (read-only, nothing posted)"))
    print(f"Checked (UTC)          : {session['checked_utc']}")
    print(f"Chrome windows visible : {session['chrome_window_count']}")
    print(f"Chrome processes alive : {session['chrome_process_count']}")
    print(f"X tab detected         : {'YES' if session['x_tab_detected'] else 'NO'}")
    for window in session["x_windows"]:
        print(f"  [X TAB] '{window['title']}'")
    if not session["x_windows"]:
        print("  (no Chrome window with an X tab title was found)")
    print(f"READY TO POST          : {'YES' if session['ready'] else 'NO'}")
    print(f"Note: {session['note']}")


# --------------------------------------------------------------------------- #
# Evidence capture
# --------------------------------------------------------------------------- #
def capture_evidence(filename: str) -> Optional[str]:
    """Capture the full desktop into the shared artifact directory."""
    try:
        module = require_desktop_automation()
        target = os.path.join(ARTIFACT_DIR, filename)
        ok, message = module.capture_desktop(target)
        if ok:
            return str(message)
        print(f"[!] Evidence capture failed for {filename}: {message}")
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Evidence capture failed for {filename}: {exc}")
    return None


# --------------------------------------------------------------------------- #
# Browser primitives (proven patterns from the existing scripts)
# --------------------------------------------------------------------------- #
def focus_chrome() -> bool:
    module = require_desktop_automation()
    ok, message = module.focus_window("Google Chrome")
    print(f"[*] Focus Chrome: {ok} ({message})")
    if not ok:
        return False
    time.sleep(1.0)
    return True


def navigate(url: str) -> None:
    """Navigate the focused Chrome window to a URL and wait for the page to settle."""
    module = require_desktop_automation()
    module.send_shortcut("ctrl+l")
    time.sleep(0.4)
    module.paste_text(url)
    time.sleep(0.4)
    module.send_key("enter")
    time.sleep(NAV_SETTLE_SECONDS)


def _read_clipboard() -> Optional[str]:
    try:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            return win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()
    except Exception:  # noqa: BLE001
        return None


DEVTOOLS_FIRST_ARTICLE = (
    "const a=document.querySelectorAll('article');"
    "if(a.length){const t=a[0].querySelector('time');"
    "if(t){copy(t.closest('a').href);}}"
)
DEVTOOLS_LAST_ARTICLE = (
    "const a=document.querySelectorAll('article');"
    "if(a.length>1){const t=a[a.length-1].querySelector('time');"
    "if(t){copy(t.closest('a').href);}}"
)


def capture_status_url(which: str = "last") -> Optional[str]:
    """Grab the newest tweet URL from the page via the DevTools console copy() trick
    (same technique as scripts/post_x_thread_continuation.py)."""
    module = require_desktop_automation()
    snippet = DEVTOOLS_FIRST_ARTICLE if which == "first" else DEVTOOLS_LAST_ARTICLE
    module.send_shortcut("ctrl+shift+j")
    time.sleep(1.5)
    module.paste_text(snippet)
    time.sleep(0.4)
    module.send_key("enter")
    time.sleep(0.8)
    module.send_shortcut("ctrl+shift+j")
    time.sleep(0.8)
    clipboard = _read_clipboard() or ""
    if "status/" in clipboard:
        return clipboard.strip()
    print("[!] Could not capture a status URL from DevTools.")
    print("    If Chrome shows 'Warning: Don't paste code...', type 'allow pasting' once.")
    return None


def submit_composer(text: str, label: str) -> None:
    """Paste copy into the focused composer and submit with Ctrl+Enter."""
    module = require_desktop_automation()
    print(f"[*] Pasting {label} ({len(text)} raw chars)...")
    module.paste_text(text)
    time.sleep(PASTE_SETTLE_SECONDS)
    print(f"[*] Submitting {label} via Ctrl+Enter...")
    module.send_shortcut("ctrl+enter")
    time.sleep(SUBMIT_SETTLE_SECONDS)


def reply_via_parent_tweet(parent_url: str, text: str, label: str) -> None:
    """Chain a reply onto a specific tweet URL (post_x_thread_continuation.py pattern)."""
    module = require_desktop_automation()
    if not focus_chrome():
        raise RuntimeError("Could not focus Chrome")
    print(f"[*] Navigating to parent tweet: {parent_url}")
    navigate(parent_url)

    windows = module.list_windows(include_empty=False)
    window = next((w for w in windows if "chrome" in str(w.get("process", "")).lower()), None)
    if window:
        rx = window["left"] + int(window["width"] * 0.45)
        ry = window["top"] + int(window["height"] * 0.45)
        module.click_at(rx, ry)
        time.sleep(1.2)

    module.send_key("r")
    time.sleep(1.5)
    submit_composer(text, label)


def reply_via_profile_top(text: str, label: str) -> None:
    """Fallback reply path: open the profile, jump to the top tweet (j) and reply (r)
    (post_x_vulnerability_thread.py pattern)."""
    module = require_desktop_automation()
    if not focus_chrome():
        raise RuntimeError("Could not focus Chrome")
    print(f"[*] Fallback: replying to the top tweet on {PROFILE_URL}")
    navigate(PROFILE_URL)
    module.send_key("j")
    time.sleep(0.5)
    module.send_key("r")
    time.sleep(1.5)
    submit_composer(text, label)


# --------------------------------------------------------------------------- #
# Publishing
# --------------------------------------------------------------------------- #
def publish_thread(
    posts: List[Dict[str, Any]],
    allow_publish: bool,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Publish the thread, chaining each reply onto the previous tweet URL."""
    if not allow_publish:
        raise PermissionError("Publishing is disabled: --post was not supplied.")

    module = require_desktop_automation()
    published: Dict[str, str] = {}
    per_post_evidence: Dict[str, str] = {}

    if not focus_chrome():
        raise RuntimeError("Could not focus the Chrome window - aborting publish.")

    for index, post in enumerate(posts):
        post_id = str(post.get("id"))
        text = str(post.get("text", ""))
        label = f"{post_id} ({index + 1}/{len(posts)})"

        if index == 0:
            print(f"\n--- Posting {label} ---")
            navigate(COMPOSE_URL)
            submit_composer(text, label)
            after = capture_evidence(f"roast_f_grades_{post_id}_after.png")
            if after:
                per_post_evidence[post_id] = after
            published[post_id] = "posted"
        else:
            parent_url = published.get("__parent__") or PROFILE_URL
            print(f"\n--- Posting {label} ---")
            try:
                reply_via_parent_tweet(parent_url, text, label)
            except RuntimeError:
                reply_via_profile_top(text, label)
            after = capture_evidence(f"roast_f_grades_{post_id}_after.png")
            if after:
                per_post_evidence[post_id] = after

        # Chain: capture the URL of what we just posted.
        navigate(PROFILE_URL if index == 0 else parent_url)
        captured = capture_status_url("first" if index == 0 else "last")
        if captured:
            published[post_id] = captured
            published["__parent__"] = captured
            print(f"    [OK] chained onto: {captured}")
        else:
            published.setdefault(post_id, "unknown")
            published["__parent__"] = parent_url
            print(f"    [!] WARNING: could not chain - next reply will attach to {parent_url}")

        time.sleep(POST_GAP_SECONDS)

    published.pop("__parent__", None)
    return {"published_urls": published, "per_post_evidence": per_post_evidence}


def publish_single(post: Dict[str, Any], allow_publish: bool, evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Publish one standalone post through the composer."""
    if not allow_publish:
        raise PermissionError("Publishing is disabled: --post was not supplied.")

    module = require_desktop_automation()
    post_id = str(post.get("id"))
    text = str(post.get("text", ""))

    if not focus_chrome():
        raise RuntimeError("Could not focus the Chrome window - aborting publish.")

    navigate(COMPOSE_URL)
    submit_composer(text, post_id)

    per_post_evidence: Dict[str, str] = {}
    after = capture_evidence(f"roast_f_grades_{post_id}_after.png")
    if after:
        per_post_evidence[post_id] = after

    # Verify it is live on the profile and capture its URL.
    navigate(PROFILE_URL)
    captured = capture_status_url("first")
    live = capture_evidence(f"roast_f_grades_{post_id}_live.png")
    if live:
        per_post_evidence[f"{post_id}_live"] = live

    published = {post_id: captured or "unknown"}
    return {"published_urls": published, "per_post_evidence": per_post_evidence}


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def print_manifest(manifest: Dict[str, Any], as_json: bool = False) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "manifest_id": manifest.get("id"),
                    "publishable": [
                        {
                            "id": p.get("id"),
                            "type": p.get("type"),
                            "position": p.get("position"),
                            "raw_chars": len(str(p.get("text", ""))),
                            "weighted_chars": require_validator().weighted_length(str(p.get("text", ""))),
                        }
                        for p in publishable_posts(manifest)
                    ],
                    "held_variants": [
                        {"id": h.get("id"), "type": h.get("type"), "status": "DO-NOT-PUBLISH"}
                        for h in held_variants(manifest)
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    print(banner("ROAST F GRADES - MANIFEST"))
    print(f"Manifest id : {manifest.get('id')}")
    print(f"Status      : {manifest.get('status')}")
    print(f"Author      : {manifest.get('author')}")
    print("")
    print("PUBLISHABLE POSTS (ids in the 'posts' array):")
    for post in publishable_posts(manifest):
        text = str(post.get("text", ""))
        weighted = require_validator().weighted_length(text)
        print(f"  - {post.get('id'):<22} type={str(post.get('type')):<10} "
              f"raw={len(text):<4} weighted={weighted:<4} headroom={280 - weighted}")
    print("")
    print("HELD VARIANTS - DO NOT PUBLISH:")
    for variant in held_variants(manifest):
        print(f"  [DO-NOT-PUBLISH] {variant.get('id')} ({variant.get('type')})")
        print(f"      {variant.get('notes', '')}")


def print_preview(post: Dict[str, Any]) -> None:
    text = str(post.get("text", ""))
    header = f"{post.get('id')}  [{post.get('type')}]  raw={len(text)} weighted={require_validator().weighted_length(text)}"
    print("-" * 78)
    print(header)
    print("-" * 78)
    print(text)
    print()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish harness for the 'roast F grades' X campaign. "
            "DEFAULT IS DRY RUN - nothing is posted unless --post is supplied."
        )
    )
    parser.add_argument("--thread", action="store_true", help="Target the 4-post thread.")
    parser.add_argument("--id", dest="post_id", help="Target a single publishable post id.")
    parser.add_argument(
        "--post",
        action="store_true",
        help="ACTUALLY publish. Without this flag the harness only performs a dry run.",
    )
    parser.add_argument("--list", action="store_true", help="Print the manifest and exit.")
    parser.add_argument(
        "--check-session",
        action="store_true",
        help="Report whether an authenticated Chrome window with an X tab is present. Posts nothing.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Override the 8h spacing / daily quota guard (NOT the length or held-copy guards).",
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable output for inspect modes.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # ------------------------------------------------------------------ #
    # Inspection modes (never publish)
    # ------------------------------------------------------------------ #
    if args.list:
        manifest = load_manifest()
        print_manifest(manifest, as_json=args.json)
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "inspect",
                "action": "list",
                "post_ids": [],
                "weighted_lengths": {},
                "result": "inspected",
                "publish_enabled": False,
                "evidence_images": {},
            }
        )
        return 0

    if args.check_session:
        session = check_session()
        if args.json:
            print(json.dumps(session, indent=2))
        else:
            print_session_report(session)
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "inspect",
                "action": "check-session",
                "post_ids": [],
                "weighted_lengths": {},
                "result": "session-check",
                "publish_enabled": False,
                "session": session,
                "evidence_images": {},
            }
        )
        return 0 if session["ready"] else 1

    # ------------------------------------------------------------------ #
    # Target resolution
    # ------------------------------------------------------------------ #
    manifest = load_manifest()
    if args.thread and args.post_id:
        print("[!] Choose either --thread or --id <post_id>, not both.")
        return 2
    if args.post and not args.thread and not args.post_id:
        print("[!] --post requires an explicit target:")
        print("      --post --thread              (publish the 4-post thread)")
        print("      --post --id <post_id>        (publish one standalone post)")
        print("    There is no 'publish everything' mode - pick a target deliberately.")
        return 2

    targets: List[Dict[str, Any]] = []
    action = "all"
    if args.thread:
        targets = thread_posts(manifest)
        action = "thread"
    elif args.post_id:
        try:
            targets = [assert_publishable(args.post_id, manifest)]
        except PermissionError as exc:
            print(f"[!] {exc}")
            append_log(
                {
                    "timestamp_utc": iso(utc_now()),
                    "mode": "post" if args.post else "dry-run",
                    "action": "post-id",
                    "requested_id": args.post_id,
                    "post_ids": [],
                    "weighted_lengths": {},
                    "result": "refused",
                    "reason": str(exc),
                    "publish_enabled": False,
                    "evidence_images": {},
                }
            )
            return 3
        except KeyError as exc:
            print(f"[!] {exc}")
            return 2
    else:
        # No target: the default no-argument run is a full dry-run preview.
        targets = publishable_posts(manifest)
        action = "all"

    if not targets:
        print("[!] No publishable targets resolved.")
        return 2

    post_ids = [str(t.get("id")) for t in targets]
    weighted = {
        str(t.get("id")): require_validator().weighted_length(str(t.get("text", "")))
        for t in targets
    }
    raw = {str(t.get("id")): len(str(t.get("text", ""))) for t in targets}

    # ------------------------------------------------------------------ #
    # Validation gate (runs before ANY browser interaction)
    # ------------------------------------------------------------------ #
    report = require_validator().validate_manifest(manifest, MANIFEST_PATH)
    validation_ok = bool(report["ok"])

    publish_enabled = bool(args.post) and validation_ok

    print(banner("ROAST F GRADES - PUBLISH HARNESS"))
    print(f"Mode            : {'POST (LIVE)' if args.post else 'DRY RUN (no browser posting)'}")
    print(f"Action          : {action}")
    print(f"Targets         : {', '.join(post_ids)}")
    print(f"Validator       : {'PASS' if validation_ok else 'FAIL'} "
          f"({report['post_count']} posts checked, {len(report['failures'])} violation(s))")
    print(f"Log file        : {LOG_PATH}")
    print("=" * 78)

    if not validation_ok:
        print("\n[!] VALIDATION FAILED - publishing is blocked.")
        for failure in report["failures"]:
            print(f"    [FAIL] {failure['rule']}: {failure['message']}")
        blocking = [f for f in report["failures"] if f.get("id") in post_ids]
        if blocking:
            print("    -> The offending post(s) are IN your target set; copy must be fixed first.")
        else:
            print("    -> The offending post(s) are elsewhere in the manifest; the copy owner")
            print("       must fix them before any publish of this campaign is allowed.")
        print("    -> This harness never rewrites copy. Fix the manifest, then re-run.")

    # ------------------------------------------------------------------ #
    # Session + quota inspection
    # ------------------------------------------------------------------ #
    session: Dict[str, Any] = {}
    quota: Dict[str, Any] = {}
    try:
        session = check_session()
        print(f"\n[*] Chrome windows visible : {session['chrome_window_count']}")
        print(f"[*] X tab detected         : {'YES' if session['x_tab_detected'] else 'NO'}")
        if not session["ready"]:
            print("[!] No Chrome window with an X tab was found on this desktop.")
    except Exception as exc:  # noqa: BLE001
        session = {"ready": False, "error": str(exc)}
        print(f"[!] Session check failed: {exc}")

    policy = load_quota_policy()
    history = collect_publish_history()
    quota = evaluate_quota(history, policy, utc_now())
    print(f"\n[*] Quota policy          : {policy['source']}")
    print(f"[*] max_daily_posts={policy['max_daily_posts']} "
          f"min_post_spacing_hours={policy['min_post_spacing_hours']} "
          f"max_hourly_posts={policy['max_hourly_posts']}")
    print(f"[*] Last publish          : {quota['last_publish']} ({quota['last_publish_source']})")
    print(f"[*] Hours since last      : {quota['hours_since_last_publish']}")
    print(f"[*] Publishes in 8h window : {quota['publishes_in_window']}")
    print(f"[*] Originals today (UTC)  : {quota['originals_today']}")
    if not quota["ok"] and not args.force:
        print("[!] Quota guard would block this publish:")
        for reason in quota["reasons"]:
            print(f"    - {reason}")
        print("    (override with --force if the operator explicitly accepts the risk)")

    # ------------------------------------------------------------------ #
    # Preview
    # ------------------------------------------------------------------ #
    print("")
    print(banner("RENDERED PREVIEW (exact copy that would be pasted)"))
    for post in targets:
        print_preview(post)

    evidence: Dict[str, Any] = {"before": None, "after": None, "per_post": {}}
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    mode_label = "post" if args.post else "dry-run"

    # ------------------------------------------------------------------ #
    # DRY RUN - stop here, nothing is ever pasted or submitted
    # ------------------------------------------------------------------ #
    if not args.post:
        print(banner("DRY RUN COMPLETE - NOTHING WAS POSTED"))
        print("No keystrokes were sent, no URL was opened, nothing was submitted to X.")
        print("Re-run with '--post' (plus --thread or --id <post_id>) to publish for real.")
        before = capture_evidence(f"roast_f_grades_{mode_label}_{stamp}_before.png")
        evidence["before"] = before
        if before:
            print(f"[*] Evidence (before): {before}")
        result = "dry-run-ok" if validation_ok else "dry-run-validation-failed"
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "dry-run",
                "action": action,
                "requested_id": args.post_id,
                "post_ids": post_ids,
                "weighted_lengths": weighted,
                "raw_lengths": raw,
                "result": result,
                "reason": "; ".join(report["failures"]) if not validation_ok else "",
                "publish_enabled": False,
                "validation_ok": validation_ok,
                "quota": quota,
                "session": session,
                "evidence_images": evidence,
            }
        )
        print(f"[*] Logged: {LOG_PATH} (mode=dry-run, result={result})")
        return 0 if validation_ok else 1

    # ------------------------------------------------------------------ #
    # LIVE PUBLISH - every guard below must pass
    # ------------------------------------------------------------------ #
    if not validation_ok:
        print("[!] ABORTED: the length validator failed. Nothing was posted.")
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "post",
                "action": action,
                "requested_id": args.post_id,
                "post_ids": post_ids,
                "weighted_lengths": weighted,
                "raw_lengths": raw,
                "result": "aborted-validation-failed",
                "reason": "; ".join(f["message"] for f in report["failures"]),
                "publish_enabled": False,
                "validation_ok": False,
                "quota": quota,
                "session": session,
                "evidence_images": evidence,
            }
        )
        return 4

    if not session.get("ready"):
        print("[!] ABORTED: no authenticated Chrome window with an X tab was found.")
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "post",
                "action": action,
                "requested_id": args.post_id,
                "post_ids": post_ids,
                "weighted_lengths": weighted,
                "raw_lengths": raw,
                "result": "aborted-no-session",
                "reason": "no Chrome window with an X tab detected",
                "publish_enabled": False,
                "validation_ok": True,
                "quota": quota,
                "session": session,
                "evidence_images": evidence,
            }
        )
        return 5

    if not quota.get("ok") and not args.force:
        print("[!] ABORTED: quota guard (8h spacing / daily cap). Re-run with --force to override.")
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "post",
                "action": action,
                "requested_id": args.post_id,
                "post_ids": post_ids,
                "weighted_lengths": weighted,
                "raw_lengths": raw,
                "result": "aborted-quota",
                "reason": "; ".join(quota["reasons"]),
                "publish_enabled": False,
                "validation_ok": True,
                "quota": quota,
                "session": session,
                "evidence_images": evidence,
            }
        )
        return 6

    if action == "all" and len(targets) > 1:
        print("[!] ABORTED: multi-post publish without --force.")
        return 7

    before = capture_evidence(f"roast_f_grades_{mode_label}_{stamp}_before.png")
    evidence["before"] = before
    print(f"[*] Evidence (before): {before}")

    published_urls: Dict[str, str] = {}
    try:
        if action == "thread":
            outcome = publish_thread(targets, allow_publish=True, evidence=evidence)
        else:
            outcome = publish_single(targets[0], allow_publish=True, evidence=evidence)
        published_urls = outcome.get("published_urls", {})
        evidence["per_post"] = outcome.get("per_post_evidence", {})
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Publish failed: {exc}")
        after = capture_evidence(f"roast_f_grades_{mode_label}_{stamp}_after.png")
        evidence["after"] = after
        append_log(
            {
                "timestamp_utc": iso(utc_now()),
                "mode": "post",
                "action": action,
                "requested_id": args.post_id,
                "post_ids": post_ids,
                "weighted_lengths": weighted,
                "raw_lengths": raw,
                "result": "failed",
                "reason": str(exc),
                "publish_enabled": True,
                "validation_ok": True,
                "quota": quota,
                "session": session,
                "published_urls": published_urls,
                "evidence_images": evidence,
            }
        )
        return 8

    after = capture_evidence(f"roast_f_grades_{mode_label}_{stamp}_after.png")
    evidence["after"] = after
    print(f"[*] Evidence (after): {after}")

    append_log(
        {
            "timestamp_utc": iso(utc_now()),
            "mode": "post",
            "action": action,
            "requested_id": args.post_id,
            "post_ids": post_ids,
            "weighted_lengths": weighted,
            "raw_lengths": raw,
            "result": "success",
            "reason": "",
            "publish_enabled": True,
            "validation_ok": True,
            "quota": quota,
            "session": session,
            "published_urls": published_urls,
            "original_count": 1,
            "reply_count": max(0, len(targets) - 1),
            "evidence_images": evidence,
        }
    )
    print(banner("PUBLISH COMPLETE"))
    print(f"Posted: {', '.join(post_ids)}")
    for post_id, url in published_urls.items():
        print(f"  {post_id}: {url}")
    print(f"Logged: {LOG_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
