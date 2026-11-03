#!/usr/bin/env python3
"""
Orbit Security (@_arsoncode) — Gamified Infosec Stack & Cyber Arcade Staging Engine
Architect: Carson Haynes & Nova
Target: 8-Part Master Deep-Dive Thread & 4 Pillar Showcase Posts for X / Twitter

Covers:
1. Live 16-Subdomain DoH Perimeter Scanner (orbit_radar.js):
   Client-side Google & Cloudflare DoH (RFC 8484), RFC 7505 Null-MX evaluation,
   two-prong takeover heuristics (NXDOMAIN vs SaaS edge), instant co-branded PDF audits.
2. Visual Attack Tree & Takeover Simulator:
   5-step interactive SVG exploit animation illustrating dangling CNAME hijacking.
3. Interactive White-Label Agency Portal Customizer:
   Real-time brand color swatch picker with WCAG contrast detection, custom logo
   drag-and-drop uploader, instant demo portal launcher (portals/orbit-core.html).
4. Astro-Cat Chief Perimeter Sentinel & Arcade Defense Mode (simple_cat.js):
   8-bit retro Web Audio synthesizer, guided conversion tour, cosmic treats mini-game,
   and full 16-threat Arcade Defense canvas shooter (#arcadeDefense).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
    console = Console(legacy_windows=False)
except ImportError:
    HAS_RICH = False
    console = None

X_LIMIT = 280
URL_WEIGHT = 23
URL_RE = re.compile(r"https?://[^\s]+")


def twitter_v3_char_count(text: str) -> Tuple[int, int, int]:
    """
    Computes Twitter character count per official Twitter text v3 specification:
    - URLs (http:// or https://) count as exactly 23 characters (t.co standard).
    - Code points [0..4351], [8192..8205], [8208..8223], [8242..8247] count as 1 character.
    - Emojis and higher Unicode characters count as 2 characters.
    Returns: (weighted_char_count, raw_string_length, url_count)
    """
    urls = URL_RE.findall(text)
    text_without_urls = URL_RE.sub("", text)

    weighted_units = len(urls) * URL_WEIGHT * 100
    for char in text_without_urls:
        cp = ord(char)
        if (0 <= cp <= 4351) or (8192 <= cp <= 8205) or (8208 <= cp <= 8223) or (8242 <= cp <= 8247):
            weighted_units += 100
        else:
            weighted_units += 200

    weighted_count = weighted_units // 100
    return weighted_count, len(text), len(urls)


def x_standard_weighted_length(text: str) -> int:
    """
    X post length validator model (compatible with validate_x_post_lengths.py):
    - URLs count as 23 characters.
    - Every other unicode code point counts as 1.
    """
    total = 0
    cursor = 0
    for match in URL_RE.finditer(text):
        total += len(text[cursor:match.start()])
        total += URL_WEIGHT
        cursor = match.end()
    total += len(text[cursor:])
    return total


MASTER_THREAD_POSTS: List[Dict[str, Any]] = [
    {
        "id": "gamified-thread-1",
        "num": 1,
        "type": "thread",
        "title": "Tweet 1: The Hook (Zero-Server Cyber Arcade)",
        "description": "Why traditional infosec landing pages fail vs browser-native weaponization.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_montage_master.mp4"),
        "media_type": "video",
        "pillar": "break_and_fix",
        "text": """Most cybersecurity sites are corporate snoozefests: stock photos of padlocks and sales forms.

We turned perimeter recon into an interactive cyber arcade.

Zero backend servers. Pure browser-native weaponization.

What we shipped: 🧵👇
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "id": "gamified-thread-2",
        "num": 2,
        "type": "thread",
        "title": "Tweet 2: 16-Subdomain DoH Perimeter Scanner",
        "description": "Client-side Google & Cloudflare DoH, RFC 7505 Null-MX, two-prong takeover checks.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_doh_encrypted_shield.jpg"),
        "media_type": "image",
        "pillar": "radar_telemetry",
        "text": """1/ Live 16-Subdomain DoH Scanner

Client-side Google & Cloudflare DoH (RFC 8484):
• 16 subdomains probed concurrently in <800ms
• 2-prong takeover triage (NXDOMAIN vs SaaS edge)
• RFC 7505 Null-MX & strict DMARC audits
• Instant co-branded client PDF export"""
    },
    {
        "id": "gamified-thread-3",
        "num": 3,
        "type": "thread",
        "title": "Tweet 3: Visual Attack Tree & Takeover Simulator",
        "description": "5-step interactive SVG exploit animation illustrating dangling CNAME hijacking.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_cname_blackhole.jpg"),
        "media_type": "image",
        "pillar": "dangling_dns",
        "text": """2/ Visual Attack Tree & Takeover Simulator

Explaining dangling DNS to clients used to take hours.

Now: an interactive 5-step SVG exploit animation showing how an abandoned SaaS trial leads to domain takeover.

Watch the exploit step-by-step:
https://cmfh009.github.io/Orbit-Security/#simulate"""
    },
    {
        "id": "gamified-thread-4",
        "num": 4,
        "type": "thread",
        "title": "Tweet 4: Interactive White-Label Portal Customizer",
        "description": "Real-time brand color swatch picker with WCAG contrast detection & demo launcher.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_agency_retainer_vault.jpg"),
        "media_type": "image",
        "pillar": "agency_retainers",
        "text": """3/ White-Label Agency Portal Customizer

Agencies use Orbit to run $250/mo retainers.

Test-drive your branded portal live:
• Palette picker with WCAG contrast detection
• Instant logo drag-and-drop
• Launch into the live demo portal:
https://cmfh009.github.io/Orbit-Security/portals/orbit-core.html"""
    },
    {
        "id": "gamified-thread-5",
        "num": 5,
        "type": "thread",
        "title": "Tweet 5: Astro-Cat Sentinel & Retro Web Audio",
        "description": "Zero-G mascot with 8-bit procedural synth, conversion tour, and treats mini-game.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_astrocat_laser_sentinel.jpg"),
        "media_type": "image",
        "pillar": "gamification",
        "text": """4/ Astro-Cat Chief Perimeter Sentinel

Meet our zero-G sentinel:
• Guided tour across your perimeter scan
• Procedural 8-bit Web Audio synth (square/sawtooth waves, zero MP3s)
• Cosmic treats mini-game with physics bounce

Infosec doesn't have to be sterile. 🐱"""
    },
    {
        "id": "gamified-thread-6",
        "num": 6,
        "type": "thread",
        "title": "Tweet 6: 16-Threat Arcade Defense Mode",
        "description": "Full canvas shooter turning scan threats into incoming orbital invaders.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_astro_cat_gameplay_x.mp4"),
        "media_type": "video",
        "pillar": "gamification",
        "text": """5/ Arcade Defense Mode

Hit #arcadeDefense and the site transforms into an 8-bit arcade canvas shooter.

Your orbital turret defends against all 16 perimeter threats (dangling CNAMEs, SPF overflows, spoofed MX).

Pilot the turret live:
https://cmfh009.github.io/Orbit-Security/#arcadeDefense"""
    },
    {
        "id": "gamified-thread-7",
        "num": 7,
        "type": "thread",
        "title": "Tweet 7: Why Client-Side Architecture Matters",
        "description": "Zero-trust privacy, 800ms speed, and high-margin agency monetization.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "fleet_command_center_live.png"),
        "media_type": "image",
        "pillar": "architecture",
        "text": """Why build all this client-side?

1. Zero Trust: we never see or store your DNS queries.
2. Speed: 800ms parallel DoH beats backend queues.
3. Retainers: instant co-branded executive audit PDFs let agencies sell recurring protection without writing code."""
    },
    {
        "id": "gamified-thread-8",
        "num": 8,
        "type": "thread",
        "title": "Tweet 8: Call to Action & Open Source Repository",
        "description": "Direct link to live GitHub Pages showcase and open-source codebase.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_cyber_command_deck.jpg"),
        "media_type": "image",
        "pillar": "cta",
        "text": """Audit your perimeter, customize your agency portal, or blast threats in Arcade Defense mode right now:

Live Showcase:
https://cmfh009.github.io/Orbit-Security/

Open-source repo & CLI on GitHub:
https://github.com/CmfH009/Orbit-Security

Drop your domain below for a free telemetry readout. 🛡️🚀"""
    }
]

STANDALONE_POSTS: List[Dict[str, Any]] = [
    {
        "id": "standalone-scanner",
        "type": "standalone",
        "title": "Pillar Spotlight: Live 16-Subdomain DoH Scanner",
        "description": "Dedicated single post focusing on RFC 8484 DoH speed and client-side audits.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_doh_encrypted_shield.jpg"),
        "media_type": "image",
        "pillar": "radar_telemetry",
        "text": """We replaced slow backend scanners with client-side DoH.

Parallel Google & Cloudflare queries (RFC 8484) audit 16 subdomains in <800ms:
• Two-prong takeover heuristics
• RFC 7505 Null-MX validation
• Instant co-branded PDF audits

Audit live:
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "id": "standalone-attack-tree",
        "type": "standalone",
        "title": "Pillar Spotlight: Visual Attack Tree & Takeover Simulator",
        "description": "Interactive SVG animation demonstrating dangling CNAME exploit flow.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_cname_blackhole.jpg"),
        "media_type": "image",
        "pillar": "dangling_dns",
        "text": """How does an abandoned $15/mo SaaS page compromise an enterprise domain?

Our 5-step SVG Attack Tree animates every stage:
1. Visitor request
2. CNAME traversal
3. Abandoned 404
4. Attacker asset claim
5. Cookie & session hijacking

Simulate:
https://cmfh009.github.io/Orbit-Security/#simulate"""
    },
    {
        "id": "standalone-customizer",
        "type": "standalone",
        "title": "Pillar Spotlight: White-Label Agency Portal Customizer",
        "description": "Real-time branding preview and live multi-client demo portal.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_agency_retainer_vault.jpg"),
        "media_type": "image",
        "pillar": "agency_retainers",
        "text": """Agencies turn DNS hygiene into $250/mo care plans.

Preview client deliverables in our interactive portal sandbox:
• Brand palette with WCAG contrast detection
• Drag-and-drop agency logo
• Instant client demo launcher

Launch demo:
https://cmfh009.github.io/Orbit-Security/portals/orbit-core.html"""
    },
    {
        "id": "standalone-arcade",
        "type": "standalone",
        "title": "Pillar Spotlight: Astro-Cat & 16-Threat Arcade Defense",
        "description": "8-bit Web Audio synth and interactive canvas shooter.",
        "attachment": str(REPO_ROOT / "docs" / "assets" / "orbit_astrocat_laser_sentinel.jpg"),
        "media_type": "image",
        "pillar": "gamification",
        "text": """Security tools take themselves too seriously.

So we added Astro-Cat:
• Custom 8-bit retro Web Audio synthesizer
• Guided walkthrough of scan vulnerabilities
• 16-threat Arcade Defense canvas shooter (blast dangling CNAMEs)

Play live:
https://cmfh009.github.io/Orbit-Security/#arcadeDefense"""
    }
]

HELD_VARIANTS: List[Dict[str, Any]] = [
    {
        "id": "held-unverified-named-targets",
        "type": "standalone",
        "status": "HELD",
        "publish": False,
        "hold": True,
        "notes": "do not publish without explicit operator approval. Holds draft containing raw prospect names.",
        "text": "do not publish. Internal draft comparing prospective agency portfolios."
    }
]

ALL_POSTS: List[Dict[str, Any]] = MASTER_THREAD_POSTS + STANDALONE_POSTS


def get_all_posts() -> List[Dict[str, Any]]:
    return ALL_POSTS


def get_post_by_id(pid: str) -> Optional[Dict[str, Any]]:
    for p in ALL_POSTS:
        if p["id"] == pid:
            return p
    return None


def verify_all_posts() -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Evaluates every post against Twitter v3 and X-standard weighted limits.
    Returns: (all_passed, results_list)
    """
    all_pass = True
    results = []

    for post in ALL_POSTS:
        text = post["text"]
        v3_count, raw_len, url_count = twitter_v3_char_count(text)
        x_std_count = x_standard_weighted_length(text)
        passed = (v3_count <= X_LIMIT) and (x_std_count <= X_LIMIT)
        buffer_v3 = X_LIMIT - v3_count
        buffer_std = X_LIMIT - x_std_count

        if not passed:
            all_pass = False

        results.append({
            "id": post["id"],
            "title": post["title"],
            "type": post["type"],
            "raw_len": raw_len,
            "v3_count": v3_count,
            "x_std_count": x_std_count,
            "urls": url_count,
            "buffer_v3": buffer_v3,
            "buffer_std": buffer_std,
            "passed": passed,
            "attachment": post.get("attachment"),
        })

    return all_pass, results


def print_verification_report(results: List[Dict[str, Any]], all_pass: bool) -> None:
    if HAS_RICH and console:
        table = Table(
            title="Orbit Security — Gamified Stack & Arcade Defense X Content Audit",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("ID", style="bold yellow", width=22)
        table.add_column("Type", justify="center", width=12)
        table.add_column("Raw", justify="center", width=6)
        table.add_column("X-v3", justify="center", width=10)
        table.add_column("X-Std", justify="center", width=10)
        table.add_column("URLs", justify="center", width=6)
        table.add_column("Headroom", justify="center", width=10)
        table.add_column("Status", justify="center", width=10)

        for r in results:
            status_style = "bold green" if r["passed"] else "bold red"
            status_str = "PASS" if r["passed"] else "FAIL"
            buf = min(r["buffer_v3"], r["buffer_std"])
            buf_str = f"+{buf}" if buf >= 0 else str(buf)
            table.add_row(
                r["id"],
                r["type"].upper(),
                str(r["raw_len"]),
                f"{r['v3_count']}/{X_LIMIT}",
                f"{r['x_std_count']}/{X_LIMIT}",
                str(r["urls"]),
                buf_str,
                f"[{status_style}]{status_str}[/{status_style}]",
            )

        console.print(table)
        verdict_color = "bold green" if all_pass else "bold red"
        verdict_text = "ALL 12 POSTS COMPLY WITH X CHARACTER LIMITS" if all_pass else "FAIL: LIMIT OVERFLOW"
        console.print(f"[{verdict_color}]Verdict: {verdict_text}[/{verdict_color}]\n")
    else:
        print("=" * 86)
        print("Orbit Security — Gamified Stack & Arcade Defense X Content Audit")
        print("=" * 86)
        print(f"{'ID':<24} | {'Type':<10} | {'Raw':<5} | {'X-v3':<9} | {'X-Std':<9} | {'URLs':<4} | {'Headroom':<8} | {'Status':<6}")
        print("-" * 86)
        for r in results:
            status_str = "PASS" if r["passed"] else "FAIL"
            buf = min(r["buffer_v3"], r["buffer_std"])
            buf_str = f"+{buf}" if buf >= 0 else str(buf)
            print(f"{r['id']:<24} | {r['type']:<10} | {r['raw_len']:<5} | {r['v3_count']:>3}/{X_LIMIT} | {r['x_std_count']:>3}/{X_LIMIT} | {r['urls']:<4} | {buf_str:<8} | {status_str:<6}")
        print("-" * 86)
        verdict_text = "ALL 12 POSTS COMPLY WITH X CHARACTER LIMITS" if all_pass else "FAIL: LIMIT OVERFLOW"
        print(f"Verdict: {verdict_text}\n")


def copy_post_to_clipboard(post_id: str) -> bool:
    post = get_post_by_id(post_id)
    if not post:
        print(f"[!] Post not found: {post_id}")
        return False

    text = post["text"]
    copied = False
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(text)
            copied = True
        except Exception:
            pass

    if not copied and os.name == "nt":
        try:
            clean_text = text.replace('"', '`"')
            cmd = f'Set-Clipboard -Value "{clean_text}"'
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd], check=True)
            copied = True
        except Exception:
            pass

    if copied:
        print(f"[+] Successfully copied post [{post_id}] to clipboard!")
        att = post.get("attachment")
        if att:
            dest_media = REPO_ROOT / "data" / "drafts" / "media" / Path(att).name
            media_to_show = dest_media if dest_media.exists() else Path(att)
            if media_to_show.exists():
                print(f"    Attached Media: {media_to_show}")
    else:
        print(f"[!] Could not copy post [{post_id}] to clipboard.")
    return copied


def display_post(post_id: str) -> None:
    post = get_post_by_id(post_id)
    if not post:
        print(f"[!] Post not found: {post_id}")
        return

    text = post["text"]
    v3_count, raw_len, url_count = twitter_v3_char_count(text)
    x_std = x_standard_weighted_length(text)
    buf = min(X_LIMIT - v3_count, X_LIMIT - x_std)
    att = post.get("attachment") or "None"

    if HAS_RICH and console:
        title = f"[bold cyan]{post['title']}[/bold cyan] ({v3_count}/{X_LIMIT} chars | Headroom: +{buf} | URLs: {url_count})"
        content = f"{text}\n\n[dim][Attached Media: {att}][/dim]"
        border_style = "green" if buf >= 0 else "red"
        panel = Panel(content, title=title, border_style=border_style, expand=False)
        console.print(panel)
    else:
        print("=" * 70)
        print(f"{post['title']} ({v3_count}/{X_LIMIT} chars | Headroom: +{buf})")
        print("=" * 70)
        print(text)
        print(f"\nAttached Media: {att}")
        print("=" * 70)


def export_validation_manifest(out_path: Optional[Path] = None) -> Path:
    """
    Exports posts in the schema required by scripts/validate_x_post_lengths.py.
    """
    target = out_path or (REPO_ROOT / "data" / "gamified_showcase_posts.json")
    manifest = {
        "id": "gamified-showcase-2026-11",
        "name": "Gamified Tools & Arcade Defense Showcase",
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "limit": X_LIMIT,
        "url_weight": URL_WEIGHT,
        "publish_policy": {
            "never": [
                "Never publish third-party client domains."
            ]
        },
        "posts": [
            {
                "id": p["id"],
                "type": p["type"],
                "position": p.get("num"),
                "text": p["text"],
                "media_path": p.get("attachment"),
                "media_type": p.get("media_type", "image"),
                "pillar": p.get("pillar", "gamification"),
                "notes": p.get("description", "")
            }
            for p in ALL_POSTS
        ],
        "held_variants": HELD_VARIANTS
    }

    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return target


def stage_to_drafts() -> Tuple[int, Path]:
    """
    Syncs the new gamified showcase drafts into data/drafts/manifest.json and DRAFTS.md.
    Preserves existing posted/draft statuses while adding or updating showcase posts.
    Stages media assets into data/drafts/media/ and enforces official X weighted character counts.
    """
    drafts_dir = REPO_ROOT / "data" / "drafts"
    media_dir = drafts_dir / "media"
    manifest_file = drafts_dir / "manifest.json"
    deck_file = drafts_dir / "DRAFTS.md"
    drafts_dir.mkdir(parents=True, exist_ok=True)
    media_dir.mkdir(parents=True, exist_ok=True)

    existing_drafts: Dict[str, Dict[str, Any]] = {}
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for d in data.get("drafts", []):
                existing_drafts[d["id"]] = d
        except Exception:
            existing_drafts = {}

    staged_count = 0
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for p in ALL_POSTS:
        pid = p["id"]
        attachment = p.get("attachment")
        staged_media_path = attachment
        if attachment and Path(attachment).exists():
            src_file = Path(attachment)
            dest_file = media_dir / src_file.name
            if not dest_file.exists():
                try:
                    shutil.copy2(src_file, dest_file)
                except Exception:
                    pass
            if dest_file.exists():
                staged_media_path = str(dest_file.resolve())

        weighted_chars = x_standard_weighted_length(p["text"])

        if pid in existing_drafts:
            # Preserve existing status if already posted
            cur = existing_drafts[pid]
            cur["text"] = p["text"]
            cur["title"] = p["title"]
            cur["media_path"] = staged_media_path
            cur["media_type"] = p.get("media_type", "image")
            cur["pillar"] = p.get("pillar", "gamification")
            cur["character_count"] = weighted_chars
            cur["notes"] = p.get("description")
        else:
            existing_drafts[pid] = {
                "id": pid,
                "title": p["title"],
                "text": p["text"],
                "media_path": staged_media_path,
                "media_type": p.get("media_type", "image"),
                "pillar": p.get("pillar", "gamification"),
                "status": "DRAFT",
                "created_at_utc": now_iso,
                "posted_at_utc": None,
                "notes": p.get("description"),
                "character_count": weighted_chars,
            }
            staged_count += 1

    payload = {
        "last_updated_utc": now_iso,
        "total_drafts": len(existing_drafts),
        "pending_drafts": sum(1 for d in existing_drafts.values() if d.get("status") == "DRAFT"),
        "posted_count": sum(1 for d in existing_drafts.values() if d.get("status") == "POSTED"),
        "drafts": list(existing_drafts.values()),
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Render updated DRAFTS.md
    lines = [
        "# 🛡️ Orbit Security — X Draft Deck",
        "",
        "> **Agent-Assisted Local Staging Mode**  ",
        "> Review, copy, and publish high-signal posts manually. Zero automated browser calls or risk to your account.",
        "",
        f"**Last Refreshed:** `{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
        f"**Total Drafts:** {payload['total_drafts']} | "
        f"**Ready to Post:** {payload['pending_drafts']} | "
        f"**Published:** {payload['posted_count']}",
        "",
        "---",
        "",
    ]

    for idx, d in enumerate(existing_drafts.values(), 1):
        status = d.get("status", "DRAFT")
        status_icon = "🟢 [READY]" if status == "DRAFT" else (
            "✔ [POSTED]" if status == "POSTED" else f"⚪ [{status}]"
        )
        media_path = d.get("media_path")
        media_link = "*(No media asset)*"
        if media_path and Path(media_path).exists():
            p = Path(media_path)
            media_link = f"[{p.name}](file:///{p.resolve().as_posix()})"

        char_count = d.get("character_count")
        if char_count is None or char_count > X_LIMIT:
            char_count = x_standard_weighted_length(d.get("text", ""))

        lines.extend([
            f"### #{idx}. {d.get('title', 'Untitled')} {status_icon}",
            f"- **Draft ID:** `{d['id']}`",
            f"- **Pillar:** `{d.get('pillar', 'general')}` | **Asset Type:** `{str(d.get('media_type', 'image')).upper()}`",
            f"- **Characters:** `{char_count}/280`",
            f"- **Media Attachment:** {media_link}",
            "",
            "```text",
            d.get("text", ""),
            "```",
            "",
            f"*CLI Quick Copy:* `python -m orbit_security.cli drafts --copy {d['id']}`  ",
            f"*Mark as Posted:* `python -m orbit_security.cli drafts --mark-posted {d['id']}`",
            "",
            "---",
            "",
        ])

    with open(deck_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return staged_count, manifest_file


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Orbit Security Gamified Infosec Stack & Cyber Arcade Staging Engine"
    )
    parser.add_argument("--verify", action="store_true", help="Verify all posts against Twitter v3 and X limits")
    parser.add_argument("--list", action="store_true", help="List all staged showcase posts")
    parser.add_argument("--display", type=str, metavar="ID", help="Display full post text and metadata by ID")
    parser.add_argument("--copy", type=str, metavar="ID", help="Copy a specific post to clipboard by ID")
    parser.add_argument("--export-manifest", action="store_true", help="Export data/gamified_showcase_posts.json")
    parser.add_argument("--stage-drafts", action="store_true", help="Sync showcase posts into data/drafts/ manifest & deck")
    args = parser.parse_args(argv)

    # Default action if no flag is provided: verify and list summary
    if not (args.verify or args.list or args.display or args.copy or args.export_manifest or args.stage_drafts):
        args.verify = True

    if args.export_manifest:
        out = export_validation_manifest()
        print(f"[+] Exported validation manifest: {out}")

    if args.stage_drafts:
        count, path = stage_to_drafts()
        print(f"[+] Staged {count} new posts into {path} and updated DRAFTS.md")

    if args.verify:
        all_ok, results = verify_all_posts()
        print_verification_report(results, all_ok)
        if not all_ok:
            return 1

    if args.list:
        for p in ALL_POSTS:
            print(f"- [{p['id']}] {p['title']} ({len(p['text'])} chars)")

    if args.display:
        display_post(args.display)

    if args.copy:
        ok = copy_post_to_clipboard(args.copy)
        if not ok:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
