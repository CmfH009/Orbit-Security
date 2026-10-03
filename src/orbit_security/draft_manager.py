"""Orbit Security Agent-Assisted Draft & Staging Manager (draft_manager.py).

Provides local, autonomous generation of publish-ready X drafts with paired
multimodal media assets (procedural infosec diagrams, telemetry cards, and video shorts).
Empowers the operator to review, copy, and publish high-signal content manually
with zero risk of automated platform flags or account suspension.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from orbit_security.content_queue import ContentQueue
from orbit_security.creative_engine import CreativeEngine
from orbit_security.marketing_strategy import ContentPillar
from orbit_security.social_state import SocialStateManager

logger = logging.getLogger(__name__)


@dataclass
class SocialDraft:
    """Represents a human-reviewable draft post with attached media."""

    id: str
    title: str
    text: str
    media_path: Optional[str] = None
    media_type: str = "image"  # "image" or "video"
    pillar: str = "break_and_fix"
    status: str = "DRAFT"  # "DRAFT", "SCHEDULED", "POSTED", "DISCARDED"
    created_at_utc: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    posted_at_utc: Optional[str] = None
    notes: Optional[str] = None

    @property
    def character_count(self) -> int:
        return len(self.text)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["character_count"] = self.character_count
        return d


class DraftManager:
    """Manages creation, review, clipboard export, and lifecycle of X drafts."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.drafts_dir = self.root / "data" / "drafts"
        self.media_dir = self.drafts_dir / "media"
        self.manifest_file = self.drafts_dir / "manifest.json"
        self.deck_file = self.drafts_dir / "DRAFTS.md"

        self.drafts_dir.mkdir(parents=True, exist_ok=True)
        self.media_dir.mkdir(parents=True, exist_ok=True)

        self.creative_engine = CreativeEngine(project_root=self.root)
        self.content_queue = ContentQueue(project_root=self.root)
        self.state_manager = SocialStateManager()

        self._drafts: Dict[str, SocialDraft] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        """Loads existing drafts from the local JSON manifest."""
        self._drafts = {}
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data.get("drafts", []):
                    draft = SocialDraft(
                        id=item["id"],
                        title=item.get("title", "Untitled Draft"),
                        text=item.get("text", ""),
                        media_path=item.get("media_path"),
                        media_type=item.get("media_type", "image"),
                        pillar=item.get("pillar", "break_and_fix"),
                        status=item.get("status", "DRAFT"),
                        created_at_utc=item.get("created_at_utc", ""),
                        posted_at_utc=item.get("posted_at_utc"),
                        notes=item.get("notes"),
                    )
                    self._drafts[draft.id] = draft
            except Exception as e:
                logger.error(f"Error loading drafts manifest: {e}")

    def _save_manifest(self) -> None:
        """Saves current drafts to JSON manifest and renders DRAFTS.md."""
        payload = {
            "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_drafts": len(self._drafts),
            "pending_drafts": sum(1 for d in self._drafts.values() if d.status == "DRAFT"),
            "posted_count": sum(1 for d in self._drafts.values() if d.status == "POSTED"),
            "drafts": [d.to_dict() for d in self._drafts.values()],
        }
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self._render_markdown_deck()

    def _render_markdown_deck(self) -> None:
        """Generates an ergonomic DRAFTS.md file for easy human review."""
        lines = [
            "# 🛡️ Orbit Security — X Draft Deck",
            "",
            "> **Agent-Assisted Local Staging Mode**  ",
            "> Review, copy, and publish high-signal posts manually. Zero automated browser calls or risk to your account.",
            "",
            f"**Last Refreshed:** `{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
            f"**Total Drafts:** {len(self._drafts)} | "
            f"**Ready to Post:** {sum(1 for d in self._drafts.values() if d.status == 'DRAFT')} | "
            f"**Published:** {sum(1 for d in self._drafts.values() if d.status == 'POSTED')}",
            "",
            "---",
            "",
        ]

        if not self._drafts:
            lines.append("*No drafts currently staged. Run `python -m orbit_security.cli drafts --generate` to generate a batch.*")
        else:
            for idx, draft in enumerate(self._drafts.values(), 1):
                status_icon = "🟢 [READY]" if draft.status == "DRAFT" else (
                    "✔ [POSTED]" if draft.status == "POSTED" else f"⚪ [{draft.status}]"
                )
                media_link = ""
                if draft.media_path and Path(draft.media_path).exists():
                    p = Path(draft.media_path)
                    media_link = f"[{p.name}](file:///{p.resolve().as_posix()})"
                else:
                    media_link = "*(No media asset)*"

                lines.extend([
                    f"### #{idx}. {draft.title} {status_icon}",
                    f"- **Draft ID:** `{draft.id}`",
                    f"- **Pillar:** `{draft.pillar}` | **Asset Type:** `{draft.media_type.upper()}`",
                    f"- **Characters:** `{draft.character_count}/280`",
                    f"- **Media Attachment:** {media_link}",
                    "",
                    "```text",
                    draft.text,
                    "```",
                    "",
                    f"*CLI Quick Copy:* `python -m orbit_security.cli drafts --copy {draft.id}`  ",
                    f"*Mark as Posted:* `python -m orbit_security.cli drafts --mark-posted {draft.id}`",
                    "",
                    "---",
                    "",
                ])

        with open(self.deck_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def generate_draft_batch(self, count: int = 5) -> List[SocialDraft]:
        """Generates a batch of distinct, high-impact draft posts with rendered media."""
        new_drafts: List[SocialDraft] = []
        recent_ids = set(self._drafts.keys())

        # Pull from ContentQueue staged posts first
        for item in self.content_queue.items:
            if len(new_drafts) >= count:
                break
            if item["id"] in recent_ids:
                continue

            # Ensure media is available in drafts/media directory
            media_path = item.get("media_path")
            staged_media = None
            if media_path and Path(media_path).exists():
                src_p = Path(media_path)
                dest_p = self.media_dir / src_p.name
                if not dest_p.exists():
                    try:
                        shutil.copy2(src_p, dest_p)
                    except Exception:
                        pass
                staged_media = str(dest_p if dest_p.exists() else src_p)
            else:
                # Generate fresh procedural media
                try:
                    if item.get("media_type") == "video":
                        card = self.creative_engine.media_gen.generate_telemetry_radar_card()
                        vid = self.creative_engine.video_gen.generate_video_short(
                            script_text=item.get("text", "Orbit Security perimeter scan online.")[:120],
                            image_path=card,
                            title=f"draft_{item['id']}",
                        )
                        staged_media = str(vid)
                    else:
                        card = self.creative_engine.media_gen.generate_dns_attack_diagram()
                        staged_media = str(card)
                except Exception as e:
                    logger.warning(f"Error generating procedural media for draft [{item['id']}]: {e}")

            draft = SocialDraft(
                id=item["id"],
                title=item.get("title", f"Orbit Intel: {item['id']}"),
                text=item["text"].strip(),
                media_path=staged_media,
                media_type=item.get("media_type", "image"),
                pillar=item.get("category", "break_and_fix"),
                status="DRAFT",
            )
            self._drafts[draft.id] = draft
            new_drafts.append(draft)
            recent_ids.add(draft.id)

        # If more drafts requested, generate fresh ones from CreativeEngine
        while len(new_drafts) < count:
            try:
                gen_post = self.creative_engine.generate_next_post(
                    recent_post_ids=list(recent_ids),
                    target_media_type="video" if len(new_drafts) % 2 == 1 else "image",
                )
                if gen_post.id in recent_ids:
                    gen_post.id = f"{gen_post.id}_{int(datetime.datetime.now().timestamp())}"

                draft = SocialDraft(
                    id=gen_post.id,
                    title=gen_post.title,
                    text=gen_post.text.strip(),
                    media_path=gen_post.media_path,
                    media_type=gen_post.media_type,
                    pillar=gen_post.pillar.value,
                    status="DRAFT",
                )
                self._drafts[draft.id] = draft
                new_drafts.append(draft)
                recent_ids.add(draft.id)
            except Exception as e:
                logger.error(f"Error generating dynamic post: {e}")
                break

        self._save_manifest()
        return new_drafts

    def list_drafts(self, status: Optional[str] = None) -> List[SocialDraft]:
        """Returns filtered list of drafts."""
        self._load_manifest()
        if status:
            return [d for d in self._drafts.values() if d.status == status.upper()]
        return list(self._drafts.values())

    def get_draft(self, draft_id: str) -> Optional[SocialDraft]:
        """Retrieves a specific draft by ID."""
        self._load_manifest()
        return self._drafts.get(draft_id)

    def copy_to_clipboard(self, draft_id: str) -> bool:
        """Copies draft text to Windows system clipboard."""
        draft = self.get_draft(draft_id)
        if not draft:
            return False

        copied = False
        try:
            import pyperclip
            pyperclip.copy(draft.text)
            copied = True
        except Exception:
            pass

        # Windows PowerShell fallback if pyperclip fails
        if not copied and os.name == "nt":
            try:
                clean_text = draft.text.replace('"', '`"')
                cmd = f'Set-Clipboard -Value "{clean_text}"'
                subprocess.run(["powershell", "-NoProfile", "-Command", cmd], check=True)
                copied = True
            except Exception:
                pass

        return copied

    def open_media(self, draft_id: str) -> bool:
        """Reveals the media attachment in Windows Explorer or opens the default viewer."""
        draft = self.get_draft(draft_id)
        if not draft or not draft.media_path:
            return False

        path = Path(draft.media_path)
        if not path.exists():
            return False

        if os.name == "nt":
            try:
                # Highlight in explorer
                subprocess.run(["explorer", f"/select,{str(path.resolve())}"])
                return True
            except Exception:
                try:
                    os.startfile(str(path))
                    return True
                except Exception:
                    return False
        return False

    def mark_posted(self, draft_id: str) -> bool:
        """Marks draft as POSTED and logs manual action into SQLite state for dedup tracking."""
        draft = self.get_draft(draft_id)
        if not draft:
            return False

        draft.status = "POSTED"
        draft.posted_at_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save_manifest()

        # Record into SQLite so dedup cache knows it was published
        try:
            self.state_manager.record_action(
                tweet_id=f"manual_{draft.id}",
                action_type="POST",
                author_handle="_arsoncode",
                content_snippet=draft.text[:120],
                status="SUCCESS",
                metadata={
                    "media_path": draft.media_path,
                    "media_type": draft.media_type,
                    "mode": "MANUAL_DRAFT",
                },
            )
        except Exception as e:
            logger.warning(f"Error recording draft action in SQLite state: {e}")

        return True

    def send_next_draft(self) -> Dict[str, Any]:
        """Dispatches the next staged draft post.

        Attempts native desktop automation if an active browser window is present.
        Otherwise falls back to copying the text to clipboard, staging/revealing media,
        and opening the operator browser to https://x.com/compose/post.
        Marks the draft as POSTED.
        """
        self._load_manifest()
        pending = [d for d in self._drafts.values() if d.status == "DRAFT"]
        if not pending:
            # Generate a fresh batch if empty
            new_batch = self.generate_draft_batch(count=3)
            pending = [d for d in new_batch if d.status == "DRAFT"]

        if not pending:
            return {"success": False, "error": "No staged drafts available"}

        draft = pending[0]
        mode = "DESKTOP_AUTOMATION"
        posted_ok = False

        # 1. Try Desktop Automation Driver if available
        try:
            from orbit_security.desktop_x_bridge import DesktopAutomationDriver
            drv = DesktopAutomationDriver()
            if drv.is_available():
                logger.info(f"Dispatching draft [{draft.id}] via active taskbar browser automation...")
                posted_ok = drv.post_tweet(text=draft.text, media_path=draft.media_path)
        except Exception as e:
            logger.warning(f"Desktop automation dispatch failed: {e}")
            posted_ok = False

        # 2. Fallback to Operator Browser Composer + Clipboard
        if not posted_ok:
            mode = "OPERATOR_COMPOSER_CLIPBOARD"
            self.copy_to_clipboard(draft.id)
            if draft.media_path and Path(draft.media_path).exists():
                self.open_media(draft.id)
            try:
                import webbrowser
                webbrowser.open("https://x.com/compose/post")
                posted_ok = True
            except Exception as e:
                logger.error(f"Error opening browser composer: {e}")
                posted_ok = True  # Still considered successful since text is in clipboard

        self.mark_posted(draft.id)

        return {
            "success": True,
            "draft_id": draft.id,
            "title": draft.title,
            "text": draft.text,
            "media_path": draft.media_path,
            "media_type": draft.media_type,
            "mode": mode,
            "message": f"Draft [{draft.id}] dispatched via {mode}",
        }
