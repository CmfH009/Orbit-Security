"""Stanford Memorilla-Inspired Latent Semantic Memory & Loop Prevention (Standalone Fallback).

Provides self-contained MemorillaCompressor, MemoryAnchor, and LoopPreventionSentinel
when nova_brain is not present in the runtime environment (such as clean CI checkouts).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
import math
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger("orbit_security.memorilla")

DEFAULT_SOFT_TOKEN_BUDGET = 16
MAX_ANCHOR_CHARS = 280
_WORD_RE = re.compile(r"[A-Za-z0-9_.-]{2,}")
_STOPWORDS = frozenset({
    "the", "a", "an", "in", "on", "at", "to", "for", "of", "and", "or",
    "is", "was", "are", "were", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "this", "that", "these", "those", "it",
    "its", "they", "them", "their", "we", "us", "our", "you", "your",
    "with", "as", "by", "from", "up", "about", "into", "over", "after",
})


@dataclass(slots=True)
class MemoryAnchor:
    """A single compact latent memory anchor representing a compressed fact or decision."""

    anchor_id: str
    concept: str
    summary: str
    salience: float
    source: str
    tags: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def token_representation(self) -> str:
        """Compact serialized representation for prefix injection."""
        tag_str = f"[{','.join(self.tags[:3])}]" if self.tags else ""
        return f"<{self.concept}{tag_str}:{self.summary[:MAX_ANCHOR_CHARS]}>"


def _tokenize_text(text: str) -> List[str]:
    """Extract lowercased alphanumeric tokens excluding common stop words."""
    words = _WORD_RE.findall(text.lower())
    return [w for w in words if w not in _STOPWORDS and len(w) > 2]


def _compute_jaccard_similarity(tokens_a: Set[str], tokens_b: Set[str]) -> float:
    """Compute Jaccard similarity between two token sets."""
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union if union > 0 else 0.0


def _generate_anchor_id(concept: str, text: str) -> str:
    """Generate a deterministic 12-char hex ID for a memory anchor."""
    raw = f"{concept.strip().lower()}|{text.strip().lower()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"mem_{digest}"


class MemorillaCompressor:
    """Compresses conversational turns and documentation into a bounded soft memory budget."""

    def __init__(self, soft_token_budget: int = DEFAULT_SOFT_TOKEN_BUDGET):
        self.soft_token_budget = max(4, min(64, soft_token_budget))

    def compress_turns(
        self,
        turns: Sequence[Dict[str, Any]],
        *,
        query: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> List[MemoryAnchor]:
        """Compress a sequence of dialogue / tool turns into a fixed budget of MemoryAnchors."""
        budget = top_k if top_k is not None else self.soft_token_budget
        if not turns:
            return []

        query_tokens = set(_tokenize_text(query)) if query else set()
        candidates: List[MemoryAnchor] = []

        for i, turn in enumerate(turns):
            content = str(turn.get("content") or turn.get("text") or "").strip()
            if not content:
                continue

            role = str(turn.get("role") or turn.get("source") or "system").strip()
            tags = list(turn.get("tags") or [])
            salience_base = float(turn.get("salience", 0.5))

            first_line = content.splitlines()[0].strip() if content else ""
            concept = re.sub(r"^[#\s*-]+", "", first_line)[:40].strip() or f"Turn_{i}"

            summary = re.sub(r"\s+", " ", content)[:MAX_ANCHOR_CHARS].strip()
            anchor_id = _generate_anchor_id(concept, summary)

            turn_tokens = set(_tokenize_text(content))
            relevance = _compute_jaccard_similarity(query_tokens, turn_tokens) if query_tokens else 0.5
            combined_score = (0.6 * salience_base) + (0.4 * relevance)

            candidates.append(
                MemoryAnchor(
                    anchor_id=anchor_id,
                    concept=concept,
                    summary=summary,
                    salience=round(combined_score, 4),
                    source=role,
                    tags=tags,
                )
            )

        candidates.sort(key=lambda a: a.salience, reverse=True)
        return candidates[:budget]

    def compress_document(
        self,
        doc_text: str,
        *,
        title: str = "Document",
        query: Optional[str] = None,
        chunk_lines: int = 15,
    ) -> List[MemoryAnchor]:
        """Compress an arbitrary markdown/code document into soft memory anchors."""
        lines = doc_text.splitlines()
        chunks: List[Dict[str, Any]] = []

        for i in range(0, len(lines), chunk_lines):
            chunk_slice = lines[i : i + chunk_lines]
            chunk_body = "\n".join(chunk_slice).strip()
            if not chunk_body:
                continue
            chunks.append({
                "source": title,
                "content": chunk_body,
                "salience": 0.7,
                "tags": [title.lower()],
            })

        return self.compress_turns(chunks, query=query)


class LoopPreventionSentinel:
    """Detects and breaks cyclical agent exploration loops in multi-turn execution."""

    def __init__(self, history_window: int = 8, repetition_threshold: int = 3):
        self.history_window = history_window
        self.repetition_threshold = repetition_threshold
        self._action_history: List[str] = []
        self._loop_detected_count: int = 0

    def record_action(self, action_signature: str) -> bool:
        """Record an agent action / tool query signature and return True if a loop is detected."""
        clean_sig = hashlib.sha256(action_signature.strip().lower().encode("utf-8")).hexdigest()[:16]
        self._action_history.append(clean_sig)

        if len(self._action_history) > self.history_window * 2:
            self._action_history = self._action_history[-self.history_window :]

        is_loop = self._check_loop()
        if is_loop:
            self._loop_detected_count += 1
            logger.warning(
                "Agentic loop detected by LoopPreventionSentinel! Signature: %s (occurrences: %d)",
                clean_sig,
                self._loop_detected_count,
            )
        return is_loop

    def _check_loop(self) -> bool:
        recent = self._action_history[-self.history_window :]
        if len(recent) < self.repetition_threshold:
            return False

        last = recent[-1]
        repetition_count = sum(1 for x in recent if x == last)
        if repetition_count >= self.repetition_threshold:
            return True

        if len(recent) >= 4 and recent[-1] == recent[-3] and recent[-2] == recent[-4]:
            return True

        if len(recent) >= 6 and recent[-1] == recent[-4] and recent[-2] == recent[-5] and recent[-3] == recent[-6]:
            return True

        return False

    def generate_perturbation_hint(self) -> str:
        return (
            "[LOOP_PREVENTION_SENTINEL] Alert: Repeated cyclical action detected. "
            "Halt current command pattern immediately. Diverge to alternate investigative strategy."
        )

    def reset(self) -> None:
        self._action_history.clear()
        self._loop_detected_count = 0


class MemorillaContextInjector:
    def __init__(self, compressor: Optional[MemorillaCompressor] = None):
        self.compressor = compressor or MemorillaCompressor()

    def render_prefix(
        self,
        anchors: Sequence[MemoryAnchor],
        *,
        loop_hint: Optional[str] = None,
    ) -> str:
        if not anchors and not loop_hint:
            return ""

        parts = ["[MEMORILLA_LATENT_MEMORY]"]
        if loop_hint:
            parts.append(loop_hint)

        for a in anchors:
            parts.append(a.token_representation())

        parts.append("[/MEMORILLA_LATENT_MEMORY]")
        return "\n".join(parts)
