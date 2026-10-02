"""Unit tests for Act IV Product 3: HyperNote Audio Briefing Engine (hypernote_briefing.py).

Covers:
  - Git commit extraction and supervisor telemetry gathering.
  - Conversational morning briefing script synthesis.
  - Word count and podcast duration estimation.
  - Audio podcast artifact generation and metadata serialization.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from orbit_security.hypernote_briefing import (
    BriefingMetadata,
    BriefingScriptSynthesizer,
    BriefingSourceCollector,
    HyperNoteAudioGenerator,
    HyperNoteBriefingEngine,
)


class TestHyperNoteBriefing:
    def test_collector_git_and_health(self):
        collector = BriefingSourceCollector()
        mock_commits = [
            "1a2b3c4 - feat: add ghostdns drift scanner",
            "5d6e7f8 - fix: resolve turnstile box offset",
        ]
        commits = collector.collect_git_commits(mock_commits=mock_commits)
        assert len(commits) == 2
        assert "ghostdns" in commits[0]

        health = collector.collect_supervisor_health()
        assert "ram_available_mb" in health
        assert "services" in health

    def test_synthesize_script_structure(self):
        commits = [
            "2fc26ae - feat: implement Act III automated bug bounty radar",
            "f969a1c - feat: integrate neural video roasts",
        ]
        health = {
            "ram_available_mb": 4200,
            "memory_band": "green",
            "bounty_radar": {"total_vulnerabilities_found": 3},
            "services": {"Ollama": {"active": True}, "Inbox": {"active": True}},
        }

        script = BriefingScriptSynthesizer.synthesize_script(
            commits=commits,
            health_state=health,
            author_name="Carson",
            persona="Nova",
        )

        assert "Good morning Carson" in script
        assert "Nova" in script
        assert "Engineering Velocity" in script
        assert "Perimeter Defense & Radar" in script
        assert "Infrastructure Telemetry" in script
        assert "4,200 megabytes" in script
        assert "total_vulnerabilities_found" not in script  # Formatted cleanly
        assert "Recommended Tactical Focus" in script
        assert "Systems are nominal" in script

    def test_audio_generator_fallback(self, tmp_path):
        gen = HyperNoteAudioGenerator(voice="en-US-AvaNeural")
        audio_file = tmp_path / "test_briefing.mp3"
        # In test environments, generate_audio gracefully succeeds (either via network edge-tts or valid audio beacon)
        success = gen.generate_audio("Hello from HyperNote test briefing.", audio_file)
        assert success is True
        assert audio_file.exists()
        assert audio_file.stat().st_size > 0

    def test_engine_generate_daily_briefing_end_to_end(self, tmp_path):
        engine = HyperNoteBriefingEngine(output_dir=tmp_path)
        meta = engine.generate_daily_briefing(
            author_name="Carson",
            synthesize_audio=True,
            mock_commits=["abc1234 - feat: automated enterprise retainers"],
            mock_health={
                "ram_available_mb": 3800,
                "memory_band": "green",
                "services": {"Supervisor": {"active": True}},
            },
        )

        assert isinstance(meta, BriefingMetadata)
        assert meta.word_count > 50
        assert meta.estimated_duration_sec > 20.0
        assert Path(meta.script_path).exists()
        assert Path(meta.audio_path).exists()

        # Check serialized metadata json
        meta_json = tmp_path / f"briefing_{meta.date_str}.json"
        assert meta_json.exists()
        with open(meta_json, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["title"] == meta.title
            assert data["word_count"] == meta.word_count
