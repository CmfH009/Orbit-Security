#!/usr/bin/env python3
"""scripts/generate_daily_briefing_audio.py: HyperNote Daily Audio Briefing Generator ($19/mo).

Usage:
    # Generate full daily briefing (script + neural audio podcast)
    python scripts/generate_daily_briefing_audio.py

    # Preview script only without audio synthesis
    python scripts/generate_daily_briefing_audio.py --no-audio

    # Customize voice or speaking rate
    python scripts/generate_daily_briefing_audio.py --voice "en-US-AvaNeural" --rate "+6%"
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Ensure local src/ is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.hypernote_briefing import (
    HyperNoteAudioGenerator,
    HyperNoteBriefingEngine,
)


def main():
    parser = argparse.ArgumentParser(
        description="HyperNote: 3-Minute Neural Audio Daily Briefing for Developers & CTOs ($19/mo)"
    )
    parser.add_argument("--voice", type=str, default="en-US-AvaNeural", help="Neural TTS voice model")
    parser.add_argument("--rate", type=str, default="+4%", help="Speech rate adjustment (e.g. '+4%', '+8%')")
    parser.add_argument("--author", type=str, default="Carson", help="Recipient founder/developer name")
    parser.add_argument("--no-audio", action="store_true", help="Generate script markdown only (skip audio)")
    parser.add_argument("--output-dir", type=str, help="Custom output directory for briefing artifacts")

    args = parser.parse_args()

    audio_gen = HyperNoteAudioGenerator(voice=args.voice, rate=args.rate)
    engine = HyperNoteBriefingEngine(
        output_dir=Path(args.output_dir) if args.output_dir else None,
        audio_generator=audio_gen,
    )

    print("\n" + "=" * 70)
    print(" 🎙️ HYPERNOTE AUDIO BRIEFING ENGINE: MORNING PODCAST SYNTHESIS")
    print("=" * 70)
    print(f" Target Author:      {args.author}")
    print(f" Neural Voice:       {args.voice} ({args.rate})")
    print(f" Audio Synthesis:    {'Disabled (--no-audio)' if args.no_audio else 'Enabled (Edge TTS Neural)'}")
    print("-" * 70)

    meta = engine.generate_daily_briefing(
        author_name=args.author,
        synthesize_audio=not args.no_audio,
    )

    print(f"✓ Daily Briefing Generated Successfully!")
    print(f"  • Title:              {meta.title}")
    print(f"  • Word Count:         {meta.word_count} words")
    print(f"  • Estimated Duration: {meta.estimated_duration_sec}s (~{round(meta.estimated_duration_sec/60, 1)} min)")
    print(f"  • Commits Ingested:   {meta.git_commits_count}")
    print(f"  • Daemons Monitored:  {meta.active_services_count}")
    print(f"  📄 Script File:       {meta.script_path}")
    if meta.audio_path:
        print(f"  🎧 Audio Podcast:     {meta.audio_path}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
