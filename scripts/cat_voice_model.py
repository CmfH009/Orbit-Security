#!/usr/bin/env python3
"""CLI utility for Orbit Security Astronaut Cat Voice Model and Video Rendering.

Usage:
    # 1. Synthesize voiceover and apply astronaut helmet DSP:
    python scripts/cat_voice_model.py --speak "Yes, our chief perimeter sentinel is an astronaut cat." --output scratch/cat_voice.wav

    # 2. Render complete video ad with voiceover:
    python scripts/cat_voice_model.py --video landing/assets/orbit_cat_humor_ad.mp4 --output landing/assets/orbit_cat_ad_final.mp4

    # 3. Analyze an audio sample to calibrate a custom voice profile:
    python scripts/cat_voice_model.py --analyze data/voice/sample.wav --save-profile data/voice/user_profile.json
"""

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from orbit_security.voice_model import CatVoiceEngine, VoiceProfile

DEFAULT_SCRIPT = (
    "Yes, our chief perimeter sentinel is an astronaut cat. "
    "No, that doesn't mean your dangling CNAME records and unauthenticated mail servers are a joke. "
    "Rogue takeovers and DNS hijacking don't wait for Monday morning. "
    "Orbit Security monitors your attack surface 24/7 so you sleep soundly. "
    "Run your free 10-second perimeter audit at cmfh009.github.io/Orbit-Security."
)


def main():
    parser = argparse.ArgumentParser(description="Orbit Security Cat Voice Model & Video Ad Stager")
    parser.add_argument("--speak", "-s", type=str, default=None, help="Text to speak")
    parser.add_argument("--text-file", type=str, default=None, help="Path to text script file")
    parser.add_argument("--input-audio", "-i", type=str, default=None, help="Input audio to apply helmet DSP to")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output path for audio or video")
    parser.add_argument("--video", "-v", type=str, default=None, help="Input video to mux voiceover onto")
    parser.add_argument("--profile", "-p", type=str, default=None, help="Path to custom VoiceProfile JSON")
    parser.add_argument("--save-profile", type=str, default=None, help="Path to save generated VoiceProfile")
    parser.add_argument("--analyze", "-a", type=str, default=None, help="Analyze audio sample with Gemini 3.8 Flash")
    parser.add_argument("--backend", choices=["gemini", "edge"], default=None, help="Speech backend engine")
    parser.add_argument("--gemini-voice", type=str, default=None, help="Gemini TTS voice (e.g. Charon, Achird, Puck, Zubenelgenubi)")
    parser.add_argument("--style", type=str, default=None, help="Natural language voice prompt styling")
    parser.add_argument("--ad", action="store_true", help="Generate full promotional video ad with default script")

    args = parser.parse_args()

    # Load custom or default profile
    if args.profile and Path(args.profile).exists():
        profile = VoiceProfile.load(args.profile)
        print(f"Loaded voice profile '{profile.name}' from {args.profile}")
    else:
        profile = VoiceProfile()

    if args.backend:
        profile.engine_backend = args.backend
    if args.gemini_voice:
        profile.gemini_voice = args.gemini_voice
    if args.style:
        profile.gemini_style_prompt = args.style

    engine = CatVoiceEngine(default_profile=profile)


    # 1. Voice Analysis Mode
    if args.analyze:
        print(f"Analyzing audio sample: {args.analyze}...")
        calibrated_prof = engine.analyze_voice_sample(args.analyze)
        save_dest = args.save_profile or (PROJECT_ROOT / "data" / "voice" / f"{Path(args.analyze).stem}_profile.json")
        calibrated_prof.save(save_dest)
        print(f"Calibrated voice profile saved to: {save_dest}")
        print(f"Profile: voice={calibrated_prof.tts_voice}, pitch={calibrated_prof.pitch}, rate={calibrated_prof.rate}")
        return

    # 2. Text or Ad Script Resolution
    script_text = args.speak
    if args.text_file and Path(args.text_file).exists():
        with open(args.text_file, "r", encoding="utf-8") as f:
            script_text = f.read().strip()
    elif not script_text and (args.ad or args.video):
        script_text = DEFAULT_SCRIPT

    # 3. Audio Generation / DSP
    final_audio_path = None
    if script_text:
        print(f"Synthesizing script ({len(script_text)} chars)...")
        raw_audio = PROJECT_ROOT / "scratch" / "cat_voice_raw.mp3"
        dsp_audio = args.output if (args.output and not args.video and args.output.endswith((".wav", ".mp3"))) else (PROJECT_ROOT / "scratch" / "cat_voice_helmet.wav")
        engine.synthesize_speech(script_text, raw_audio, profile=profile)
        print("Applying astronaut helmet radio DSP chain...")
        engine.apply_helmet_dsp(raw_audio, dsp_audio, profile=profile)
        final_audio_path = dsp_audio
        print(f"Helmet voiceover ready: {dsp_audio}")
    elif args.input_audio:
        inp = Path(args.input_audio)
        dsp_audio = args.output or (PROJECT_ROOT / "scratch" / f"{inp.stem}_helmet.wav")
        print(f"Applying astronaut helmet radio DSP to: {inp}...")
        engine.apply_helmet_dsp(inp, dsp_audio, profile=profile)
        final_audio_path = dsp_audio
        print(f"Helmet voiceover ready: {dsp_audio}")

    # 4. Video Muxing Mode
    video_source = args.video
    if args.ad and not video_source:
        default_vid = PROJECT_ROOT / "landing" / "assets" / "orbit_cat_humor_ad.mp4"
        if default_vid.exists():
            video_source = str(default_vid)
        else:
            video_source = str(PROJECT_ROOT / "landing" / "assets" / "orbit_security_ad_video.mp4")

    if video_source:
        out_vid = args.output or (PROJECT_ROOT / "landing" / "assets" / "orbit_cat_ad_final.mp4")
        if not final_audio_path:
            raise RuntimeError("No voiceover audio available to mux with video.")
        print(f"Muxing voiceover onto video: {video_source} -> {out_vid}...")
        engine.render_ad_video(
            video_path=video_source,
            voice_audio_path=final_audio_path,
            output_video_path=out_vid,
            bg_duck_db=-18.0,
        )
        print(f"Broadcast video ad successfully rendered: {out_vid}")


if __name__ == "__main__":
    main()
