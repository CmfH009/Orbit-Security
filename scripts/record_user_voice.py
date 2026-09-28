#!/usr/bin/env python3
"""1-Click Mic Voice Capture and Acoustic Profiler for Orbit Security.

Records a high-fidelity voice sample from the microphone, saves it,
and runs acoustic analysis with Gemini 3.8 Flash to calibrate your custom voice profile.

Usage:
    python scripts/record_user_voice.py --seconds 10
    python scripts/record_user_voice.py --list-devices
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from orbit_security.voice_model import CatVoiceEngine, VoiceProfile


def get_available_audio_devices() -> list[str]:
    """Queries ffmpeg dshow for available audio input devices."""
    cmd = ["ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy"]
    res = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    devices = []
    lines = res.stderr.splitlines()
    for line in lines:
        if '(audio)' in line:
            m = re.search(r'"([^"]+)"\s+\(audio\)', line)
            if m:
                devices.append(m.group(1))
    return devices


def record_sample(output_wav: Path, duration: int = 10, device_name: str | None = None) -> Path:
    devices = get_available_audio_devices()
    if not devices:
        print("[!] No DirectShow audio input devices detected.")
        sys.exit(1)

    target_device = device_name or devices[0]
    # Prefer Intel Smart Sound / default mic
    for d in devices:
        if "Intel" in d or "Microphone" in d:
            target_device = d
            break

    print(f"[*] Selected audio device: '{target_device}'")
    print(f"[*] Recording {duration} seconds of audio... Speak now!")
    output_wav.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "dshow",
        "-i",
        f"audio={target_device}",
        "-t",
        str(duration),
        "-ar",
        "48000",
        "-ac",
        "1",
        str(output_wav),
    ]

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        print(f"[!] Recording error: {p.stderr.decode('utf-8', errors='ignore')}")
        sys.exit(1)

    print(f"[+] Recording saved to: {output_wav}")
    return output_wav


def main():
    parser = argparse.ArgumentParser(description="Record user voice and calibrate voice model")
    parser.add_argument("--seconds", "-s", type=int, default=10, help="Duration in seconds (default: 10)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output wav file")
    parser.add_argument("--device", "-d", type=str, default=None, help="Specific dshow audio device name")
    parser.add_argument("--list-devices", action="store_true", help="List available microphone devices")
    parser.add_argument("--no-analyze", action="store_true", help="Skip Gemini voice analysis")

    args = parser.parse_args()

    if args.list_devices:
        devs = get_available_audio_devices()
        print("Available Audio Devices:")
        for idx, d in enumerate(devs):
            print(f"  [{idx + 1}] {d}")
        return

    out_file = Path(args.output) if args.output else (PROJECT_ROOT / "data" / "voice" / "carson_reference.wav")
    recorded = record_sample(out_file, duration=args.seconds, device_name=args.device)

    if not args.no_analyze:
        print("\n[*] Running Gemini 3.8 Flash acoustic analysis on voice recording...")
        engine = CatVoiceEngine()
        profile = engine.analyze_voice_sample(recorded)
        profile_path = PROJECT_ROOT / "data" / "voice" / "carson_profile.json"
        profile.save(profile_path)
        print(f"[+] Successfully calibrated voice profile saved to: {profile_path}")
        print(f"    Voice Base: {profile.tts_voice}")
        print(f"    Pitch Modulation: {profile.pitch}")
        print(f"    Speaking Rate: {profile.rate}")


if __name__ == "__main__":
    main()
