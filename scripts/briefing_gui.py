import ctypes
import os
import sys
import threading
import subprocess
from pathlib import Path
from typing import Optional

# Attach current thread to the user's interactive desktop WinSta0\Default
def attach_to_interactive_desktop() -> bool:
    try:
        user32 = ctypes.windll.user32
        DESKTOP_ALL = 0x01FF
        hdesk = user32.OpenDesktopW("Default", 0, False, DESKTOP_ALL)
        if hdesk:
            return bool(user32.SetThreadDesktop(hdesk))
    except Exception:
        pass
    return False

attach_to_interactive_desktop()

import tkinter as tk
from tkinter import scrolledtext


def show_briefing_gui(content: str, spoken_summary: Optional[str] = None):
    """Displays the daily briefing in a dedicated, dark-mode GUI window.
    
    Guarantees:
    - Never closes on Enter or any keystroke (safe from accidental dismissal).
    - Can only be closed by physically clicking the red [X] in the top corner.
    - Speaks the audio summary in the background so operator hears it clearly.
    """
    attach_to_interactive_desktop()
    root = tk.Tk()
    root.title("Orbit Security Morning Briefing")
    root.geometry("1100x850")
    root.configure(bg="#0d1117")

    # Header bar
    header = tk.Frame(root, bg="#161b22", height=50)
    header.pack(fill=tk.X, side=tk.TOP)

    lbl_title = tk.Label(
        header,
        text="  ORBIT SECURITY · DAILY OPERATIONAL & REVENUE BRIEFING",
        font=("Segoe UI", 12, "bold"),
        fg="#58a6ff",
        bg="#161b22",
        pady=10,
    )
    lbl_title.pack(side=tk.LEFT)

    lbl_hint = tk.Label(
        header,
        text="[Window locked open · Click X in top corner when done]  ",
        font=("Segoe UI", 9, "italic"),
        fg="#8b949e",
        bg="#161b22",
        pady=10,
    )
    lbl_hint.pack(side=tk.RIGHT)

    # Scrolled Text Box
    txt = scrolledtext.ScrolledText(
        root,
        wrap=tk.WORD,
        bg="#0d1117",
        fg="#c9d1d9",
        insertbackground="#58a6ff",
        font=("Consolas", 11),
        padx=20,
        pady=15,
        relief=tk.FLAT,
    )
    txt.pack(fill=tk.BOTH, expand=True)
    txt.insert(tk.END, content)
    txt.configure(state=tk.DISABLED)

    # Unbind Return / Enter / Escape to prevent keyboard dismissal
    root.bind("<Return>", lambda e: "break")
    root.bind("<KP_Enter>", lambda e: "break")
    root.bind("<Escape>", lambda e: "break")

    # Force to front
    root.lift()
    root.attributes("-topmost", True)
    root.after_idle(root.attributes, "-topmost", False)

    # Background Nova Voice TTS debrief
    if spoken_summary:
        def speak():
            hook_script = r"C:\Users\purav\.gemini\config\scripts\nova_voice_hook.py"
            py_bin = r"A:\projects\orbit-security\.venv\Scripts\python.exe"
            if os.path.exists(hook_script) and os.path.exists(py_bin):
                subprocess.run([py_bin, hook_script, "--speak", spoken_summary])

        t = threading.Thread(target=speak, daemon=True)
        t.start()

    root.mainloop()


def main():
    briefing_file = Path(r"A:\projects\orbit-security\daily_briefings\briefing_2026-11-16.md")
    content = briefing_file.read_text(encoding="utf-8") if briefing_file.exists() else "Briefing file not found."
    summary = (
        "Morning Carson. Nova here with your unified 10 AM cockpit briefing. "
        "Hardware pulse: CPU is running cool at 52.0 degrees, and RAM is at 54.5 percent. "
        "Supervisor and Sentinel are green on PID 20552. Over on GitHub, heads up, 1 GitHub CI workflows failing on HEAD. "
        "Option C status: 48 verified bounty bundles staged with Spotify Tier-1 ready, Track B checkout ready, awaiting physical ID for KYC payout unlock. "
        "In your workspace, 4 active repos plus 8 root workspace commits in the last forty-eight hours. "
        "Mailbox has 0 unread non-CI messages, with zero new urgent emergencies. "
        "On the AI radar: AI models running stable. World headline: James Bond live updates: Robert Pattinson named as new 007. "
        "Let's knock out the priority queue."
    )
    show_briefing_gui(content, spoken_summary=summary)


if __name__ == "__main__":
    main()
