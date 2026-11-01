#!/usr/bin/env python3
"""
test_m1_adversarial_verify_landing.py
Adversarial stress harness for scripts/verify_landing_pages.py under constrained encodings:
- Forced cp1252, ascii, latin-1, utf-8 stdout streams (strict and replace modes)
- Subprocess execution across diverse PYTHONIOENCODING settings
- PYTHONUTF8=0 and PYTHONLEGACYWINDOWSSTDIO=1 legacy modes
- Piped stdout / stderr capture
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_landing_pages.py"
PYTHON_EXE = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON_EXE.exists():
    PYTHON_EXE = Path(sys.executable)


class TestVerifyLandingPagesEncodingStress(unittest.TestCase):
    def run_script_with_env(self, extra_env: dict):
        env = os.environ.copy()
        env.update(extra_env)
        proc = subprocess.run(
            [str(PYTHON_EXE), str(SCRIPT_PATH)],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        return proc

    def test_subprocess_cp1252_default(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "cp1252"})
        self.assertEqual(proc.returncode, 0, f"Failed on cp1252. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_cp1252_strict(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "cp1252:strict"})
        self.assertEqual(proc.returncode, 0, f"Failed on cp1252:strict. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_ascii_default(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "ascii"})
        self.assertEqual(proc.returncode, 0, f"Failed on ascii. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_ascii_strict(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "ascii:strict"})
        self.assertEqual(proc.returncode, 0, f"Failed on ascii:strict. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_utf8_default(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "utf-8"})
        self.assertEqual(proc.returncode, 0, f"Failed on utf-8. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_latin1_strict(self):
        proc = self.run_script_with_env({"PYTHONIOENCODING": "latin-1:strict"})
        self.assertEqual(proc.returncode, 0, f"Failed on latin-1:strict. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_pythonutf8_disabled(self):
        proc = self.run_script_with_env({"PYTHONUTF8": "0", "PYTHONIOENCODING": "cp1252:strict"})
        self.assertEqual(proc.returncode, 0, f"Failed on PYTHONUTF8=0. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_subprocess_legacy_windows_stdio(self):
        proc = self.run_script_with_env({"PYTHONLEGACYWINDOWSSTDIO": "1", "PYTHONIOENCODING": "cp1252"})
        self.assertEqual(proc.returncode, 0, f"Failed on PYTHONLEGACYWINDOWSSTDIO=1. Stderr: {proc.stderr}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("ALL EMPIRICAL VERIFICATIONS PASSED 100%", proc.stdout)

    def test_piped_stdout_subprocess(self):
        """Simulate piping output to another process (common in CI/CD)."""
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "cp1252:strict"
        p1 = subprocess.Popen(
            [str(PYTHON_EXE), str(SCRIPT_PATH)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(REPO_ROOT),
        )
        stdout, stderr = p1.communicate()
        self.assertEqual(p1.returncode, 0, f"Pipe failed: {stderr.decode('utf-8', errors='replace')}")
        self.assertNotIn(b"UnicodeEncodeError", stderr)
        self.assertIn(b"ALL EMPIRICAL VERIFICATIONS PASSED 100%", stdout)


if __name__ == "__main__":
    unittest.main()
