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

    def test_github_pages_parity_nojekyll_and_payment_link_fallbacks(self):
        """Verify landing/ <-> docs/ byte parity, .nojekyll, canonical URLs, and Payment Links."""
        import importlib.util

        sync_path = REPO_ROOT / "scripts" / "sync_landing_to_docs.py"
        spec = importlib.util.spec_from_file_location("sync_landing_to_docs_mod", sync_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        sync_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync_mod)

        report = sync_mod.compare(REPO_ROOT / "landing", REPO_ROOT / "docs")
        self.assertEqual(report["mismatched"], [], f"Drift between landing/ and docs/: {report['mismatched']}")
        self.assertGreaterEqual(len(report["identical"]), 96)

        for tree in (REPO_ROOT / "landing", REPO_ROOT / "docs"):
            self.assertTrue((tree / ".nojekyll").is_file(), f"Missing .nojekyll in {tree}")
            signup_html = (tree / "signup.html").read_text(encoding="utf-8")
            self.assertIn("/create-checkout-session", signup_html)
            self.assertIn("https://buy.stripe.com/8x29ASgAk3V15X2el6cs801", signup_html)
            self.assertIn("https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800", signup_html)
            self.assertIn("https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802", signup_html)
            self.assertIn("prefilled_email", signup_html)
            self.assertIn("client_reference_id", signup_html)
            audit_html = (tree / "audit.html").read_text(encoding="utf-8")
            self.assertIn('href="https://cmfh009.github.io/Orbit-Security/audit.html"', audit_html)

    def test_deploy_landing_resolves_key_fails_closed_and_passes_ast_sentinel(self):
        """Verify deploy_landing.py has zero hardcoded keys, fails closed, and uses egress_guard."""
        import contextlib
        import importlib.util
        import io
        import tempfile

        deploy_path = REPO_ROOT / "scripts" / "deploy_landing.py"
        deploy_src = deploy_path.read_text(encoding="utf-8")

        self.assertNotRegex(deploy_src, r"ak_[0-9a-f]{16,}", "Hardcoded AppDeploy key literal must be removed")
        self.assertIn("create_guarded_httpx_client", deploy_src)
        self.assertIn("PublicHostOnlyRoE", deploy_src)
        self.assertNotRegex(deploy_src, r"(?m)^\s*import\s+httpx\b")
        self.assertNotIn("httpx.post(", deploy_src)

        src_dir = REPO_ROOT / "src"
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))
        from orbit_security import ast_sentinel
        from orbit_security.scanner import PublicHostOnlyRoE

        violations = ast_sentinel.check_file_egress_compliance(deploy_path, deploy_src)
        self.assertEqual(violations, [], f"ROE egress violations in deploy_landing.py: {violations}")
        sentinel_proc = subprocess.run(
            [str(PYTHON_EXE), "-m", "orbit_security.ast_sentinel", "--check", str(deploy_path)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(
            sentinel_proc.returncode,
            0,
            f"ast_sentinel --check failed:\n{sentinel_proc.stdout}\n{sentinel_proc.stderr}",
        )

        saved_key = os.environ.pop("APPDEPLOY_API_KEY", None)
        try:
            spec = importlib.util.spec_from_file_location("deploy_landing_test_mod", deploy_path)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            with tempfile.TemporaryDirectory() as tmp_dir_str:
                tmp_dir = Path(tmp_dir_str)
                orig_root = mod.PROJECT_ROOT
                orig_html = mod.HTML_PATH
                try:
                    mod.PROJECT_ROOT = tmp_dir
                    mod.HTML_PATH = tmp_dir / "docs" / "index.html"
                    self.assertIsNone(mod._resolve_appdeploy_api_key(tmp_dir))
                    with self.assertRaises(RuntimeError) as ctx:
                        mod.deploy()
                    self.assertIn("APPDEPLOY_API_KEY is not configured in environment or .env", str(ctx.exception))

                    synthetic_dotenv_secret = "ak_test_dotenv_" + "001122334455"
                    (tmp_dir / ".env").write_text(
                        f'# sample config\nAPPDEPLOY_API_KEY="{synthetic_dotenv_secret}"\n',
                        encoding="utf-8",
                    )
                    self.assertEqual(mod._resolve_appdeploy_api_key(tmp_dir), synthetic_dotenv_secret)

                    synthetic_env_secret = "ak_test_envvar_" + "aabbccddeeff"
                    os.environ["APPDEPLOY_API_KEY"] = synthetic_env_secret
                    self.assertEqual(mod._resolve_appdeploy_api_key(tmp_dir), synthetic_env_secret)

                    (tmp_dir / "docs").mkdir(parents=True, exist_ok=True)
                    (tmp_dir / "docs" / "index.html").write_text("<html><body>Orbit</body></html>", encoding="utf-8")

                    captured = {}

                    class _FakeResp:
                        status_code = 200

                        def json(self):
                            return {"ok": True}

                    class _FakeClient:
                        def __enter__(self):
                            return self

                        def __exit__(self, exc_type, exc, tb):
                            return False

                        def post(self, url, headers=None, json=None):
                            captured["url"] = url
                            captured["headers"] = headers
                            captured["json"] = json
                            return _FakeResp()

                    orig_factory = mod.create_guarded_httpx_client

                    def _fake_factory(**kwargs):
                        captured["factory_kwargs"] = kwargs
                        return _FakeClient()

                    mod.create_guarded_httpx_client = _fake_factory
                    stdout_buf = io.StringIO()
                    try:
                        with contextlib.redirect_stdout(stdout_buf):
                            res = mod.deploy()
                    finally:
                        mod.create_guarded_httpx_client = orig_factory

                    self.assertEqual(res, {"ok": True})
                    self.assertEqual(captured["url"], mod.ENDPOINT)
                    self.assertEqual(captured["headers"]["Authorization"], f"Bearer {synthetic_env_secret}")
                    self.assertIsInstance(captured["factory_kwargs"]["roe_engine"], PublicHostOnlyRoE)
                    self.assertNotIn(synthetic_env_secret, stdout_buf.getvalue())
                    self.assertNotIn(synthetic_dotenv_secret, stdout_buf.getvalue())
                finally:
                    mod.PROJECT_ROOT = orig_root
                    mod.HTML_PATH = orig_html
        finally:
            os.environ.pop("APPDEPLOY_API_KEY", None)
            if saved_key is not None:
                os.environ["APPDEPLOY_API_KEY"] = saved_key

    def test_index_html_cta_stripe_and_signup_attribution(self):
        """Verify landing/docs index.html preserve Stripe base links and attribute CTAs cleanly."""
        import json
        import re
        import shutil
        import textwrap

        node_exe = shutil.which("node")
        self.assertIsNotNone(node_exe, "Node.js is required to exercise index.html CTA attribution")

        expected_links = (
            "https://buy.stripe.com/8x29ASgAk3V15X2el6cs801",
            "https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800",
            "https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802",
        )
        landing_html = (REPO_ROOT / "landing" / "index.html").read_text(encoding="utf-8")
        docs_html = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(landing_html, docs_html, "landing/index.html and docs/index.html must be synced")
        for url in expected_links:
            self.assertIn(url, landing_html)

        scripts = re.findall(r"<script>([\s\S]*?)</script>", landing_html)
        target_scripts = [s for s in scripts if "decorateStripeAndSignupLinks" in s]
        self.assertEqual(len(target_scripts), 1, "Expected inline script defining decorateStripeAndSignupLinks")
        inline_script = target_scripts[0]

        harness = textwrap.dedent(
            """
            const assert = require('assert');
            const vm = require('vm');
            const scriptSource = __INLINE_SCRIPT__;

            function makeEl(id, initialHref) {
                const attrs = {};
                if (initialHref !== undefined) attrs.href = initialHref;
                return {
                    id,
                    value: '',
                    href: initialHref || '',
                    textContent: '',
                    innerHTML: '',
                    className: '',
                    classList: { add() {}, remove() {}, contains() { return false; } },
                    addEventListener() {},
                    scrollIntoView() {},
                    getAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null; },
                    setAttribute(name, val) {
                        attrs[name] = String(val);
                        if (name === 'href') this.href = String(val);
                    },
                };
            }

            const storage = new Map();
            const links = {
                heroStripe: makeEl('heroStripe', 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800'),
                roiRecommendedCta: makeEl('roiRecommendedCta', 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800'),
                starterStripe: makeEl('starterStripe', 'https://buy.stripe.com/8x29ASgAk3V15X2el6cs801'),
                growthStripe: makeEl('growthStripe', 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800'),
                proStripe: makeEl('proStripe', 'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802'),
                navSignup: makeEl('navSignup', 'signup.html'),
                starterSignup: makeEl('starterSignup', 'signup.html?tier=starter'),
                growthSignup: makeEl('growthSignup', 'signup.html?tier=growth'),
                proSignup: makeEl('proSignup', 'signup.html?tier=pro'),
            };
            const byId = {
                radarAgencyName: makeEl('radarAgencyName'),
                customAgencyName: makeEl('customAgencyName'),
                portalAgencyNameInput: makeEl('portalAgencyNameInput'),
                brandNameDisplay: makeEl('brandNameDisplay'),
                portalMockupAgencyName: makeEl('portalMockupAgencyName'),
                portalMockupUrlDisplay: makeEl('portalMockupUrlDisplay'),
                roiClientCount: Object.assign(makeEl('roiClientCount'), { value: '25' }),
                roiRetainerFee: Object.assign(makeEl('roiRetainerFee'), { value: '250' }),
                roiRecommendedCta: links.roiRecommendedCta,
                roiRecommendedCtaText: makeEl('roiRecommendedCtaText'),
            };

            const stripeLinks = [links.heroStripe, links.roiRecommendedCta, links.starterStripe, links.growthStripe, links.proStripe];
            const signupLinks = [links.navSignup, links.starterSignup, links.growthSignup, links.proSignup];

            const mockDocument = {
                getElementById(id) { return byId[id] || null; },
                addEventListener() {},
                querySelectorAll(sel) {
                    if (sel === 'a[href^="https://buy.stripe.com/"]') {
                        return stripeLinks.filter(l => (l.getAttribute('href') || l.href).startsWith('https://buy.stripe.com/'));
                    }
                    if (sel === 'a[href^="signup.html"]') {
                        return signupLinks.filter(l => (l.getAttribute('href') || l.href).startsWith('signup.html'));
                    }
                    return [];
                },
                body: { classList: { add() {}, remove() {} } },
            };

            const sandbox = {
                window: { location: { hash: '' }, addEventListener() {} },
                document: mockDocument,
                localStorage: {
                    getItem(k) { return storage.has(k) ? storage.get(k) : null; },
                    setItem(k, v) { storage.set(k, String(v)); },
                },
                navigator: {},
                setTimeout: (fn) => 0,
                encodeURIComponent,
                URLSearchParams,
            };
            sandbox.window.document = mockDocument;
            vm.createContext(sandbox);
            vm.runInContext(scriptSource, sandbox);

            // 1. Decorate via syncAgencyName
            sandbox.syncAgencyName('Acme Digital Studio');
            for (const link of stripeLinks) {
                const href = link.getAttribute('href');
                assert(href.endsWith('?client_reference_id=acme-digital-studio'), 'Unexpected stripe href: ' + href);
                assert.strictEqual(href.split('?').length, 2, 'Double question mark in: ' + href);
            }
            assert.strictEqual(links.navSignup.getAttribute('href'), 'signup.html?agency=Acme%20Digital%20Studio');
            assert.strictEqual(links.starterSignup.getAttribute('href'), 'signup.html?tier=starter&agency=Acme%20Digital%20Studio');
            assert.strictEqual(links.growthSignup.getAttribute('href'), 'signup.html?tier=growth&agency=Acme%20Digital%20Studio');
            assert.strictEqual(links.proSignup.getAttribute('href'), 'signup.html?tier=pro&agency=Acme%20Digital%20Studio');

            // 2. Replace agency cleanly without duplicate params or double '?'
            sandbox.syncAgencyName('Orbit Ops & Co!');
            for (const link of stripeLinks) {
                const href = link.getAttribute('href');
                assert(href.endsWith('?client_reference_id=orbit-ops-co'), 'Expected replaced slug: ' + href);
                assert.strictEqual(href.split('?').length, 2);
            }
            assert.strictEqual(links.starterSignup.getAttribute('href'), 'signup.html?tier=starter&agency=Orbit%20Ops%20%26%20Co!');

            // 3. ROI calculator preserves agency attribution across all 3 tiers
            byId.roiClientCount.value = '10';
            sandbox.updateRoiCalculator();
            assert.strictEqual(
                links.roiRecommendedCta.getAttribute('href'),
                'https://buy.stripe.com/8x29ASgAk3V15X2el6cs801?client_reference_id=orbit-ops-co'
            );
            byId.roiClientCount.value = '55';
            sandbox.updateRoiCalculator();
            assert.strictEqual(
                links.roiRecommendedCta.getAttribute('href'),
                'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802?client_reference_id=orbit-ops-co'
            );

            // 4. Clearing agency strips client_reference_id & agency while preserving tier param
            sandbox.syncAgencyName('');
            sandbox.updateRoiCalculator();
            assert.strictEqual(
                links.roiRecommendedCta.getAttribute('href'),
                'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802'
            );
            assert.strictEqual(links.navSignup.getAttribute('href'), 'signup.html');
            assert.strictEqual(links.starterSignup.getAttribute('href'), 'signup.html?tier=starter');
            console.log('INDEX_CTA_ATTRIBUTION_OK');
            """
        ).replace("__INLINE_SCRIPT__", json.dumps(inline_script))

        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir_str:
            harness_path = Path(tmp_dir_str) / "cta_harness.js"
            harness_path.write_text(harness, encoding="utf-8")
            proc = subprocess.run(
                [node_exe, str(harness_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
            )
        self.assertEqual(
            proc.returncode,
            0,
            f"Node CTA attribution harness failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )
        self.assertIn("INDEX_CTA_ATTRIBUTION_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
