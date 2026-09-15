"""#149 R5A: companion pin is the exact Zero candidate; wheel verifier checks HEAD."""

import importlib.util
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE


ROOT = Path(__file__).resolve().parents[2]
ZERO_CANDIDATE = '462c83b59edfb51011b4373e8214b2daaab7f500'
STALE_ZERO_38 = 'c7dc4f11f728ad3c4c22249e471daa4bf9849404'


def _load_companion_wheels():
    path = ROOT / 'scripts' / 'verify-companion-wheels.py'
    spec = importlib.util.spec_from_file_location('verify_companion_wheels', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _init_git_checkout(root):
    env = os.environ.copy()
    env['GIT_AUTHOR_NAME'] = 'R5A'
    env['GIT_AUTHOR_EMAIL'] = 'r5a@example.test'
    env['GIT_COMMITTER_NAME'] = 'R5A'
    env['GIT_COMMITTER_EMAIL'] = 'r5a@example.test'
    subprocess.run(['git', 'init'], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ['git', 'config', 'user.email', 'r5a@example.test'],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', 'config', 'user.name', 'R5A'],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / 'README').write_text('r5a probe\n', encoding='utf-8')
    subprocess.run(['git', 'add', 'README'], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ['git', '-c', 'commit.gpgsign=false', 'commit', '-m', 'r5a probe'],
        cwd=str(root),
        check=True,
        capture_output=True,
        env=env,
    )
    return subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'],
        text=True,
    ).strip()


class ExactZeroCandidatePinTest(SimpleTestCase):
    def test_suite_lists_this_module(self):
        self.assertIn('tests.core.test_issue149', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue149', PAIR_KERNEL_SUITE)

    def test_ci_and_verifier_pin_the_exact_zero_candidate(self):
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text()
        wheels = (ROOT / 'scripts' / 'verify-companion-wheels.py').read_text()
        self.assertIn('COMPANION_ZERO_SHA: %s' % ZERO_CANDIDATE, ci)
        self.assertIn("ZERO_HEAD = '%s'" % ZERO_CANDIDATE, wheels)
        self.assertNotIn(STALE_ZERO_38, ci)
        self.assertNotIn(STALE_ZERO_38, wheels)
        self.assertNotIn('Zero #38 register()', ci)
        self.assertNotIn('Zero #38 register()', wheels)
        wheels_mod = _load_companion_wheels()
        self.assertEqual(wheels_mod.ZERO_HEAD, ZERO_CANDIDATE)
        self.assertIn('assert_zero_checkout_matches_head(zero_root)', wheels)
        self.assertNotIn("print('zero_head', ZERO_HEAD)", wheels)

    def test_verifier_fails_when_checkout_head_does_not_match(self):
        wheels_mod = _load_companion_wheels()
        tmp = Path(tempfile.mkdtemp(prefix='trusts-r5a-mismatch-'))
        try:
            head = _init_git_checkout(tmp)
            self.assertNotEqual(head, ZERO_CANDIDATE)
            with self.assertRaises(SystemExit) as ctx:
                wheels_mod.assert_zero_checkout_matches_head(tmp)
            message = str(ctx.exception)
            self.assertIn(head, message)
            self.assertIn(ZERO_CANDIDATE, message)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_fails_when_checkout_is_not_git(self):
        wheels_mod = _load_companion_wheels()
        tmp = Path(tempfile.mkdtemp(prefix='trusts-r5a-nogit-'))
        try:
            with self.assertRaises(SystemExit) as ctx:
                wheels_mod.assert_zero_checkout_matches_head(tmp)
            self.assertIn(str(tmp), str(ctx.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_accepts_checkout_that_resolves_to_expected(self):
        wheels_mod = _load_companion_wheels()
        tmp = Path(tempfile.mkdtemp(prefix='trusts-r5a-match-'))
        try:
            head = _init_git_checkout(tmp)
            resolved = wheels_mod.assert_zero_checkout_matches_head(
                tmp,
                expected=head,
            )
            self.assertEqual(resolved, head)
            self.assertEqual(wheels_mod.resolved_zero_head(tmp), head)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
