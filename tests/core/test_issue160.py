"""#160: shallow DEV.md pass. No transitional *.dev / staged-pair framing."""

import re
from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_LINK = re.compile(r'\[[^\]]+\]\(([^)]+)\)')
PACKAGE_VERSION = re.compile(r'(?<![\d.])\d+\.\d+\.\d+(?:(?:\.dev|rc|a|b)\d+)?')
PAIRING_SHA = re.compile(r'\b[0-9a-f]{40}\b')


class DevMdTransitionalFramingTest(SimpleTestCase):
    def setUp(self):
        self.dev = (ROOT / 'DEV.md').read_text()
        self.pyproject = (ROOT / 'pyproject.toml').read_text()

    def test_dev_md_rejects_transitional_dev_and_stage_pairing(self):
        forbidden = (
            '1.0.0.dev3',
            '1.0.0.dev0',
            '1.0.0.dev1',
            '1.0.0.dev2',
            '1.0.0rc1',
            'django-trusts==',
            'django-trusts-zero==',
            'final core-library cut',
            'final core cut',
            'development-staircase',
            'development-line identifier',
            'Current pairing',
            'STAGE 1',
            'STAGE 2',
            'STAGE 3',
            'Stage I',
            'Stage II',
            'Stage III',
            'Step I',
            'Step II',
            'Step III',
            '11058641',
            'f0b25c55',
            '73b74b42',
            '94e0fa1',
            'not yet a published production 1.0',
            'not a published PyPI release',
            'not a published production',
            'Django>=',
            'Python 3.12',
            'Python 3.13',
            'Python 3.14',
            'Django 6.1',
        )
        offenders = [needle for needle in forbidden if needle in self.dev]
        self.assertEqual(offenders, [])
        self.assertEqual(PACKAGE_VERSION.findall(self.dev), [])
        self.assertEqual(PAIRING_SHA.findall(self.dev), [])

    def test_dev_md_keeps_durable_zero_x_versus_current_core(self):
        self.assertIn('internal', self.dev[:800].lower())
        self.assertIn('development', self.dev[:800].lower())
        self.assertIn('README.md', self.dev[:800])
        self.assertIn('0.x', self.dev)
        self.assertIn('current Core', self.dev)
        self.assertIn('schema-neutral', self.dev)
        self.assertIn('django-trusts-zero', self.dev)
        self.assertIn('continuation/bridge', self.dev)
        self.assertIn('not itself a Django app', self.dev)
        self.assertIn('owns no concrete permission schema', self.dev)
        self.assertIn("Do **not** list `'trusts'` in `INSTALLED_APPS`", self.dev)
        self.assertIn('TrustModelBackendMixin', self.dev)
        self.assertIn('docs/legacy-baseline.md', self.dev)
        self.assertIn('BeeDesk, Inc.', self.dev)
        self.assertIn('BSD-2-Clause', self.dev)

    def test_dev_md_links_and_contributor_commands_resolve(self):
        required = (
            ROOT / 'README.md',
            ROOT / 'docs' / 'source' / 'index.rst',
            ROOT / 'docs' / 'support-matrix.md',
            ROOT / 'docs' / 'legacy-baseline.md',
            ROOT / 'migrates.md',
            ROOT / '.github' / 'workflows' / 'ci.yml',
            ROOT / 'LICENSE',
        )
        for path in required:
            self.assertTrue(path.is_file(), path)

        missing = []
        for href in MARKDOWN_LINK.findall(self.dev):
            target = href.split('#', 1)[0].strip()
            if not target or target.startswith(('http://', 'https://')):
                continue
            resolved = (ROOT / target).resolve()
            if not resolved.exists():
                missing.append(href)
        self.assertEqual(missing, [])
        self.assertIn(
            'https://github.com/django-trusts/django-trusts-zero',
            self.dev,
        )

        self.assertIn('python -m pip install -e ".[test]"', self.dev)
        self.assertIn('python -m tests.runtests', self.dev)
        self.assertIn(
            'python -m django check --settings=tests.settings',
            self.dev,
        )
        self.assertIn('[project.optional-dependencies]', self.pyproject)
        self.assertIn('coverage', self.pyproject)
        self.assertIn('"Django>=', self.pyproject)
        self.assertNotIn('"Django>=', self.dev)
