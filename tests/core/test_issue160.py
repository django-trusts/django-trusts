"""#160: DEV.md must not reintroduce transitional dev-version framing."""

from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]


class DevMdTransitionalFramingTest(SimpleTestCase):
    def test_dev_md_is_0x_versus_current_without_dev_pins(self):
        dev = (ROOT / 'DEV.md').read_text()
        forbidden = (
            '1.0.0.dev3',
            '1.0.0.dev0',
            'django-trusts==',
            'django-trusts-zero==',
            'STAGE 1',
            'STAGE 2',
            'STAGE 3',
            'Stage I',
            'Stage II',
            'Stage III',
            '11058641',
            'f0b25c55',
            '73b74b42',
            'final core-library cut',
            'final core cut',
            'not a production 1.0',
            'not a published PyPI release',
            'not yet a published',
            '1.0.0rc1',
            'rc1',
            'Python 3.12',
            'Django 6.1',
            'Django>=6.1',
        )
        offenders = [needle for needle in forbidden if needle in dev]
        self.assertEqual(offenders, [])
        self.assertNotRegex(dev, r'(?i)\b1\.0\.0\b')
        self.assertIn('0.x', dev)
        self.assertIn('schema-neutral Core', dev)
        self.assertIn('django-trusts-zero', dev)
        self.assertIn("do **not** list `'trusts'` in", dev)
        self.assertIn('INSTALLED_APPS', dev)
        self.assertIn('no Django `AppConfig`', dev)
        self.assertIn('docs/support-matrix.md', dev)
        self.assertIn('.github/workflows/ci.yml', dev)
        self.assertIn('README.md', dev)
        self.assertIn('migrates.md', dev)
        self.assertIn('docs/legacy-baseline.md', dev)
        self.assertIn('python -m pip install .', dev)
        self.assertIn('python -m pip install -e ".[test]"', dev)
        self.assertIn('python -m tests.runtests', dev)
        self.assertIn('python -m django check --settings=tests.settings', dev)
        self.assertTrue((ROOT / 'docs' / 'support-matrix.md').is_file())
        self.assertTrue((ROOT / 'docs' / 'legacy-baseline.md').is_file())
        self.assertTrue((ROOT / 'docs' / 'development-version.md').is_file())
        self.assertTrue((ROOT / 'README.md').is_file())
        self.assertTrue((ROOT / 'migrates.md').is_file())
        self.assertTrue((ROOT / '.github' / 'workflows' / 'ci.yml').is_file())
