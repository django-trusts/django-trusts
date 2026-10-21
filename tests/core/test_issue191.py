"""#191 C3: Core no longer exposes the legacy request decorator family."""

from pathlib import Path

from django.test import SimpleTestCase

from trusts.decorators import authorization_required


ROOT = Path(__file__).resolve().parents[2]
LEGACY_NAMES = (
    'P',
    'R',
    'K',
    'G',
    'O',
    'permission_required',
    'request_passes_test',
)


class LegacyDecoratorFamilyRemovedTest(SimpleTestCase):
    def test_core_decorators_keep_only_the_trusts_guard(self):
        import trusts.decorators as decorators_mod

        self.assertIs(decorators_mod.authorization_required, authorization_required)
        for name in LEGACY_NAMES:
            self.assertFalse(hasattr(decorators_mod, name), name)
            with self.assertRaises(ImportError):
                exec('from trusts.decorators import %s' % name)

    def test_core_decorators_do_not_import_or_forward_to_zero(self):
        source = (ROOT / 'trusts' / 'decorators.py').read_text()
        self.assertNotIn('trusts.zero', source)
        self.assertNotIn('django-trusts-zero', source)
        self.assertNotIn('importlib', source)
        self.assertIn('def authorization_required(', source)
        for name in ('class P', 'class R', 'class K', 'class G', 'class O'):
            self.assertNotIn(name, source)
        self.assertNotIn('def permission_required(', source)
        self.assertNotIn('def request_passes_test(', source)


