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
ZERO_PIN = 'd413bde81738966930c5733e3971bbfe8b350bf7'
STALE_ZERO_R5A = '462c83b59edfb51011b4373e8214b2daaab7f500'
STALE_ZERO_191 = '517307170f954f187da78c56e236ec1779c46e29'
STALE_ZERO_38 = 'c7dc4f11f728ad3c4c22249e471daa4bf9849404'


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

    def test_kernel_views_exercise_authorization_required(self):
        views = (ROOT / 'tests' / 'myapp' / 'views.py').read_text()
        self.assertIn('from trusts.decorators import authorization_required', views)
        self.assertIn('@authorization_required(Document, \'myapp.change_document\')', views)
        self.assertNotIn('permission_required', views)
        self.assertNotIn('fieldlookups', views)
        self.assertNotIn('trusts.zero', views)

    def test_companion_pin_is_exact_zero_candidate(self):
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text()
        wheels = (ROOT / 'scripts' / 'verify-companion-wheels.py').read_text()
        self.assertIn('COMPANION_ZERO_SHA: %s' % ZERO_PIN, ci)
        self.assertIn("ZERO_HEAD = '%s'" % ZERO_PIN, wheels)
        self.assertNotIn(STALE_ZERO_R5A, ci)
        self.assertNotIn(STALE_ZERO_R5A, wheels)
        self.assertNotIn(STALE_ZERO_191, ci)
        self.assertNotIn(STALE_ZERO_191, wheels)
        self.assertNotIn(STALE_ZERO_38, ci)
        self.assertNotIn(STALE_ZERO_38, wheels)
        self.assertNotIn('f50946f7112702a41bd63a3e044b44a0d4ec3297', ci)
        self.assertNotIn('f50946f7112702a41bd63a3e044b44a0d4ec3297', wheels)

    def test_docs_do_not_publish_the_legacy_core_import(self):
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        security = (ROOT / 'SECURITY_AUDIT.md').read_text()
        readme = (ROOT / 'README.md').read_text()
        for text in (rst, security, readme):
            self.assertNotIn('from trusts.decorators import permission_required', text)
            self.assertNotIn('from trusts.decorators import P', text)
        self.assertIn('from trusts.decorators import authorization_required', rst)
        self.assertIn('authorization_required(', security)

    def test_wheel_proof_rejects_legacy_symbols(self):
        script = (ROOT / 'scripts' / 'verify-wheel-install.py').read_text()
        self.assertIn('legacy decorator family absent', script)
        self.assertIn('permission_required', script)
        self.assertIn('request_passes_test', script)
        self.assertIn('library wheel still exposes trusts.decorators.', script)
        self.assertIn('library wheel decorators import Zero', script)
