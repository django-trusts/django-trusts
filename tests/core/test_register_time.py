"""Register-time checks, ready() for deferred cases, and dotless has_perm."""

import inspect
import subprocess
import sys
import traceback

from django.contrib.auth import get_user_model
from django.test import TestCase

from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import TrustsConfigMixin
from trusts.errors import TrustsConfigurationError


class _Probe(TrustsConfigMixin):
    name = 'tests.core'
    label = 'register_time_probe'
    default = False


def _probe():
    import tests.core as tests_core
    return _Probe('tests.core', tests_core)


def _recorder(config):
    from trusts.backends import RELATIONSHIP_BACKEND_KEY, RelationshipBackend
    return config.get_or_create_config(
        RELATIONSHIP_BACKEND_KEY, RelationshipBackend,
    ).recorder


def _grant(**kwargs):
    base = dict(
        trust=DocumentGrant,
        user='user',
        permission='permission',
        content='document',
    )
    base.update(kwargs)
    return base


class RegisterTimeCheckTest(TestCase):

    def test_duplicate_raises_at_the_register_call(self):
        config = _probe()
        _recorder(config).register(**_grant())
        line = inspect.currentframe().f_lineno + 2
        try:
            _recorder(config).register(**_grant())
        except TrustsConfigurationError as exc:
            frames = traceback.extract_tb(exc.__traceback__)
            message = str(exc)
        else:
            self.fail('Duplicate registration was not raised')
        self.assertTrue(any(frame.lineno == line for frame in frames))
        self.assertIn('Duplicate registration', message)

    def test_user_override_after_register_raises(self):
        config = _probe()
        _recorder(config).register(**_grant())
        with self.assertRaises(TrustsConfigurationError) as caught:
            _recorder(config).set_user_condition(
                'active', lambda user: user.is_active,
            )
        self.assertIn('before register()', str(caught.exception))
        with self.assertRaises(TrustsConfigurationError) as caught:
            _recorder(config).set_user_override(
                'active', lambda user: user.is_active,
            )
        self.assertIn('before register()', str(caught.exception))

    def test_bad_condition_raises_at_register(self):
        config = _probe()
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as caught:
                _recorder(config).register(**_grant(
                    condition=lambda trust: trust.user + trust.permission,
                ))
        self.assertNotIn('frozen', str(caught.exception).lower())

    def test_missing_field_is_raised_by_ready(self):
        config = _probe()
        _recorder(config).register(**_grant(content='not_a_field'))
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.ready()
        self.assertIn('missing field', str(caught.exception))

    def test_ready_raises_when_no_backend_resolves_to_the_app(self):
        config = _probe()
        _recorder(config).register(**_grant())
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as caught:
                config.ready()
        message = str(caught.exception)
        self.assertIn(
            'Trusts app register_time_probe has registrations but no '
            'AUTHENTICATION_BACKENDS entry resolves to it.',
            message,
        )
        self.assertIn(
            'List a backend whose module lives in this app.', message,
        )

    def test_register_after_ready_is_refused(self):
        with self.assertRaises(TrustsConfigurationError) as caught:
            DocumentBackend().get_registry().register(**_grant())
        self.assertEqual(
            str(caught.exception),
            'register refused: this registry is frozen. '
            'The catalog is already built.',
        )

    def test_app_config_import_does_not_load_the_compiler(self):
        script = (
            'import os\n'
            'os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"\n'
            'import sys\n'
            'from django.apps import apps\n'
            'before = {app: set(models) for app, models in apps.all_models.items()}\n'
            'import trusts.apps\n'
            'after = {app: set(models) for app, models in apps.all_models.items()}\n'
            'assert before == after, (before, after)\n'
            'assert apps.ready is False\n'
            'assert "trusts.compile.compilers" not in sys.modules\n'
            'print("apps-import-ok")\n'
        )
        completed = subprocess.run(
            [sys.executable, '-c', script],
            check=True, capture_output=True, text=True,
        )
        self.assertIn('apps-import-ok', completed.stdout)


class DotlessHasPermTest(TestCase):

    def test_dotless_permission_returns_false(self):
        from django.apps import apps
        if not apps.is_installed('tests.myapp'):
            self.skipTest('document app is not installed')
        user = get_user_model().objects.create_user('dotless-user', password='x')
        document = Document.objects.create(title='dotless')
        backend = DocumentBackend()
        with self.assertNumQueries(0):
            self.assertIs(backend.has_perm(user, 'nodot', document), False)
            self.assertIs(user.has_perm('nodot', document), False)

    def test_non_string_permission_returns_false(self):
        from django.apps import apps
        if not apps.is_installed('tests.myapp'):
            self.skipTest('document app is not installed')
        user = get_user_model().objects.create_user('bad-type-user', password='x')
        document = Document.objects.create(title='bad-type')
        backend = DocumentBackend()
        with self.assertNumQueries(0):
            self.assertIs(backend.has_perm(user, None, document), False)
            self.assertIs(backend.has_perm(user, 42, document), False)
            self.assertIs(user.has_perm(None, document), False)
            self.assertIs(user.has_perm(42, document), False)
