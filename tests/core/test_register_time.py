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
        config.recorder.register(**_grant())
        line = inspect.currentframe().f_lineno + 2
        try:
            config.recorder.register(**_grant())
        except TrustsConfigurationError as exc:
            frames = traceback.extract_tb(exc.__traceback__)
            message = str(exc)
        else:
            self.fail('Duplicate registration was not raised')
        self.assertTrue(any(frame.lineno == line for frame in frames))
        self.assertIn('Duplicate registration', message)

    def test_user_override_after_register_raises(self):
        config = _probe()
        config.recorder.register(**_grant())
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.recorder.set_user_condition(
                'active', lambda user: user.is_active,
            )
        self.assertIn('before register()', str(caught.exception))
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.recorder.set_user_override(
                'active', lambda user: user.is_active,
            )
        self.assertIn('before register()', str(caught.exception))

    def test_bad_condition_raises_at_register(self):
        config = _probe()
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as caught:
                config.recorder.register(**_grant(
                    condition=lambda trust: trust.user + trust.permission,
                ))
        self.assertNotIn('frozen', str(caught.exception).lower())

    def test_missing_field_is_raised_by_ready(self):
        config = _probe()
        config.recorder.register(**_grant(content='not_a_field'))
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.ready()
        self.assertIn('missing field', str(caught.exception))

    def test_register_after_ready_is_refused(self):
        config = _probe()
        config.recorder.register(**_grant())
        config.ready()
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.recorder.register(**_grant())
        self.assertEqual(
            str(caught.exception),
            'register refused: this registry is frozen. '
            'The catalog is already built.',
        )

    def test_listener_import_loads_no_models(self):
        script = (
            'import os\n'
            'os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"\n'
            'from django.apps import apps\n'
            'before = {app: set(models) for app, models in apps.all_models.items()}\n'
            'import trusts.compile.listener\n'
            'after = {app: set(models) for app, models in apps.all_models.items()}\n'
            'assert before == after, (before, after)\n'
            'assert apps.ready is False\n'
            'print("listener-import-ok")\n'
        )
        completed = subprocess.run(
            [sys.executable, '-c', script],
            check=True, capture_output=True, text=True,
        )
        self.assertIn('listener-import-ok', completed.stdout)


class DotlessHasPermTest(TestCase):

    def test_dotless_permission_returns_false(self):
        user = get_user_model().objects.create_user('dotless-user', password='x')
        document = Document.objects.create(title='dotless')
        backend = DocumentBackend()
        with self.assertNumQueries(0):
            self.assertIs(backend.has_perm(user, 'nodot', document), False)
            self.assertIs(user.has_perm('nodot', document), False)
