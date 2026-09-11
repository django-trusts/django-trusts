"""#115: user-facing README and package metadata for the final core library.

Behavioral fragments are the same spellings as README.md. Structural
checks reject internal-status language and removed surfaces.
"""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.apps import isolate_live_registry, live_config
from tests.backends import HostTrustModelBackend
from tests.kernel_host.apps import HOST_BACKEND, KernelHostConfig
from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin
from trusts.core import Ref
from trusts.decorators import permission_required
from trusts.query import AuthorizedManager, AuthorizedQuerySet


ROOT = Path(__file__).resolve().parents[1]


def _readme_models():
    """Ordinary models copied into README.md."""
    User = get_user_model()

    class Document(models.Model):
        title = models.CharField(max_length=200)
        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class DocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Document, DocumentGrant


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


def _perm(codename):
    ct, _created = ContentType.objects.get_or_create(
        app_label='trusts_tests', model='document',
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ReadmeExampleAuthorizationTest(TransactionTestCase):
    def setUp(self):
        self.Document, self.DocumentGrant = _readme_models()
        self._table_cm = _tables(self.Document, self.DocumentGrant)
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-115', password='x')
        self.bob = User.objects.create_user(username='bob-115', password='x')
        self.change_permission = _perm('change_document')
        self.document = self.Document.objects.create(title='readme')
        self.other = self.Document.objects.create(title='other')
        self.registry = self._register()
        self.live = live_config()
        self._saved = dict(self.live.registries)
        isolate_live_registry(self.live, self.registry)
        self.DocumentGrant.objects.create(
            document=self.document,
            user=self.alice,
            permission=self.change_permission,
        )

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self._saved)
        self._table_cm.__exit__(None, None, None)

    def _register(self):
        from trusts.core import TrustsRegistry

        registry = TrustsRegistry()
        j = Ref(self.DocumentGrant)
        registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        return registry

    def test_object_has_perm_and_authorized_queryset(self):
        self.assertTrue(
            self.alice.has_perm('trusts_tests.change_document', self.document),
        )
        self.assertFalse(
            self.bob.has_perm('trusts_tests.change_document', self.document),
        )
        self.assertFalse(
            self.alice.has_perm('trusts_tests.change_document', self.other),
        )
        self.assertFalse(
            self.alice.has_perm('trusts_tests.change_document'),
        )
        backend = HostTrustModelBackend()
        self.assertTrue(
            backend.has_perm(
                self.alice, 'trusts_tests.change_document', self.document,
            ),
        )
        qs = self.Document.objects.authorized(self.alice, self.change_permission)
        self.assertIsInstance(qs, AuthorizedQuerySet)
        self.assertEqual(
            set(qs.values_list('pk', flat=True)),
            {self.document.pk},
        )
        self.assertFalse(
            self.Document.objects.authorized(
                self.bob, self.change_permission,
            ).exists()
        )

    def test_permission_required_guard_uses_has_perms(self):
        group = Group.objects.create(name='readme-115')
        request = HttpRequest()
        request.user = self.alice
        request.META['SERVER_NAME'] = 'testserver'
        request.META['SERVER_PORT'] = '80'
        mock = Mock(return_value='ok')
        has_perms = Mock(return_value=True)
        self.alice.has_perms = has_perms
        decorated = permission_required(
            'auth.read_group',
            fieldlookups_kwargs={'pk': 'pk'},
        )(mock)
        response = decorated(request, pk=group.pk)
        self.assertEqual(response, 'ok')
        self.assertTrue(has_perms.called)
        self.assertEqual(has_perms.call_args[0][0], ('auth.read_group',))
        items = has_perms.call_args[0][1]
        self.assertEqual(items.get().pk, group.pk)


class ReadmeHostSurfaceTest(SimpleTestCase):
    def test_verified_host_spellings(self):
        self.assertTrue(issubclass(HostTrustModelBackend, TrustModelBackendMixin))
        self.assertEqual(HOST_BACKEND, 'tests.backends.HostTrustModelBackend')
        self.assertTrue(issubclass(KernelHostConfig, TrustsImplementationConfig))
        self.assertEqual(KernelHostConfig.trusts_backend_paths, (HOST_BACKEND,))
        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )
        owner = live_config()
        self.assertIs(type(owner), KernelHostConfig)
        labels = {config.label for config in owner.apps.get_app_configs()}
        names = {config.name for config in owner.apps.get_app_configs()}
        self.assertNotIn('trusts', labels)
        self.assertNotIn('trusts', names)


class UserFacingReadmeAndPackageTest(SimpleTestCase):
    def test_license_notice_is_beedesk_2015_2026(self):
        text = (ROOT / 'LICENSE').read_text()
        self.assertIn('Copyright (c) 2015-2026, BeeDesk, Inc.', text)
        self.assertNotIn('and contributors', text.split('THIS SOFTWARE')[0])
        pyproject = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('license = "BSD-2-Clause"', pyproject)
        self.assertIn('readme = "README.md"', pyproject)
        self.assertNotIn('readme = "DEV.md"', pyproject)
        self.assertIn('version = "1.0.0.dev3"', pyproject)
        self.assertNotIn(
            'multiple organizations and object-level permission settings',
            pyproject,
        )
        self.assertNotIn('"organizations"', pyproject)

    def test_user_readme_is_not_internal_status(self):
        readme = (ROOT / 'README.md').read_text()
        forbidden = (
            'Step I',
            'Step II',
            'Step III',
            'C1',
            'C2',
            'Z1',
            'pair pin',
            'baton',
            'code budget',
            'kernel_config',
            'trusts.core_backends',
            'from trusts.backends import TrustModelBackend\n',
            'from trusts.models import Trust',
            'trusts.models.Trust',
            '1.0.0.dev1',
            '1.0.0.dev2',
            '1.0.0.dev3',
            '11058641',
            'f0b25c55',
            '94e0fa1',
        )
        offenders = [needle for needle in forbidden if needle in readme]
        self.assertEqual(offenders, [])
        self.assertNotIn("'trusts',", readme)
        self.assertIn("Do **not** list `'trusts'` in `INSTALLED_APPS`", readme)
        self.assertIn('non-standalone Python dependency', readme)
        self.assertIn('TrustsImplementationConfig', readme)
        self.assertIn('from trusts.backends import TrustModelBackendMixin', readme)
        self.assertIn('from trusts.core import Ref', readme)
        self.assertIn("'tests.kernel_host.apps.KernelHostConfig'", readme)
        self.assertIn("'tests.backends.HostTrustModelBackend'", readme)
        self.assertIn('user.has_perm', readme)
        self.assertIn('Document.objects.authorized', readme)
        self.assertIn('permission_required', readme)
        self.assertIn('fieldlookups_kwargs', readme)
        self.assertIn('django-trusts-zero', readme)
        self.assertIn('django-trusts-gh-permissions', readme)
        self.assertIn('migrates.md', readme)
        self.assertIn('forthcoming', readme.lower())
        self.assertIn('not complete', readme.lower())
        self.assertIn('BeeDesk, Inc.', readme)
        self.assertIn('DEV.md', readme)
        dev = (ROOT / 'DEV.md').read_text()
        self.assertIn('internal', dev[:800].lower())
        self.assertIn('development', dev[:800].lower())
        self.assertIn('README.md', dev[:800])

    def test_readme_examples_match_verified_settings(self):
        settings_text = (ROOT / 'tests' / 'settings.py').read_text()
        self.assertIn("'tests.kernel_host.apps.KernelHostConfig'", settings_text)
        self.assertIn("'tests.backends.HostTrustModelBackend'", settings_text)
        self.assertNotIn("'trusts',", settings_text)
        backends = (ROOT / 'tests' / 'backends.py').read_text()
        self.assertIn(
            'class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):',
            backends,
        )
        host = (ROOT / 'tests' / 'kernel_host' / 'apps.py').read_text()
        self.assertIn('class KernelHostConfig(TrustsImplementationConfig):', host)
        self.assertIn("HOST_BACKEND = 'tests.backends.HostTrustModelBackend'", host)
        readme = (ROOT / 'README.md').read_text()
        self.assertIn(
            'class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):',
            readme,
        )
        self.assertIn('class KernelHostConfig(TrustsImplementationConfig):', readme)
        self.assertIn(
            "HOST_BACKEND = 'tests.backends.HostTrustModelBackend'",
            readme,
        )
        self.assertIn(
            'user.has_perm(\'trusts_tests.change_document\', document)',
            readme,
        )
        self.assertIn(
            'Document.objects.authorized(user, change_permission)',
            readme,
        )
        self.assertIn(
            "fieldlookups_kwargs={'pk': 'pk'}",
            readme,
        )
        self.assertIn(
            "@permission_required('auth.read_group', fieldlookups_kwargs={'pk': 'pk'})",
            readme,
        )
