"""#115: user-facing README and package metadata for the final core library.

The README consumer is ``tests.myapp``. Behavioral tests load that
exact documented configuration and use the owner ``ready()`` registry.
"""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import SimpleTestCase, TestCase
from django.test.utils import override_settings

from tests.apps import live_config
from tests.kernel_host.apps import KernelHostConfig
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from tests.myapp.settings import AUTHENTICATION_BACKENDS, INSTALLED_APPS
from tests.myapp.views import edit_document
from trusts.apps import TrustsImplementationConfig, implementation_for_path
from trusts.backends import TrustModelBackendMixin
from trusts.query import AuthorizedQuerySet


ROOT = Path(__file__).resolve().parents[2]


def _change_permission():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='change_document',
        defaults={'name': 'Can change document'},
    )
    return permission


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


class ReadmeExampleAuthorizationTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._auth_override = override_settings(
            AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS,
        )
        cls._auth_override.enable()
        cls._apps_override = override_settings(INSTALLED_APPS=INSTALLED_APPS)
        cls._apps_override.enable()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls._apps_override.disable()
        cls._auth_override.disable()

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-115', password='x')
        self.bob = User.objects.create_user(username='bob-115', password='x')
        self.change_permission = _change_permission()
        self.document = Document.objects.create(title='readme')
        self.other = Document.objects.create(title='other')
        DocumentGrant.objects.create(
            document=self.document,
            user=self.alice,
            permission=self.change_permission,
        )

    def test_ready_contributed_the_documented_ref_to_the_owner_registry(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        self.assertIs(type(owner), DocumentConfig)
        self.assertIsInstance(owner, TrustsImplementationConfig)
        handle = owner.configured_backend()
        self.assertEqual(handle.path, DOCUMENT_BACKEND)
        self.assertIs(handle.registry, owner.registries[DOCUMENT_BACKEND])
        self.assertTrue(handle.registry.records)
        self.assertIs(
            handle.registry.records[0].content_model,
            Document,
        )
        record = handle.registry.get_permission_condition_record(
            Document, 'non_confidential',
        )
        self.assertIsNotNone(record)
        self.assertEqual(
            record.expr.to_tuple(),
            (
                'ne',
                ('ref', 'object', ('confidential',)),
                ('const', True),
            ),
        )
        field = Document._meta.get_field('confidential')
        self.assertFalse(field.null)
        self.assertIs(field.default, False)

    def test_object_has_perm_and_authorized_queryset(self):
        self.assertTrue(
            self.alice.has_perm('myapp.change_document', self.document),
        )
        self.assertFalse(
            self.bob.has_perm('myapp.change_document', self.document),
        )
        self.assertFalse(
            self.alice.has_perm('myapp.change_document', self.other),
        )
        self.assertFalse(self.alice.has_perm('myapp.change_document'))
        backend = DocumentBackend()
        self.assertTrue(
            backend.has_perm(
                self.alice, 'myapp.change_document', self.document,
            ),
        )
        qs = Document.objects.authorized(self.alice, self.change_permission)
        self.assertIsInstance(qs, AuthorizedQuerySet)
        self.assertEqual(set(qs.values_list('pk', flat=True)), {self.document.pk})
        self.assertFalse(
            Document.objects.authorized(self.bob, self.change_permission).exists()
        )

    def test_documented_non_confidential_builder_overlays_the_grant(self):
        self.assertTrue(
            self.alice.has_perm(
                'myapp.change_document:non_confidential', self.document,
            ),
        )
        secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=secret,
            user=self.alice,
            permission=self.change_permission,
        )
        self.assertTrue(
            self.alice.has_perm('myapp.change_document', secret),
        )
        self.assertFalse(
            self.alice.has_perm(
                'myapp.change_document:non_confidential', secret,
            ),
        )
        owner = implementation_for_path(DOCUMENT_BACKEND)
        with self.assertNumQueries(0):
            owner.ready()

    def test_permission_required_uses_the_same_permission(self):
        allowed = edit_document(_request(self.alice), pk=self.document.pk)
        self.assertEqual(allowed, 'ok')
        with self.assertRaises(PermissionDenied):
            edit_document(_request(self.bob), pk=self.document.pk)
        with self.assertRaises(PermissionDenied):
            edit_document(_request(self.alice), pk=self.other.pk)


class ReadmeHostSurfaceTest(SimpleTestCase):
    def test_default_suite_still_has_no_trusts_app(self):
        owner = live_config()
        self.assertIs(type(owner), KernelHostConfig)
        labels = {config.label for config in owner.apps.get_app_configs()}
        names = {config.name for config in owner.apps.get_app_configs()}
        self.assertNotIn('trusts', labels)
        self.assertNotIn('trusts', names)
        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )
        self.assertTrue(issubclass(DocumentBackend, TrustModelBackendMixin))
        self.assertEqual(DOCUMENT_BACKEND, 'tests.myapp.backends.DocumentBackend')


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
            'pip install django-trusts',
            'auth.read_group',
            'tests.kernel_host',
            'HostTrustModelBackend',
            'isolate_live_registry',
        )
        offenders = [needle for needle in forbidden if needle in readme]
        self.assertEqual(offenders, [])
        self.assertNotIn("'trusts',", readme)
        self.assertIn("Do **not** list `'trusts'` in `INSTALLED_APPS`", readme)
        self.assertIn('non-standalone Python dependency', readme)
        self.assertIn('python -m pip install .', readme)
        self.assertIn('TrustsImplementationConfig', readme)
        self.assertIn('from trusts.backends import TrustModelBackendMixin', readme)
        self.assertNotIn('from trusts.core import Ref', readme)
        self.assertNotIn('.registry.register(', readme)
        self.assertIn('handle.register(', readme)
        self.assertIn('super().ready()', readme)
        self.assertIn("'tests.myapp.apps.DocumentConfig'", readme)
        self.assertIn("'tests.myapp.backends.DocumentBackend'", readme)
        self.assertIn("user.has_perm('myapp.change_document', document)", readme)
        self.assertIn('Document.objects.authorized(user, change_permission)', readme)
        self.assertIn("app_label = 'myapp'", readme)
        self.assertIn(
            "@permission_required('myapp.change_document', fieldlookups_kwargs={'pk': 'pk'})",
            readme,
        )
        self.assertIn('django-trusts-zero', readme)
        self.assertIn('django-trusts-gh-permissions', readme)
        self.assertIn('migrates.md', readme)
        self.assertIn('forthcoming', readme.lower())
        self.assertIn('not complete', readme.lower())
        self.assertIn('BeeDesk, Inc., 2015–2026 (BSD-2-Clause)', readme)
        self.assertIn('DEV.md', readme)
        dev = (ROOT / 'DEV.md').read_text()
        self.assertIn('internal', dev[:800].lower())
        self.assertIn('development', dev[:800].lower())
        self.assertIn('README.md', dev[:800])

    def test_readme_examples_match_consumer_modules(self):
        readme = (ROOT / 'README.md').read_text()
        settings_text = (ROOT / 'tests' / 'myapp' / 'settings.py').read_text()
        self.assertIn("'tests.myapp.apps.DocumentConfig'", settings_text)
        self.assertIn("'tests.myapp.backends.DocumentBackend'", settings_text)
        self.assertNotIn("'trusts',", settings_text)
        self.assertIn(settings_text.strip(), readme)
        backends = (ROOT / 'tests' / 'myapp' / 'backends.py').read_text()
        self.assertIn(
            'class DocumentBackend(TrustModelBackendMixin, ModelBackend):',
            backends,
        )
        self.assertIn(DOCUMENT_BACKEND, readme)
        apps = (ROOT / 'tests' / 'myapp' / 'apps.py').read_text()
        self.assertIn('class DocumentConfig(TrustsImplementationConfig):', apps)
        self.assertIn('super().ready()', apps)
        self.assertIn("content='document'", apps)
        self.assertIn("content='document'", readme)
        self.assertIn('handle.register(', apps)
        self.assertNotIn('from trusts.core import Ref', apps)
        self.assertNotIn('.registry.register(', apps)
        models_text = (ROOT / 'tests' / 'myapp' / 'models.py').read_text()
        self.assertIn('confidential = models.BooleanField(default=False)', models_text)
        self.assertIn('confidential = models.BooleanField(default=False)', readme)
        self.assertIn('handle.register_permission_condition(', readme)
        self.assertIn('o.confidential != True', readme)
        self.assertIn('handle.register_permission_condition(', apps)
        self.assertNotIn('RegistryConditionLookup', readme)
        self.assertNotIn('RegistryConditionLookup', apps)
        self.assertNotIn('trusts.conditions._ir', readme)
        self.assertNotIn('trusts.conditions._ir', apps)
        self.assertNotIn('set_condition_lookup', readme)
        self.assertNotIn('set_condition_lookup', apps)
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        self.assertNotIn('RegistryConditionLookup', rst)
        self.assertNotIn('trusts.conditions._ir', rst)
        self.assertNotIn('set_condition_lookup', rst)
        views = (ROOT / 'tests' / 'myapp' / 'views.py').read_text()
        self.assertIn(
            "@permission_required('myapp.change_document', fieldlookups_kwargs={'pk': 'pk'})",
            views,
        )
        default_settings = (ROOT / 'tests' / 'settings.py').read_text()
        self.assertIn("'tests.myapp.apps.DocumentConfig'", default_settings)
        self.assertIn("'tests.myapp.backends.DocumentBackend'", default_settings)
        self.assertNotIn("'trusts',", default_settings)

    def test_no_test_modules_in_installable_trusts_package(self):
        import importlib.util

        trusts_dir = ROOT / 'trusts'
        offenders = [
            path.relative_to(ROOT).as_posix()
            for path in trusts_dir.rglob('*.py')
            if path.name == 'tests.py' or path.name.startswith('test_')
            or path.parent.name in {'tests', 'test'}
        ]
        self.assertEqual(offenders, [])
        self.assertIsNone(importlib.util.find_spec('trusts.tests'))
        self.assertIsNone(importlib.util.find_spec('trusts.test_issue16'))
        self.assertIsNone(importlib.util.find_spec('trusts.test_issue115'))
        def _find_spec(name):
            try:
                return importlib.util.find_spec(name)
            except ModuleNotFoundError:
                return None

        self.assertIsNone(_find_spec('trusts.management'))
        self.assertIsNone(_find_spec('trusts.management.commands.create_trust_root'))
        self.assertTrue((ROOT / 'tests' / 'core' / 'test_issue16.py').is_file())
        self.assertFalse((ROOT / 'trusts' / 'tests.py').exists())
        self.assertFalse((ROOT / 'trusts' / 'management').exists())
