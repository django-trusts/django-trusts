"""#199 / #189 B1: backend principal, object, and ownership fail-closed.

Public ``TrustModelBackendMixin`` methods, ``set_condition_lookup``,
and ``TrustsImplementationConfig.ready()`` only. Does not invent a
``Permission``-instance ``has_perm`` contract, assert
``_trust_perm_cache`` shape, or patch private match/compiler helpers.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import SimpleTestCase, TestCase, override_settings

import tests as tests_module
from tests.backends import HostTrustModelBackend
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import TrustsImplementationConfig, implementation_for_path
from trusts.core import TrustsConfigurationError


PERM = 'myapp.change_document'
FILTERED = 'myapp.change_document:non_confidential'
MODEL_BACKEND = 'django.contrib.auth.backends.ModelBackend'
HOST = 'tests.backends.HostTrustModelBackend'


class _UnauthenticatedPrincipal(object):
    """Principal that is not anonymous, not inactive, and not authenticated."""

    is_authenticated = False
    is_anonymous = False
    is_active = True


class NonMixinOwnerConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_199_nonmixin'
    trusts_backend_paths = (MODEL_BACKEND,)


class _AppsView(object):
    def __init__(self, configs, ready=True):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return tuple(self._configs)


def _bind(config_cls, ready=True):
    config = config_cls('tests', tests_module)
    view = _AppsView([config], ready=ready)
    config.apps = view
    return config


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


class BackendFailClosedPrincipalObjectTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-199', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.document = Document.objects.create(title='granted-199')
        DocumentGrant.objects.create(
            document=self.document,
            user=self.alice,
            permission=self.change,
        )
        self.host = HostTrustModelBackend()
        self.document_backend = DocumentBackend()

    def test_none_and_unauthenticated_principals_deny_at_zero_sql(self):
        inactive = get_user_model().objects.get(pk=self.alice.pk)
        inactive.is_active = False
        unauthenticated = _UnauthenticatedPrincipal()
        anonymous = AnonymousUser()

        with self.assertNumQueries(0):
            self.assertFalse(
                self.document_backend.has_perm(None, PERM, self.document),
            )
            self.assertFalse(self.host.has_perm(None, PERM, self.document))
            self.assertFalse(
                self.document_backend.has_perm(
                    unauthenticated, PERM, self.document,
                ),
            )
            self.assertFalse(
                self.host.has_perm(unauthenticated, PERM, self.document),
            )
            self.assertFalse(
                self.document_backend.has_perm(inactive, PERM, self.document),
            )
            self.assertFalse(
                self.document_backend.has_perm(anonymous, PERM, self.document),
            )

    def test_unsupported_object_enumeration_is_empty_at_zero_sql(self):
        mapping = {'pk': self.document.pk, 'title': self.document.title}
        other = [self.document]

        with self.assertNumQueries(0):
            self.assertEqual(
                self.document_backend.get_group_permissions(self.alice, mapping),
                set(),
            )
            self.assertEqual(
                self.host.get_group_permissions(self.alice, mapping),
                set(),
            )
            self.assertEqual(
                self.document_backend.get_group_permissions(self.alice, other),
                set(),
            )
            self.assertEqual(
                self.document_backend.get_all_permissions(self.alice, mapping),
                set(),
            )
            self.assertEqual(
                self.document_backend.get_all_permissions(self.alice, other),
                set(),
            )
            self.assertFalse(
                self.document_backend.has_perm(self.alice, PERM, mapping),
            )

    def test_owned_unbound_named_condition_raises_on_instance_at_zero_sql(self):
        registry = implementation_for_path(DOCUMENT_BACKEND).configured_backend().registry
        previous = registry.condition_lookup
        qs = Document.objects.filter(pk=self.document.pk)
        try:
            registry.set_condition_lookup(None)
            with self.assertNumQueries(0):
                with self.assertRaises(AttributeError) as ctx:
                    self.document_backend.has_perm(
                        self.alice, FILTERED, self.document,
                    )
                self.assertIn('not associate', str(ctx.exception))
                self.assertIn('non_confidential', str(ctx.exception))
                self.assertFalse(
                    self.host.has_perm(self.alice, FILTERED, self.document),
                )
                with self.assertRaises(AttributeError):
                    self.alice.has_perm(FILTERED, self.document)
                self.assertFalse(
                    self.document_backend.has_perm(self.alice, FILTERED, qs),
                )
        finally:
            registry.set_condition_lookup(previous)
        self.assertIs(registry.condition_lookup, previous)

        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(
                    self.alice, FILTERED, self.document,
                ),
            )

    def test_supported_grant_stays_one_sql_and_superuser_is_not_a_shortcut(self):
        admin = get_user_model().objects.create_user('admin-199', password='x')
        admin.is_superuser = True
        admin.save(update_fields=['is_superuser'])

        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, PERM, self.document),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(admin, PERM, self.document),
            )


class ImplementationOwnershipReadyTest(TestCase):
    def test_owned_non_mixin_path_fails_at_ready_with_zero_sql(self):
        config = _bind(NonMixinOwnerConfig, ready=False)
        self.assertEqual(config.registries, {})
        with override_settings(AUTHENTICATION_BACKENDS=(MODEL_BACKEND, HOST)):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    config.ready()
        self.assertIn('not a TrustModelBackendMixin', str(ctx.exception))
        self.assertIn(MODEL_BACKEND, str(ctx.exception))
        self.assertEqual(config.registries, {})


class Issue199SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue199', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue199', PAIR_KERNEL_SUITE)
