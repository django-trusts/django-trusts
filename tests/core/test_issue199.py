from tests.support import configured_catalog, unbound_named_filters
"""#199 / #189 B1: backend principal, object, and ownership fail-closed.

Public ``TrustModelBackendMixin`` methods and
``TrustsConfigMixin.ready()`` only. Does not invent a
``Permission``-instance ``has_perm`` contract, assert
``_trust_perm_cache`` shape, or patch private match/compiler helpers.
"""


from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

import tests as tests_module
from tests.kernel_host.backends import HostTrustModelBackend
from tests.backends import MixinOnlyBackend
from tests.core import KernelHostRequiredMixin
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import TrustsConfigMixin


PERM = 'myapp.change_document'
FILTERED = 'myapp.change_document:non_confidential'
MODEL_BACKEND = 'django.contrib.auth.backends.ModelBackend'
HOST = 'tests.kernel_host.backends.HostTrustModelBackend'


class _UnauthenticatedPrincipal(object):
    """Principal that is not anonymous, not inactive, and not authenticated."""

    is_authenticated = False
    is_anonymous = False
    is_active = True


class NonMixinOwnerConfig(TrustsConfigMixin):
    name = 'tests'
    label = 'trusts_impl_199_nonmixin'


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
        inactive.save(update_fields=['is_active'])
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
                self.document_backend.has_perm(anonymous, PERM, self.document),
            )
        self.assertFalse(
            self.document_backend.has_perm(inactive, PERM, self.document),
        )

    def test_unowned_backend_rejects_identity_before_registry(self):
        backend = MixinOnlyBackend()
        anonymous = AnonymousUser()
        unauthenticated = _UnauthenticatedPrincipal()
        with self.assertNumQueries(0):
                self.assertFalse(
                    backend.has_perm(None, PERM, self.document),
                )
                self.assertFalse(
                    backend.has_perm(anonymous, PERM, self.document),
                )
                self.assertFalse(
                    backend.has_perm(
                        anonymous, PERM, self.document, skip_is_active=True,
                    ),
                )
                self.assertFalse(
                    backend.has_perm(unauthenticated, PERM, self.document),
                )
                self.assertEqual(
                    backend.get_all_permissions(anonymous, self.document),
                    set(),
                )
                self.assertEqual(
                    backend.get_group_permissions(
                        unauthenticated, self.document,
                    ),
                    set(),
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

    def test_missing_named_condition_denies_on_instance_at_zero_sql(self):
        from tests.myapp.backends import DocumentBackend

        qs = Document.objects.filter(pk=self.document.pk)
        with unbound_named_filters(DocumentBackend):
            document_backend = DocumentBackend()
            with self.assertNumQueries(0):
                self.assertFalse(
                    document_backend.has_perm(
                        self.alice, FILTERED, self.document,
                    ),
                )
                self.assertFalse(
                    self.host.has_perm(self.alice, FILTERED, self.document),
                )
                self.assertFalse(self.alice.has_perm(FILTERED, self.document))
                self.assertFalse(
                    document_backend.has_perm(self.alice, FILTERED, qs),
                )

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
    def test_non_mixin_path_is_skipped_at_ready_with_zero_sql(self):
        from django.apps import apps

        from tests.support import read_catalog
        from trusts.backends import RELATIONSHIP_BACKEND_KEY, RelationshipBackend

        config = _bind(NonMixinOwnerConfig, ready=False)
        config.get_or_create_config(
            RELATIONSHIP_BACKEND_KEY, RelationshipBackend,
        )
        before = configured_catalog(HOST)
        self.assertFalse(hasattr(config, 'registries'))
        with override_settings(AUTHENTICATION_BACKENDS=(MODEL_BACKEND, HOST)):
            with self.assertNumQueries(0):
                config.ready()
        self.assertIs(configured_catalog(HOST), before)
        paths = [
            catalog.path
            for installed in apps.get_app_configs()
            if isinstance(installed, TrustsConfigMixin)
            for catalog in (read_catalog(installed),)
            if catalog is not None
        ]
        built = read_catalog(config)
        self.assertEqual(built.records, ())
        self.assertEqual(built.delegations, ())
        self.assertEqual(
            built.path,
            'tests.core.test_issue199.NonMixinOwnerConfig',
        )
        self.assertNotIn(MODEL_BACKEND, paths)
        self.assertFalse(hasattr(config, 'registries'))
        self.assertFalse(hasattr(config, 'trusts_backend_paths'))


