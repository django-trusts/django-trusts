"""#132 / #137 block A: unsupported content fails closed before SQL.

Public mixin and manager surfaces only. A registered Document
relationship stays live; an unregistered model is denied with zero
queries. Extra Trusts handles and named filters cannot manufacture a
plan. Private ``plan_for`` is not the assertion.
"""
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.test import TestCase, override_settings
from tests.apps import listed_relationship, configured_catalog, live_config, built_registries
from tests.backends import HostTrustModelBackend
from tests.core import KernelHostRequiredMixin
from tests.gh_permissions.models import Repository
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant

from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.factory import RegistryFactory
from trusts.query import AuthorizedQuerySet
PERM = 'myapp.change_document'

def _change_document():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(content_type=ct, codename='change_document', defaults={'name': 'Can change document'})
    return permission

def _extra_handle():
    """Second complete Document path plus an always-true filter on B."""
    handle = RegistryFactory(path='tests.core.issue132-extra')
    handle.register_public(trust=DocumentGrant, user='user', permission='permission', content='document')
    handle.register_permission_condition(Repository, 'always', lambda u, p, o: o.name != '')
    return handle

class UnsupportedContentPublicBoundaryTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-132', password='x')
        self.change = _change_document()
        self.document = Document.objects.create(title='registered')
        DocumentGrant.objects.create(document=self.document, user=self.alice, permission=self.change)
        self.report = Repository.objects.create(name='unregistered')
        from tests.kernel_host.apps import HOST_BACKEND
        self.host_handle = configured_catalog(HOST_BACKEND)
        self.document_handle = configured_catalog(DOCUMENT_BACKEND)
        self.host_backend = HostTrustModelBackend()
        self.document_backend = DocumentBackend()

    def _assert_public_deny(self):
        self.assertFalse(self.alice.has_perm(PERM, self.report))
        self.assertFalse(self.host_backend.has_perm(self.alice, PERM, self.report))
        self.assertFalse(self.document_backend.has_perm(self.alice, PERM, self.report))
        self.assertEqual(self.alice.get_all_permissions(self.report), set())
        self.assertEqual(self.alice.get_group_permissions(self.report), set())
        qs = Repository.objects.authorized(self.alice, self.change)
        self.assertIsInstance(qs, AuthorizedQuerySet)
        self.assertIs(qs.model, Repository)
        self.assertIsNone(qs._result_cache)
        self.assertEqual(list(qs), [])
        self.assertFalse(qs.exists())
        self.assertFalse(Repository.objects.authorized(self.alice, self.change, extra_q=Q(pk=self.report.pk)).exists())
        self.assertFalse(self.alice.has_perm('%s:non_confidential' % PERM, self.report))
        self.assertFalse(self.document_backend.has_perm(self.alice, '%s:non_confidential' % PERM, self.report))

    def test_unregistered_content_is_rejected_before_sql(self):
        self.assertTrue(self.alice.has_perm(PERM, self.document))
        self.assertIn(PERM, self.alice.get_all_permissions(self.document))
        from trusts.backends import configured_catalogs
        handles = configured_catalogs()
        self.assertGreaterEqual(len(handles), 2)
        extra = _extra_handle()
        with self.assertNumQueries(0):
            self._assert_public_deny()
            from tests.apps import bound_handle
            from trusts.apps import catalogs
            from trusts.compile.catalogs import Catalog
            cls = type(self.document_backend)
            saved = catalogs.get(cls)
            factory = extra
            catalogs[cls] = Catalog(cls=cls, path=extra.path, family=cls.family if saved is None else saved.family, registry=factory.build_registry(), family_registries=built_registries(() if saved is None else saved.family_registries))
            try:
                with bound_handle(self.document_backend, extra):
                    self.assertFalse(self.document_backend.has_perm(self.alice, '%s:always' % PERM, self.report))
            finally:
                if saved is None:
                    catalogs.pop(cls, None)
                else:
                    catalogs[cls] = saved
            for bundled in ((self.host_handle, self.document_handle, extra), (extra, self.host_handle, self.document_handle)):
                with listed_relationship(built_registries(bundled)):
                    qs = Repository.objects.authorized(self.alice, self.change)
                    self.assertIsInstance(qs, AuthorizedQuerySet)
                    self.assertIsNone(qs._result_cache)
                    self.assertEqual(list(qs), [])
                    self.assertFalse(qs.exists())
                    self.assertFalse(Repository.objects.authorized(self.alice, self.change, extra_q=Q(pk=self.report.pk)).exists())
        with override_settings(AUTHENTICATION_BACKENDS=(HOST_BACKEND, DOCUMENT_BACKEND, 'django.contrib.auth.backends.ModelBackend')):
            with self.assertNumQueries(0):
                self.assertFalse(self.alice.has_perm(PERM, self.report))
                self.assertEqual(self.alice.get_all_permissions(self.report), set())
                self.assertFalse(Repository.objects.authorized(self.alice, self.change).exists())
