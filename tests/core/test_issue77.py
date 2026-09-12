"""#77: compiler isolation, multi-handle aggregation, common-permission projection.

Live one-path Trust/Content ``has_perm`` stays on Zero ``tests/legacy/``.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import QuerySet
from django.test import TestCase

from tests.apps import live_config
from tests.core import KernelHostRequiredMixin
from tests.backends import RaisingCompilerBackend
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsCompilerError,
    TrustsRegistry,
    common_permissions,
    compiler_for_class,
    granted,
)
from tests.backends import MissingCompilerBackend


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _change_document():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='change_document',
        defaults={'name': 'Can change document'},
    )
    return permission


def _contribute_document(registry):
    from trusts.core import Ref

    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


class CompilerFailureTest(KernelHostRequiredMixin, TestCase):
    def test_raising_compiler_propagates_on_granted(self):
        User = get_user_model()
        handle = BackendHandle(
            path='tests.backends.RaisingCompilerBackend',
            registry=TrustsRegistry(),
            compiler=RaisingCompilerBackend.query_compiler,
        )
        _contribute_document(handle.registry)
        with self.assertRaises(RuntimeError) as ctx:
            granted(
                (handle,), Document, User(), Permission(), kind='complete',
            )
        self.assertIn('compiler exploded', str(ctx.exception))

    def test_missing_compiler_fails_loud(self):
        with self.assertRaises(TrustsCompilerError):
            compiler_for_class(MissingCompilerBackend)

    def test_unconfigured_and_ambiguous_path_fail_loud(self):
        live = live_config()
        with self.assertRaises(Exception):
            live.configured_backend('tests.backends.MixinOnlyBackend')


class CompilerIsolationBackendTest(KernelHostRequiredMixin, TestCase):
    def test_document_grant_is_not_inherited_by_host(self):
        host = live_config().configured_backend()
        document = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        self.assertFalse(host.registry.plan_for(Document).records)
        self.assertTrue(document.registry.plan_for(Document).records)

    def test_mixin_only_alone_does_not_see_document_plan(self):
        mixin = BackendHandle(
            path='tests.backends.MixinOnlyBackend',
            registry=TrustsRegistry(),
            compiler=PlanQueryCompiler(),
        )
        self.assertFalse(mixin.registry.plan_for(Document).records)


class CoordinatorQueryCountTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-77', password='x')
        self.change = _change_document()
        self.doc = Document.objects.create(title='coord')
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.change,
        )
        self.host = live_config().configured_backend()
        self.document = implementation_for_path(DOCUMENT_BACKEND).configured_backend()

    def test_coordinator_one_sql_noncoordinator_zero(self):
        qs = Document.objects.all()
        pred = granted(
            (self.host, self.document), qs, self.alice, self.change,
            kind='complete',
        )
        self.assertIsNotNone(pred)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs.filter(pred).distinct()), {self.doc.pk})
        empty = granted(
            (self.host,), qs, self.alice, self.change, kind='complete',
        )
        self.assertIsNone(empty)


class CoreCommonPermissionsProjectionTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-77p', password='x')
        self.change = _change_document()
        self.doc = Document.objects.create(title='proj')
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.change,
        )
        self.handle = implementation_for_path(DOCUMENT_BACKEND).configured_backend()

    def test_plan_and_handle_common_permissions_are_one_sql(self):
        plan = self.handle.registry.plan_for(self.doc, user=self.alice)
        with self.assertNumQueries(1):
            codes = set(
                plan.common_permissions(self.alice, self.doc).values_list(
                    'codename', flat=True,
                )
            )
        self.assertIn('change_document', codes)
        qs = Document.objects.filter(pk=self.doc.pk)
        with self.assertNumQueries(1):
            rows = list(common_permissions((self.handle,), qs, self.alice))
        self.assertTrue(any(row.codename == 'change_document' for row in rows))
        empty = Document.objects.none()
        with self.assertNumQueries(1):
            self.assertFalse(list(common_permissions((self.handle,), empty, self.alice)))


class RegisteredOrdinaryModelTest(KernelHostRequiredMixin, TestCase):
    def test_registered_ordinary_instance_queryset_and_authorized(self):
        User = get_user_model()
        alice = User.objects.create_user('alice-77r', password='x')
        bob = User.objects.create_user('bob-77r', password='x')
        change = _change_document()
        keep = Document.objects.create(title='keep')
        Document.objects.create(title='drop')
        DocumentGrant.objects.create(document=keep, user=alice, permission=change)
        qs = Document.objects.authorized(alice, change)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        self.assertEqual(_pks(qs), {keep.pk})
        self.assertFalse(Document.objects.authorized(bob, change).exists())
