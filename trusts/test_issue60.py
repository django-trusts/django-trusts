"""Isolated common-plan projection tests (issue #60).

One registered-relation plan drives permission enumeration, object
authorization, and authorized-content filtering. Ordinary test-only
models; no historical Trusts types required.
"""

import inspect
import re
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models.query import QuerySet
from django.test import TestCase
from django.test.utils import isolate_apps

from trusts.core import (
    Ref,
    RelationPlan,
    TrustsConfigurationError,
    TrustsRegistry,
)


def _projection_models():
    """Document + two independent direct-FK grant roots, plus fail-closed extras."""

    class Document(models.Model):
        title = models.CharField(max_length=200)

        class Meta:
            app_label = 'trusts_tests'

    class Folder(models.Model):
        title = models.CharField(max_length=200)

        class Meta:
            app_label = 'trusts_tests'

    class Account(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Action(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentPermit(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class AccountGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        account = models.ForeignKey(Account, on_delete=models.CASCADE)
        action = models.ForeignKey(Action, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return (
        Document, Folder, Account, Action,
        DocumentGrant, DocumentPermit, AccountGrant,
    )


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


def _register(registry, grant, *, content='document', user='user', permission='permission'):
    j = Ref(grant)
    return registry.register(
        content=getattr(j, content),
        user=getattr(j, user),
        permission=getattr(j, permission),
    )


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


def _pks(rows):
    return {row.pk for row in rows}


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryProjectionTest(TestCase):
    def setUp(self):
        (
            self.Document,
            self.Folder,
            self.Account,
            self.Action,
            self.DocumentGrant,
            self.DocumentPermit,
            self.AccountGrant,
        ) = _projection_models()
        self._table_cm = _tables(
            self.Document,
            self.Folder,
            self.Account,
            self.Action,
            self.DocumentGrant,
            self.DocumentPermit,
            self.AccountGrant,
        )
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice', password='x')
        self.bob = User.objects.create_user(username='bob', password='x')
        self.read = _perm('read_document')
        self.write = _perm('write_document')
        self.doc_a = self.Document.objects.create(title='A')
        self.doc_b = self.Document.objects.create(title='B')
        self.doc_c = self.Document.objects.create(title='C')
        self.folder = self.Folder.objects.create(title='F')

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _registry(self, *grants):
        registry = TrustsRegistry()
        for grant in grants or (self.DocumentGrant,):
            _register(registry, grant)
        return registry

    def test_permission_enumeration_matching_and_non_matching(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.write,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_b, user=self.bob, permission=self.read,
        )

        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_a)),
            {self.read.pk, self.write.pk},
        )
        self.assertEqual(
            list(registry.permissions_for(self.alice, self.doc_b)),
            [],
        )
        self.assertEqual(
            list(registry.permissions_for(self.bob, self.doc_a)),
            [],
        )
        self.assertEqual(
            _pks(registry.permissions_for(self.bob, self.doc_b)),
            {self.read.pk},
        )

    def test_object_authorization_agrees_with_enumeration_membership(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        granted = _pks(registry.permissions_for(self.alice, self.doc_a))
        self.assertIn(self.read.pk, granted)
        self.assertNotIn(self.write.pk, granted)
        self.assertTrue(
            registry.has_permission(self.alice, self.doc_a, self.read),
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.doc_a, self.write),
        )
        self.assertFalse(
            registry.has_permission(self.bob, self.doc_a, self.read),
        )

    def test_authorized_content_agrees_with_object_checks_as_one_queryset(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_c, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_b, user=self.bob, permission=self.read,
        )

        expected = [
            document for document in self.Document.objects.order_by('pk')
            if registry.has_permission(self.alice, document, self.read)
        ]
        qs = registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )
        self.assertIsInstance(qs, QuerySet)
        self.assertEqual(list(qs), expected)
        self.assertEqual(_pks(expected), {self.doc_a.pk, self.doc_c.pk})

        with self.assertNumQueries(1):
            self.assertEqual(list(qs), expected)

    def test_shared_row_correlation_does_not_combine_split_facts(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_b, user=self.alice, permission=self.write,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.bob, permission=self.write,
        )

        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_a)),
            {self.read.pk},
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.doc_a, self.write),
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.doc_b, self.read),
        )
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.write,
            )),
            {self.doc_b.pk},
        )
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )),
            {self.doc_a.pk},
        )

    def test_two_registered_roots_or_for_all_three_projections(self):
        registry = self._registry(self.DocumentGrant, self.DocumentPermit)
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentPermit.objects.create(
            document=self.doc_b, user=self.alice, permission=self.write,
        )

        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_a)),
            {self.read.pk},
        )
        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_b)),
            {self.write.pk},
        )
        self.assertTrue(
            registry.has_permission(self.alice, self.doc_a, self.read),
        )
        self.assertTrue(
            registry.has_permission(self.alice, self.doc_b, self.write),
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.doc_a, self.write),
        )
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )),
            {self.doc_a.pk},
        )
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.write,
            )),
            {self.doc_b.pk},
        )

        self.DocumentPermit.objects.create(
            document=self.doc_a, user=self.alice, permission=self.write,
        )
        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_a)),
            {self.read.pk, self.write.pk},
        )
        sql = registry.filter_authorized(
            self.Document.objects.all(), self.alice, self.read,
        ).query
        compiled = str(sql).upper()
        self.assertIn('EXISTS', compiled)
        self.assertIn(' OR ', compiled)

    def test_duplicate_grant_rows_yield_distinct_permissions_and_content(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        permissions = list(registry.permissions_for(self.alice, self.doc_a))
        self.assertEqual(len(permissions), 1)
        self.assertEqual(permissions[0].pk, self.read.pk)
        documents = list(registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        ))
        self.assertEqual(documents, [self.doc_a])
        self.assertTrue(
            registry.has_permission(self.alice, self.doc_a, self.read),
        )

    def test_unregistered_content_fails_closed_for_all_three(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.assertEqual(
            list(registry.permissions_for(self.alice, self.folder)),
            [],
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.folder, self.read),
        )
        empty = registry.filter_authorized(
            self.Folder.objects.all(), self.alice, self.read,
        )
        self.assertIsInstance(empty, QuerySet)
        self.assertEqual(list(empty), [])
        self.assertEqual(empty.model, self.Folder)

    def test_authorized_content_is_lazy_and_not_a_per_object_loop(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_b, user=self.alice, permission=self.read,
        )
        with self.assertNumQueries(0):
            qs = registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )
            plan = registry.plan_for(
                self.Document.objects.all(),
                user=self.alice,
                permission=self.read,
            )
            enumerated = registry.permissions_for(self.alice, self.doc_a)
        self.assertIsInstance(plan, RelationPlan)
        self.assertIsInstance(enumerated, QuerySet)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.doc_a.pk, self.doc_b.pk})
        page = registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )[:1]
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.doc_a])

    def test_object_authorization_is_sql_exists_not_python_membership(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        registry_src = inspect.getsource(TrustsRegistry.has_permission)
        plan_src = inspect.getsource(RelationPlan.has_permission)
        self.assertNotIn('permissions_for', registry_src)
        self.assertNotIn('list(', plan_src)
        self.assertNotIn('permissions_for', plan_src)
        body = plan_src.split('def has_permission', 1)[-1]
        self.assertNotIn('for ', body)

        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as captured:
            self.assertTrue(
                registry.has_permission(self.alice, self.doc_a, self.read),
            )
        self.assertEqual(len(captured.captured_queries), 1)
        self.assertIn('EXISTS', captured.captured_queries[0]['sql'].upper())

    def test_three_projections_share_one_plan_builder(self):
        for name in ('permissions_for', 'has_permission', 'filter_authorized'):
            source = inspect.getsource(getattr(TrustsRegistry, name))
            self.assertIn('plan_for', source)
        plan_source = inspect.getsource(RelationPlan)
        self.assertIn('_correlated_exists', plan_source)
        self.assertIn('_bound_root_qs', plan_source)
        for name in ('permissions', 'has_permission', 'filter_content'):
            method = inspect.getsource(getattr(RelationPlan, name))
            self.assertIn('_correlated_exists', method)

    def test_configured_user_model_uses_registered_terminal_metadata(self):
        User = get_user_model()
        registry = self._registry()
        record = registry.records[0]
        self.assertIs(record.user_model, User)
        self.assertEqual(record.user_field, 'user')
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.assertEqual(
            _pks(registry.permissions_for(self.alice, self.doc_a)),
            {self.read.pk},
        )
        self.assertTrue(
            registry.has_permission(self.alice, self.doc_a, self.read),
        )
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )),
            {self.doc_a.pk},
        )

    def test_custom_user_terminal_works_through_registered_metadata(self):
        registry = TrustsRegistry()
        _register(
            registry,
            self.AccountGrant,
            content='document',
            user='account',
            permission='action',
        )
        account = self.Account.objects.create(name='acct')
        other = self.Account.objects.create(name='other')
        action = self.Action.objects.create(name='read')
        extra = self.Action.objects.create(name='write')
        self.AccountGrant.objects.create(
            document=self.doc_a, account=account, action=action,
        )
        self.assertEqual(
            _pks(registry.permissions_for(account, self.doc_a)),
            {action.pk},
        )
        self.assertTrue(registry.has_permission(account, self.doc_a, action))
        self.assertFalse(registry.has_permission(other, self.doc_a, action))
        self.assertFalse(registry.has_permission(account, self.doc_a, extra))
        self.assertEqual(
            _pks(registry.filter_authorized(
                self.Document.objects.all(), account, action,
            )),
            {self.doc_a.pk},
        )
        self.assertEqual(
            list(registry.permissions_for(self.alice, self.doc_a)),
            [],
        )
        self.assertFalse(
            registry.has_permission(self.alice, self.doc_a, self.read),
        )

    def test_no_historical_model_is_required(self):
        for model in (
            self.Document, self.DocumentGrant, self.DocumentPermit, self.Folder,
        ):
            names = {cls.__name__ for cls in model.__mro__}
            self.assertNotIn('Trust', names)
            self.assertNotIn('Content', names)
            self.assertNotIn('Junction', names)
        self.assertEqual(self.DocumentGrant.__module__, __name__)
        self.assertEqual(self.DocumentPermit.__module__, __name__)

    def test_package_surface_does_not_reexport_registry(self):
        import trusts
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RelationPlan', None))

    def test_core_module_does_not_name_historical_types(self):
        source = Path(__import__('trusts.core', fromlist=['core']).__file__).read_text()
        forbidden = (
            r'\bTrust\b',
            r'\bContent\b',
            r'\bJunction\b',
            r'\bTrustUserPermission\b',
            r'\bTrustGroupPermission\b',
            r'\bGroup\b',
            r'\bRole\b',
        )
        for pattern in forbidden:
            self.assertIsNone(
                re.search(pattern, source),
                'trusts/core.py must not name %s' % pattern,
            )

    def test_instances_are_isolated(self):
        left = self._registry()
        right = TrustsRegistry()
        self.assertEqual(len(left.records), 1)
        self.assertEqual(right.records, ())
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.assertTrue(
            left.has_permission(self.alice, self.doc_a, self.read),
        )
        self.assertFalse(
            right.has_permission(self.alice, self.doc_a, self.read),
        )

    def test_incoming_queryset_is_preserved_as_candidate_set(self):
        registry = self._registry()
        self.DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.read,
        )
        self.DocumentGrant.objects.create(
            document=self.doc_b, user=self.alice, permission=self.read,
        )
        subset = self.Document.objects.filter(pk=self.doc_a.pk)
        self.assertEqual(
            list(registry.filter_authorized(subset, self.alice, self.read)),
            [self.doc_a],
        )

    def test_non_queryset_filter_authorized_rejected(self):
        registry = self._registry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'QuerySet'):
            registry.filter_authorized(
                [self.doc_a], self.alice, self.read,
            )
