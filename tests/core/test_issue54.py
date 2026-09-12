"""#54: generic kernel, lookup/compiler-protocol, and queryset seams.

Zero-owned pair/live Trust proofs stay on ``tests/legacy/test_issue54.py``.
"""

from contextlib import contextmanager
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import Q
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.apps import live_config
from tests.core import kernel_host_listed
from tests.kernel_host.apps import KernelHostConfig
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import TrustsImplementationConfig
from trusts.core import (
    ConditionLookup,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    filter_authorized_scopes,
)
from trusts.query import AuthorizedManager, AuthorizedQuerySet, is_active_principal


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


class _Handle(object):
    def __init__(self, registry):
        self.registry = registry
        self.compiler = PlanQueryCompiler()


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


def _scope_models():
    class Folder(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Payload(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Row(models.Model):
        folder = models.ForeignKey(
            Folder, related_name='rows', on_delete=models.CASCADE,
        )
        content = models.ForeignKey(
            Payload, related_name='rows', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Other(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    User = get_user_model()

    class FolderGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Folder, Payload, Row, Other, FolderGrant


def _register_payload(registry, grant):
    j = Ref(grant)
    return registry.register(
        content=j.folder.rows.content,
        user=j.user,
        permission=j.permission,
    )


class KernelConfigTest(SimpleTestCase):
    def test_live_owner_is_host_and_kernel_config_is_gone(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        import trusts.apps as apps_mod

        config = live_config()
        self.assertIs(type(config), KernelHostConfig)
        self.assertIsInstance(config, TrustsImplementationConfig)
        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertFalse(hasattr(apps_mod, 'AppConfig'))

    def test_legacy_query_helpers_remain_importable(self):
        from trusts.query import trust_grant_q

        self.assertTrue(callable(trust_grant_q))
        self.assertTrue(callable(filter_authorized_scopes))


class ConditionLookupBindTest(TestCase):
    def test_unbound_is_none_and_bind_is_zero_sql(self):
        registry = TrustsRegistry()
        with self.assertNumQueries(0):
            self.assertIsNone(registry.condition_lookup)

        class Bound(ConditionLookup):
            def record_for(self, model, cond_code):
                raise AssertionError('must not invoke at bind')

            def compile_q(self, model, perm_string, user):
                raise AssertionError('must not invoke at bind')

        lookup = Bound()
        with self.assertNumQueries(0):
            registry.set_condition_lookup(lookup)
        self.assertIs(registry.condition_lookup, lookup)
        with self.assertNumQueries(0):
            registry.set_condition_lookup(None)
        self.assertIsNone(registry.condition_lookup)

    def test_missing_methods_raise_and_do_not_partial_bind(self):
        registry = TrustsRegistry()

        class Complete(object):
            def record_for(self, model, cond_code):
                return None

            def compile_q(self, model, perm_string, user):
                return Q(pk__isnull=True)

        class OnlyRecord(object):
            def record_for(self, model, cond_code):
                return None

        class OnlyCompile(object):
            def compile_q(self, model, perm_string, user):
                return Q()

        complete = Complete()
        with self.assertNumQueries(0):
            registry.set_condition_lookup(complete)
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                registry.set_condition_lookup(OnlyRecord())
            with self.assertRaises(TrustsConfigurationError):
                registry.set_condition_lookup(OnlyCompile())
            with self.assertRaises(TrustsConfigurationError):
                registry.set_condition_lookup(object())
        self.assertIs(registry.condition_lookup, complete)

    def test_callable_policy_is_not_invoked_by_the_protocol(self):
        called = []

        def callback(user, perm, obj):
            called.append((user, perm, obj))
            return True

        class Refusing(ConditionLookup):
            def record_for(self, model, cond_code):
                return type('Rec', (), {'expr': None, 'func': callback})()

            def compile_q(self, model, perm_string, user):
                raise PermissionError('callables stay object-only')

        lookup = Refusing()
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionError):
                lookup.compile_q(Document, 'myapp.change_document:own', None)
        self.assertEqual(called, [])


class AuthorizedQuerySetSurfaceTest(SimpleTestCase):
    def test_no_permitted_or_get_permission_on_generic_surface(self):
        self.assertFalse(hasattr(AuthorizedQuerySet, 'permitted'))
        self.assertFalse(hasattr(AuthorizedQuerySet, 'get_permission'))
        self.assertFalse(hasattr(AuthorizedManager, 'permitted'))
        self.assertFalse(hasattr(AuthorizedManager, 'get_permission'))
        self.assertTrue(hasattr(AuthorizedManager, 'authorized'))
        self.assertTrue(issubclass(Document._default_manager._queryset_class, AuthorizedQuerySet))


class AuthorizedQuerySetLiveTest(TestCase):
    def setUp(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        User = get_user_model()
        self.alice = User.objects.create_user('alice-54', password='x')
        self.bob = User.objects.create_user('bob-54', password='x')
        self.change = _change_document()
        self.doc_a = Document.objects.create(title='a')
        self.doc_b = Document.objects.create(title='b')
        DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.change,
        )

    def test_wrong_permission_type_is_zero_sql_configuration_error(self):
        qs = AuthorizedQuerySet(Document)
        with patch('trusts.query.is_active_principal', wraps=is_active_principal) as active:
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    qs.authorized(self.alice, 'change_document')
                with self.assertRaises(TrustsConfigurationError):
                    qs.authorized(self.alice, 'myapp.change_document')
                with self.assertRaises(TrustsConfigurationError):
                    qs.authorized(self.alice, None)
        active.assert_not_called()

    def test_instance_filter_matches_grant_and_stays_lazy(self):
        qs = Document.objects.authorized(self.alice, self.change)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            pks = _pks(qs)
        self.assertEqual(pks, {self.doc_a.pk})
        self.assertNotIn(self.doc_b.pk, pks)
        self.assertFalse(Document.objects.authorized(self.bob, self.change).exists())

    def test_does_not_call_is_active_principal(self):
        self.alice.is_active = False
        self.alice.save()
        with patch('trusts.query.is_active_principal') as active:
            pks = _pks(Document.objects.authorized(self.alice, self.change))
        active.assert_not_called()
        self.assertEqual(pks, {self.doc_a.pk})

    def test_extra_q_is_and_overlay(self):
        extra = Q(pk=self.doc_a.pk)
        self.assertEqual(
            _pks(Document.objects.authorized(self.alice, self.change, extra_q=extra)),
            {self.doc_a.pk},
        )
        self.assertFalse(
            Document.objects.authorized(
                self.alice, self.change, extra_q=Q(pk=self.doc_b.pk),
            ).exists()
        )

    def test_unknown_terminal_is_none_without_grant_sql(self):
        from tests.models import Organization

        qs = AuthorizedQuerySet(Organization).authorized(self.alice, self.change)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(0):
            self.assertFalse(qs.exists())

    def test_non_instance_user_is_configuration_error(self):
        with self.assertNumQueries(0):
            with self.assertRaises((TrustsConfigurationError, TypeError, AttributeError)):
                Document.objects.authorized(AnonymousUser(), self.change)
            with self.assertRaises((TrustsConfigurationError, TypeError, AttributeError)):
                Document.objects.authorized(None, self.change)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FilterAuthorizedScopesIsolatedTest(TransactionTestCase):
    def setUp(self):
        (
            self.Folder,
            self.Payload,
            self.Row,
            self.Other,
            self.FolderGrant,
        ) = _scope_models()
        self._table_cm = _tables(
            self.Folder,
            self.Payload,
            self.Row,
            self.Other,
            self.FolderGrant,
        )
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='c1-scope-alice', password='x')
        self.bob = User.objects.create_user(username='c1-scope-bob', password='x')
        ct, _created = ContentType.objects.get_or_create(
            app_label='trusts_tests', model='payload',
        )
        self.add, _created = Permission.objects.get_or_create(
            content_type=ct,
            codename='add_payload',
            defaults={'name': 'add payload'},
        )
        self.change, _created = Permission.objects.get_or_create(
            content_type=ct,
            codename='change_payload',
            defaults={'name': 'change payload'},
        )
        self.folder_a = self.Folder.objects.create(title='A')
        self.folder_b = self.Folder.objects.create(title='B')
        self.payload = self.Payload.objects.create(title='P')
        self.row = self.Row.objects.create(folder=self.folder_a, content=self.payload)
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.add,
        )
        registry = TrustsRegistry()
        _register_payload(registry, self.FolderGrant)
        self.handle = _Handle(registry)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _filter(self, queryset, user=None, permission=None, content=None, handles=None):
        if handles is None:
            handles = (self.handle,)
        return filter_authorized_scopes(
            queryset,
            self.alice if user is None else user,
            self.add if permission is None else permission,
            content=self.Payload if content is None else content,
            handles=handles,
        )

    def test_prefix_folder_is_create_under_scope_without_naming_zero(self):
        qs = self._filter(self.Folder.objects.all(), handles=(self.handle,))
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            pks = _pks(qs)
        self.assertEqual(pks, {self.folder_a.pk})
        self.assertNotIn(self.folder_b.pk, pks)

    def test_prefix_row_correlates_and_terminal_is_none(self):
        self.assertEqual(
            _pks(self._filter(self.Row.objects.all(), handles=(self.handle,))),
            {self.row.pk},
        )
        qs = self._filter(self.Payload.objects.all(), handles=(self.handle,))
        with self.assertNumQueries(0):
            self.assertFalse(qs.exists())

    def test_unknown_terminal_empty_handles_and_off_path_are_none(self):
        cases = (
            self._filter(
                self.Folder.objects.all(), content=self.Other, handles=(self.handle,),
            ),
            self._filter(self.Folder.objects.all(), handles=()),
            self._filter(
                self.Other.objects.all(), content=self.Payload, handles=(self.handle,),
            ),
        )
        for qs in cases:
            self.assertIsInstance(qs, QuerySet)
            self.assertIsNone(qs._result_cache)
            with self.assertNumQueries(0):
                self.assertFalse(qs.exists())

    def test_wrong_permission_type_is_zero_sql(self):
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                filter_authorized_scopes(
                    self.Folder.objects.all(),
                    self.alice,
                    'add_payload',
                    content=self.Payload,
                    handles=(self.handle,),
                )
            with self.assertRaises(TrustsConfigurationError):
                filter_authorized_scopes(
                    self.Folder.objects.all(),
                    self.alice,
                    None,
                    content=self.Payload,
                    handles=(self.handle,),
                )

    def test_wrong_user_and_wrong_permission_deny(self):
        self.assertFalse(
            self._filter(
                self.Folder.objects.all(), user=self.bob, handles=(self.handle,),
            ).exists()
        )
        self.assertFalse(
            self._filter(
                self.Folder.objects.all(),
                permission=self.change,
                handles=(self.handle,),
            ).exists()
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FilterAuthorizedScopesToFieldTest(TransactionTestCase):
    def test_non_pk_to_field_prefix_returns_authorized_scope(self):
        User = get_user_model()

        class Scope(models.Model):
            slug = models.SlugField(unique=True)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Payload(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Row(models.Model):
            scope = models.ForeignKey(
                Scope, related_name='rows', on_delete=models.CASCADE,
            )
            content = models.ForeignKey(
                Payload, related_name='rows', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            scope = models.ForeignKey(
                Scope, to_field='slug', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Scope, Payload, Row, Grant):
            registry = TrustsRegistry()
            j = Ref(Grant)
            record = registry.register(
                content=j.scope.rows.content,
                user=j.user,
                permission=j.permission,
            )
            self.assertEqual(record.content_path[0], 'scope')
            self.assertNotEqual(record.content_target, 'slug')

            alice = User.objects.create_user(username='c1-tf-alice', password='x')
            bob = User.objects.create_user(username='c1-tf-bob', password='x')
            ct, _created = ContentType.objects.get_or_create(
                app_label='trusts_tests', model='payload',
            )
            add, _created = Permission.objects.get_or_create(
                content_type=ct,
                codename='add_payload_tf',
                defaults={'name': 'add payload tf'},
            )
            scope_a = Scope.objects.create(slug='alpha', title='A')
            scope_b = Scope.objects.create(slug='beta', title='B')
            self.assertNotEqual(scope_a.pk, 'alpha')
            payload = Payload.objects.create(title='P')
            Row.objects.create(scope=scope_a, content=payload)
            Grant.objects.create(scope=scope_a, user=alice, permission=add)

            handle = _Handle(registry)
            qs = filter_authorized_scopes(
                Scope.objects.order_by('pk'), alice, add,
                content=Payload, handles=(handle,),
            )
            self.assertIsInstance(qs, QuerySet)
            self.assertIsNone(qs._result_cache)
            sql = str(qs.query).lower()
            self.assertIn('exists', sql)
            self.assertIn('slug', sql)
            with self.assertNumQueries(1):
                pks = _pks(qs)
            self.assertEqual(pks, {scope_a.pk})
            self.assertNotIn(scope_b.pk, pks)
            self.assertFalse(
                filter_authorized_scopes(
                    Scope.objects.all(), bob, add,
                    content=Payload, handles=(handle,),
                ).exists()
            )
