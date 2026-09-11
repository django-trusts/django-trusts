"""#54 C1: additive generic public seams.

AuthorizedQuerySet / AuthorizedManager, filter_authorized_scopes,
ConditionLookup / set_condition_lookup, and kernel_config(). Structural
and behavioral tests only — no source-token or inspect.getsource
assertions. Does not retarget the app label, move models, bind a Zero
Content lookup, or delete the legacy compiler.
"""

import sys
from contextlib import contextmanager
from unittest.mock import Mock, patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection, models
from django.db.migrations.loader import MigrationLoader
from django.db.models import Q
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.models import Category, Organization, Ticket
from trusts.apps import AppConfig, kernel_config
from trusts.backends import HistoricalGroupQueryCompiler
from trusts.core import (
    ConditionLookup,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    filter_authorized_scopes,
)
from trusts.models import (
    ContentQuerySet,
    PermissionConditionNotQueryable,
    Trust,
    TrustUserPermission,
    trust_grant_q,
)
from trusts.query import (
    AuthorizedManager,
    AuthorizedQuerySet,
    is_active_principal,
    trust_grant_q as query_trust_grant_q,
)
from trusts.tests import (
    enable_local_group_grant,
    get_or_create_root_user,
)


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _perm(model, codename):
    return Permission.objects.get(
        content_type=ContentType.objects.get_for_model(model),
        codename=codename,
    )


def _authorized(model, user, permission, extra_q=None):
    return AuthorizedQuerySet(model).authorized(user, permission, extra_q=extra_q)


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
    """FolderGrant → Folder ← Row → Payload (J1). Isolated nouns only."""

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


class _UsersMixin(object):
    def _make_users(self, suffix):
        get_or_create_root_user(self)
        call_command('create_trust_root')
        self.alice = User.objects.create_user(
            'alice-%s' % suffix, 'alice-%s@example.com' % suffix, 'x',
        )
        self.bob = User.objects.create_user(
            'bob-%s' % suffix, 'bob-%s@example.com' % suffix, 'x',
        )
        self.carol = User.objects.create_user(
            'carol-%s' % suffix, 'carol-%s@example.com' % suffix, 'x',
        )
        for user in (self.alice, self.bob, self.carol):
            user.is_active = True
            user.save()
        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='C1 A %s' % suffix)
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='C1 B %s' % suffix)
        self.trust_b.save()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)


class KernelConfigTest(TestCase):
    def test_kernel_config_is_today_s_trusts_appconfig(self):
        with self.assertNumQueries(0):
            config = kernel_config()
        live = apps.get_app_config('trusts')
        self.assertIs(config, live)
        self.assertIs(type(config), AppConfig)
        self.assertEqual(config.name, 'trusts')
        self.assertEqual(config.label, 'trusts')
        self.assertIs(config, kernel_config())

    def test_legacy_helpers_and_compiler_remain_importable(self):
        from trusts.query import (
            group_local_grant_exists,
            historical_group_grant_exists,
            trust_grant_q,
        )
        self.assertTrue(callable(trust_grant_q))
        self.assertTrue(callable(group_local_grant_exists))
        self.assertTrue(callable(historical_group_grant_exists))
        self.assertTrue(getattr(HistoricalGroupQueryCompiler(), 'historical_fallback', False))


class LegacyMatrixATest(TestCase):
    def test_core_alone_still_populates_trusts_label_and_migrations(self):
        config = kernel_config()
        self.assertIs(config, apps.get_app_config('trusts'))
        self.assertEqual(config.name, 'trusts')
        self.assertEqual(config.label, 'trusts')
        self.assertIs(apps.get_model('trusts', 'Trust'), Trust)
        self.assertTrue(apps.is_installed('trusts'))
        self.assertFalse(apps.is_installed('trusts.zero'))
        self.assertNotIn('trusts.zero', sys.modules)
        loader = MigrationLoader(connection)
        keys = {
            key for key in loader.disk_migrations
            if key[0] == 'trusts'
        }
        self.assertEqual(
            keys,
            {('trusts', '0001_initial'), ('trusts', '0002_trustgroup')},
        )
        initial = loader.disk_migrations[('trusts', '0001_initial')]
        self.assertTrue(initial.__module__.startswith('trusts.migrations'))
        group = loader.disk_migrations[('trusts', '0002_trustgroup')]
        self.assertTrue(group.__module__.startswith('trusts.migrations'))
        self.assertTrue(
            Trust.objects.filter(pk=Trust.objects.get_root().pk).exists()
        )


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
                raise PermissionConditionNotQueryable('callables stay object-only')

        lookup = Refusing()
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionNotQueryable):
                lookup.compile_q(Category, 'read_category:own', None)
        self.assertEqual(called, [])


class ConditionLookupBackendAdapterTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('cond')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='c1-cond')
        self.read = _perm(Category, 'read_category')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.read,
        ).save()
        self._reload()
        self.handle = kernel_config().configured_backend()
        self.saved_lookup = self.handle.registry.condition_lookup

    def tearDown(self):
        self.handle.registry.set_condition_lookup(self.saved_lookup)
        super().tearDown()

    def test_unbound_preserves_content_condition_registry(self):
        self.assertIsNone(self.handle.registry.condition_lookup)
        with self.assertRaises(AttributeError):
            self.alice.has_perm('trusts_tests.read_category:missing', self.cat_a)

    def test_bound_lookup_is_used_and_unregistered_is_attributeerror(self):
        record_for = Mock(return_value=None)
        compile_q = Mock(side_effect=AssertionError('compile_q must not run'))

        class Bound(object):
            pass

        lookup = Bound()
        lookup.record_for = record_for
        lookup.compile_q = compile_q
        self.handle.registry.set_condition_lookup(lookup)
        with self.assertNumQueries(0):
            with self.assertRaises(AttributeError):
                self.alice.has_perm('trusts_tests.read_category:missing', self.cat_a)
        record_for.assert_called()
        compile_q.assert_not_called()


class AuthorizedQuerySetSurfaceTest(SimpleTestCase):
    def test_no_permitted_or_get_permission_on_generic_surface(self):
        self.assertFalse(hasattr(AuthorizedQuerySet, 'permitted'))
        self.assertFalse(hasattr(AuthorizedQuerySet, 'get_permission'))
        self.assertFalse(hasattr(AuthorizedManager, 'permitted'))
        self.assertFalse(hasattr(AuthorizedManager, 'get_permission'))
        self.assertTrue(issubclass(ContentQuerySet, QuerySet))
        self.assertFalse(issubclass(ContentQuerySet, AuthorizedQuerySet))
        self.assertTrue(hasattr(AuthorizedManager, 'authorized'))
        self.assertFalse(hasattr(AuthorizedManager, 'permitted'))
        self.assertFalse(hasattr(AuthorizedManager, 'get_permission'))


class AuthorizedQuerySetLiveTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('authz')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='c1-a')
        self.cat_b = Category.objects.create(trust=self.trust_b, name='c1-b')
        self.read = _perm(Category, 'read_category')
        self.change = _perm(Category, 'change_category')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.read,
        ).save()
        self.carol_group = Group.objects.create(name='carol-c1')
        self.carol.groups.add(self.carol_group)
        self.read.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.read)
        self._reload()

    def test_wrong_permission_type_is_zero_sql_configuration_error(self):
        qs = AuthorizedQuerySet(Category)
        with patch('trusts.query.is_active_principal', wraps=is_active_principal) as active:
            with patch.object(Category.objects, 'get_permission') as get_perm:
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        qs.authorized(self.alice, 'read_category')
                    with self.assertRaises(TrustsConfigurationError):
                        qs.authorized(self.alice, 'trusts_tests.read_category')
                    with self.assertRaises(TrustsConfigurationError):
                        qs.authorized(self.alice, 'read_category:own')
                    with self.assertRaises(TrustsConfigurationError):
                        qs.authorized(self.alice, None)
        active.assert_not_called()
        get_perm.assert_not_called()

    def test_instance_filter_matches_trustee_and_group_and_stays_lazy(self):
        qs = _authorized(Category, self.alice, self.read)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            pks = _pks(qs)
        self.assertEqual(pks, {self.cat_a.pk})
        self.assertNotIn(self.cat_b.pk, pks)
        self.assertEqual(
            _pks(_authorized(Category, self.carol, self.read)),
            {self.cat_a.pk},
        )
        self.assertFalse(_authorized(Category, self.bob, self.read).exists())
        self.assertFalse(_authorized(Category, self.alice, self.change).exists())

    def test_does_not_call_is_active_principal_or_get_permission(self):
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        with patch('trusts.query.is_active_principal') as active:
            with patch('trusts.models.is_active_principal') as models_active:
                with patch.object(Category.objects, 'get_permission') as get_perm:
                    pks = _pks(_authorized(Category, self.alice, self.read))
        active.assert_not_called()
        models_active.assert_not_called()
        get_perm.assert_not_called()
        self.assertEqual(pks, {self.cat_a.pk})

    def test_extra_q_is_and_overlay_and_never_creates_a_grant(self):
        extra = Q(pk=self.cat_a.pk)
        self.assertEqual(
            _pks(_authorized(Category, self.alice, self.read, extra_q=extra)),
            {self.cat_a.pk},
        )
        self.assertFalse(
            _authorized(
                Category, self.alice, self.read, extra_q=Q(pk=self.cat_b.pk),
            ).exists()
        )
        self.assertFalse(
            _authorized(Category, self.bob, self.read, extra_q=extra).exists()
        )

    def test_unknown_terminal_is_none_without_grant_sql(self):
        qs = _authorized(Organization, self.alice, self.read)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(0):
            self.assertFalse(qs.exists())

    def test_non_instance_user_is_configuration_error_without_codec(self):
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                _authorized(Category, AnonymousUser(), self.read)
            with self.assertRaises(TrustsConfigurationError):
                _authorized(Category, None, self.read)


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


class FilterAuthorizedScopesLiveTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('scope-live')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='c1-scope')
        self.add = _perm(Category, 'add_category')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.add,
        ).save()
        self.carol_group = Group.objects.create(name='carol-c1-scope')
        self.carol.groups.add(self.carol_group)
        self.add.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.add)
        self._reload()
        self.handles = kernel_config().configured_handles()

    def test_trust_is_prefix_of_category_for_trustee_not_historical_group(self):
        qs = filter_authorized_scopes(
            Trust.objects.all(), self.alice, self.add,
            content=Category, handles=self.handles,
        )
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            pks = _pks(qs)
        self.assertEqual(pks, {self.trust_a.pk})
        self.assertNotIn(self.trust_b.pk, pks)
        self.assertFalse(
            filter_authorized_scopes(
                Trust.objects.all(), self.carol, self.add,
                content=Category, handles=self.handles,
            ).exists()
        )
        self.assertIn(
            self.trust_a.pk,
            _pks(Trust.objects.filter_by_user_content_perm(
                self.carol, Category, 'add_category',
            )),
        )

    def test_content_terminal_and_unknown_scope_are_none(self):
        with self.assertNumQueries(0):
            self.assertFalse(
                filter_authorized_scopes(
                    Category.objects.all(), self.alice, self.add,
                    content=Category, handles=self.handles,
                ).exists()
            )
            self.assertFalse(
                filter_authorized_scopes(
                    Organization.objects.all(), self.alice, self.add,
                    content=Category, handles=self.handles,
                ).exists()
            )
            self.assertFalse(
                filter_authorized_scopes(
                    Trust.objects.all(), self.alice, self.add,
                    content=Organization, handles=self.handles,
                ).exists()
            )
            self.assertFalse(
                filter_authorized_scopes(
                    Trust.objects.all(), self.alice, self.add,
                    content=Ticket, handles=(),
                ).exists()
            )

    def test_legacy_create_under_trust_path_is_unchanged(self):
        self.assertIs(query_trust_grant_q, trust_grant_q)
        pks = _pks(Trust.objects.filter_by_user_content_perm(
            self.alice, Category, 'add_category',
        ))
        self.assertEqual(pks, {self.trust_a.pk})
