"""S3b: backend authorization and enumeration on compiler handles (issue #77).

Structural and behavioral tests only — no source-token or
``inspect.getsource`` assertions.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection, models
from django.db.models.query import QuerySet
from django.test import TestCase, TransactionTestCase, override_settings

from tests.apps import install_writable_registry
from tests.backends import GroupOnlyBackend, MixinOnlyBackend
from tests.models import Category, Organization, Ticket, TestGroupJunction
from trusts.backends import HistoricalGroupQueryCompiler, TrustModelBackend
from trusts.conditions import condition_refs
from trusts.core import (
    PlanQueryCompiler,
    Ref,
    TrustsCompilerError,
    TrustsConfigurationError,
    TrustsRegistry,
    common_permissions,
)
from trusts.models import (
    Content,
    ContentManager,
    PermissionConditionNotQueryable,
    Trust,
    TrustUserPermission,
)
from trusts.query import is_active_principal, trust_grant_q
from trusts.tests import (
    enable_local_group_grant,
    get_or_create_root_user,
)


CONCRETE = 'trusts.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
GROUP_ONLY = 'tests.backends.GroupOnlyBackend'
MISSING = 'tests.backends.MissingCompilerBackend'
RAISING = 'tests.backends.RaisingCompilerBackend'
MODEL = 'django.contrib.auth.backends.ModelBackend'


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _perm(model, codename):
    return Permission.objects.get(
        content_type=ContentType.objects.get_for_model(model),
        codename=codename,
    )


def _codes(perms):
    return set(perms)


def _contribute_category(registry):
    j = Ref(TrustUserPermission)
    rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
    registry.register(
        content=getattr(j.trust, rev),
        user=j.entity,
        permission=j.permission,
    )


class _RegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = apps.get_app_config('trusts')
        self.saved_registries = dict(self.live.registries)
        self.saved_trust_sentinel = getattr(
            self.live, '_trusts_tup_trust_registry_id', None
        )
        self.saved_trust_ids = getattr(
            self.live, '_trusts_tup_trust_registry_ids', None
        )
        self.live_contributor = apps.get_app_config('trusts_tests')
        self.saved_category_sentinel = getattr(
            self.live_contributor, '_trusts_tup_category_registry_id', None
        )
        self.saved_ticket_sentinel = getattr(
            self.live_contributor, '_trusts_tup_ticket_registry_id', None
        )
        self.saved_group_sentinel = getattr(
            self.live_contributor, '_trusts_tup_group_registry_id', None
        )

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved_registries)
        self.live._trusts_tup_trust_registry_id = self.saved_trust_sentinel
        if self.saved_trust_ids is None:
            if hasattr(self.live, '_trusts_tup_trust_registry_ids'):
                delattr(self.live, '_trusts_tup_trust_registry_ids')
        else:
            self.live._trusts_tup_trust_registry_ids = self.saved_trust_ids
        self.live_contributor._trusts_tup_category_registry_id = (
            self.saved_category_sentinel
        )
        self.live_contributor._trusts_tup_ticket_registry_id = (
            self.saved_ticket_sentinel
        )
        self.live_contributor._trusts_tup_group_registry_id = (
            self.saved_group_sentinel
        )
        super().tearDown()


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
        self.trust_a = Trust(settlor=self.alice, trust=root, title='S3b A %s' % suffix)
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='S3b B %s' % suffix)
        self.trust_b.save()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)


class OnePathAuthorizationTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('one')
        self.cat_a1 = Category.objects.create(trust=self.trust_a, name='keep')
        self.cat_a2 = Category.objects.create(trust=self.trust_a, name='drop')
        self.cat_b = Category.objects.create(trust=self.trust_b, name='other')
        self.change = _perm(Category, 'change_category')
        self.add = _perm(Category, 'add_category')
        self.change_code = 'trusts_tests.change_category'
        self.add_code = 'trusts_tests.add_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s3b')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self._reload()
        u, p, o = condition_refs()
        Content.register_permission_condition(Category, 'named', o.name == 'keep')

    def test_category_trustee_and_group_object_and_queryset(self):
        qs = Category.objects.filter(pk__in=[self.cat_a1.pk, self.cat_a2.pk])
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a2))
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_b))
        self.assertFalse(self.alice.has_perm(self.add_code, self.cat_a1))
        self.assertFalse(self.bob.has_perm(self.change_code, self.cat_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, qs))
        self.assertFalse(self.alice.has_perm(self.change_code, Category.objects.all()))
        self.assertTrue(self.carol.has_perm(self.change_code, self.cat_a1))
        self.assertTrue(self.carol.has_perm(self.change_code, qs))
        self.assertFalse(self.carol.has_perm(self.change_code, self.cat_b))
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.alice)),
            {self.cat_a1.pk, self.cat_a2.pk},
        )
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.carol)),
            {self.cat_a1.pk, self.cat_a2.pk},
        )

    def test_ticket_and_trust_object_queryset_parity(self):
        organization = Organization.objects.create(name='Org', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='t', owner=self.alice,
            organization=organization, status='open',
        )
        ticket_perm = _perm(Ticket, 'change_ticket')
        ticket_code = 'trusts_tests.change_ticket'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=ticket_perm,
        ).save()
        change_trust = _perm(Trust, 'change_trust')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=change_trust,
        ).save()
        child = Trust(settlor=self.alice, trust=self.trust_a, title='Child')
        child.save()
        self._reload()
        self.assertTrue(self.alice.has_perm(ticket_code, ticket))
        self.assertTrue(
            self.alice.has_perm(ticket_code, Ticket.objects.filter(pk=ticket.pk))
        )
        self.assertTrue(self.alice.has_perm('trusts.change_trust', child))
        self.assertTrue(
            self.alice.has_perm(
                'trusts.change_trust', Trust.objects.filter(pk=child.pk),
            )
        )
        self.assertFalse(self.bob.has_perm(ticket_code, ticket))
        self.assertIn(ticket.pk, _pks(Ticket.objects.permitted(ticket_code, self.alice)))
        self.assertIn(child.pk, _pks(Trust.objects.permitted('trusts.change_trust', self.alice)))

    def test_named_condition_constrains_and_does_not_create(self):
        conditioned = '%s:named' % self.change_code
        self.assertTrue(self.alice.has_perm(conditioned, self.cat_a1))
        self.assertFalse(self.alice.has_perm(conditioned, self.cat_a2))
        self.assertTrue(self.carol.has_perm(conditioned, self.cat_a1))
        qs_keep = Category.objects.filter(pk=self.cat_a1.pk)
        qs_drop = Category.objects.filter(pk=self.cat_a2.pk)
        self.assertTrue(self.alice.has_perm(conditioned, qs_keep))
        self.assertFalse(self.alice.has_perm(conditioned, qs_drop))
        self.assertFalse(self.bob.has_perm(conditioned, self.cat_a1))
        self.assertEqual(
            _pks(Category.objects.permitted(conditioned, self.alice)),
            {self.cat_a1.pk},
        )

    def test_inactive_and_anonymous_denied(self):
        self.alice.is_active = False
        self.alice.save()
        self.alice = User.objects.get(pk=self.alice.pk)
        self.assertFalse(is_active_principal(self.alice))
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a1))
        self.assertFalse(
            self.alice.has_perm(
                self.change_code,
                Category.objects.filter(pk=self.cat_a1.pk),
            )
        )
        self.assertEqual(
            TrustModelBackend().get_all_permissions(self.alice, self.cat_a1),
            set(),
        )
        anon = AnonymousUser()
        self.assertFalse(
            TrustModelBackend().has_perm(anon, self.change_code, self.cat_a1)
        )
        self.assertEqual(
            TrustModelBackend().get_all_permissions(anon, self.cat_a1),
            set(),
        )

    def test_permission_identity_and_group_enumeration(self):
        backend = TrustModelBackend()
        all_perms = backend.get_all_permissions(self.alice, self.cat_a1)
        self.assertIn(self.change_code, all_perms)
        self.assertNotIn(self.add_code, all_perms)
        group_perms = backend.get_group_permissions(self.alice, self.cat_a1)
        self.assertNotIn(self.change_code, group_perms)
        carol_all = backend.get_all_permissions(self.carol, self.cat_a1)
        carol_group = backend.get_group_permissions(self.carol, self.cat_a1)
        self.assertIn(self.change_code, carol_all)
        self.assertIn(self.change_code, carol_group)
        qs = Category.objects.filter(pk__in=[self.cat_a1.pk, self.cat_a2.pk])
        self.assertIn(self.change_code, backend.get_all_permissions(self.alice, qs))
        self.assertIn(self.change_code, backend.get_all_permissions(self.carol, qs))
        self.assertNotIn(self.change_code, backend.get_group_permissions(self.alice, qs))
        self.assertIn(self.change_code, backend.get_group_permissions(self.carol, qs))

    def test_cache_attribute_is_not_an_authorization_source(self):
        backend = TrustModelBackend()
        self.assertFalse(hasattr(self.alice, '_trust_perm_cache'))
        backend.get_all_permissions(self.alice, self.cat_a1)
        self.assertTrue(hasattr(self.alice, '_trust_perm_cache'))
        self.assertIsInstance(self.alice._trust_perm_cache, dict)
        delattr(self.alice, '_trust_perm_cache')
        self.assertFalse(hasattr(self.alice, '_trust_perm_cache'))
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a1))
        TrustUserPermission.objects.filter(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).delete()
        self.alice = User.objects.get(pk=self.alice.pk)
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a1))

    def test_query_bounds_one_path(self):
        backend = TrustModelBackend()
        qs = Category.objects.filter(pk__in=[self.cat_a1.pk, self.cat_a2.pk])
        with self.assertNumQueries(1):
            self.assertTrue(backend.has_perm(self.alice, self.change_code, qs))
        with self.assertNumQueries(1):
            self.assertTrue(backend.has_perm(self.alice, self.change_code, self.cat_a1))
        with self.assertNumQueries(1):
            backend.get_all_permissions(self.alice, qs)
        with self.assertNumQueries(1):
            backend.get_group_permissions(self.carol, qs)
        self.assertTrue(
            self.alice.has_perms((self.change_code, self.change_code), qs)
        )
        with self.assertNumQueries(2):
            backend.has_perm(self.alice, self.change_code, qs)
            backend.has_perm(self.alice, self.add_code, qs)
        permitted = Category.objects.permitted(self.change_code, self.alice)
        self.assertIsInstance(permitted, QuerySet)
        self.assertIsNone(permitted._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(permitted), {self.cat_a1.pk, self.cat_a2.pk})
        page = Category.objects.permitted(
            self.change_code, self.alice,
        ).order_by('pk')[:1]
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.cat_a1])


class DistributiveLawTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('dist')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='c-a')
        self.cat_b = Category.objects.create(trust=self.trust_b, name='c-b')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        # A (group-only compiler): historical group on C1 only.
        # B (mixin): TUP on C2 only. Shared TUP rows cannot split a
        # HistoricalGroupQueryCompiler path, so A omits content_exists.
        self.alice_group = Group.objects.create(name='alice-dist')
        self.alice.groups.add(self.alice_group)
        self.change.group_set.add(self.alice_group)
        enable_local_group_grant(self.trust_a, self.alice_group, self.change)
        TrustUserPermission(
            trust=self.trust_b, entity=self.alice, permission=self.change,
        ).save()
        self._reload()

    def _two_path(self):
        return override_settings(AUTHENTICATION_BACKENDS=(GROUP_ONLY, MIXIN))

    def test_split_coverage_object_queryset_and_permitted(self):
        with self._two_path():
            install_writable_registry(self.live, GROUP_ONLY, _contribute_category)
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_a = self.live.configured_backend(GROUP_ONLY)
            handle_b = self.live.configured_backend(MIXIN)
            group_only = GroupOnlyBackend()
            mixin = MixinOnlyBackend()
            self.assertTrue(group_only.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertFalse(group_only.has_perm(self.alice, self.change_code, self.cat_b))
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertTrue(mixin.has_perm(self.alice, self.change_code, self.cat_b))
            self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a))
            self.assertTrue(self.alice.has_perm(self.change_code, self.cat_b))
            qs = Category.objects.filter(pk__in=[self.cat_a.pk, self.cat_b.pk])
            self.assertTrue(self.alice.has_perm(self.change_code, qs))
            self.assertTrue(self.alice.has_perms((self.change_code,), qs))
            self.assertIn(
                self.change_code,
                group_only.get_all_permissions(self.alice, qs),
            )
            self.assertEqual(mixin.get_all_permissions(self.alice, qs), set())
            self.assertIn(self.change_code, self.alice.get_all_permissions(qs))
            permitted = Category.objects.permitted(self.change_code, self.alice)
            with self.assertNumQueries(1):
                self.assertEqual(_pks(permitted), {self.cat_a.pk, self.cat_b.pk})

    def test_failed_ceiling_cannot_borrow_other_path_fragment(self):
        self.change.group_set.remove(self.alice_group)
        TrustUserPermission.objects.filter(
            trust=self.trust_b, entity=self.alice,
        ).delete()
        self._reload()
        with self._two_path():
            install_writable_registry(self.live, GROUP_ONLY, _contribute_category)
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_a = self.live.configured_backend(GROUP_ONLY)
            handle_b = self.live.configured_backend(MIXIN)
            qs = Category.objects.filter(pk__in=[self.cat_a.pk, self.cat_b.pk])
            self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a))
            self.assertFalse(self.alice.has_perm(self.change_code, self.cat_b))
            self.assertFalse(self.alice.has_perm(self.change_code, qs))
            self.assertNotIn(
                self.change_code,
                GroupOnlyBackend().get_all_permissions(self.alice, qs),
            )
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.alice).exists()
            )


class CompilerIsolationBackendTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('iso')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='iso')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        self.carol_group = Group.objects.create(name='carol-iso-s3b')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self._reload()

    def test_concrete_group_grant_not_inherited_by_mixin(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            concrete = TrustModelBackend()
            mixin = MixinOnlyBackend()
            self.assertTrue(concrete.has_perm(self.carol, self.change_code, self.cat_a))
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, self.cat_a))
            self.assertTrue(self.carol.has_perm(self.change_code, self.cat_a))
            self.assertIn(
                self.change_code,
                concrete.get_group_permissions(self.carol, self.cat_a),
            )
            self.assertEqual(
                mixin.get_group_permissions(self.carol, self.cat_a),
                set(),
            )
            qs = Category.objects.filter(pk=self.cat_a.pk)
            self.assertTrue(concrete.has_perm(self.carol, self.change_code, qs))
            with self.assertNumQueries(0):
                self.assertFalse(mixin.has_perm(self.carol, self.change_code, qs))
            self.assertIsInstance(mixin.query_compiler, PlanQueryCompiler)

    def test_mixin_only_alone_denies_historical_group(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle = self.live.configured_backend()
            mixin = MixinOnlyBackend()
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, self.cat_a))
            self.assertFalse(self.carol.has_perm(self.change_code, self.cat_a))
            self.assertEqual(
                mixin.get_group_permissions(self.carol, self.cat_a),
                set(),
            )
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.carol).exists()
            )


class CoordinatorQueryCountTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('coord')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='coord')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()
        self.qs = Category.objects.filter(pk=self.cat_a.pk)

    def test_coordinator_one_sql_noncoordinator_zero(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            concrete = TrustModelBackend()
            mixin = MixinOnlyBackend()
            self.assertTrue(concrete._is_collection_coordinator())
            self.assertFalse(mixin._is_collection_coordinator())
            with self.assertNumQueries(1):
                self.assertTrue(concrete.has_perm(self.alice, self.change_code, self.qs))
            with self.assertNumQueries(0):
                self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.qs))
            with self.assertNumQueries(0):
                self.assertEqual(mixin.get_all_permissions(self.alice, self.qs), set())
            with self.assertNumQueries(0):
                self.assertEqual(mixin.get_group_permissions(self.alice, self.qs), set())
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(self.change_code, self.qs))

    def test_reversed_backend_order(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN, CONCRETE)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            concrete = TrustModelBackend()
            mixin = MixinOnlyBackend()
            self.assertTrue(mixin._is_collection_coordinator())
            self.assertFalse(concrete._is_collection_coordinator())
            with self.assertNumQueries(1):
                self.assertTrue(mixin.has_perm(self.alice, self.change_code, self.qs))
            with self.assertNumQueries(0):
                self.assertFalse(concrete.has_perm(self.alice, self.change_code, self.qs))
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(self.change_code, self.qs))

    def test_duplicate_exact_path_strings_dedupe(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, CONCRETE)):
            self.assertEqual(self.live._configured_trusts_paths(), (CONCRETE,))
            concrete = TrustModelBackend()
            self.assertTrue(concrete._is_collection_coordinator())
            self.assertTrue(self.alice.has_perm(self.change_code, self.qs))
            self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a))


class ObjNoneBoundaryTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('none')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='none')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.global_perm = _perm(User, 'change_user')
        self.alice.user_permissions.add(self.global_perm)
        self._reload()

    def test_trusts_only_obj_none_is_false_empty(self):
        backend = TrustModelBackend()
        self.assertFalse(backend.has_perm(self.alice, 'auth.change_user'))
        self.assertFalse(backend.has_perm(self.alice, self.change_code))
        self.assertEqual(backend.get_all_permissions(self.alice), set())
        self.assertEqual(backend.get_group_permissions(self.alice), set())
        self.assertFalse(self.alice.has_perm('auth.change_user'))
        self.assertFalse(self.alice.has_perms(('auth.change_user',)))
        self.assertEqual(self.alice.get_all_permissions(), set())
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a))
        self.assertNotIn('auth.change_user', backend.get_all_permissions(self.alice, self.cat_a))

    def test_modelbackend_plus_trusts_restores_globals_not_object_grants(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MODEL, CONCRETE)):
            self.assertTrue(self.alice.has_perm('auth.change_user'))
            self.assertTrue(self.alice.has_perms(('auth.change_user',)))
            self.assertIn('auth.change_user', self.alice.get_all_permissions())
            self.assertFalse(
                TrustModelBackend().has_perm(self.alice, 'auth.change_user')
            )
            self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a))
            self.assertFalse(self.alice.has_perm('auth.change_user', self.cat_a))
            self.assertNotIn(
                'auth.change_user',
                self.alice.get_all_permissions(self.cat_a),
            )


class UndeclaredJunctionRemainsHistoricalTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('junc')
        self.group = Group.objects.create(name='junc-group')
        self.junction = TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group, name='junc',
        )
        group_ct = ContentType.objects.get_for_model(Group)
        self.change_group, _created = Permission.objects.get_or_create(
            content_type=group_ct, codename='change_group',
            defaults={'name': 'Can change group'},
        )
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change_group,
        ).save()
        self._reload()

    def test_junction_group_uses_registered_plan(self):
        handle = apps.get_app_config('trusts').configured_backend()
        self.assertTrue(handle.registry.plan_for(Group).records)
        self.assertFalse(handle.registry.plan_for(TestGroupJunction).records)
        code = 'auth.change_group'
        self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
        self.assertTrue(self.alice.has_perm(code, self.group))
        self.assertFalse(self.bob.has_perm(code, self.group))
        qs = Group.objects.filter(pk=self.group.pk)
        self.assertTrue(self.alice.has_perm(code, qs))


class CompilerFailureTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('fail')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='fail')
        self.change_code = 'trusts_tests.change_category'

    def test_raising_compiler_propagates_on_has_perm(self):
        from tests.backends import RaisingCompilerBackend

        with override_settings(AUTHENTICATION_BACKENDS=(RAISING,)):
            install_writable_registry(self.live, RAISING, _contribute_category)
            handle = self.live.configured_backend()
            with self.assertRaises(RuntimeError):
                RaisingCompilerBackend().has_perm(
                    self.alice, self.change_code, self.cat_a,
                )

    def test_missing_compiler_fails_loud(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING,)):
            with self.assertRaises(TrustsCompilerError):
                from tests.backends import MissingCompilerBackend
                MissingCompilerBackend().has_perm(
                    self.alice, self.change_code, self.cat_a,
                )

    def test_unconfigured_and_ambiguous_path_fail_loud(self):
        backend = MixinOnlyBackend()
        with self.assertRaises(TrustsConfigurationError):
            backend.has_perm(self.alice, self.change_code, self.cat_a)
        with override_settings(AUTHENTICATION_BACKENDS=(
            CONCRETE, 'tests.backends.AliasedTrustModelBackend',
        )):
            with self.assertRaises(TrustsConfigurationError):
                TrustModelBackend().has_perm(
                    self.alice, self.change_code, self.cat_a,
                )

    def test_silenced_e004_still_raises(self):
        with override_settings(
            AUTHENTICATION_BACKENDS=(MISSING,),
            SILENCED_SYSTEM_CHECKS=['trusts.E004', 'fields.W342'],
        ):
            from tests.backends import MissingCompilerBackend
            with self.assertRaises(TrustsCompilerError):
                MissingCompilerBackend().has_perm(
                    self.alice, self.change_code, self.cat_a,
                )


class CoreCommonPermissionsProjectionTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('proj')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='proj')
        self.change = _perm(Category, 'change_category')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()

    def test_plan_and_handle_common_permissions_are_one_sql(self):
        handle = apps.get_app_config('trusts').configured_backend()
        plan = handle.registry.plan_for(self.cat_a, user=self.alice)
        with self.assertNumQueries(1):
            codes = set(
                plan.common_permissions(self.alice, self.cat_a).values_list(
                    'codename', flat=True,
                )
            )
        self.assertIn('change_category', codes)
        qs = Category.objects.filter(pk=self.cat_a.pk)
        with self.assertNumQueries(1):
            rows = list(common_permissions((handle,), qs, self.alice))
        self.assertTrue(any(row.codename == 'change_category' for row in rows))
        empty = Category.objects.none()
        with self.assertNumQueries(1):
            self.assertFalse(list(common_permissions((handle,), empty, self.alice)))


class _CallLog(object):
    def __init__(self, impl):
        self.impl = impl
        self.calls = []

    def __call__(self, user, perm, obj):
        self.calls.append((user, perm, obj))
        return self.impl(user, perm, obj)


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
        all_models = apps.all_models
        for model in model_classes:
            all_models[model._meta.app_label].pop(model._meta.model_name, None)
        apps.clear_cache()


def _ordinary_memo_models():
    class Memo(models.Model):
        title = models.CharField(max_length=40)
        objects = ContentManager()

        class Meta:
            app_label = 'trusts_tests'

    class MemoGrant(models.Model):
        memo = models.ForeignKey(Memo, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Memo, MemoGrant


class RegisteredOrdinaryModelTest(_RegistryRestoreMixin, _UsersMixin, TransactionTestCase):
    """Registered non-Content models route through the handle, not Content._contents."""

    def test_registered_ordinary_instance_queryset_enum_and_permitted(self):
        Memo, MemoGrant = _ordinary_memo_models()
        with _tables(Memo, MemoGrant):
            self._make_users('memo')
            memo = Memo.objects.create(title='note')
            other = Memo.objects.create(title='other')
            self.assertFalse(hasattr(Content, 'is_content'))
            self.assertFalse(hasattr(Content, 'is_content_model'))
            ct = ContentType.objects.get_for_model(Memo)
            change, _created = Permission.objects.get_or_create(
                content_type=ct,
                codename='change_memo',
                defaults={'name': 'Can change memo'},
            )
            code = 'trusts_tests.change_memo'
            MemoGrant.objects.create(memo=memo, user=self.alice, permission=change)
            with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
                isolated = TrustsRegistry()
                j = Ref(MemoGrant)
                isolated.register(
                    content=j.memo, user=j.user, permission=j.permission,
                )
                self.live.registries[MIXIN] = isolated
                handle = self.live.configured_backend()
                self.assertFalse(handle.historical_fallback)
                self.assertIsInstance(handle.compiler, PlanQueryCompiler)
                mixin = MixinOnlyBackend()
                self.assertTrue(mixin.has_perm(self.alice, code, memo))
                self.assertFalse(mixin.has_perm(self.alice, code, other))
                self.assertFalse(mixin.has_perm(self.bob, code, memo))
                self.assertTrue(self.alice.has_perm(code, memo))
                self.assertIn(code, mixin.get_all_permissions(self.alice, memo))
                self.assertEqual(mixin.get_group_permissions(self.alice, memo), set())
                qs = Memo.objects.filter(pk=memo.pk)
                self.assertTrue(mixin.has_perm(self.alice, code, qs))
                self.assertIn(code, mixin.get_all_permissions(self.alice, qs))
                self.assertEqual(mixin.get_group_permissions(self.alice, qs), set())
                self.assertFalse(
                    mixin.has_perm(
                        self.alice, code,
                        Memo.objects.filter(pk__in=[memo.pk, other.pk]),
                    )
                )
                self.assertEqual(_pks(Memo.objects.permitted(code, self.alice)), {memo.pk})
                self.assertFalse(Memo.objects.permitted(code, self.bob).exists())


class HistoricalFallbackCapabilityTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    """Historical fallback is a concrete compiler capability, not Content membership."""

    def setUp(self):
        super().setUp()
        self._make_users('hist')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='hist')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.carol_group = Group.objects.create(name='carol-hist-s3b')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self._reload()

    def _empty_plans(self, *paths):
        for path in paths:
            self.live.registries[path] = TrustsRegistry()

    def test_compiler_advertises_fallback_only_on_historical_route(self):
        self.assertTrue(HistoricalGroupQueryCompiler.historical_fallback)
        self.assertFalse(PlanQueryCompiler.historical_fallback)
        concrete = self.live.configured_backend(CONCRETE)
        self.assertTrue(concrete.historical_fallback)
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            mixin = self.live.configured_backend()
            self.assertFalse(mixin.historical_fallback)

    def test_mixin_only_no_plan_denies_tup_and_trustgroup(self):
        self.assertFalse(hasattr(Content, 'is_content'))
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            handle = self.live.configured_backend()
            self.assertFalse(handle.registry.plan_for(Category).records)
            self.assertFalse(handle.historical_fallback)
            mixin = MixinOnlyBackend()
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, self.cat_a))
            self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a))
            self.assertFalse(self.carol.has_perm(self.change_code, self.cat_a))
            self.assertEqual(
                mixin.get_all_permissions(self.alice, self.cat_a), set(),
            )
            self.assertEqual(
                mixin.get_group_permissions(self.carol, self.cat_a), set(),
            )
            qs = Category.objects.filter(pk=self.cat_a.pk)
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, qs))
            self.assertEqual(mixin.get_all_permissions(self.alice, qs), set())
            self.assertEqual(mixin.get_group_permissions(self.carol, qs), set())
            with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
                self.assertFalse(
                    Category.objects.permitted(self.change_code, self.alice).exists()
                )
                self.assertFalse(
                    Category.objects.permitted(self.change_code, self.carol).exists()
                )
            grant_q.assert_not_called()

    def test_concrete_no_plan_fails_closed_for_undeclared_content(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE,)):
            self._empty_plans(CONCRETE)
            handle = self.live.configured_backend()
            self.assertFalse(handle.registry.plan_for(Category).records)
            self.assertTrue(handle.historical_fallback)
            self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
            concrete = TrustModelBackend()
            self.assertFalse(concrete.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertFalse(concrete.has_perm(self.carol, self.change_code, self.cat_a))
            self.assertEqual(
                concrete.get_all_permissions(self.alice, self.cat_a), set(),
            )
            self.assertEqual(
                concrete.get_group_permissions(self.carol, self.cat_a), set(),
            )
            qs = Category.objects.filter(pk=self.cat_a.pk)
            self.assertFalse(concrete.has_perm(self.alice, self.change_code, qs))
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.alice).exists()
            )
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.carol).exists()
            )

    def test_inapplicable_mixin_neither_adds_nor_reopens_deleted_fallback(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN, CONCRETE)):
            self._empty_plans(MIXIN, CONCRETE)
            mixin_handle = self.live.configured_backend(MIXIN)
            concrete_handle = self.live.configured_backend(CONCRETE)
            self.assertFalse(mixin_handle.registry.plan_for(Category).records)
            self.assertFalse(concrete_handle.registry.plan_for(Category).records)
            self.assertFalse(mixin_handle.historical_fallback)
            self.assertTrue(concrete_handle.historical_fallback)
            mixin = MixinOnlyBackend()
            concrete = TrustModelBackend()
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertFalse(concrete.has_perm(self.alice, self.change_code, self.cat_a))
            self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a))
            self.assertEqual(mixin.get_all_permissions(self.alice, self.cat_a), set())
            self.assertEqual(
                concrete.get_all_permissions(self.alice, self.cat_a), set(),
            )
            qs = Category.objects.filter(pk=self.cat_a.pk)
            self.assertTrue(mixin._is_collection_coordinator())
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, qs))
            with self.assertNumQueries(0):
                self.assertFalse(concrete.has_perm(self.alice, self.change_code, qs))
            self.assertFalse(self.alice.has_perm(self.change_code, qs))
            self.assertEqual(mixin.get_all_permissions(self.alice, qs), set())
            self.assertEqual(concrete.get_all_permissions(self.alice, qs), set())
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.alice).exists()
            )
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.carol).exists()
            )


class MixedPathUndeclaredJunctionTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('mixj')
        self.group = Group.objects.create(name='mixj-group')
        self.junction = TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group, name='mixj',
        )
        group_ct = ContentType.objects.get_for_model(Group)
        self.change_group, _created = Permission.objects.get_or_create(
            content_type=group_ct, codename='change_group',
            defaults={'name': 'Can change group'},
        )
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change_group,
        ).save()
        self._reload()
        self.code = 'auth.change_group'

    def test_concrete_authorizes_declared_junction_group(self):
        handle = self.live.configured_backend()
        self.assertTrue(handle.registry.plan_for(Group).records)
        self.assertTrue(handle.historical_fallback)
        self.assertTrue(self.alice.has_perm(self.code, self.group))
        self.assertFalse(self.bob.has_perm(self.code, self.group))
        qs = Group.objects.filter(pk=self.group.pk)
        self.assertTrue(self.alice.has_perm(self.code, qs))

    def test_mixin_does_not_add_or_suppress_junction_plan(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN, CONCRETE)):
            mixin = MixinOnlyBackend()
            concrete = TrustModelBackend()
            self.assertFalse(
                self.live.configured_backend(MIXIN).registry.plan_for(Group).records
            )
            self.assertTrue(
                self.live.configured_backend(CONCRETE).registry.plan_for(Group).records
            )
            self.assertFalse(mixin.has_perm(self.alice, self.code, self.group))
            self.assertTrue(concrete.has_perm(self.alice, self.code, self.group))
            self.assertTrue(self.alice.has_perm(self.code, self.group))
            qs = Group.objects.filter(pk=self.group.pk)
            self.assertTrue(mixin._is_collection_coordinator())
            self.assertTrue(mixin.has_perm(self.alice, self.code, qs))
            with self.assertNumQueries(0):
                self.assertFalse(concrete.has_perm(self.alice, self.code, qs))


class QuerySetCallableConditionTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('cb')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='keep')
        self.cat_b = Category.objects.create(trust=self.trust_a, name='drop')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()
        self.log = _CallLog(lambda user, perm, obj: obj.name == 'keep')
        Content.register_permission_condition(Category, 'spy', self.log)
        self.conditioned = '%s:spy' % self.change_code

    def tearDown(self):
        from trusts import utils
        Content._conditions.get(
            utils.get_short_model_name(Category), {},
        ).pop('spy', None)
        super().tearDown()

    def _assert_zero_queryset_callbacks(self):
        qs = Category.objects.filter(pk__in=[self.cat_a.pk, self.cat_b.pk])
        backend = TrustModelBackend()
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionNotQueryable):
                backend.has_perm(self.alice, self.conditioned, qs)
        self.assertEqual(self.log.calls, [])
        with self.assertRaises(PermissionConditionNotQueryable):
            self.alice.has_perm(self.conditioned, qs)
        self.assertEqual(self.log.calls, [])
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionNotQueryable):
                self.alice.has_perms((self.conditioned,), qs)
        self.assertEqual(self.log.calls, [])

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_queryset_callable_raises_before_sql_or_callback(self):
        self._assert_zero_queryset_callbacks()
        self.assertTrue(self.alice.has_perm(self.conditioned, self.cat_a))
        self.assertEqual(len(self.log.calls), 1)
        self.assertFalse(self.alice.has_perm(self.conditioned, self.cat_b))
        self.assertEqual(len(self.log.calls), 2)

    def test_queryset_callable_raises_when_callbacks_disabled(self):
        self._assert_zero_queryset_callbacks()
        self.assertEqual(self.log.calls, [])
