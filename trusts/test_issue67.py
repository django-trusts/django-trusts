"""Child H: first historical TUP→Trust←Category reader (issue #67).

Migrates the trustee half of ``ContentQuerySet.permitted`` for the
explicitly registered Category terminal. Backend ``has_perm`` stays on
the old path. Isolated core tests keep constructing their own
``TrustsRegistry()``.
"""

import types
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import models
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps

from tests.apps import TestsConfig
import tests as tests_module
from tests.models import Category, Ticket
from trusts.apps import AppConfig as TrustsAppConfig
from trusts.conditions import condition_refs
from trusts.core import (
    Ref,
    RelationPlan,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.models import (
    Content,
    Trust,
    TrustUserPermission,
)
from trusts.query import trust_grant_q
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


def _new_contributor(apps_registry):
    contributor = TestsConfig('tests', tests_module)
    contributor.apps = apps_registry
    return contributor


class TrustsRegistryOwnershipTest(SimpleTestCase):
    def test_package_registry_is_created_in_init_not_replaced_by_ready(self):
        import trusts

        config = TrustsAppConfig('trusts', trusts)
        self.assertIsInstance(config.registry, TrustsRegistry)
        self.assertEqual(config.registry.records, ())
        first = config.registry
        config.ready()
        self.assertIs(config.registry, first)

        live = apps.get_app_config('trusts')
        before = live.registry
        live.ready()
        self.assertIs(live.registry, before)

    def test_reader_obtains_registry_via_app_config_not_package_root(self):
        import trusts

        live = apps.get_app_config('trusts').registry
        self.assertIsInstance(live, TrustsRegistry)
        self.assertIsNone(getattr(trusts, 'registry', None))
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RelationPlan', None))

    def test_isolated_core_registries_stay_independent(self):
        live = apps.get_app_config('trusts').registry
        isolated = TrustsRegistry()
        self.assertIsNot(isolated, live)
        self.assertEqual(isolated.records, ())
        self.assertTrue(live.records)

    def test_core_module_has_no_historical_import_or_global(self):
        import trusts.core as core

        forbidden = {
            'Trust',
            'Content',
            'Junction',
            'TrustUserPermission',
            'TrustGroupPermission',
            'Group',
            'Role',
            'Category',
        }
        self.assertFalse(forbidden.intersection(vars(core)))
        imported = {
            value.__name__
            for value in vars(core).values()
            if isinstance(value, types.ModuleType)
        }
        self.assertTrue(
            all(
                name == 'trusts.core' or not name.startswith('trusts.')
                for name in imported
            ),
            imported,
        )

    def test_trusts_does_not_import_or_discover_tests_category(self):
        import trusts.apps as trusts_apps
        import trusts.core as core
        import trusts.models as trusts_models

        for module in (trusts_apps, core, trusts_models):
            self.assertNotIn('Category', vars(module))


class ContributorIdempotenceTest(SimpleTestCase):
    def setUp(self):
        self.live_trusts = apps.get_app_config('trusts')
        self.live_registry = self.live_trusts.registry
        self.live_contributor = apps.get_app_config('trusts_tests')

    def tearDown(self):
        self.live_trusts.registry = self.live_registry
        self.live_contributor._trusts_tup_category_registry_id = self.live_registry

    def test_reenter_same_contributor_ready_is_noop(self):
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id,
            self.live_registry,
        )
        before = self.live_registry.records
        with patch.object(
            self.live_registry, 'register', wraps=self.live_registry.register,
        ) as register:
            self.live_contributor.ready()
        register.assert_not_called()
        self.assertEqual(self.live_registry.records, before)

    def test_different_root_category_registration_does_not_suppress_tup(self):
        class OtherCategoryGrant(models.Model):
            category = models.ForeignKey(Category, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        isolated = TrustsRegistry()
        other = Ref(OtherCategoryGrant)
        isolated.register(
            content=other.category, user=other.user, permission=other.permission,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertEqual(len(isolated.records), 2)
        roots = {record.root for record in isolated.records}
        self.assertEqual(roots, {OtherCategoryGrant, TrustUserPermission})
        plan = isolated.plan_for(Category)
        self.assertEqual(len(plan.records), 2)

    def test_conflicting_contribution_reaches_register_and_fails_closed(self):
        isolated = TrustsRegistry()
        j = Ref(TrustUserPermission)
        rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
        isolated.register(
            content=getattr(j.trust, rev),
            user=j.permission,
            permission=j.entity,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        with self.assertRaises(TrustsConfigurationError):
            contributor.ready()
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_category_registry_id', None)
        )
        self.assertEqual(len(isolated.records), 1)

    def test_new_appconfig_registry_receives_declaration_again(self):
        import trusts

        new_trusts = TrustsAppConfig('trusts', trusts)
        self.assertEqual(new_trusts.registry.records, ())
        new_apps = apps
        original = self.live_trusts.registry
        try:
            self.live_trusts.registry = new_trusts.registry
            contributor = _new_contributor(new_apps)
            contributor.ready()
            self.assertIs(
                contributor._trusts_tup_category_registry_id,
                new_trusts.registry,
            )
            self.assertEqual(len(new_trusts.registry.records), 1)
            record = new_trusts.registry.records[0]
            self.assertIs(record.root, TrustUserPermission)
            self.assertIs(record.content_model, Category._meta.concrete_model)
        finally:
            self.live_trusts.registry = original


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateToLiveRegistryTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = apps.get_app_config('trusts').registry
        tup_category = [
            record for record in live.records
            if record.root is TrustUserPermission
            and record.content_model is Category._meta.concrete_model
        ]
        self.assertEqual(len(tup_category), 1)
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertEqual(
            [
                record for record in live.records
                if record.root is TrustUserPermission
                and record.content_model is Category._meta.concrete_model
            ],
            tup_category,
        )


class CategoryPermittedRegistryTest(TestCase):
    def setUp(self):
        super().setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)

        self.alice = User.objects.create_user('alice', 'alice@example.com', 'x')
        self.bob = User.objects.create_user('bob', 'bob@example.com', 'x')
        self.carol = User.objects.create_user('carol', 'carol@example.com', 'x')
        for user in (self.alice, self.bob, self.carol):
            user.is_active = True
            user.save()

        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='Trust A')
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.bob, trust=root, title='Trust B')
        self.trust_b.save()

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

        self.carol_group = Group.objects.create(name='carol-group')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)

        self._reload()

        u, _p, o = condition_refs()
        Content.register_permission_condition(Category, 'named', o.name == 'keep')
        self.addCleanup(self._clear_named_condition)

    def _clear_named_condition(self):
        from trusts import utils

        short = utils.get_short_model_name(Category)
        codes = Content._conditions.get(short)
        if codes is not None:
            codes.pop('named', None)

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)

    def _direct_pks(self, perm, user):
        return {
            obj.pk for obj in Category.objects.all()
            if user.has_perm(perm, obj)
        }

    def test_live_declaration_uses_meta_reverse_not_hardcoded_accessor(self):
        registry = apps.get_app_config('trusts').registry
        rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
        self.assertNotEqual(rev, 'tests_category_content')
        record = registry.plan_for(Category).records[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Category._meta.concrete_model)
        self.assertEqual(record.content_field, 'trust__%s' % rev)
        self.assertEqual(record.user_field, 'entity')
        self.assertEqual(record.permission_field, 'permission')

    def test_alice_tup_grants_sibling_categories_on_trust_a_not_b(self):
        qs = Category.objects.permitted(self.change_code, self.alice)
        self.assertEqual(_pks(qs), {self.cat_a1.pk, self.cat_a2.pk})
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, self.cat_a2))
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_b))

    def test_bob_without_tup_is_denied(self):
        self.assertFalse(self.bob.has_perm(self.change_code, self.cat_a1))
        self.assertFalse(Category.objects.permitted(self.change_code, self.bob).exists())

    def test_wrong_permission_is_denied(self):
        self.assertFalse(self.alice.has_perm(self.add_code, self.cat_a1))
        self.assertFalse(Category.objects.permitted(self.add_code, self.alice).exists())

    def test_carol_group_only_grant_is_not_erased_by_trustee_branch(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        self.assertTrue(self.carol.has_perm(self.change_code, self.cat_a1))
        self.assertTrue(self.carol.has_perm(self.change_code, self.cat_a2))
        self.assertFalse(self.carol.has_perm(self.change_code, self.cat_b))
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.carol)),
            {self.cat_a1.pk, self.cat_a2.pk},
        )

    def test_has_perm_and_permitted_are_result_equivalent(self):
        for user, perm in (
            (self.alice, self.change_code),
            (self.bob, self.change_code),
            (self.carol, self.change_code),
            (self.alice, self.add_code),
        ):
            self.assertEqual(
                _pks(Category.objects.permitted(perm, user)),
                self._direct_pks(perm, user),
                (user.username, perm),
            )

    def test_permitted_is_lazy_paginated_and_one_query(self):
        qs = Category.objects.permitted(self.change_code, self.alice)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.cat_a1.pk, self.cat_a2.pk})
        page = Category.objects.permitted(
            self.change_code, self.alice,
        ).order_by('pk')[:1]
        self.assertIsNone(page._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.cat_a1])

    def test_no_tup_rows_deny_without_changing_registration(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Category).records)
        TrustUserPermission.objects.all().delete()
        self._reload()
        self.assertTrue(registry.plan_for(Category).records)
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a1))
        self.assertFalse(
            Category.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.carol)),
            {self.cat_a1.pk, self.cat_a2.pk},
        )

    def test_named_condition_constrains_the_complete_grant(self):
        conditioned = '%s:named' % self.change_code
        self.assertTrue(self.alice.has_perm(conditioned, self.cat_a1))
        self.assertFalse(self.alice.has_perm(conditioned, self.cat_a2))
        self.assertTrue(self.carol.has_perm(conditioned, self.cat_a1))
        self.assertFalse(self.carol.has_perm(conditioned, self.cat_a2))
        self.assertEqual(
            _pks(Category.objects.permitted(conditioned, self.alice)),
            {self.cat_a1.pk},
        )
        self.assertEqual(
            _pks(Category.objects.permitted(conditioned, self.carol)),
            {self.cat_a1.pk},
        )
        self.assertEqual(
            _pks(Category.objects.permitted(conditioned, self.alice)),
            self._direct_pks(conditioned, self.alice),
        )

    def test_unregistered_models_stay_on_old_trust_grant_q_path(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Category).records)
        self.assertFalse(registry.plan_for(Ticket).records)
        self.assertFalse(registry.plan_for(Trust).records)
        self.assertFalse(registry.plan_for(Group).records)

        from tests.models import Organization

        org = Organization.objects.create(name='Org', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='t', owner=self.alice,
            organization=org, status='open',
        )
        TrustUserPermission(
            trust=self.trust_a,
            entity=self.alice,
            permission=_perm(Ticket, 'change_ticket'),
        ).save()
        self._reload()

        with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
            list(Category.objects.permitted(self.change_code, self.alice))
            self.assertEqual(grant_q.call_count, 0)
            list(Ticket.objects.permitted('trusts_tests.change_ticket', self.alice))
            self.assertEqual(grant_q.call_count, 1)
            list(Trust.objects.permitted('trusts.change_trust', self.alice))
            self.assertEqual(grant_q.call_count, 2)
        self.assertIn(ticket.pk, _pks(
            Ticket.objects.permitted('trusts_tests.change_ticket', self.alice)
        ))

    def test_reader_uses_content_exists_not_filter_authorized(self):
        registry = apps.get_app_config('trusts').registry
        with patch.object(registry, 'filter_authorized') as filtered:
            with patch.object(
                RelationPlan, 'content_exists', wraps=RelationPlan.content_exists,
            ) as exists:
                list(Category.objects.permitted(self.change_code, self.carol))
        filtered.assert_not_called()
        self.assertEqual(exists.call_count, 1)

    def test_inactive_and_anonymous_remain_empty(self):
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(
            Category.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertFalse(self.alice.has_perm(self.change_code, self.cat_a1))
        self.assertFalse(
            Category.objects.permitted(self.change_code, AnonymousUser()).exists()
        )
