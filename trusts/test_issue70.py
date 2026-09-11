"""S1: package-owned Trust-as-content contribution (issue #70).

Registers ``TrustUserPermission → parent Trust ← child Trust`` on the
AppConfig-owned ``TrustsRegistry`` so ``Trust.objects.permitted(...)``
uses the common relation plan. Backend ``has_perm`` and
``filter_by_user_content_perm`` stay on the old path. Isolated core
tests keep constructing their own ``TrustsRegistry()``.
"""

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


class _UnusableContents(object):
    """Stand-in that fails if the static content registry is read."""

    def __getitem__(self, key):
        raise AssertionError('Content._contents must not be consulted')

    def __contains__(self, key):
        raise AssertionError('Content._contents must not be consulted')

    def get(self, *args, **kwargs):
        raise AssertionError('Content._contents must not be consulted')

    def keys(self):
        raise AssertionError('Content._contents must not be consulted')

    def values(self):
        raise AssertionError('Content._contents must not be consulted')

    def items(self):
        raise AssertionError('Content._contents must not be consulted')


class TrustContributionIdempotenceTest(SimpleTestCase):
    def setUp(self):
        self.live = apps.get_app_config('trusts')
        self.live_registry = self.live.registry
        self.live_sentinel = getattr(
            self.live, '_trusts_tup_trust_registry_id', None
        )

    def tearDown(self):
        self.live.registry = self.live_registry
        self.live._trusts_tup_trust_registry_id = self.live_sentinel

    def test_reenter_same_contributor_ready_is_noop(self):
        self.assertIs(self.live._trusts_tup_trust_registry_id, self.live_registry)
        before = self.live_registry.records
        with patch.object(
            self.live_registry, 'register', wraps=self.live_registry.register,
        ) as register:
            self.live.ready()
        register.assert_not_called()
        self.assertIs(self.live.registry, self.live_registry)
        self.assertEqual(self.live.registry.records, before)

    def test_ready_does_not_replace_registry(self):
        import trusts

        config = TrustsAppConfig('trusts', trusts)
        first = config.registry
        config.ready()
        self.assertIs(config.registry, first)
        self.assertIs(config._trusts_tup_trust_registry_id, first)

        before = self.live.registry
        self.live.ready()
        self.assertIs(self.live.registry, before)

    def test_different_root_trust_registration_does_not_suppress_tup(self):
        class OtherTrustGrant(models.Model):
            trust = models.ForeignKey(Trust, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts'

        import trusts

        isolated = TrustsAppConfig('trusts', trusts)
        other = Ref(OtherTrustGrant)
        isolated.registry.register(
            content=other.trust, user=other.user, permission=other.permission,
        )
        isolated.ready()
        self.assertIs(isolated._trusts_tup_trust_registry_id, isolated.registry)
        self.assertEqual(len(isolated.registry.records), 2)
        roots = {record.root for record in isolated.registry.records}
        self.assertEqual(roots, {OtherTrustGrant, TrustUserPermission})
        plan = isolated.registry.plan_for(Trust)
        self.assertEqual(len(plan.records), 2)

    def test_conflicting_contribution_reaches_register_and_fails_closed(self):
        import trusts

        isolated = TrustsAppConfig('trusts', trusts)
        j = Ref(TrustUserPermission)
        rev = Trust._meta.get_field('trust').remote_field.get_accessor_name()
        isolated.registry.register(
            content=getattr(j.trust, rev),
            user=j.permission,
            permission=j.entity,
        )
        with self.assertRaises(TrustsConfigurationError):
            isolated.ready()
        self.assertIsNone(
            getattr(isolated, '_trusts_tup_trust_registry_id', None)
        )
        self.assertEqual(len(isolated.registry.records), 1)
        with self.assertRaises(TrustsConfigurationError):
            isolated.ready()
        self.assertIsNone(
            getattr(isolated, '_trusts_tup_trust_registry_id', None)
        )

    def test_new_appconfig_registry_receives_declaration_again(self):
        import trusts

        live_before = self.live_registry.records
        isolated = TrustsAppConfig('trusts', trusts)
        self.assertEqual(isolated.registry.records, ())
        isolated.ready()
        self.assertIs(isolated._trusts_tup_trust_registry_id, isolated.registry)
        self.assertIsNot(isolated.registry, self.live_registry)
        self.assertEqual(len(isolated.registry.records), 1)
        record = isolated.registry.records[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Trust._meta.concrete_model)
        self.assertEqual(self.live_registry.records, live_before)

    def test_declaration_uses_meta_reverse_not_contents(self):
        import trusts

        isolated = TrustsAppConfig('trusts', trusts)
        remote = Trust._meta.get_field('trust').remote_field
        with patch.object(
            remote, 'get_accessor_name', wraps=remote.get_accessor_name,
        ) as accessor:
            with patch.object(Content, '_contents', _UnusableContents()):
                isolated.ready()
        accessor.assert_called()
        rev = remote.get_accessor_name()
        self.assertEqual(len(isolated.registry.records), 1)
        record = isolated.registry.records[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Trust._meta.concrete_model)
        self.assertEqual(record.content_field, 'trust__%s' % rev)
        self.assertEqual(record.user_field, 'entity')
        self.assertEqual(record.permission_field, 'permission')
        self.assertNotEqual(record.content_field, 'trust')

    def test_swapped_live_registry_receives_declaration_again(self):
        isolated = TrustsRegistry()
        self.live.registry = isolated
        self.live.ready()
        self.assertIs(self.live._trusts_tup_trust_registry_id, isolated)
        self.assertIs(self.live.registry, isolated)
        tup_trust = [
            record for record in isolated.records
            if record.root is TrustUserPermission
            and record.content_model is Trust._meta.concrete_model
        ]
        self.assertEqual(len(tup_trust), 1)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateTrustContributionTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = apps.get_app_config('trusts').registry
        tup_trust = [
            record for record in live.records
            if record.root is TrustUserPermission
            and record.content_model is Trust._meta.concrete_model
        ]
        self.assertEqual(len(tup_trust), 1)
        self.assertFalse(self.isolated_apps.is_installed('trusts'))

        import trusts

        isolated = TrustsAppConfig('trusts', trusts)
        isolated.apps = self.isolated_apps
        isolated.ready()
        self.assertIs(isolated._trusts_tup_trust_registry_id, isolated.registry)
        self.assertIsNot(isolated.registry, live)
        self.assertEqual(
            [
                record for record in live.records
                if record.root is TrustUserPermission
                and record.content_model is Trust._meta.concrete_model
            ],
            tup_trust,
        )

        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertEqual(
            [
                record for record in live.records
                if record.root is TrustUserPermission
                and record.content_model is Trust._meta.concrete_model
            ],
            tup_trust,
        )


class TrustPermittedRegistryTest(TestCase):
    def setUp(self):
        super().setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)

        self.alice = User.objects.create_user('alice', 'alice@example.com', 'x')
        self.bob = User.objects.create_user('bob', 'bob@example.com', 'x')
        self.carol = User.objects.create_user('carol', 'carol@example.com', 'x')
        self.dave = User.objects.create_user('dave', 'dave@example.com', 'x')
        for user in (self.alice, self.bob, self.carol, self.dave):
            user.is_active = True
            user.save()

        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='Trust A')
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.bob, trust=root, title='Trust B')
        self.trust_b.save()

        self.child_a1 = Trust(
            settlor=self.alice, trust=self.trust_a, title='Child A1',
        )
        self.child_a1.save()
        self.child_a2 = Trust(
            settlor=self.carol, trust=self.trust_a, title='Child A2',
        )
        self.child_a2.save()
        self.child_b = Trust(
            settlor=self.bob, trust=self.trust_b, title='Child B',
        )
        self.child_b.save()

        self.change = _perm(Trust, 'change_trust')
        self.add = _perm(Trust, 'add_trust')
        self.change_code = 'trusts.change_trust'
        self.add_code = 'trusts.add_trust'
        self.change_own = 'trusts.change_trust:own'

        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()

        self.carol_group = Group.objects.create(name='carol-group')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)

        self._reload()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)
        self.dave = User.objects.get(pk=self.dave.pk)

    def _direct_pks(self, perm, user):
        return {
            obj.pk for obj in Trust.objects.all()
            if user.has_perm(perm, obj)
        }

    def test_alice_tup_grants_sibling_children_on_trust_a_not_b(self):
        qs = Trust.objects.permitted(self.change_code, self.alice)
        self.assertEqual(_pks(qs), {self.child_a1.pk, self.child_a2.pk})
        self.assertTrue(self.alice.has_perm(self.change_code, self.child_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, self.child_a2))
        self.assertFalse(self.alice.has_perm(self.change_code, self.child_b))
        self.assertFalse(self.alice.has_perm(self.change_code, self.trust_a))
        self.assertFalse(self.alice.has_perm(self.change_code, self.trust_b))

    def test_bob_without_tup_is_denied(self):
        self.assertFalse(self.bob.has_perm(self.change_code, self.child_a1))
        self.assertFalse(Trust.objects.permitted(self.change_code, self.bob).exists())

    def test_wrong_permission_is_denied(self):
        self.assertFalse(self.alice.has_perm(self.add_code, self.child_a1))
        self.assertFalse(Trust.objects.permitted(self.add_code, self.alice).exists())

    def test_carol_group_only_grant_is_not_erased_by_trustee_branch(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        self.assertTrue(self.carol.has_perm(self.change_code, self.child_a1))
        self.assertTrue(self.carol.has_perm(self.change_code, self.child_a2))
        self.assertFalse(self.carol.has_perm(self.change_code, self.child_b))
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_code, self.carol)),
            {self.child_a1.pk, self.child_a2.pk},
        )

    def test_has_perm_and_permitted_are_result_equivalent(self):
        for user, perm in (
            (self.alice, self.change_code),
            (self.bob, self.change_code),
            (self.carol, self.change_code),
            (self.alice, self.add_code),
            (self.alice, self.change_own),
            (self.carol, self.change_own),
            (self.bob, self.change_own),
        ):
            self.assertEqual(
                _pks(Trust.objects.permitted(perm, user)),
                self._direct_pks(perm, user),
                (user.username, perm),
            )

    def test_permitted_is_lazy_paginated_and_one_query(self):
        qs = Trust.objects.permitted(self.change_code, self.alice)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.child_a1.pk, self.child_a2.pk})
        page = Trust.objects.permitted(
            self.change_code, self.alice,
        ).order_by('pk')[:1]
        self.assertIsNone(page._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.child_a1])

    def test_no_tup_rows_deny_without_changing_registration(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Trust).records)
        TrustUserPermission.objects.all().delete()
        self._reload()
        self.assertTrue(registry.plan_for(Trust).records)
        self.assertFalse(self.alice.has_perm(self.change_code, self.child_a1))
        self.assertFalse(
            Trust.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_code, self.carol)),
            {self.child_a1.pk, self.child_a2.pk},
        )

    def test_own_is_condition_overlay_and_does_not_create_a_grant(self):
        self.assertTrue(self.alice.has_perm(self.change_own, self.child_a1))
        self.assertFalse(self.alice.has_perm(self.change_own, self.child_a2))
        self.assertFalse(self.carol.has_perm(self.change_own, self.child_a1))
        self.assertTrue(self.carol.has_perm(self.change_own, self.child_a2))
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_own, self.alice)),
            {self.child_a1.pk},
        )
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_own, self.carol)),
            {self.child_a2.pk},
        )
        self.assertFalse(
            Trust.objects.permitted(self.change_own, self.bob).exists()
        )

        child_dave = Trust(
            settlor=self.dave, trust=self.trust_a, title='Child Dave',
        )
        child_dave.save()
        self.assertFalse(self.dave.has_perm(self.change_code, child_dave))
        self.assertFalse(self.dave.has_perm(self.change_own, child_dave))
        self.assertFalse(
            Trust.objects.permitted(self.change_own, self.dave).exists()
        )

        TrustUserPermission.objects.filter(entity=self.alice).delete()
        self._reload()
        self.assertFalse(self.alice.has_perm(self.change_own, self.child_a1))
        self.assertFalse(
            Trust.objects.permitted(self.change_own, self.alice).exists()
        )
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_own, self.carol)),
            {self.child_a2.pk},
        )

    def test_sibling_and_mixed_parent_isolation(self):
        TrustUserPermission(
            trust=self.trust_b, entity=self.alice, permission=self.add,
        ).save()
        self._reload()
        self.assertEqual(
            _pks(Trust.objects.permitted(self.change_code, self.alice)),
            {self.child_a1.pk, self.child_a2.pk},
        )
        self.assertEqual(
            _pks(Trust.objects.permitted(self.add_code, self.alice)),
            {self.child_b.pk},
        )
        self.assertNotIn(
            self.child_b.pk,
            _pks(Trust.objects.permitted(self.change_code, self.alice)),
        )
        self.assertNotIn(
            self.child_a1.pk,
            _pks(Trust.objects.permitted(self.add_code, self.alice)),
        )

    def test_reader_uses_content_exists_not_filter_authorized(self):
        registry = apps.get_app_config('trusts').registry
        plan = registry.plan_for(
            Trust.objects.all(), user=self.carol, permission=self.change,
        )
        with patch.object(registry, 'filter_authorized') as filtered:
            with patch.object(
                RelationPlan, 'content_exists', wraps=plan.content_exists,
            ) as exists:
                list(Trust.objects.permitted(self.change_code, self.carol))
        filtered.assert_not_called()
        self.assertEqual(exists.call_count, 1)

    def test_create_under_trust_stays_on_trust_grant_q(self):
        with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
            pks = _pks(Trust.objects.filter_by_user_content_perm(
                self.alice, Trust, 'change_trust',
            ))
            self.assertGreaterEqual(grant_q.call_count, 1)
        self.assertIn(self.trust_a.pk, pks)
        self.assertNotIn(self.child_a1.pk, pks)
        self.assertNotIn(self.child_a2.pk, pks)
        self.assertNotIn(self.trust_b.pk, pks)
        self.assertNotIn(self.child_b.pk, pks)

    def test_ticket_and_junction_stay_on_old_path(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Category).records)
        self.assertTrue(registry.plan_for(Trust).records)
        self.assertFalse(registry.plan_for(Ticket).records)
        self.assertFalse(registry.plan_for(Group).records)

    def test_inactive_and_anonymous_remain_empty(self):
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(
            Trust.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertFalse(self.alice.has_perm(self.change_code, self.child_a1))
        self.assertFalse(
            Trust.objects.permitted(self.change_code, AnonymousUser()).exists()
        )
