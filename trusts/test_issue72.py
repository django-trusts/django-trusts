"""S2: external Ticket AppConfig contribution (issue #72).

Registers ``TrustUserPermission → Trust ← Ticket`` from
``tests.apps.TestsConfig.ready()`` so ``Ticket.objects.permitted(...)``
uses the common relation plan. Ticket has its own sentinel; Category's
sentinel is not reused. Backend ``has_perm`` and
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
from tests.models import Category, Organization, Ticket
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


def _new_contributor(apps_registry):
    contributor = TestsConfig('tests', tests_module)
    contributor.apps = apps_registry
    return contributor


def _ticket_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Ticket._meta.concrete_model
    ]


def _category_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Category._meta.concrete_model
    ]


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


class TicketContributionIdempotenceTest(SimpleTestCase):
    def setUp(self):
        self.live_trusts = apps.get_app_config('trusts')
        self.live_registry = self.live_trusts.registry
        self.live_contributor = apps.get_app_config('trusts_tests')
        self.live_category_sentinel = getattr(
            self.live_contributor, '_trusts_tup_category_registry_id', None
        )
        self.live_ticket_sentinel = getattr(
            self.live_contributor, '_trusts_tup_ticket_registry_id', None
        )
        self.live_group_sentinel = getattr(
            self.live_contributor, '_trusts_tup_group_registry_id', None
        )

    def tearDown(self):
        self.live_trusts.registry = self.live_registry
        self.live_contributor._trusts_tup_category_registry_id = (
            self.live_category_sentinel
        )
        self.live_contributor._trusts_tup_ticket_registry_id = (
            self.live_ticket_sentinel
        )
        self.live_contributor._trusts_tup_group_registry_id = (
            self.live_group_sentinel
        )

    def test_reenter_same_contributor_ready_is_noop(self):
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id,
            self.live_registry,
        )
        self.assertIs(
            self.live_contributor._trusts_tup_ticket_registry_id,
            self.live_registry,
        )
        self.assertIs(
            self.live_contributor._trusts_tup_group_registry_id,
            self.live_registry,
        )
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id,
            self.live_contributor._trusts_tup_ticket_registry_id,
        )
        before = self.live_registry.records
        with patch.object(
            self.live_registry, 'register', wraps=self.live_registry.register,
        ) as register:
            self.live_contributor.ready()
        register.assert_not_called()
        self.assertEqual(self.live_registry.records, before)

    def test_category_sentinel_does_not_complete_ticket(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        contributor._trusts_tup_category_registry_id = isolated
        contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_ticket_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_group_registry_id, isolated)
        self.assertEqual(len(_category_rows(isolated)), 0)
        self.assertEqual(len(_ticket_rows(isolated)), 1)

    def test_different_root_ticket_registration_does_not_suppress_tup(self):
        class OtherTicketGrant(models.Model):
            ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        isolated = TrustsRegistry()
        other = Ref(OtherTicketGrant)
        isolated.register(
            content=other.ticket, user=other.user, permission=other.permission,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        contributor.ready()
        self.assertIs(contributor._trusts_tup_ticket_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_group_registry_id, isolated)
        roots = {record.root for record in isolated.records}
        self.assertEqual(
            roots, {OtherTicketGrant, TrustUserPermission},
        )
        plan = isolated.plan_for(Ticket)
        self.assertEqual(len(plan.records), 2)
        self.assertEqual(len(_ticket_rows(isolated)), 1)
        self.assertEqual(len(_category_rows(isolated)), 1)
        self.assertTrue(
            any(record.root is OtherTicketGrant for record in isolated.records)
        )

    def test_conflicting_contribution_fails_closed_without_ticket_sentinel(self):
        isolated = TrustsRegistry()
        j = Ref(TrustUserPermission)
        rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
        isolated.register(
            content=getattr(j.trust, rev),
            user=j.permission,
            permission=j.entity,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        with self.assertRaises(TrustsConfigurationError):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertEqual(len(isolated.records), 2)
        self.assertEqual(len(_category_rows(isolated)), 1)
        with self.assertRaises(TrustsConfigurationError):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertEqual(len(isolated.records), 2)

    def test_new_appconfig_registry_receives_declaration_again(self):
        import trusts

        new_trusts = TrustsAppConfig('trusts', trusts)
        self.assertEqual(new_trusts.registry.records, ())
        original = self.live_trusts.registry
        try:
            self.live_trusts.registry = new_trusts.registry
            contributor = _new_contributor(apps)
            contributor.ready()
            self.assertIs(
                contributor._trusts_tup_ticket_registry_id,
                new_trusts.registry,
            )
            self.assertIs(
                contributor._trusts_tup_category_registry_id,
                new_trusts.registry,
            )
            self.assertIs(
                contributor._trusts_tup_group_registry_id,
                new_trusts.registry,
            )
            self.assertIsNot(new_trusts.registry, self.live_registry)
            terminals = {
                record.content_model for record in new_trusts.registry.records
            }
            self.assertEqual(
                terminals,
                {
                    Category._meta.concrete_model,
                    Ticket._meta.concrete_model,
                    Group._meta.concrete_model,
                },
            )
            self.assertEqual(len(_ticket_rows(new_trusts.registry)), 1)
            record = _ticket_rows(new_trusts.registry)[0]
            self.assertIs(record.root, TrustUserPermission)
            self.assertEqual(self.live_registry.records, original.records)
        finally:
            self.live_trusts.registry = original

    def test_declaration_uses_meta_reverse_not_contents(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        remote = Ticket._meta.get_field('trust').remote_field
        with patch.object(
            remote, 'get_accessor_name', wraps=remote.get_accessor_name,
        ) as accessor:
            with patch.object(Content, '_contents', _UnusableContents()):
                contributor.ready()
        accessor.assert_called()
        rev = remote.get_accessor_name()
        self.assertEqual(len(_ticket_rows(isolated)), 1)
        record = _ticket_rows(isolated)[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Ticket._meta.concrete_model)
        self.assertEqual(record.content_field, 'trust__%s' % rev)
        self.assertEqual(record.user_field, 'entity')
        self.assertEqual(record.permission_field, 'permission')
        self.assertNotEqual(record.content_field, 'trust')
        self.assertIs(contributor._trusts_tup_ticket_registry_id, isolated)

    def test_swapped_live_registry_receives_declaration_again(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        self.live_contributor.ready()
        self.assertIs(self.live_contributor._trusts_tup_ticket_registry_id, isolated)
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id, isolated,
        )
        self.assertIs(self.live_trusts.registry, isolated)
        self.assertEqual(len(_ticket_rows(isolated)), 1)
        self.assertEqual(len(_category_rows(isolated)), 1)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateTicketContributionTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = apps.get_app_config('trusts').registry
        tup_ticket = _ticket_rows(live)
        tup_category = _category_rows(live)
        self.assertEqual(len(tup_ticket), 1)
        self.assertEqual(len(tup_category), 1)
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_category_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_group_registry_id', None)
        )
        self.assertEqual(_ticket_rows(live), tup_ticket)
        self.assertEqual(_category_rows(live), tup_category)


class TicketPermittedRegistryTest(TestCase):
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

        self.org = Organization.objects.create(name='Org', manager=self.alice)
        self.ticket_a1 = Ticket.objects.create(
            trust=self.trust_a, title='keep', owner=self.alice,
            organization=self.org, status='open',
        )
        self.ticket_a2 = Ticket.objects.create(
            trust=self.trust_a, title='drop', owner=self.carol,
            organization=self.org, status='open',
        )
        self.ticket_b = Ticket.objects.create(
            trust=self.trust_b, title='other', owner=self.bob,
            organization=self.org, status='open',
        )

        self.change = _perm(Ticket, 'change_ticket')
        self.add = _perm(Ticket, 'add_ticket')
        self.change_code = 'trusts_tests.change_ticket'
        self.add_code = 'trusts_tests.add_ticket'
        self.change_own = 'trusts_tests.change_ticket:meta_own'

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
            obj.pk for obj in Ticket.objects.all()
            if user.has_perm(perm, obj)
        }

    def test_live_declaration_uses_meta_reverse_not_hardcoded_accessor(self):
        registry = apps.get_app_config('trusts').registry
        rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
        self.assertNotEqual(rev, 'tests_ticket_content')
        record = registry.plan_for(Ticket).records[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Ticket._meta.concrete_model)
        self.assertEqual(record.content_field, 'trust__%s' % rev)
        self.assertEqual(record.user_field, 'entity')
        self.assertEqual(record.permission_field, 'permission')

    def test_alice_tup_grants_sibling_tickets_on_trust_a_not_b(self):
        qs = Ticket.objects.permitted(self.change_code, self.alice)
        self.assertEqual(_pks(qs), {self.ticket_a1.pk, self.ticket_a2.pk})
        self.assertTrue(self.alice.has_perm(self.change_code, self.ticket_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, self.ticket_a2))
        self.assertFalse(self.alice.has_perm(self.change_code, self.ticket_b))

    def test_bob_without_tup_is_denied(self):
        self.assertFalse(self.bob.has_perm(self.change_code, self.ticket_a1))
        self.assertFalse(Ticket.objects.permitted(self.change_code, self.bob).exists())

    def test_wrong_permission_is_denied(self):
        self.assertFalse(self.alice.has_perm(self.add_code, self.ticket_a1))
        self.assertFalse(Ticket.objects.permitted(self.add_code, self.alice).exists())

    def test_carol_group_only_grant_is_not_erased_by_trustee_branch(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        self.assertTrue(self.carol.has_perm(self.change_code, self.ticket_a1))
        self.assertTrue(self.carol.has_perm(self.change_code, self.ticket_a2))
        self.assertFalse(self.carol.has_perm(self.change_code, self.ticket_b))
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_code, self.carol)),
            {self.ticket_a1.pk, self.ticket_a2.pk},
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
                _pks(Ticket.objects.permitted(perm, user)),
                self._direct_pks(perm, user),
                (user.username, perm),
            )

    def test_permitted_is_lazy_paginated_and_one_query(self):
        qs = Ticket.objects.permitted(self.change_code, self.alice)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.ticket_a1.pk, self.ticket_a2.pk})
        page = Ticket.objects.permitted(
            self.change_code, self.alice,
        ).order_by('pk')[:1]
        self.assertIsNone(page._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.ticket_a1])

    def test_no_tup_rows_deny_without_changing_registration(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Ticket).records)
        TrustUserPermission.objects.all().delete()
        self._reload()
        self.assertTrue(registry.plan_for(Ticket).records)
        self.assertFalse(self.alice.has_perm(self.change_code, self.ticket_a1))
        self.assertFalse(
            Ticket.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_code, self.carol)),
            {self.ticket_a1.pk, self.ticket_a2.pk},
        )

    def test_meta_own_is_condition_overlay_and_does_not_create_a_grant(self):
        self.assertTrue(self.alice.has_perm(self.change_own, self.ticket_a1))
        self.assertFalse(self.alice.has_perm(self.change_own, self.ticket_a2))
        self.assertFalse(self.carol.has_perm(self.change_own, self.ticket_a1))
        self.assertTrue(self.carol.has_perm(self.change_own, self.ticket_a2))
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_own, self.alice)),
            {self.ticket_a1.pk},
        )
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_own, self.carol)),
            {self.ticket_a2.pk},
        )
        self.assertFalse(
            Ticket.objects.permitted(self.change_own, self.bob).exists()
        )

        ticket_dave = Ticket.objects.create(
            trust=self.trust_a, title='dave', owner=self.dave,
            organization=self.org, status='open',
        )
        self.assertFalse(self.dave.has_perm(self.change_code, ticket_dave))
        self.assertFalse(self.dave.has_perm(self.change_own, ticket_dave))
        self.assertFalse(
            Ticket.objects.permitted(self.change_own, self.dave).exists()
        )

        TrustUserPermission.objects.filter(entity=self.alice).delete()
        self._reload()
        self.assertFalse(self.alice.has_perm(self.change_own, self.ticket_a1))
        self.assertFalse(
            Ticket.objects.permitted(self.change_own, self.alice).exists()
        )
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_own, self.carol)),
            {self.ticket_a2.pk},
        )

    def test_sibling_and_mixed_trust_isolation(self):
        TrustUserPermission(
            trust=self.trust_b, entity=self.alice, permission=self.add,
        ).save()
        self._reload()
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.change_code, self.alice)),
            {self.ticket_a1.pk, self.ticket_a2.pk},
        )
        self.assertEqual(
            _pks(Ticket.objects.permitted(self.add_code, self.alice)),
            {self.ticket_b.pk},
        )
        self.assertNotIn(
            self.ticket_b.pk,
            _pks(Ticket.objects.permitted(self.change_code, self.alice)),
        )
        self.assertNotIn(
            self.ticket_a1.pk,
            _pks(Ticket.objects.permitted(self.add_code, self.alice)),
        )

    def test_reader_uses_content_exists_not_filter_authorized(self):
        registry = apps.get_app_config('trusts').registry
        plan = registry.plan_for(
            Ticket.objects.all(), user=self.carol, permission=self.change,
        )
        with patch.object(registry, 'filter_authorized') as filtered:
            with patch.object(
                RelationPlan, 'content_exists', wraps=plan.content_exists,
            ) as exists:
                list(Ticket.objects.permitted(self.change_code, self.carol))
        filtered.assert_not_called()
        self.assertEqual(exists.call_count, 1)

    def test_junction_stays_on_old_path(self):
        registry = apps.get_app_config('trusts').registry
        self.assertTrue(registry.plan_for(Category).records)
        self.assertTrue(registry.plan_for(Trust).records)
        self.assertTrue(registry.plan_for(Ticket).records)
        self.assertTrue(registry.plan_for(Group).records)

    def test_create_under_trust_stays_on_trust_grant_q(self):
        with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
            pks = _pks(Trust.objects.filter_by_user_content_perm(
                self.alice, Ticket, 'change_ticket',
            ))
            self.assertGreaterEqual(grant_q.call_count, 1)
        self.assertIn(self.trust_a.pk, pks)
        self.assertNotIn(self.trust_b.pk, pks)

    def test_inactive_and_anonymous_remain_empty(self):
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(
            Ticket.objects.permitted(self.change_code, self.alice).exists()
        )
        self.assertFalse(self.alice.has_perm(self.change_code, self.ticket_a1))
        self.assertFalse(
            Ticket.objects.permitted(self.change_code, AnonymousUser()).exists()
        )
