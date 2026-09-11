"""S6: Junction-backed Group contribution and backend routing (issue #85).

The host test app contributes ``TrustUserPermission → Trust ← Junction
→ Group`` onto the configured Trusts handle. Group instance and
QuerySet authorization use the registered plan. Structural and
behavioral tests only — no source-token or ``inspect.getsource``
assertions.
"""

from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import models
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import isolate_apps

from tests.apps import (
    TestsConfig,
    install_writable_registry,
    junction_content_field,
    junction_group_content_ref,
    override_apps_ready,
)
from tests.backends import MixinOnlyBackend
import tests as tests_module
from tests.models import Category, Organization, TestGroupJunction, Ticket
from trusts.apps import AppConfig as TrustsAppConfig
from trusts.backends import TrustModelBackend
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


CONCRETE = 'trusts.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'


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


def _group_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Group._meta.concrete_model
    ]


def _category_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Category._meta.concrete_model
    ]


def _ticket_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Ticket._meta.concrete_model
    ]


def _contribute_group(registry, junction_model=TestGroupJunction):
    j = Ref(TrustUserPermission)
    registry.register(
        content=junction_group_content_ref(j, junction_model),
        user=j.entity,
        permission=j.permission,
    )


def _j1_lookup(junction_model=TestGroupJunction):
    rev = junction_model._meta.get_field('trust').remote_field.get_accessor_name()
    content_name = junction_content_field(junction_model).name
    return rev, content_name, 'trust__%s__%s' % (rev, content_name)


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


class GroupContributionIdempotenceTest(SimpleTestCase):
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
            self.live_contributor._trusts_tup_group_registry_id,
            self.live_registry,
        )
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id,
            self.live_contributor._trusts_tup_group_registry_id,
        )
        before = self.live_registry.records
        with patch.object(
            self.live_registry, 'register', wraps=self.live_registry.register,
        ) as register:
            self.live_contributor.ready()
        register.assert_not_called()
        self.assertEqual(self.live_registry.records, before)

    def test_category_and_ticket_sentinels_do_not_complete_group(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        contributor._trusts_tup_category_registry_id = isolated
        contributor._trusts_tup_ticket_registry_id = isolated
        with override_apps_ready(False):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_ticket_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_group_registry_id, isolated)
        self.assertEqual(len(_category_rows(isolated)), 0)
        self.assertEqual(len(_ticket_rows(isolated)), 0)
        self.assertEqual(len(_group_rows(isolated)), 1)

    def test_different_root_group_registration_does_not_suppress_tup(self):
        class OtherGroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        isolated = TrustsRegistry()
        other = Ref(OtherGroupGrant)
        isolated.register(
            content=other.group, user=other.user, permission=other.permission,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        with override_apps_ready(False):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_group_registry_id, isolated)
        roots = {record.root for record in isolated.records}
        self.assertEqual(roots, {OtherGroupGrant, TrustUserPermission})
        plan = isolated.plan_for(Group)
        self.assertEqual(len(plan.records), 2)
        self.assertEqual(len(_group_rows(isolated)), 1)

    def test_conflicting_contribution_fails_closed_without_group_sentinel(self):
        isolated = TrustsRegistry()
        j = Ref(TrustUserPermission)
        isolated.register(
            content=junction_group_content_ref(j, TestGroupJunction),
            user=j.permission,
            permission=j.entity,
        )
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        with override_apps_ready(False):
            with self.assertRaises(TrustsConfigurationError):
                contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_ticket_registry_id, isolated)
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_group_registry_id', None)
        )
        self.assertEqual(len(isolated.records), 3)
        self.assertEqual(len(_group_rows(isolated)), 1)
        with override_apps_ready(False):
            with self.assertRaises(TrustsConfigurationError):
                contributor.ready()
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_group_registry_id', None)
        )
        self.assertEqual(len(isolated.records), 3)

    def test_new_appconfig_registry_receives_declaration_again(self):
        import trusts

        new_trusts = TrustsAppConfig('trusts', trusts)
        original = self.live_registry
        try:
            self.live_trusts.registry = new_trusts.registry
            contributor = _new_contributor(apps)
            with override_apps_ready(False):
                contributor.ready()
            self.assertIs(contributor._trusts_tup_group_registry_id, new_trusts.registry)
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
            self.assertEqual(len(_group_rows(new_trusts.registry)), 1)
            self.assertEqual(self.live_registry.records, original.records)
        finally:
            self.live_trusts.registry = original

    def test_declaration_is_j1_metadata_derived_and_independent_of_contents(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        contributor = _new_contributor(apps)
        remote = TestGroupJunction._meta.get_field('trust').remote_field
        with patch.object(
            remote, 'get_accessor_name', wraps=remote.get_accessor_name,
        ) as accessor:
            with patch.object(
                TestGroupJunction, 'get_content_model',
                wraps=TestGroupJunction.get_content_model,
            ) as content_model:
                self.assertFalse(hasattr(Content, '_contents'))
                with override_apps_ready(False):
                    contributor.ready()
        accessor.assert_called()
        content_model.assert_called()
        rev, content_name, lookup = _j1_lookup()
        self.assertEqual(len(_group_rows(isolated)), 1)
        record = _group_rows(isolated)[0]
        self.assertIs(record.root, TrustUserPermission)
        self.assertIs(record.content_model, Group._meta.concrete_model)
        self.assertEqual(record.content_path, ('trust', rev, content_name))
        self.assertEqual(record.content_field, lookup)
        self.assertEqual(record.user_field, 'entity')
        self.assertEqual(record.permission_field, 'permission')
        self.assertEqual(record.content_target, Group._meta.pk.attname)
        self.assertNotEqual(record.content_field, 'trust')
        self.assertNotEqual(record.content_path, ('trust', rev))
        self.assertFalse(isolated.plan_for(TestGroupJunction).records)
        self.assertIs(contributor._trusts_tup_group_registry_id, isolated)

    def test_swapped_live_registry_receives_declaration_again(self):
        isolated = TrustsRegistry()
        self.live_trusts.registry = isolated
        with override_apps_ready(False):
            self.live_contributor.ready()
        self.assertIs(self.live_contributor._trusts_tup_group_registry_id, isolated)
        self.assertEqual(len(_group_rows(isolated)), 1)
        self.assertEqual(len(_category_rows(isolated)), 1)
        self.assertEqual(len(_ticket_rows(isolated)), 1)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateGroupContributionTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = apps.get_app_config('trusts').registry
        tup_group = _group_rows(live)
        self.assertEqual(len(tup_group), 1)
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
        self.assertEqual(_group_rows(live), tup_group)


class GroupContributionPathTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_omitted_ambiguous_path_fails_before_writing(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            contributor = _new_contributor(apps)
            before_a = self.live.registries[CONCRETE].records
            with self.assertRaises(TrustsConfigurationError) as ctx:
                contributor.ready()
            self.assertIn('explicit path', str(ctx.exception))
            self.assertNotIn(MIXIN, self.live.registries)
            self.assertEqual(self.live.registries[CONCRETE].records, before_a)
            self.assertIsNone(
                getattr(contributor, '_trusts_tup_group_registry_id', None)
            )

    def test_no_mixin_fan_out(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            handle_b = self.live.configured_backend(MIXIN)
            self.assertFalse(handle_b.registry.plan_for(Group).records)
            handle_a = self.live.configured_backend(CONCRETE)
            self.assertTrue(handle_a.registry.plan_for(Group).records)
            self.assertFalse(handle_a.registry.plan_for(TestGroupJunction).records)

    def test_unconfigured_path_fails_loud(self):
        with self.assertRaises(TrustsConfigurationError):
            self.live.configured_backend(MIXIN)

    def test_duplicate_exact_paths_dedupe(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, CONCRETE)):
            handle = self.live.configured_backend()
            self.assertEqual(handle.path, CONCRETE)
            self.assertTrue(handle.registry.plan_for(Group).records)
            self.assertEqual(len(_group_rows(handle.registry)), 1)


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
        self.trust_a = Trust(settlor=self.alice, trust=root, title='S6 A %s' % suffix)
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='S6 B %s' % suffix)
        self.trust_b.save()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)


class GroupAuthorizationRegistryTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('auth')
        self.group_a1 = Group.objects.create(name='s6-a1')
        self.group_a2 = Group.objects.create(name='s6-a2')
        self.group_b = Group.objects.create(name='s6-b')
        TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group_a1, name='j-a1',
        )
        TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group_a2, name='j-a2',
        )
        TestGroupJunction.objects.create(
            trust=self.trust_b, content=self.group_b, name='j-b',
        )
        self.change = _perm(Group, 'change_group')
        self.add = _perm(Group, 'add_group')
        self.change_code = 'auth.change_group'
        self.add_code = 'auth.add_group'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s6')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self.cat_a = Category.objects.create(trust=self.trust_a, name='s6-cat')
        self.cat_change = _perm(Category, 'change_category')
        self.cat_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.cat_change,
        ).save()
        self._reload()

    def test_live_declaration_is_on_the_configured_handle(self):
        handle = apps.get_app_config('trusts').configured_backend()
        self.assertTrue(handle.registry.plan_for(Group).records)
        self.assertFalse(handle.registry.plan_for(TestGroupJunction).records)
        rev, content_name, lookup = _j1_lookup()
        record = handle.registry.plan_for(Group).records[0]
        self.assertEqual(record.content_path, ('trust', rev, content_name))
        self.assertEqual(record.content_field, lookup)

    def test_direct_trustee_allow_and_deny(self):
        self.assertTrue(self.alice.has_perm(self.change_code, self.group_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, self.group_a2))
        self.assertFalse(self.alice.has_perm(self.change_code, self.group_b))
        self.assertFalse(self.alice.has_perm(self.add_code, self.group_a1))
        self.assertFalse(self.bob.has_perm(self.change_code, self.group_a1))

    def test_group_only_grant_allow_and_deny(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        self.assertTrue(self.carol.has_perm(self.change_code, self.group_a1))
        self.assertTrue(self.carol.has_perm(self.change_code, self.group_a2))
        self.assertFalse(self.carol.has_perm(self.change_code, self.group_b))
        self.assertFalse(self.carol.has_perm(self.add_code, self.group_a1))

    def test_instance_and_queryset_has_perm_has_perms(self):
        qs = Group.objects.filter(pk__in=[self.group_a1.pk, self.group_a2.pk])
        self.assertTrue(self.alice.has_perm(self.change_code, qs))
        self.assertTrue(self.alice.has_perms((self.change_code,), self.group_a1))
        self.assertTrue(self.alice.has_perms((self.change_code,), qs))
        self.assertFalse(self.alice.has_perms((self.add_code,), self.group_a1))
        self.assertFalse(self.alice.has_perms((self.change_code, self.add_code), qs))
        self.assertFalse(
            self.alice.has_perm(
                self.change_code,
                Group.objects.filter(pk__in=[self.group_a1.pk, self.group_b.pk]),
            )
        )

    def test_mixed_trust_all_match_denies(self):
        mixed = Group.objects.filter(pk__in=[self.group_a1.pk, self.group_b.pk])
        self.assertFalse(self.alice.has_perm(self.change_code, mixed))
        self.assertFalse(self.carol.has_perm(self.change_code, mixed))
        self.assertFalse(self.bob.has_perm(self.change_code, mixed))

    def test_enumeration_parity_and_direct_vs_group_split(self):
        alice_all = self.alice.get_all_permissions(self.group_a1)
        alice_group = self.alice.get_group_permissions(self.group_a1)
        self.assertIn(self.change_code, alice_all)
        self.assertNotIn(self.change_code, alice_group)
        self.assertEqual(alice_group, set())
        carol_all = self.carol.get_all_permissions(self.group_a1)
        carol_group = self.carol.get_group_permissions(self.group_a1)
        self.assertIn(self.change_code, carol_all)
        self.assertIn(self.change_code, carol_group)
        self.assertNotIn(self.add_code, carol_all)
        qs = Group.objects.filter(pk__in=[self.group_a1.pk, self.group_a2.pk])
        self.assertIn(self.change_code, self.alice.get_all_permissions(qs))
        self.assertEqual(self.alice.get_group_permissions(qs), set())
        self.assertIn(self.change_code, self.carol.get_group_permissions(qs))
        self.assertEqual(self.bob.get_all_permissions(self.group_a1), set())
        self.assertEqual(self.alice.get_all_permissions(self.group_b), set())

    def test_wrong_user_perm_sibling_inactive_anonymous_obj_none(self):
        self.assertFalse(self.bob.has_perm(self.change_code, self.group_a1))
        self.assertFalse(self.alice.has_perm(self.add_code, self.group_a1))
        self.assertFalse(self.alice.has_perm(self.change_code, self.group_b))
        self.assertFalse(self.alice.has_perm(self.change_code))
        self.assertEqual(self.alice.get_all_permissions(), set())
        self.assertEqual(self.alice.get_group_permissions(), set())
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(self.alice.has_perm(self.change_code, self.group_a1))
        self.assertEqual(self.alice.get_all_permissions(self.group_a1), set())
        anon = AnonymousUser()
        self.assertFalse(anon.has_perm(self.change_code, self.group_a1))
        self.assertEqual(anon.get_all_permissions(self.group_a1), set())

    def test_group_does_not_reach_get_trusts_or_filter_by_content(self):
        self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
        self.assertFalse(hasattr(Trust.objects, 'filter_by_content'))
        qs = Group.objects.filter(pk=self.group_a1.pk)
        self.assertTrue(self.alice.has_perm(self.change_code, self.group_a1))
        self.assertTrue(self.alice.has_perm(self.change_code, qs))
        self.assertIn(
            self.change_code,
            self.alice.get_all_permissions(self.group_a1),
        )
        self.assertIn(
            self.change_code,
            self.carol.get_group_permissions(self.group_a1),
        )

    def test_category_ticket_trust_unchanged(self):
        self.assertTrue(self.alice.has_perm(self.cat_code, self.cat_a))
        self.assertFalse(self.bob.has_perm(self.cat_code, self.cat_a))
        child = Trust(settlor=self.alice, trust=self.trust_a, title='s6-child')
        child.save()
        change_trust = _perm(Trust, 'change_trust')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=change_trust,
        ).save()
        org = Organization.objects.create(name='s6-org', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='s6-t', owner=self.alice,
            organization=org, status='open',
        )
        ticket_change = _perm(Ticket, 'change_ticket')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=ticket_change,
        ).save()
        self._reload()
        self.assertTrue(self.alice.has_perm('trusts.change_trust', child))
        self.assertFalse(self.bob.has_perm('trusts.change_trust', child))
        self.assertTrue(self.alice.has_perm('trusts_tests.change_ticket', ticket))
        self.assertFalse(self.bob.has_perm('trusts_tests.change_ticket', ticket))

    def test_protected_group_membership_is_not_a_category_trustee(self):
        self.alice.groups.add(self.group_a1)
        self._reload()
        lonely = Category.objects.create(trust=self.trust_b, name='lonely')
        self.assertFalse(self.alice.has_perm(self.cat_code, lonely))
        self.assertTrue(self.alice.has_perm(self.change_code, self.group_a1))

    def test_one_sql_grant_all_match_and_enumeration(self):
        extras = [Group.objects.create(name='s6-extra-%s' % i) for i in range(8)]
        for extra in extras:
            TestGroupJunction.objects.create(
                trust=self.trust_a, content=extra, name='j-%s' % extra.pk,
            )
        qs = Group.objects.filter(
            pk__in=[self.group_a1.pk, self.group_a2.pk] + [g.pk for g in extras],
        )
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.change_code, self.group_a1))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.change_code, qs))
        with self.assertNumQueries(1):
            self.assertIn(self.change_code, self.alice.get_all_permissions(qs))
        with self.assertNumQueries(1):
            self.assertIn(self.change_code, self.carol.get_group_permissions(qs))
        handle = apps.get_app_config('trusts').configured_backend()
        plan = handle.registry.plan_for(qs, user=self.alice)
        with self.assertNumQueries(1):
            self.assertTrue(
                list(plan.common_permissions(self.alice, qs).values_list(
                    'codename', flat=True,
                ))
            )

    def test_create_under_trust_gate_opens_for_declared_group(self):
        with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
            pks = _pks(Trust.objects.filter_by_user_content_perm(
                self.alice, Group, 'change_group',
            ))
            self.assertGreaterEqual(grant_q.call_count, 1)
        self.assertEqual(pks, {self.trust_a.pk})
        self.assertFalse(
            Trust.objects.filter_by_user_content_perm(
                self.bob, Group, 'change_group',
            ).exists()
        )


class GroupCompilerIsolationTest(_RegistryRestoreMixin, _UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('iso')
        self.group = Group.objects.create(name='s6-iso')
        TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group, name='iso',
        )
        self.change = _perm(Group, 'change_group')
        self.change_code = 'auth.change_group'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.carol_group = Group.objects.create(name='carol-iso-s6')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self._reload()

    def test_mixin_only_without_plan_denies_tup_and_trustgroup(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            handle = self.live.configured_backend()
            self.assertFalse(handle.registry.plan_for(Group).records)
            self.assertFalse(handle.historical_fallback)
            mixin = MixinOnlyBackend()
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.group))
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, self.group))
            self.assertEqual(mixin.get_all_permissions(self.alice, self.group), set())
            self.assertEqual(mixin.get_group_permissions(self.carol, self.group), set())
            qs = Group.objects.filter(pk=self.group.pk)
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, qs))

    def test_mixin_only_with_plan_gets_trustee_not_historical_group(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            install_writable_registry(self.live, MIXIN, _contribute_group)
            handle = self.live.configured_backend()
            mixin = MixinOnlyBackend()
            self.assertTrue(mixin.has_perm(self.alice, self.change_code, self.group))
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, self.group))
            self.assertIn(
                self.change_code,
                mixin.get_all_permissions(self.alice, self.group),
            )
            self.assertEqual(mixin.get_group_permissions(self.carol, self.group), set())
            qs = Group.objects.filter(pk=self.group.pk)
            self.assertTrue(mixin.has_perm(self.alice, self.change_code, qs))
            self.assertFalse(mixin.has_perm(self.carol, self.change_code, qs))

    def test_concrete_keeps_trustee_and_historical_group(self):
        concrete = TrustModelBackend()
        self.assertTrue(concrete.has_perm(self.alice, self.change_code, self.group))
        self.assertTrue(concrete.has_perm(self.carol, self.change_code, self.group))
        self.assertIn(
            self.change_code,
            concrete.get_group_permissions(self.carol, self.group),
        )

    def test_inapplicable_mixin_neither_adds_nor_suppresses_concrete(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN, CONCRETE)):
            mixin = MixinOnlyBackend()
            concrete = TrustModelBackend()
            self.assertFalse(
                self.live.configured_backend(MIXIN).registry.plan_for(Group).records
            )
            self.assertTrue(
                self.live.configured_backend(CONCRETE).registry.plan_for(Group).records
            )
            self.assertFalse(mixin.has_perm(self.alice, self.change_code, self.group))
            self.assertTrue(concrete.has_perm(self.alice, self.change_code, self.group))
            self.assertTrue(self.alice.has_perm(self.change_code, self.group))
            qs = Group.objects.filter(pk=self.group.pk)
            self.assertTrue(mixin._is_collection_coordinator())
            self.assertTrue(mixin.has_perm(self.alice, self.change_code, qs))
            with self.assertNumQueries(0):
                self.assertFalse(concrete.has_perm(self.alice, self.change_code, qs))


class GroupPlanUsesContentExistsTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('exists')
        self.group = Group.objects.create(name='s6-exists')
        TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group, name='exists',
        )
        self.change = _perm(Group, 'change_group')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()

    def test_authorization_uses_content_exists_not_filter_authorized(self):
        registry = apps.get_app_config('trusts').registry
        plan = registry.plan_for(
            self.group, user=self.alice, permission=self.change,
        )
        with patch.object(registry, 'filter_authorized') as filtered:
            with patch.object(
                RelationPlan, 'content_exists', wraps=plan.content_exists,
            ) as exists:
                self.assertTrue(self.alice.has_perm('auth.change_group', self.group))
        filtered.assert_not_called()
        self.assertGreaterEqual(exists.call_count, 1)
