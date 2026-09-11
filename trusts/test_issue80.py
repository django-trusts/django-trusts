"""S4: filter_by_user_content_perm registration gate (issue #80).

Aggregate support rule: any configured path with
``plan_for(content).records`` establishes that the terminal is known.
The grant stays ``trust_grant_q`` on Trust rows. Structural and
behavioral tests only — no source-token or ``inspect.getsource``
assertions.
"""

from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings

from tests.models import AutoAdminCategory, Category, Organization, Ticket
from trusts.core import (
    Ref,
    TrustsRegistry,
    any_plan_records,
)
from trusts.models import (
    Content,
    PermissionConditionNotQueryable,
    Trust,
    TrustUserPermission,
)
from trusts.query import trust_grant_q
from trusts.tests import (
    enable_local_group_grant,
    get_or_create_root_user,
)
from trusts.views import NewTeamForm


CONCRETE = 'trusts.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _perm(model, codename):
    return Permission.objects.get(
        content_type=ContentType.objects.get_for_model(model),
        codename=codename,
    )


def _contribute_category(registry):
    j = Ref(TrustUserPermission)
    rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
    registry.register(
        content=getattr(j.trust, rev),
        user=j.entity,
        permission=j.permission,
    )


def _contribute_ticket(registry):
    j = Ref(TrustUserPermission)
    rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
    registry.register(
        content=getattr(j.trust, rev),
        user=j.entity,
        permission=j.permission,
    )


class _Handle(object):
    """Isolated handle: registry only. Compiler must stay unused."""

    def __init__(self, registry, historical_fallback=True):
        self.registry = registry
        self.historical_fallback = historical_fallback
        self.compiler = _UnusedCompiler()


class _UnusedCompiler(object):
    historical_fallback = True

    def complete_exists(self, *args, **kwargs):
        raise AssertionError('compiler must not decide the create-under-trust gate')

    def group_exists(self, *args, **kwargs):
        raise AssertionError('compiler must not decide the create-under-trust gate')


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
        self.trust_a = Trust(settlor=self.alice, trust=root, title='S4 A %s' % suffix)
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='S4 B %s' % suffix)
        self.trust_b.save()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)


class AnyPlanRecordsGateRuleTest(SimpleTestCase):
    """Chosen aggregate: any path with plan records supports the terminal."""

    def test_any_path_establishes_support_empty_and_other_terminals_do_not(self):
        empty = TrustsRegistry()
        filled = TrustsRegistry()
        _contribute_category(filled)
        unused = _Handle(empty, historical_fallback=True)
        supporting = _Handle(filled, historical_fallback=False)
        self.assertFalse(any_plan_records((), Category))
        self.assertFalse(any_plan_records((unused,), Category))
        self.assertTrue(any_plan_records((unused, supporting), Category))
        self.assertTrue(any_plan_records((supporting, unused), Category))
        self.assertTrue(any_plan_records((supporting,), AutoAdminCategory))
        self.assertFalse(any_plan_records((supporting,), Organization))
        self.assertFalse(any_plan_records((supporting,), Group))
        self.assertFalse(any_plan_records((supporting,), Ticket))


class FilterByUserContentPermRegistryGateTest(
    _RegistryRestoreMixin, _UsersMixin, TestCase
):
    def setUp(self):
        super().setUp()
        self._make_users('gate')
        self.cat_a = Category.objects.create(trust=self.trust_a, name='s4-a')
        self.add = _perm(Category, 'add_category')
        self.change = _perm(Category, 'change_category')
        self.add_code = 'trusts_tests.add_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.add,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s4')
        self.carol.groups.add(self.carol_group)
        self.add.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.add)
        self._reload()

    def _filter(self, user, content=Category, perm='add_category', **kwargs):
        return Trust.objects.filter_by_user_content_perm(
            user, content, perm, **kwargs
        )

    def test_registered_model_is_lazy_distinct_and_one_query(self):
        extra = [
            Trust(settlor=self.alice, trust=Trust.objects.get_root(), title='S4 extra %s' % i)
            for i in range(8)
        ]
        Trust.objects.bulk_create(extra)
        qs = self._filter(self.alice)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            pks = _pks(qs)
        self.assertEqual(pks, {self.trust_a.pk})
        self.assertNotIn(self.trust_b.pk, pks)
        self.assertNotIn(Trust.objects.get_root().pk, pks)

    def test_instance_and_proxy_use_the_same_registered_terminal(self):
        self.assertEqual(
            _pks(self._filter(self.alice, self.cat_a)),
            {self.trust_a.pk},
        )
        self.assertEqual(
            _pks(self._filter(self.alice, AutoAdminCategory, 'add_category')),
            {self.trust_a.pk},
        )

    def test_correct_permission_grants_wrong_permission_and_trust_deny(self):
        self.assertEqual(_pks(self._filter(self.alice, Category, 'add')), {self.trust_a.pk})
        self.assertFalse(self._filter(self.alice, Category, 'change_category').exists())
        self.assertFalse(self._filter(self.bob, Category, 'add_category').exists())
        self.assertNotIn(self.trust_b.pk, _pks(self._filter(self.alice)))

    def test_group_grant_and_excluded_root(self):
        self.assertIn(self.trust_a.pk, _pks(self._filter(self.carol)))
        root = Trust.objects.get_root()
        TrustUserPermission(
            trust=root, entity=self.alice, permission=self.add,
        ).save()
        self._reload()
        self.assertNotIn(root.pk, _pks(self._filter(self.alice, exclude_root=True)))
        self.assertIn(root.pk, _pks(self._filter(self.alice, exclude_root=False)))

    def test_inactive_and_anonymous_deny_before_gate(self):
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        with patch('trusts.models.any_plan_records') as gate:
            with patch('trusts.models.trust_grant_q') as grant_q:
                self.assertFalse(self._filter(self.alice).exists())
                self.assertFalse(self._filter(AnonymousUser()).exists())
        gate.assert_not_called()
        grant_q.assert_not_called()

    def test_condition_raises_before_gate_or_grant(self):
        with patch('trusts.models.any_plan_records') as gate:
            with patch('trusts.models.trust_grant_q') as grant_q:
                with self.assertRaises(PermissionConditionNotQueryable):
                    self._filter(self.alice, Category, 'add_category:own')
                with self.assertRaises(PermissionConditionNotQueryable):
                    self._filter(self.alice, Organization, 'add:never')
        gate.assert_not_called()
        grant_q.assert_not_called()

    def test_unknown_model_is_none_and_does_not_run_grant(self):
        with patch('trusts.models.trust_grant_q') as grant_q:
            qs = self._filter(self.alice, Organization, 'add')
            self.assertIsInstance(qs, QuerySet)
            self.assertIsNone(qs._result_cache)
            grant_q.assert_not_called()
            with self.assertNumQueries(0):
                self.assertFalse(qs.exists())
        with patch('trusts.models.trust_grant_q') as grant_q:
            self.assertFalse(self._filter(self.alice, User, 'add_user').exists())
            grant_q.assert_not_called()

    def test_declared_group_opens_the_gate_emptied_content_does_not_use_fallback(self):
        self.assertTrue(Content.is_content_model(Group))
        self.assertTrue(Content.is_content_model(Category))
        handle = self.live.configured_backend()
        self.assertTrue(handle.historical_fallback)
        self.assertTrue(handle.registry.plan_for(Group).records)
        with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
            self.assertFalse(
                self._filter(self.alice, Group, 'change_group').exists()
            )
            self.assertGreaterEqual(grant_q.call_count, 1)
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE,)):
            self.live.registries[CONCRETE] = TrustsRegistry()
            emptied = self.live.configured_backend()
            self.assertFalse(emptied.registry.plan_for(Category).records)
            self.assertTrue(emptied.historical_fallback)
            self.assertTrue(Content.is_content_model(Category))
            with patch('trusts.models.trust_grant_q') as grant_q:
                with patch.object(Content, 'is_content_model') as is_content:
                    qs = self._filter(self.alice, Category, 'add_category')
                    is_content.assert_not_called()
                    grant_q.assert_not_called()
            self.assertFalse(qs.exists())

    def test_registered_path_does_not_consult_contents_or_filter_authorized(self):
        registry = self.live.configured_backend().registry
        with patch.object(Content, '_contents', _UnusableContents()):
            with patch.object(Content, 'is_content_model') as is_content:
                with patch.object(registry, 'filter_authorized') as filtered:
                    with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
                        pks = _pks(self._filter(self.alice))
        is_content.assert_not_called()
        filtered.assert_not_called()
        self.assertGreaterEqual(grant_q.call_count, 1)
        self.assertEqual(pks, {self.trust_a.pk})

    def test_ticket_and_trust_remain_supported(self):
        organization = Organization.objects.create(name='S4Org', manager=self.alice)
        Ticket.objects.create(
            trust=self.trust_a, title='s4-t', owner=self.alice,
            organization=organization, status='open',
        )
        ticket_add = _perm(Ticket, 'add_ticket')
        change_trust = _perm(Trust, 'change_trust')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=ticket_add,
        ).save()
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=change_trust,
        ).save()
        self._reload()
        self.assertEqual(
            _pks(self._filter(self.alice, Ticket, 'add_ticket')),
            {self.trust_a.pk},
        )
        self.assertEqual(
            _pks(self._filter(self.alice, Trust, 'change_trust')),
            {self.trust_a.pk},
        )


class MultiPathCreateUnderTrustGateTest(
    _RegistryRestoreMixin, _UsersMixin, TestCase
):
    def setUp(self):
        super().setUp()
        self._make_users('mp')
        self.add = _perm(Category, 'add_category')
        self.ticket_add = _perm(Ticket, 'add_ticket')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.add,
        ).save()
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.ticket_add,
        ).save()
        self._reload()

    def test_declaration_on_one_path_supports_but_grant_stays_trust_grant_q(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            self.live.registries[CONCRETE] = TrustsRegistry()
            handle_a = self.live.configured_backend(CONCRETE)
            handle_b = self.live.configured_backend(MIXIN)
            _contribute_category(handle_b.registry)
            self.assertFalse(handle_a.registry.plan_for(Category).records)
            self.assertTrue(handle_b.registry.plan_for(Category).records)
            self.assertTrue(any_plan_records((handle_a, handle_b), Category))
            with patch.object(
                handle_b.compiler, 'complete_exists',
                wraps=handle_b.compiler.complete_exists,
            ) as complete:
                with patch.object(handle_b.registry, 'filter_authorized') as filtered:
                    with patch('trusts.models.trust_grant_q', wraps=trust_grant_q) as grant_q:
                        qs = Trust.objects.filter_by_user_content_perm(
                            self.alice, Category, 'add_category',
                        )
                        self.assertIsNone(qs._result_cache)
                        with self.assertNumQueries(1):
                            pks = _pks(qs)
            complete.assert_not_called()
            filtered.assert_not_called()
            self.assertGreaterEqual(grant_q.call_count, 1)
            self.assertEqual(pks, {self.trust_a.pk})

    def test_split_terminals_do_not_leak_the_other_path(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            self.live.registries[CONCRETE] = TrustsRegistry()
            handle_a = self.live.configured_backend(CONCRETE)
            handle_b = self.live.configured_backend(MIXIN)
            _contribute_category(handle_a.registry)
            _contribute_ticket(handle_b.registry)
            self.assertTrue(handle_a.registry.plan_for(Category).records)
            self.assertFalse(handle_a.registry.plan_for(Ticket).records)
            self.assertFalse(handle_b.registry.plan_for(Category).records)
            self.assertTrue(handle_b.registry.plan_for(Ticket).records)
            self.assertEqual(
                _pks(Trust.objects.filter_by_user_content_perm(
                    self.alice, Category, 'add_category',
                )),
                {self.trust_a.pk},
            )
            self.assertEqual(
                _pks(Trust.objects.filter_by_user_content_perm(
                    self.alice, Ticket, 'add_ticket',
                )),
                {self.trust_a.pk},
            )
            with patch('trusts.models.trust_grant_q') as grant_q:
                self.assertFalse(
                    Trust.objects.filter_by_user_content_perm(
                        self.alice, Organization, 'add',
                    ).exists()
                )
                self.assertFalse(
                    Trust.objects.filter_by_user_content_perm(
                        self.alice, Group, 'change_group',
                    ).exists()
                )
            grant_q.assert_not_called()


class NewTeamFormTrustChangeTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('form')
        self.change_trust = _perm(Trust, 'change_trust')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change_trust,
        ).save()
        self._reload()

    def test_new_team_form_lists_change_trust_targets_excluding_root(self):
        form = NewTeamForm(user=self.alice)
        qs = form.fields['trust'].queryset
        self.assertIsInstance(qs, QuerySet)
        self.assertIsNone(qs._result_cache)
        pks = _pks(qs)
        self.assertEqual(pks, {self.trust_a.pk})
        self.assertNotIn(Trust.objects.get_root().pk, pks)
        self.assertNotIn(self.trust_b.pk, pks)
        denied = NewTeamForm(user=self.bob)
        self.assertFalse(denied.fields['trust'].queryset.exists())
