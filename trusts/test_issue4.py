"""Queryable V1 permission conditions (issue #4).

Parity between ``has_perm`` and ``ContentQuerySet.permitted`` for the
restricted declarative grammar; arbitrary callbacks stay object-only.
"""

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from trusts.conditions import (
    PermissionConditionBooleanError,
    PermissionConditionError,
    build_expression,
    object_ref,
    permission_ref,
    principal_ref,
)
from trusts.models import (
    Content,
    PermissionConditionNotQueryable,
    Trust,
    TrustUserPermission,
)
from trusts.tests import (
    create_test_users,
    get_or_create_root_user,
    reload_test_users,
)
from tests.models import Organization, Ticket
from django.core.management import call_command


OWNED_OR_MANAGER_UNLOCKED = lambda u, p, o: (
    (u == o.owner) |
    ((u == o.organization.manager) & (o.status != 'locked'))
)


class QueryableConditionTest(TestCase):
    def setUp(self):
        super(QueryableConditionTest, self).setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        create_test_users(self)

        self.org_trust = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Tickets Org'
        )
        self.org_trust.save()
        self.other_trust = Trust(
            settlor=self.user1, trust=Trust.objects.get_root(), title='Other Org'
        )
        self.other_trust.save()

        self.company = Organization.objects.create(name='Acme', manager=self.user)
        self.other_company = Organization.objects.create(
            name='OtherCo', manager=self.user1
        )

        self.owned_open = Ticket.objects.create(
            trust=self.org_trust, title='owned-open', owner=self.user,
            organization=self.other_company, status='open',
        )
        self.owned_locked = Ticket.objects.create(
            trust=self.org_trust, title='owned-locked', owner=self.user,
            organization=self.other_company, status='locked', region='west',
        )
        self.managed_open = Ticket.objects.create(
            trust=self.org_trust, title='managed-open', owner=self.user1,
            organization=self.company, status='open',
        )
        self.managed_locked = Ticket.objects.create(
            trust=self.org_trust, title='managed-locked', owner=self.user1,
            organization=self.company, status='locked',
        )
        self.unrelated = Ticket.objects.create(
            trust=self.org_trust, title='unrelated', owner=self.user1,
            organization=self.other_company, status='open',
        )
        self.no_grant = Ticket.objects.create(
            trust=self.other_trust, title='owned-no-grant', owner=self.user,
            organization=self.company, status='open',
        )

        self.perm_change = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Ticket),
            codename='change_ticket',
        )
        TrustUserPermission(
            trust=self.org_trust, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)

        Content.register_permission_condition(
            Ticket, 'editable', OWNED_OR_MANAGER_UNLOCKED
        )
        Content.register_permission_condition(
            Ticket, 'unlocked',
            lambda u, p, o: (
                ((u == o.owner) | (u == o.organization.manager)) &
                (o.status != 'locked')
            )
        )
        Content.register_permission_condition(
            Ticket, 'own', lambda u, p, o: u == o.owner
        )
        Content.register_permission_condition(
            Ticket, 'open', lambda u, p, o: o.status == 'open'
        )
        Content.register_permission_condition(
            Ticket, 'never', lambda u, p, o: False
        )
        Content.register_permission_condition(
            Ticket, 'python_or', lambda u, p, o: u == o.owner or o.status == 'open'
        )
        Content.register_permission_condition(
            Ticket, 'called', lambda u, p, o: o.status.lower() == 'open'
        )

        self.change = 'trusts_tests.change_ticket'
        self.change_editable = 'trusts_tests.change_ticket:editable'
        self.change_own = 'trusts_tests.change_ticket:own'
        self.change_open = 'trusts_tests.change_ticket:open'

    def _direct_pks(self, perm, user):
        return set(
            obj.pk for obj in Ticket.objects.all()
            if user.has_perm(perm, obj)
        )

    def _assert_parity(self, perm, user):
        qs = Ticket.objects.permitted(perm, user)
        self.assertEqual(set(qs.values_list('pk', flat=True)), self._direct_pks(perm, user))
        sql = str(qs.query)
        self.assertTrue(
            'JOIN' in sql.upper() or 'EXISTS' in sql.upper() or 'trusts_trustuserpermission' in sql,
            'permitted() must filter in SQL. SQL was: %s' % sql,
        )
        self.assertEqual(list(qs[:50]), list(qs))

    def test_expression_tree_preserves_nested_grouping(self):
        u, p, o = principal_ref(), permission_ref(), object_ref()
        expr = (u == o.owner) | ((u == o.organization.manager) & (o.status != 'locked'))
        self.assertEqual(
            expr.to_tuple(),
            (
                'or',
                ('eq', ('ref', 'principal', ()), ('ref', 'object', ('owner',))),
                (
                    'and',
                    (
                        'eq',
                        ('ref', 'principal', ()),
                        ('ref', 'object', ('organization', 'manager')),
                    ),
                    ('ne', ('ref', 'object', ('status',)), ('const', 'locked')),
                ),
            ),
        )
        captured = build_expression(OWNED_OR_MANAGER_UNLOCKED)
        self.assertEqual(captured.to_tuple(), expr.to_tuple())

    def test_nested_expression_object_and_queryset_parity(self):
        self.assertTrue(self.user.has_perm(self.change, self.owned_open))
        self.assertTrue(self.user.has_perm(self.change_editable, self.owned_open))
        self.assertTrue(self.user.has_perm(self.change_editable, self.owned_locked))
        self.assertTrue(self.user.has_perm(self.change_editable, self.managed_open))
        self.assertFalse(self.user.has_perm(self.change_editable, self.managed_locked))
        self.assertFalse(self.user.has_perm(self.change_editable, self.unrelated))
        self.assertFalse(self.user.has_perm(self.change, self.no_grant))
        self.assertFalse(self.user.has_perm(self.change_editable, self.no_grant))

        pks = set(Ticket.objects.permitted(self.change_editable, self.user).values_list('pk', flat=True))
        self.assertEqual(pks, {self.owned_open.pk, self.owned_locked.pk, self.managed_open.pk})
        self._assert_parity(self.change_editable, self.user)

        unlocked = 'trusts_tests.change_ticket:unlocked'
        self.assertTrue(self.user.has_perm(unlocked, self.owned_open))
        self.assertFalse(self.user.has_perm(unlocked, self.owned_locked))
        self.assertTrue(self.user.has_perm(unlocked, self.managed_open))
        self.assertFalse(self.user.has_perm(unlocked, self.managed_locked))
        unlocked_pks = set(Ticket.objects.permitted(unlocked, self.user).values_list('pk', flat=True))
        self.assertEqual(unlocked_pks, {self.owned_open.pk, self.managed_open.pk})
        self._assert_parity(unlocked, self.user)

    def test_relationship_traversal_and_constants(self):
        self.assertTrue(self.user.has_perm(self.change_own, self.owned_open))
        self.assertFalse(self.user.has_perm(self.change_own, self.managed_open))
        self.assertTrue(self.user.has_perm(self.change_open, self.owned_open))
        self.assertFalse(self.user.has_perm(self.change_open, self.managed_locked))

        own_pks = set(Ticket.objects.permitted(self.change_own, self.user).values_list('pk', flat=True))
        self.assertEqual(own_pks, {self.owned_open.pk, self.owned_locked.pk})
        open_pks = set(Ticket.objects.permitted(self.change_open, self.user).values_list('pk', flat=True))
        self.assertEqual(
            open_pks,
            {self.owned_open.pk, self.managed_open.pk, self.unrelated.pk},
        )
        self._assert_parity(self.change_own, self.user)
        self._assert_parity(self.change_open, self.user)

    def test_condition_does_not_grant_without_base_permission(self):
        self.assertTrue(self.user.has_perm(self.change_own, self.owned_open))
        self.assertFalse(self.user.has_perm(self.change_own, self.no_grant))
        self.assertNotIn(
            self.no_grant.pk,
            Ticket.objects.permitted(self.change_own, self.user).values_list('pk', flat=True),
        )
        self.assertFalse(self.user1.has_perm(self.change, self.owned_open))
        self.assertFalse(self.user1.has_perm(self.change_own, self.owned_open))
        self.assertFalse(Ticket.objects.permitted(self.change_own, self.user1).exists())

    def test_inactive_user_empty_on_both_paths(self):
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)
        self.assertFalse(self.user.has_perm(self.change, self.owned_open))
        self.assertFalse(self.user.has_perm(self.change_editable, self.owned_open))
        self.assertFalse(Ticket.objects.permitted(self.change, self.user).exists())
        self.assertFalse(Ticket.objects.permitted(self.change_editable, self.user).exists())

    def test_unconditioned_grant_is_still_unfiltered(self):
        pks = set(Ticket.objects.permitted(self.change, self.user).values_list('pk', flat=True))
        self.assertEqual(
            pks,
            {
                self.owned_open.pk, self.owned_locked.pk, self.managed_open.pk,
                self.managed_locked.pk, self.unrelated.pk,
            },
        )
        self._assert_parity(self.change, self.user)

    def test_arbitrary_callback_object_only_queryset_fails_closed(self):
        never = 'trusts_tests.change_ticket:never'
        self.assertTrue(self.user.has_perm(self.change, self.owned_open))
        self.assertFalse(self.user.has_perm(never, self.owned_open))
        with self.assertRaises(PermissionConditionNotQueryable):
            Ticket.objects.permitted(never, self.user)
        # Must not silently list the underlying grant.
        self.assertIn(
            self.owned_open.pk,
            Ticket.objects.permitted(self.change, self.user).values_list('pk', flat=True),
        )

    def test_python_and_or_raises_clear_error_on_queryset(self):
        conditioned = 'trusts_tests.change_ticket:python_or'
        with self.assertRaises(PermissionConditionBooleanError) as ctx:
            Ticket.objects.permitted(conditioned, self.user)
        self.assertIn('&', str(ctx.exception))
        self.assertIn('|', str(ctx.exception))
        # Object-only path still evaluates the original callback.
        self.assertTrue(self.user.has_perm(conditioned, self.owned_open))

    def test_unsupported_syntax_fails_closed_on_queryset(self):
        called = 'trusts_tests.change_ticket:called'
        with self.assertRaises(PermissionConditionNotQueryable):
            Ticket.objects.permitted(called, self.user)
        # Method calls remain object-only; they must not over-grant on lists.
        self.assertTrue(self.user.has_perm(called, self.owned_open))
        self.assertFalse(self.user.has_perm(called, self.managed_locked))

    def test_invalid_field_path_fails_closed(self):
        Content.register_permission_condition(
            Ticket, 'missing', lambda u, p, o: u == o.not_a_field
        )
        missing = 'trusts_tests.change_ticket:missing'
        with self.assertRaises(PermissionConditionError):
            Ticket.objects.permitted(missing, self.user)
        with self.assertRaises(PermissionConditionError):
            self.user.has_perm(missing, self.owned_open)

    def test_misspelled_principal_field_does_not_match_null_object_field(self):
        """A typo on ``u`` must not compile to ``region__isnull=True``.

        ``owned_open.region`` is NULL and the user has a base grant. Binding
        a missing principal attribute as ``None`` would allow that row.
        """
        Content.register_permission_condition(
            Ticket, 'typo', lambda u, p, o: u.regoin == o.region
        )
        typo = 'trusts_tests.change_ticket:typo'
        with self.assertRaises(PermissionConditionError) as direct:
            self.user.has_perm(typo, self.owned_open)
        self.assertIn('regoin', str(direct.exception))
        with self.assertRaises(PermissionConditionError) as listed:
            Ticket.objects.permitted(typo, self.user)
        self.assertIn('regoin', str(listed.exception))
        # Unconditioned grant still includes the NULL-region row; the typo
        # must not have been treated as a successful condition.
        self.assertIn(
            self.owned_open.pk,
            Ticket.objects.permitted(self.change, self.user).values_list('pk', flat=True),
        )
        self.assertIsNone(self.owned_open.region)

    def test_nullable_object_field_none_is_not_a_missing_attribute(self):
        Content.register_permission_condition(
            Ticket, 'unset_region', lambda u, p, o: o.region == None
        )
        unset = 'trusts_tests.change_ticket:unset_region'
        self.assertTrue(self.user.has_perm(unset, self.owned_open))
        self.assertFalse(self.user.has_perm(unset, self.owned_locked))
        pks = set(Ticket.objects.permitted(unset, self.user).values_list('pk', flat=True))
        self.assertIn(self.owned_open.pk, pks)
        self.assertNotIn(self.owned_locked.pk, pks)
        self._assert_parity(unset, self.user)

    def test_validated_principal_field_path(self):
        self.owned_open.region = self.user.username
        self.owned_open.save()
        Content.register_permission_condition(
            Ticket, 'named', lambda u, p, o: u.username == o.region
        )
        named = 'trusts_tests.change_ticket:named'
        self.assertTrue(self.user.has_perm(named, self.owned_open))
        self.assertFalse(self.user.has_perm(named, self.owned_locked))
        pks = set(Ticket.objects.permitted(named, self.user).values_list('pk', flat=True))
        self.assertEqual(pks, {self.owned_open.pk})
        self._assert_parity(named, self.user)

    def test_builtin_own_on_trust_is_queryable(self):
        change_trust = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(
            trust=self.org_trust, entity=self.user, permission=change_trust
        ).save()
        TrustUserPermission(
            trust=self.org_trust, entity=self.user1, permission=change_trust
        ).save()
        reload_test_users(self)
        child = Trust(
            settlor=self.user, title='Child owned', trust=self.org_trust
        )
        child.save()
        perm = 'trusts.change_trust:own'
        self.assertTrue(self.user.has_perm('trusts.change_trust', child))
        self.assertTrue(self.user.has_perm(perm, child))
        self.assertTrue(self.user1.has_perm('trusts.change_trust', child))
        self.assertFalse(self.user1.has_perm(perm, child))
        self.assertIn(
            child.pk,
            Trust.objects.permitted(perm, self.user).values_list('pk', flat=True),
        )
        self.assertNotIn(
            child.pk,
            Trust.objects.permitted(perm, self.user1).values_list('pk', flat=True),
        )
        self.assertEqual(
            set(Trust.objects.permitted(perm, self.user).values_list('pk', flat=True)),
            set(
                t.pk for t in Trust.objects.all()
                if self.user.has_perm(perm, t)
            ),
        )
