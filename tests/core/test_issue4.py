"""#4: noun-neutral V1 condition grammar.

QueryableConditionTest (Trust/Content/Ticket runtime) stays on Zero
``tests/legacy/test_issue4.py``. This module keeps the generic Expr
grammar and ``validate_expression`` / register-shape proofs.
"""

from django.contrib.auth import get_user_model
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from django_trusts import Query as DjangoTrustsQuery, TQ as DjangoTrustsTQ
from django_trusts import condition_refs as django_condition_refs
from trusts.conditions import (
    Const,
    Expr,
    PermissionConditionBooleanError,
    PermissionConditionError,
    PermissionConditionUnsupported,
    Query,
    TQ,
    condition_refs,
    is_predicate,
    object_ref,
    permission_ref,
    principal_ref,
    validate_expression,
)
from trusts.core import TrustsRegistry


u, p, o = condition_refs()
OWNED_OR_MANAGER_UNLOCKED = (
    (u == o.owner) |
    ((u == o.organization.manager) & (o.status != 'locked'))
)


def _ticket_model():
    User = get_user_model()

    class Organization(models.Model):
        manager = models.ForeignKey(User, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class Ticket(models.Model):
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
        status = models.CharField(max_length=20)
        amount = models.IntegerField(null=True)
        region = models.CharField(max_length=40, null=True)

        class Meta:
            app_label = 'trusts_tests'

    return Ticket


class ConditionGrammarTest(SimpleTestCase):
    def test_supported_nodes_to_tuple(self):
        u, p, o = condition_refs()
        eq = u == o.owner
        ne = o.status != 'locked'
        conjunction = eq & ne
        disjunction = eq | ne
        self.assertEqual(
            eq.to_tuple(),
            ('eq', ('ref', 'principal', ()), ('ref', 'object', ('owner',))),
        )
        self.assertEqual(
            ne.to_tuple(),
            ('ne', ('ref', 'object', ('status',)), ('const', 'locked')),
        )
        self.assertEqual(conjunction.to_tuple()[0], 'and')
        self.assertEqual(disjunction.to_tuple()[0], 'or')
        self.assertEqual(Const(None).to_tuple(), ('const', None))
        self.assertEqual(principal_ref().to_tuple(), ('ref', 'principal', ()))
        self.assertEqual(permission_ref().to_tuple(), ('ref', 'permission', ()))
        self.assertEqual(object_ref().to_tuple(), ('ref', 'object', ()))
        self.assertTrue(is_predicate(eq))
        self.assertTrue(is_predicate(conjunction))
        self.assertFalse(is_predicate(o.owner))

    def test_nested_grouping_is_preserved(self):
        self.assertEqual(
            OWNED_OR_MANAGER_UNLOCKED.to_tuple(),
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

    def test_python_or_at_construction_raises_boolean_error(self):
        u, p, o = condition_refs()
        with self.assertRaises(PermissionConditionBooleanError) as ctx:
            (u == o.owner) or (o.status == 'open')
        self.assertIn('&', str(ctx.exception))
        self.assertIn('|', str(ctx.exception))

    def test_chained_comparison_raises_boolean_error(self):
        u, p, o = condition_refs()
        with self.assertRaises(PermissionConditionBooleanError) as ctx:
            0 < o.amount < 100
        self.assertIn('chained', str(ctx.exception))

    def test_ordering_expr_is_not_a_v1_predicate(self):
        u, p, o = condition_refs()
        ordering = o.amount < 100
        self.assertIsInstance(ordering, Expr)
        self.assertFalse(is_predicate(ordering))
        with self.assertRaises(PermissionConditionError):
            TrustsRegistry().register_permission_condition(
                object, 'range', ordering,
            )

    def test_calls_indexing_arithmetic_setters_rejected(self):
        u, p, o = condition_refs()
        with self.assertRaises(PermissionConditionUnsupported):
            o.status.lower()
        with self.assertRaises(PermissionConditionUnsupported):
            o.status[0]
        with self.assertRaises(PermissionConditionUnsupported):
            o.amount + 1
        with self.assertRaises(PermissionConditionUnsupported):
            o.owner = u
        with self.assertRaises(PermissionConditionUnsupported):
            o.status[0] = 'x'
        with self.assertRaises(PermissionConditionUnsupported):
            ~ (u == o.owner)
        with self.assertRaises(PermissionConditionUnsupported):
            1 in o.status
        with self.assertRaises(PermissionConditionUnsupported):
            list(o.owner)

    def test_tq_namespace_is_reserved_without_v1_lookups(self):
        self.assertIs(Query, TQ)
        self.assertIs(DjangoTrustsQuery, Query)
        self.assertIs(DjangoTrustsTQ, TQ)
        self.assertEqual(django_condition_refs()[0].to_tuple(), ('ref', 'principal', ()))
        with self.assertRaises(PermissionConditionUnsupported) as ctx:
            TQ.iexact
        self.assertIn('iexact', str(ctx.exception))
        with self.assertRaises(PermissionConditionUnsupported):
            TQ.isin

    def test_non_predicate_and_non_callable_rejected_at_register(self):
        u, p, o = condition_refs()
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(object, 'bare', o.owner)
        with self.assertRaises(TypeError):
            registry.register_permission_condition(object, 'bad', 'not-a-condition')

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_incompatible_literal_types_rejected_at_validate(self):
        Ticket = _ticket_model()
        u, p, o = condition_refs()
        with self.assertRaises(PermissionConditionError) as ctx:
            validate_expression(o.status == 1, Ticket)
        self.assertIn('incompatible', str(ctx.exception))
        with self.assertRaises(PermissionConditionError):
            validate_expression(o.status != 1, Ticket)
        with self.assertRaises(PermissionConditionError):
            validate_expression(o.owner == '1', Ticket)
        with self.assertRaises(PermissionConditionError):
            validate_expression(o.owner != 1, Ticket)
        validate_expression(o.status == 'open', Ticket)
        validate_expression(u == o.owner, Ticket)
        validate_expression(o.region == None, Ticket)
