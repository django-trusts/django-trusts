"""#4: noun-neutral V1 condition grammar.

QueryableConditionTest (Trust/Content/Ticket runtime) stays on Zero
``tests/legacy/test_issue4.py``. This module keeps the public
``add_named_filter`` grammar: ``==``, ``!=``, ``&``, ``|``, constants,
and the shared rejection messages.
"""

from django.contrib.auth import get_user_model
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.conditions import PermissionConditionError
from tests.support import compiler


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
    def test_python_or_raises_the_shared_boolean_message(self):
        with self.assertRaises(PermissionConditionError) as ctx:
            compiler().add_named_filter(
                object,
                'either',
                lambda u, p, o: (u == o.owner) or (o.status == 'open'),
            )
        self.assertIn('&', str(ctx.exception))
        self.assertIn('|', str(ctx.exception))

    def test_chained_comparison_raises_the_shared_boolean_message(self):
        with self.assertRaises(PermissionConditionError) as ctx:
            compiler().add_named_filter(
                object,
                'range',
                lambda u, p, o: o.low == o.amount == o.high,
            )
        self.assertIn('chained', str(ctx.exception))

    def test_ordering_is_not_a_predicate(self):
        with self.assertRaises(PermissionConditionError) as ctx:
            compiler().add_named_filter(
                object,
                'range',
                lambda u, p, o: o.amount < 100,
            )
        self.assertIn('Ordered comparison', str(ctx.exception))
        with self.assertRaises(TypeError):
            compiler().add_named_filter(object, 'range', 1)

    def test_calls_indexing_arithmetic_and_python_in_are_rejected(self):
        rejected = (
            lambda u, p, o: o.status.lower(),
            lambda u, p, o: o.status[0],
            lambda u, p, o: o.amount + 1,
            lambda u, p, o: ~(u == o.owner),
            lambda u, p, o: 1 in o.status,
            lambda u, p, o: list(o.owner),
        )
        for builder in rejected:
            with self.subTest(builder=builder):
                with self.assertRaises(PermissionConditionError):
                    compiler().add_named_filter(object, 'bad', builder)

    def test_assignment_is_rejected(self):
        def assign(u, p, o):
            o.owner = u
            return u == o.owner

        with self.assertRaises(PermissionConditionError):
            compiler().add_named_filter(object, 'assign', assign)

    def test_non_callable_rejected_at_register(self):
        registry = compiler()
        with self.assertRaises(TypeError):
            registry.add_named_filter(object, 'bad', 'not-a-condition')
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(object, 'truth', lambda u, p, o: True)
        registry.add_named_filter(object, 'truth', lambda u, p, o: u == o.owner)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_incompatible_literal_types_rejected_at_register(self):
        Ticket = _ticket_model()
        registry = compiler()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.add_named_filter(
                Ticket, 'bad_status', lambda u, p, o: o.status == 1,
            )
        self.assertIn('incompatible', str(ctx.exception))
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Ticket, 'bad_ne', lambda u, p, o: o.status != 1,
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Ticket, 'bad_owner', lambda u, p, o: o.owner == '1',
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Ticket, 'bad_owner_ne', lambda u, p, o: o.owner != 1,
            )
        registry.add_named_filter(
            Ticket, 'open', lambda u, p, o: o.status == 'open',
        )
        registry.add_named_filter(
            Ticket, 'owned', lambda u, p, o: u == o.owner,
        )
        registry.add_named_filter(
            Ticket, 'blank_region', lambda u, p, o: o.region == None,
        )

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_builder_runs_once(self):
        Ticket = _ticket_model()
        calls = []

        def owned(u, p, o):
            calls.append(1)
            return u == o.owner

        registry = compiler()
        registry.add_named_filter(Ticket, 'own', owned)
        self.assertEqual(calls, [1])
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Ticket, 'own', owned)
        self.assertEqual(calls, [1])
