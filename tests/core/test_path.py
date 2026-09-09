"""Kernel tests for the composed AuthorizationPath IR (#43 Step 1).

Uses isolated Context / Trustee registries so the process-wide Zero
adapters stay on their current path. Does not close #43. Does not
relocate concrete models.
"""

import inspect
import re
from pathlib import Path

from django.test import TestCase, TransactionTestCase

from trusts.context import Context, ContextRegistry
from trusts.models import Trust, prepare_context_registry, prepare_trustee_registry
from trusts.path import (
    AuthorizationPath,
    AuthorizationPathError,
    OrderedContribution,
    RecursiveEdge,
    compose,
    empty_grant_q,
    filter_granted,
    row_is_granted,
)
from trusts.trustee import Trustee, TrusteeRegistry
from tests.models import (
    TEST_TEAM_TRUSTEE,
    TrusteeDirectGrant,
    TrusteeOperation,
    TrusteeRequester,
    TrusteeResource,
    TrusteeScope,
    TrusteeTrapGrant,
)
from tests.core.test_trustee import _kernel_registry


PRODUCT_NOUNS = (
    'Trust', 'Content', 'Junction', 'Group', 'Role', 'Team', 'User',
    'TrustGroup', 'TrustUser', 'TrustRole',
)


def _path_source():
    return Path(inspect.getfile(AuthorizationPath)).read_text()


def _resource_maps():
    context = ContextRegistry()
    context.register_direct(TrusteeResource, scope_field='scope')
    trustee = _kernel_registry()
    return context, trustee


class AuthorizationPathReusableLayerTest(TestCase):
    def test_reusable_module_has_no_product_nouns(self):
        source = _path_source()
        for noun in PRODUCT_NOUNS:
            self.assertIsNone(
                re.search(r'\b%s\b' % noun, source),
                '%r appears as a product noun in trusts.path' % noun,
            )
        self.assertNotIn('__subclasses__', source)
        self.assertNotIn('GitHub', source)

    def test_public_imports(self):
        from trusts.path import AuthorizationPath as Imported
        self.assertIs(Imported, AuthorizationPath)
        self.assertTrue(callable(compose))
        self.assertTrue(callable(row_is_granted))
        self.assertTrue(callable(filter_granted))

    def test_no_trusts_schema_migration_added(self):
        migrations = Path(inspect.getfile(Trust)).resolve().parent / 'migrations'
        names = sorted(
            path.name for path in migrations.glob('*.py')
            if path.name != '__init__.py'
        )
        self.assertEqual(names, ['0001_initial.py', '0002_trustgroup.py'])

    def test_reserved_slots_reject_construction(self):
        with self.assertRaises(AuthorizationPathError) as ctx:
            RecursiveEdge(
                from_model=TrusteeResource, edge_path='scope', max_depth=2,
            )
        self.assertIn('reserved', str(ctx.exception).lower())
        with self.assertRaises(AuthorizationPathError) as ctx:
            OrderedContribution(sequence=(), combine='remaining-bits')
        self.assertIn('reserved', str(ctx.exception).lower())


class AuthorizationPathComposeTest(TestCase):
    def test_compose_joins_context_scope_with_trustee_grant(self):
        context, trustee = _resource_maps()
        operation = TrusteeOperation(pk=-1, code='read')
        path = compose(
            TrusteeResource, operation, context=context, trustee=trustee,
        )
        self.assertIsInstance(path, AuthorizationPath)
        self.assertIs(path.resource_model, TrusteeResource)
        self.assertEqual(path.resource_to_scope, 'scope')
        self.assertIs(path.scope_model, TrusteeScope)
        self.assertIs(path.requester_model, TrusteeRequester)
        self.assertIs(path.operation_model, TrusteeOperation)
        self.assertEqual(
            set(path.adapter_names),
            {'collective', 'direct'},
        )
        self.assertIsNone(path.condition)
        self.assertIsNone(path.recursive_edge)
        self.assertIsNone(path.ordered_contribution)

    def test_single_adapter_ir_fields_are_scalars(self):
        context, trustee = _resource_maps()
        path = compose(
            TrusteeResource, None, context=context, trustee=trustee,
            names=('direct',),
        )
        self.assertEqual(path.adapter_names, ('direct',))
        self.assertEqual(path.requester_from_grant, 'requester')
        self.assertIs(path.subject_model, TrusteeRequester)
        self.assertEqual(path.subject_from_grant, 'requester')
        self.assertEqual(path.membership_path, '')
        self.assertIs(path.grant_model, TrusteeDirectGrant)
        self.assertEqual(path.grant_to_scope, 'scope')
        self.assertEqual(path.grant_to_operation, 'operation')
        self.assertEqual(path.constraint_paths, ())

    def test_unregistered_resource_fails_closed(self):
        context, trustee = _resource_maps()
        with self.assertRaises(AuthorizationPathError) as ctx:
            compose(
                TrusteeScope, None, context=context, trustee=trustee,
            )
        self.assertIn('not a registered', str(ctx.exception))

    def test_empty_grant_adapters_fail_closed(self):
        context = ContextRegistry()
        context.register_direct(TrusteeResource, scope_field='scope')
        trustee = TrusteeRegistry(
            requester_model=TrusteeRequester,
            scope_model=TrusteeScope,
            operation_model=TrusteeOperation,
        )
        with self.assertRaises(AuthorizationPathError) as ctx:
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
            )
        self.assertIn('No grant adapters', str(ctx.exception))

    def test_scope_terminal_mismatch_fails_closed(self):
        context = ContextRegistry()
        context.register_direct(TrusteeResource, scope_field='scope')
        trustee = TrusteeRegistry(
            requester_model=TrusteeRequester,
            scope_model=TrusteeRequester,
            operation_model=TrusteeOperation,
        )
        trustee.register(
            name='direct',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeDirectGrant,
            trustee_path='requester',
            scope_path='requester',
            operation_path='operation',
        )
        with self.assertRaises(AuthorizationPathError) as ctx:
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
            )
        self.assertIn('does not match', str(ctx.exception))

    def test_operation_model_mismatch_fails_closed(self):
        context, trustee = _resource_maps()
        with self.assertRaises(AuthorizationPathError) as ctx:
            compose(
                TrusteeResource, TrusteeRequester, context=context,
                trustee=trustee,
            )
        self.assertIn('does not match', str(ctx.exception))

    def test_missing_adapter_name_fails_closed(self):
        context, trustee = _resource_maps()
        with self.assertRaises(AuthorizationPathError) as ctx:
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
                names=('missing',),
            )
        self.assertIn('not registered', str(ctx.exception))

    def test_reserved_condition_and_slots_fail_closed(self):
        context, trustee = _resource_maps()
        with self.assertRaises(AuthorizationPathError):
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
                condition=object(),
            )
        with self.assertRaises(AuthorizationPathError):
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
                recursive_edge=object(),
            )
        with self.assertRaises(AuthorizationPathError):
            compose(
                TrusteeResource, None, context=context, trustee=trustee,
                ordered_contribution=object(),
            )

    def test_process_wide_maps_do_not_register_isolated_resources(self):
        prepare_context_registry()
        prepare_trustee_registry()
        labels = [adapter.label for adapter in Context.adapters()]
        self.assertNotIn(TrusteeResource._meta.label, labels)
        names = [adapter.name for adapter in Trustee.adapters()]
        self.assertIn(TEST_TEAM_TRUSTEE, names)
        self.assertNotIn('gh', ''.join(names))

    def test_empty_grant_q_matches_nothing(self):
        self.assertFalse(
            TrusteeScope.objects.filter(empty_grant_q()).exists()
        )


class AuthorizationPathQueryTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(AuthorizationPathQueryTest, self).setUp()
        self.requester = TrusteeRequester.objects.create(name='alice')
        self.scope_a = TrusteeScope.objects.create(title='A')
        self.scope_b = TrusteeScope.objects.create(title='B')
        self.read = TrusteeOperation.objects.create(code='read')
        self.resource_a = TrusteeResource.objects.create(
            scope=self.scope_a, title='Res A',
        )
        self.resource_b = TrusteeResource.objects.create(
            scope=self.scope_b, title='Res B',
        )
        self.context, self.trustee = _resource_maps()
        self.path = compose(
            TrusteeResource, self.read, context=self.context,
            trustee=self.trustee,
        )

    def test_exists_and_list_share_one_query_predicate(self):
        TrusteeDirectGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.read,
        )
        with self.assertNumQueries(1):
            listed = list(
                self.path.filter_granted(
                    TrusteeResource.objects.all(), self.requester, self.read,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.resource_a.pk])
        with self.assertNumQueries(1):
            self.assertTrue(
                self.path.row_is_granted(
                    self.resource_a, self.requester, self.read,
                )
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.path.row_is_granted(
                    self.resource_b, self.requester, self.read,
                )
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                row_is_granted(
                    self.resource_a, self.requester, self.read,
                    context=self.context, trustee=self.trustee,
                )
            )
        with self.assertNumQueries(1):
            module_listed = list(
                filter_granted(
                    TrusteeResource.objects.all(), self.requester, self.read,
                    context=self.context, trustee=self.trustee,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(module_listed, [self.resource_a.pk])

    def test_getters_and_properties_are_not_executed(self):
        grant = TrusteeTrapGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.read,
        )
        trap_trustee = TrusteeRegistry(
            requester_model=TrusteeRequester,
            scope_model=TrusteeScope,
            operation_model=TrusteeOperation,
        )
        trap_trustee.register(
            name='trap',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeTrapGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )
        path = compose(
            TrusteeResource, self.read, context=self.context,
            trustee=trap_trustee,
        )
        with self.assertNumQueries(1):
            self.assertTrue(
                path.row_is_granted(
                    self.resource_a, self.requester, self.read,
                )
            )
        with self.assertRaises(AssertionError):
            grant.forbidden
        with self.assertRaises(AssertionError):
            grant.get_requester()

    def test_wrong_queryset_model_fails_closed(self):
        with self.assertRaises(AuthorizationPathError):
            self.path.filter_granted(
                TrusteeScope.objects.all(), self.requester, self.read,
            )
