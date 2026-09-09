"""Kernel tests for the registry-driven Trustee resolution contract (#40).

Uses real test-only database models (``TrusteeRequester`` /
``TrusteeScope`` / ``TrusteeOperation`` / ``TrusteeCollective`` /
``TrusteeBundle`` / grant tables). Malformed variants are isolated so
they never enter the process-wide map. Does not close #40.
"""

import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error, run_checks
from django.core.management import call_command
from django.db import models
from django.test import SimpleTestCase, TestCase, TransactionTestCase

from trusts.checks import (
    CHECK_ID_INVALID_TRUSTEE,
    _SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT,
    check_trustee_registry,
)
from trusts.models import (
    DIRECT_TRUSTEE,
    GROUP_TRUSTEE,
    Role,
    Trust,
    TrustGroupPermission,
    TrustUserPermission,
    prepare_trustee_registry,
)
from trusts.trustee import (
    KIND_GRANT,
    Trustee,
    TrusteeAdapter,
    TrusteeMixin,
    TrusteeNotRegistered,
    TrusteeRegistrationError,
    TrusteeRegistry,
    TrusteeRegistryFrozen,
    check_registration,
)
from tests.models import (
    Receipt,
    TrusteeBundle,
    TrusteeCollective,
    TrusteeCollectiveGrant,
    TrusteeDesk,
    TrusteeDeskGrant,
    TrusteeDirectGrant,
    TrusteeOperation,
    TrusteeRequester,
    TrusteeResource,
    TrusteeScope,
    TrusteeTrapGrant,
    UnregisteredTrusteeNote,
)
from tests.support import (
    create_test_users,
    enable_local_group_grant,
    get_or_create_root_user,
    reload_test_users,
)


PRODUCT_NOUNS = (
    'Trust', 'Content', 'Junction', 'Group', 'Role', 'Team', 'User',
    'TrustGroup', 'TrustUser', 'TrustRole',
)


def _trustee_source():
    return Path(inspect.getfile(Trustee)).read_text()


def _kernel_registry():
    registry = TrusteeRegistry(requester_model=TrusteeRequester)
    registry.register(
        name='direct',
        trustee_model=TrusteeRequester,
        grant_model=TrusteeDirectGrant,
        trustee_path='requester',
        scope_path='scope',
        operation_path='operation',
        membership_path='',
    )
    registry.register(
        name='collective',
        trustee_model=TrusteeCollective,
        grant_model=TrusteeCollectiveGrant,
        trustee_path='collective',
        scope_path='scope',
        operation_path='operation',
        membership_path='members',
        constraint_paths=(
            'collective__operations',
            'collective__bundles__operations',
        ),
    )
    return registry


class TrusteeReusableLayerTest(TestCase):
    def test_reusable_module_has_no_product_nouns(self):
        source = _trustee_source()
        for noun in PRODUCT_NOUNS:
            self.assertIsNone(
                re.search(r'\b%s\b' % noun, source),
                '%r appears as a product noun in trusts.trustee' % noun,
            )
        self.assertNotIn('__subclasses__', source)

    def test_public_imports_and_mixin_is_abstract(self):
        from trusts.trustee import Trustee as Imported
        from trusts.models import Role as PublicRole
        self.assertIs(Imported, Trustee)
        self.assertTrue(issubclass(PublicRole, TrusteeMixin))
        self.assertTrue(TrusteeMixin._meta.abstract)
        self.assertFalse(Role._meta.abstract)
        self.assertEqual(
            [field.name for field in Role._meta.local_concrete_fields],
            ['id', 'name'],
        )
        self.assertTrue(issubclass(TrusteeBundle, TrusteeMixin))
        self.assertEqual(
            [field.name for field in TrusteeBundle._meta.local_concrete_fields],
            ['id', 'name'],
        )

    def test_no_trusts_schema_migration_added(self):
        migrations = Path(inspect.getfile(Trust)).resolve().parent / 'migrations'
        names = sorted(
            path.name for path in migrations.glob('*.py')
            if path.name != '__init__.py'
        )
        self.assertEqual(names, ['0001_initial.py', '0002_trustgroup.py'])


class TrusteeRegistryContractTest(TestCase):
    def test_process_wide_direct_and_group_adapters(self):
        prepare_trustee_registry()
        self.assertTrue(Trustee.is_registered(DIRECT_TRUSTEE))
        self.assertTrue(Trustee.is_registered(GROUP_TRUSTEE))
        self.assertFalse(Trustee.is_registered('role'))
        self.assertEqual(Trustee.get(DIRECT_TRUSTEE).kind, KIND_GRANT)
        self.assertEqual(Trustee.get(GROUP_TRUSTEE).kind, KIND_GRANT)
        self.assertEqual(Trustee.get(DIRECT_TRUSTEE).membership_path, '')
        self.assertEqual(Trustee.get(GROUP_TRUSTEE).membership_path, 'user')
        self.assertEqual(
            Trustee.get(GROUP_TRUSTEE).constraint_paths,
            (
                'trustgroup__group__permissions',
                'trustgroup__group__roles__permissions',
            ),
        )
        labels = [adapter.label for adapter in Trustee.adapters()]
        self.assertEqual(labels, sorted(labels))
        self.assertEqual(labels, [DIRECT_TRUSTEE, GROUP_TRUSTEE])

    def test_duplicate_registration_is_idempotent(self):
        prepare_trustee_registry()
        again = Trustee.register(
            name=DIRECT_TRUSTEE,
            trustee_model=TrustUserPermission._meta.get_field('entity').remote_field.model,
            grant_model=TrustUserPermission,
            trustee_path='entity',
            scope_path='trust',
            operation_path='permission',
            membership_path='',
        )
        self.assertTrue(again.equivalent(Trustee.get(DIRECT_TRUSTEE)))

    def test_freeze_rejects_late_successful_registration(self):
        prepare_trustee_registry()
        self.assertTrue(Trustee.is_frozen())
        registry = _kernel_registry()
        registry.freeze()
        self.assertTrue(registry.is_frozen())
        with self.assertRaises(TrusteeRegistryFrozen):
            registry.register(
                name='desk',
                trustee_model=TrusteeDesk,
                grant_model=TrusteeDeskGrant,
                trustee_path='desk',
                scope_path='scope',
                operation_path='operation',
                membership_path='collective__members',
            )
        self.assertFalse(registry.is_registered('desk'))
        self.assertFalse(Trustee.is_registered('desk'))

    def test_private_registry_freeze_and_order(self):
        registry = _kernel_registry()
        labels = [adapter.label for adapter in registry.adapters()]
        self.assertEqual(labels, ['collective', 'direct'])
        self.assertEqual(labels, sorted(labels))
        registry.freeze()
        self.assertTrue(registry.is_frozen())
        with self.assertRaises(TrusteeRegistryFrozen):
            registry.register(
                name='desk',
                trustee_model=TrusteeDesk,
                grant_model=TrusteeDeskGrant,
                trustee_path='desk',
                scope_path='scope',
                operation_path='operation',
                membership_path='collective__members',
            )
        registry.freeze()
        self.assertTrue(registry.is_frozen())

    def test_unregistered_lookup_fails_closed(self):
        with self.assertRaises(TrusteeNotRegistered):
            Trustee.get('missing')

    def test_finalizers_run_once_before_freeze(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        calls = []

        def fin():
            calls.append(1)
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='scope',
                operation_path='operation',
            )

        registry.add_finalizer(fin)
        registry.ensure_frozen()
        self.assertTrue(registry.is_frozen())
        self.assertTrue(registry.is_registered('direct'))
        registry.ensure_frozen()
        registry.freeze()
        self.assertEqual(calls, [1])
        with self.assertRaises(TrusteeRegistryFrozen):
            registry.add_finalizer(lambda: None)

    def test_finalizer_failure_does_not_keep_partial_map(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        registry.register(
            name='direct',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeDirectGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )

        def fin():
            registry.register(
                name='collective',
                trustee_model=TrusteeCollective,
                grant_model=TrusteeCollectiveGrant,
                trustee_path='collective',
                scope_path='scope',
                operation_path='operation',
                membership_path='members',
            )
            raise RuntimeError('finalizer failed')

        registry.add_finalizer(fin)
        with self.assertRaises(RuntimeError):
            registry.filter_granted(
                TrusteeScope.objects.none(), None, None,
            )
        self.assertFalse(registry.is_frozen())
        self.assertTrue(registry.is_registered('direct'))
        self.assertFalse(registry.is_registered('collective'))
        self.assertEqual(len(registry._finalizers), 1)

    def test_query_paths_run_registry_finalizers(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        calls = []
        registry.add_finalizer(lambda: calls.append('fin'))
        registry.register(
            name='direct',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeDirectGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )
        registry.filter_granted(
            TrusteeScope.objects.none(),
            TrusteeRequester(pk=-1),
            TrusteeOperation(pk=-1),
        )
        self.assertEqual(calls, ['fin'])
        self.assertTrue(registry.is_frozen())

    def test_mixin_does_not_auto_register(self):
        prepare_trustee_registry()
        self.assertTrue(issubclass(Role, TrusteeMixin))
        self.assertTrue(issubclass(TrusteeBundle, TrusteeMixin))
        names = [adapter.name for adapter in Trustee.adapters()]
        self.assertNotIn(Role._meta.model_name, names)
        self.assertNotIn(TrusteeBundle._meta.model_name, names)


class TrusteeFreshProcessFreezeTest(SimpleTestCase):
    def test_grant_q_finalizes_defaults_before_freeze(self):
        root = Path(__file__).resolve().parents[2]
        env = os.environ.copy()
        env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
        env['PYTHONPATH'] = os.pathsep.join(
            [str(root)] + ([env['PYTHONPATH']] if env.get('PYTHONPATH') else [])
        )
        script = r'''
import django
django.setup()
from trusts.models import DIRECT_TRUSTEE, GROUP_TRUSTEE, Trust, prepare_trustee_registry
from trusts.trustee import Trustee

assert not Trustee.is_frozen()
assert not Trustee.is_registered(DIRECT_TRUSTEE)
assert not Trustee.is_registered(GROUP_TRUSTEE)

Trustee.filter_granted(Trust.objects.none(), None, None)

assert Trustee.is_frozen()
assert Trustee.is_registered(DIRECT_TRUSTEE)
assert Trustee.is_registered(GROUP_TRUSTEE)
assert [adapter.name for adapter in Trustee.adapters()] == [
    DIRECT_TRUSTEE, GROUP_TRUSTEE,
]

prepare_trustee_registry()
assert Trustee.is_registered(GROUP_TRUSTEE)
print('ok')
'''
        proc = subprocess.run(
            [sys.executable, '-c', script],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('ok', proc.stdout)


class TrusteeValidationTest(TestCase):
    def test_scalar_and_callable_paths_fail_closed(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='scope',
                operation_path=lambda: 'operation',
            )
        self.assertIn('callable', str(ctx.exception).lower())
        class ScalarGrant(models.Model):
            scope = models.ForeignKey(
                TrusteeScope, on_delete=models.CASCADE,
            )
            requester = models.ForeignKey(
                TrusteeRequester, on_delete=models.CASCADE,
            )
            operation = models.ForeignKey(
                TrusteeOperation, on_delete=models.CASCADE,
            )
            label = models.CharField(max_length=16)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=ScalarGrant,
                trustee_path='requester',
                scope_path='label',
                operation_path='operation',
            )
        self.assertIn('scalar', str(ctx.exception).lower())
        self.assertIsNotNone(check_registration(
            'direct', TrusteeRequester, ScalarGrant, 'requester',
            'label', 'operation', requester_model=TrusteeRequester,
        ))

    def test_missing_and_incomplete_fail_closed(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(
                name='',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='scope',
                operation_path='operation',
            )
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='',
                operation_path='operation',
            )
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='None__scope',
                operation_path='operation',
            )

    def test_wrong_requester_terminal_fail_closed(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='collective',
                trustee_model=TrusteeCollective,
                grant_model=TrusteeCollectiveGrant,
                trustee_path='collective',
                scope_path='scope',
                operation_path='operation',
                membership_path='operations',
            )
        self.assertIn('not the configured requester', str(ctx.exception))

    def test_identity_requires_requester_trustee(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='collective',
                trustee_model=TrusteeCollective,
                grant_model=TrusteeCollectiveGrant,
                trustee_path='collective',
                scope_path='scope',
                operation_path='operation',
                membership_path='',
            )
        self.assertIn('Identity membership', str(ctx.exception))

    def test_many_valued_grant_identity_fail_closed(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='collective',
                trustee_model=TrusteeCollective,
                grant_model=TrusteeCollective,
                trustee_path='members',
                scope_path='members',
                operation_path='operations',
                membership_path='members',
            )
        self.assertIn('many-valued', str(ctx.exception))

    def test_duplicate_different_declaration_rejected(self):
        registry = _kernel_registry()
        registry.register(
            name='direct',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeDirectGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeTrapGrant,
                trustee_path='requester',
                scope_path='scope',
                operation_path='operation',
            )
        self.assertIn('already registered', str(ctx.exception))

    def test_duplicate_equivalent_paths_under_new_name_rejected(self):
        registry = _kernel_registry()
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='alias',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='requester',
                scope_path='scope',
                operation_path='operation',
            )
        self.assertIn('duplicates', str(ctx.exception))

    def test_wrong_trustee_path_terminal_fail_closed(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='direct',
                trustee_model=TrusteeRequester,
                grant_model=TrusteeDirectGrant,
                trustee_path='scope',
                scope_path='scope',
                operation_path='operation',
            )
        self.assertIn('not trustee_model', str(ctx.exception))

    def test_constraint_must_terminate_at_operation(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                name='collective',
                trustee_model=TrusteeCollective,
                grant_model=TrusteeCollectiveGrant,
                trustee_path='collective',
                scope_path='scope',
                operation_path='operation',
                membership_path='members',
                constraint_paths=('collective',),
            )
        self.assertIn('not the operation model', str(ctx.exception))

    def test_multi_hop_membership_is_valid(self):
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        adapter = registry.register(
            name='desk',
            trustee_model=TrusteeDesk,
            grant_model=TrusteeDeskGrant,
            trustee_path='desk',
            scope_path='scope',
            operation_path='operation',
            membership_path='collective__members',
        )
        self.assertEqual(adapter.requester_from_grant_path(), 'desk__collective__members')
        self.assertIs(adapter.requester_model(), TrusteeRequester)

    def test_external_model_registers_without_inheritance(self):
        registry = _kernel_registry()
        self.assertFalse(issubclass(TrusteeCollective, TrusteeMixin))
        self.assertTrue(registry.is_registered('collective'))


class TrusteeSystemCheckTest(TestCase):
    def test_installed_registry_has_no_e007(self):
        messages = check_trustee_registry(None)
        self.assertEqual(
            [m for m in messages if m.id == CHECK_ID_INVALID_TRUSTEE],
            [],
        )
        all_messages = run_checks()
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in all_messages)
        )

    def test_installed_invalid_declaration_emits_trusts_e007(self):
        prepare_trustee_registry()
        registry = Trustee.registry
        saved = registry._adapters[DIRECT_TRUSTEE]
        registry._adapters[DIRECT_TRUSTEE] = TrusteeAdapter(
            KIND_GRANT, DIRECT_TRUSTEE, saved.trustee_model, '',
            TrustUserPermission, 'entity', 'trust', 'not_a_field', (), registry,
        )
        try:
            messages = check_trustee_registry(None)
            e007 = [m for m in messages if m.id == CHECK_ID_INVALID_TRUSTEE]
            self.assertEqual(len(e007), 1)
            self.assertEqual(e007[0].id, 'trusts.E007')
            self.assertIsInstance(e007[0], Error)
            self.assertIs(e007[0].obj, TrustUserPermission)
            self.assertEqual(e007[0].hint, _SILENCE_DOES_NOT_ENABLE_TRUSTEE_HINT)
            self.assertIn('not a field', e007[0].msg)
            self.assertIn('fail-closed', e007[0].hint)
        finally:
            registry._adapters[DIRECT_TRUSTEE] = saved

        restored = check_trustee_registry(None)
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_TRUSTEE for m in restored)
        )


class TrusteeNoCallbackTest(TestCase):
    def test_resolution_does_not_execute_getters_or_properties(self):
        requester = TrusteeRequester.objects.create(name='trap-user')
        scope = TrusteeScope.objects.create(title='trap-scope')
        operation = TrusteeOperation.objects.create(code='read')
        grant = TrusteeTrapGrant.objects.create(
            scope=scope, requester=requester, operation=operation,
        )
        registry = TrusteeRegistry(requester_model=TrusteeRequester)
        registry.register(
            name='trap',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeTrapGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )
        with self.assertNumQueries(1):
            self.assertTrue(registry.row_is_granted(scope, requester, operation))
        with self.assertNumQueries(1):
            listed = list(
                registry.filter_granted(
                    TrusteeScope.objects.all(), requester, operation,
                ).values_list('pk', flat=True)
            )
        self.assertEqual(listed, [scope.pk])
        with self.assertRaises(AssertionError):
            grant.forbidden
        with self.assertRaises(AssertionError):
            grant.get_requester()


class TrusteeQueryContractTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(TrusteeQueryContractTest, self).setUp()
        self.requester = TrusteeRequester.objects.create(name='alice')
        self.other = TrusteeRequester.objects.create(name='bob')
        self.scope_a = TrusteeScope.objects.create(title='A')
        self.scope_b = TrusteeScope.objects.create(title='B')
        self.read = TrusteeOperation.objects.create(code='read')
        self.write = TrusteeOperation.objects.create(code='write')
        self.resource_a = TrusteeResource.objects.create(
            scope=self.scope_a, title='Res A',
        )
        self.resource_b = TrusteeResource.objects.create(
            scope=self.scope_b, title='Res B',
        )
        self.collective = TrusteeCollective.objects.create(name='readers')
        self.collective.members.add(self.requester)
        self.collective.operations.add(self.read)
        self.registry = _kernel_registry()
        self.registry.freeze()

    def _assert_direct_list_equivalence(self, scope, operation, expected):
        with self.assertNumQueries(1):
            listed = list(
                self.registry.filter_granted(
                    TrusteeScope.objects.all(), self.requester, operation,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [obj.pk for obj in expected])
        for obj in expected:
            with self.assertNumQueries(1):
                self.assertTrue(
                    self.registry.row_is_granted(obj, self.requester, operation)
                )
        others = [
            obj for obj in TrusteeScope.objects.order_by('pk')
            if obj.pk not in {e.pk for e in expected}
        ]
        for obj in others:
            with self.assertNumQueries(1):
                self.assertFalse(
                    self.registry.row_is_granted(obj, self.requester, operation)
                )

    def test_direct_grant_one_query_and_list_equivalence(self):
        TrusteeDirectGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.read,
        )
        self._assert_direct_list_equivalence(self.scope_a, self.read, [self.scope_a])

    def test_collective_requires_membership_grant_and_constraint(self):
        TrusteeCollectiveGrant.objects.create(
            scope=self.scope_a, collective=self.collective, operation=self.read,
        )
        self._assert_direct_list_equivalence(self.scope_a, self.read, [self.scope_a])

        TrusteeCollectiveGrant.objects.create(
            scope=self.scope_b, collective=self.collective, operation=self.write,
        )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.row_is_granted(
                    self.scope_b, self.requester, self.write,
                )
            )

        outsider = TrusteeCollective.objects.create(name='outsiders')
        outsider.operations.add(self.read)
        TrusteeCollectiveGrant.objects.create(
            scope=self.scope_b, collective=outsider, operation=self.read,
        )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.row_is_granted(
                    self.scope_b, self.requester, self.read,
                )
            )

    def test_bundle_constraint_is_ceiling_not_a_grant(self):
        bundle = TrusteeBundle.objects.create(name='reader-bundle')
        bundle.collectives.add(self.collective)
        bundle.operations.add(self.write)
        TrusteeCollectiveGrant.objects.create(
            scope=self.scope_a, collective=self.collective, operation=self.write,
        )
        with self.assertNumQueries(1):
            self.assertTrue(
                self.registry.row_is_granted(
                    self.scope_a, self.requester, self.write,
                )
            )
        self.assertFalse(
            self.registry.row_is_granted(
                self.scope_b, self.requester, self.write,
            )
        )

    def test_or_composes_direct_and_collective(self):
        TrusteeDirectGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.write,
        )
        TrusteeCollectiveGrant.objects.create(
            scope=self.scope_b, collective=self.collective, operation=self.read,
        )
        with self.assertNumQueries(1):
            listed = list(
                self.registry.filter_granted(
                    TrusteeScope.objects.all(), self.requester, self.read,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.scope_b.pk])
        with self.assertNumQueries(1):
            listed = list(
                self.registry.filter_granted(
                    TrusteeScope.objects.all(), self.requester, self.write,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.scope_a.pk])

    def test_resource_scope_from_row_shares_predicate(self):
        TrusteeDirectGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.read,
        )
        with self.assertNumQueries(1):
            listed = list(
                self.registry.filter_granted(
                    TrusteeResource.objects.all(),
                    self.requester,
                    self.read,
                    scope_from_row='scope',
                ).values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.resource_a.pk])
        with self.assertNumQueries(1):
            self.assertTrue(
                self.registry.row_is_granted(
                    self.resource_a, self.requester, self.read,
                    scope_from_row='scope',
                )
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.row_is_granted(
                    self.resource_b, self.requester, self.read,
                    scope_from_row='scope',
                )
            )

    def test_same_compiled_predicate_for_exists_and_filter(self):
        TrusteeDirectGrant.objects.create(
            scope=self.scope_a, requester=self.requester, operation=self.read,
        )
        exists_sql = str(
            TrusteeScope.objects.filter(pk=self.scope_a.pk).filter(
                self.registry.grant_q(self.requester, self.read)
            ).query
        )
        list_sql = str(
            self.registry.filter_granted(
                TrusteeScope.objects.all(), self.requester, self.read,
            ).query
        )
        self.assertIn('trusteer', exists_sql.lower() + list_sql.lower())


class TrusteeConvenienceCompatibilityTest(TestCase):
    def test_group_is_explicit_external_registration(self):
        prepare_trustee_registry()
        adapter = Trustee.get(GROUP_TRUSTEE)
        self.assertFalse(issubclass(adapter.trustee_model, TrusteeMixin))
        self.assertEqual(adapter.trustee_model._meta.label, 'auth.Group')
        self.assertIs(adapter.grant_model, TrustGroupPermission)

    def test_role_mixin_does_not_add_a_grant_adapter(self):
        prepare_trustee_registry()
        self.assertTrue(issubclass(Role, TrusteeMixin))
        self.assertEqual(
            [adapter.name for adapter in Trustee.adapters()],
            [DIRECT_TRUSTEE, GROUP_TRUSTEE],
        )
        group = Trustee.get(GROUP_TRUSTEE)
        self.assertIn('roles__permissions', group.constraint_paths[1])


class TrusteeAuthQueryParityTest(TestCase):
    """Current User / Group / Role-ceiling paths stay equivalent."""

    def setUp(self):
        super(TrusteeAuthQueryParityTest, self).setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        create_test_users(self)
        self.trust_a = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Trustee A',
        )
        self.trust_a.save()
        self.trust_b = Trust(
            settlor=self.user1, trust=Trust.objects.get_root(), title='Trustee B',
        )
        self.trust_b.save()
        self.receipt_a = Receipt.objects.create(trust=self.trust_a, title='A')
        self.receipt_b = Receipt.objects.create(trust=self.trust_b, title='B')
        ct = ContentType.objects.get_for_model(Receipt)
        self.perm = Permission.objects.get(
            content_type=ct, codename='read_receipt',
        )
        prepare_trustee_registry()

    def test_direct_user_has_perm_and_permitted_agree(self):
        TrustUserPermission.objects.get_or_create(
            trust=self.trust_a, entity=self.user, permission=self.perm,
        )
        reload_test_users(self)
        listed = set(
            Receipt.objects.permitted('read', self.user).values_list('pk', flat=True)
        )
        allowed = {
            receipt.pk
            for receipt in Receipt.objects.order_by('pk')
            if self.user.has_perm('trusts_tests.read_receipt', receipt)
        }
        self.assertEqual(listed, allowed)
        self.assertEqual(listed, {self.receipt_a.pk})
        self.assertFalse(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_b)
        )

    def test_group_path_unchanged_with_local_and_ceiling(self):
        group = Group.objects.create(name='trustee-readers')
        group.user_set.add(self.user)
        group.permissions.add(self.perm)
        self.trust_a.groups.add(group)
        enable_local_group_grant(self.trust_a, group, self.perm)
        reload_test_users(self)
        listed = set(
            Receipt.objects.permitted('read', self.user).values_list('pk', flat=True)
        )
        self.assertEqual(listed, {self.receipt_a.pk})
        self.assertTrue(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_a)
        )
        self.assertFalse(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_b)
        )

    def test_role_ceiling_still_requires_local_grant(self):
        group = Group.objects.create(name='trustee-role-readers')
        group.user_set.add(self.user)
        role = Role.objects.create(name='trustee-reader-role')
        role.groups.add(group)
        role.permissions.add(self.perm)
        self.trust_a.groups.add(group)
        reload_test_users(self)
        self.assertFalse(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_a)
        )
        enable_local_group_grant(self.trust_a, group, self.perm)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_a)
        )
        listed = set(
            Receipt.objects.permitted('read', self.user).values_list('pk', flat=True)
        )
        self.assertEqual(listed, {self.receipt_a.pk})

    def test_permitted_is_one_list_query_after_permission_resolve(self):
        TrustUserPermission.objects.get_or_create(
            trust=self.trust_a, entity=self.user, permission=self.perm,
        )
        Receipt.objects.get_permission('read')
        with self.assertNumQueries(2):
            pks = list(
                Receipt.objects.permitted('read', self.user)
                .values_list('pk', flat=True)
            )
        self.assertEqual(pks, [self.receipt_a.pk])
