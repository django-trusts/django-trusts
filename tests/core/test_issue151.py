"""#151 C1: construct-time self-bind of Core's private condition lookup.

Library-only proofs. Applications register builders; they do not import
``trusts.conditions._ir`` or call ``set_condition_lookup``.
"""

import os
import subprocess
import sys
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document
from trusts.apps import TrustsImplementationConfig, implementation_for_path
from trusts.conditions import (
    PermissionConditionError,
    permission_condition_code,
    permission_has_condition,
)
from trusts.conditions._ir import ConditionRecord, RegistryConditionLookup
from trusts.core import TrustsConfigurationError, TrustsRegistry


ROOT = Path(__file__).resolve().parents[2]

PUBLIC_SURFACE_NAMES = (
    'PermissionConditionBooleanError',
    'PermissionConditionError',
    'PermissionConditionNotQueryable',
    'PermissionConditionUnsupported',
    'permission_condition_code',
    'permission_has_condition',
)


def _note_model():
    User = get_user_model()

    class Note(models.Model):
        title = models.CharField(max_length=40)
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        status = models.CharField(max_length=20, default='open')

        class Meta:
            app_label = 'trusts_tests'

    return Note


class _IsolatedTables(object):
    def __init__(self, *model_classes):
        self.model_classes = model_classes

    def __enter__(self):
        with connection.schema_editor() as editor:
            for model in self.model_classes:
                editor.create_model(model)
        return self

    def __exit__(self, exc_type, exc, tb):
        with connection.schema_editor() as editor:
            for model in reversed(self.model_classes):
                editor.delete_model(model)


class ConstructTimeSelfBindTest(SimpleTestCase):
    def test_new_registry_self_binds_private_store_adapter(self):
        registry = TrustsRegistry()
        lookup = registry.condition_lookup
        self.assertIsInstance(lookup, RegistryConditionLookup)
        self.assertIs(lookup.conditions, registry.conditions)
        self.assertFalse(registry.frozen)

    def test_handles_do_not_share_lookup_or_store(self):
        left = TrustsRegistry()
        right = TrustsRegistry()
        self.assertIsNot(left.conditions, right.conditions)
        self.assertIsNot(left.condition_lookup, right.condition_lookup)
        self.assertIs(left.condition_lookup.conditions, left.conditions)
        self.assertIs(right.condition_lookup.conditions, right.conditions)

    def test_freeze_and_ready_do_not_bind_or_rebind(self):
        import inspect

        registry = TrustsRegistry()
        lookup = registry.condition_lookup
        registry.freeze()
        self.assertTrue(registry.frozen)
        self.assertIs(registry.condition_lookup, lookup)
        self.assertIs(lookup.conditions, registry.conditions)
        self.assertNotIn(
            'set_condition_lookup',
            inspect.getsource(TrustsRegistry.freeze),
        )
        self.assertNotIn(
            'RegistryConditionLookup',
            inspect.getsource(TrustsRegistry.freeze),
        )
        self.assertNotIn(
            'set_condition_lookup',
            inspect.getsource(TrustsImplementationConfig.ready),
        )
        self.assertNotIn(
            'RegistryConditionLookup',
            inspect.getsource(TrustsImplementationConfig.ready),
        )

    def test_public_conditions_surface_stays_six_names(self):
        import django_trusts
        import trusts.conditions as conditions_mod

        self.assertEqual(tuple(conditions_mod.__all__), PUBLIC_SURFACE_NAMES)
        self.assertFalse(hasattr(conditions_mod, 'RegistryConditionLookup'))
        self.assertFalse(hasattr(conditions_mod, 'ConditionRegistry'))
        self.assertFalse(hasattr(django_trusts, 'RegistryConditionLookup'))
        self.assertTrue(permission_has_condition('change_note:own'))
        self.assertEqual(permission_condition_code('change_note:own'), 'own')


class ImportOrderStandaloneConstructionTest(SimpleTestCase):
    def _run_isolated(self, source):
        env = os.environ.copy()
        env.pop('DJANGO_SETTINGS_MODULE', None)
        pythonpath = [str(ROOT)]
        existing = env.get('PYTHONPATH')
        if existing:
            pythonpath.append(existing)
        env['PYTHONPATH'] = os.pathsep.join(pythonpath)
        result = subprocess.run(
            [sys.executable, '-c', source],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            result.stdout + result.stderr,
        )
        return result.stdout

    def test_import_core_then_construct_does_not_preload_ir(self):
        stdout = self._run_isolated(
            'import sys\n'
            'import trusts.core\n'
            'assert "trusts.conditions._ir" not in sys.modules\n'
            'registry = trusts.core.TrustsRegistry()\n'
            'assert "trusts.conditions._ir" in sys.modules\n'
            'lookup = registry.condition_lookup\n'
            'assert lookup is not None\n'
            'assert lookup.conditions is registry.conditions\n'
            'print("core-then-construct-ok")\n'
        )
        self.assertIn('core-then-construct-ok', stdout)

    def test_import_ir_then_construct_is_not_circular(self):
        stdout = self._run_isolated(
            'import trusts.conditions._ir\n'
            'import trusts.core\n'
            'registry = trusts.core.TrustsRegistry()\n'
            'lookup = registry.condition_lookup\n'
            'assert isinstance(\n'
            '    lookup, trusts.conditions._ir.RegistryConditionLookup,\n'
            ')\n'
            'assert lookup.conditions is registry.conditions\n'
            'print("ir-then-construct-ok")\n'
        )
        self.assertIn('ir-then-construct-ok', stdout)


class LiveEnsureSelfBindTest(SimpleTestCase):
    def test_live_ensure_registry_is_self_bound_without_host_wiring(self):
        apps_text = (ROOT / 'tests' / 'myapp' / 'apps.py').read_text()
        self.assertNotIn('RegistryConditionLookup', apps_text)
        self.assertNotIn('set_condition_lookup', apps_text)
        owner = implementation_for_path(DOCUMENT_BACKEND)
        registry = owner.configured_backend().registry
        self.assertTrue(registry.frozen)
        lookup = registry.condition_lookup
        self.assertIsInstance(lookup, RegistryConditionLookup)
        self.assertIs(lookup.conditions, registry.conditions)


class OverrideUnbindAndFailClosedTest(TestCase):
    def test_explicit_unbind_and_partial_bind_do_not_mutate_wrongly(self):
        registry = TrustsRegistry()
        default = registry.condition_lookup
        self.assertIs(default.conditions, registry.conditions)

        class OnlyRecord(object):
            def record_for(self, model, cond_code):
                return None

        with self.assertRaises(TrustsConfigurationError):
            registry.set_condition_lookup(OnlyRecord())
        self.assertIs(registry.condition_lookup, default)

        registry.set_condition_lookup(None)
        self.assertIsNone(registry.condition_lookup)
        registry.set_condition_lookup(default)
        self.assertIs(registry.condition_lookup, default)

    def test_unknown_condition_fail_closes_through_supported_backend_path(self):
        backend = DocumentBackend()
        document = Document(title='probe')
        user = get_user_model()(username='probe-151')
        with self.assertRaises(AttributeError) as ctx:
            backend._condition_overlay(
                'myapp.change_document:missing', document, user,
            )
        self.assertIn('missing', str(ctx.exception))

    def test_explicit_unbind_fail_closes_named_condition_overlay(self):
        backend = DocumentBackend()
        registry = backend._own_handle().registry
        previous = registry.condition_lookup
        document = Document(title='unbind')
        user = get_user_model()(username='unbind-151')
        try:
            registry.set_condition_lookup(None)
            with self.assertRaises(AttributeError):
                backend._condition_overlay(
                    'myapp.change_document:non_confidential',
                    document,
                    user,
                )
        finally:
            registry.set_condition_lookup(previous)
        self.assertIs(registry.condition_lookup, previous)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedConditionCompilationTest(TransactionTestCase):
    def test_zero_sql_construction_registration_and_finalization(self):
        Note = _note_model()
        with self.assertNumQueries(0):
            registry = TrustsRegistry()
            lookup = registry.condition_lookup
            self.assertIs(lookup.conditions, registry.conditions)
            registry.register_permission_condition(
                Note, 'owned', lambda u, p, o: u == o.owner,
            )
            registry.freeze()
        self.assertTrue(registry.frozen)
        self.assertIs(registry.condition_lookup, lookup)
        self.assertIsNotNone(
            registry.get_permission_condition_record(Note, 'owned'),
        )

    def test_core_only_named_condition_compiles_through_supported_calls(self):
        Note = _note_model()
        User = get_user_model()
        with _IsolatedTables(Note):
            alice = User.objects.create_user(
                'alice-151', 'alice-151@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-151', 'bob-151@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice)
            drop = Note.objects.create(title='drop', owner=bob)
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                registry.register_permission_condition(
                    Note, 'owned', lambda u, p, o: u == o.owner,
                )
            lookup = registry.condition_lookup
            self.assertIs(lookup.conditions, registry.conditions)
            record = lookup.record_for(Note, 'owned')
            self.assertIsNotNone(record)
            self.assertIs(
                record,
                registry.get_permission_condition_record(Note, 'owned'),
            )
            perm = 'trusts_tests.change_note:owned'
            compiled = lookup.compile_q(Note, perm, alice)
            stored = registry.compile_registered_condition_q(Note, perm, alice)
            self.assertEqual(str(compiled), str(stored))
            listed = set(Note.objects.filter(compiled).values_list('pk', flat=True))
            self.assertEqual(listed, {keep.pk})
            self.assertNotIn(drop.pk, listed)
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'owned', alice, 'trusts_tests.change_note', keep,
                )
            )
            self.assertFalse(
                registry.evaluate_permission_condition(
                    Note, 'owned', alice, 'trusts_tests.change_note', drop,
                )
            )

    def test_unknown_unbound_and_malformed_fail_closed(self):
        Note = _note_model()
        User = get_user_model()
        with _IsolatedTables(Note):
            alice = User.objects.create_user(
                'alice-151u', 'alice-151u@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice)
            registry = TrustsRegistry()
            lookup = registry.condition_lookup
            self.assertIsNone(lookup.record_for(Note, 'missing'))
            with self.assertRaises(AttributeError) as missing:
                registry.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:missing', alice,
                )
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(TypeError):
                registry.register_permission_condition(
                    Note, 'typo', 'not-a-builder',
                )
            self.assertIsNone(
                registry.get_permission_condition_record(Note, 'typo'),
            )
            with self.assertRaises(PermissionConditionError):
                registry.register_permission_condition(
                    Note, 'typo', lambda u, p, o: u == o.nope,
                )
            self.assertIsNone(
                registry.get_permission_condition_record(Note, 'typo'),
            )
            registry.conditions._records[(Note._meta.label, 'empty')] = (
                ConditionRecord(model=Note)
            )
            with self.assertRaises(PermissionConditionError) as unbound:
                registry.evaluate_permission_condition(
                    Note, 'empty', alice, 'trusts_tests.change_note', note,
                )
            self.assertIn('unbound', str(unbound.exception))
