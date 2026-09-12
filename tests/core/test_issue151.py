"""#151 C1: Core-owned default condition lookup.

Library-only. Does not import Zero nouns. ``RegistryConditionLookup``
stays on ``trusts.conditions._ir``.
"""

import os
import subprocess
import sys
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from trusts.conditions._ir import ConditionRecord, RegistryConditionLookup
from trusts.core import TrustsConfigurationError, TrustsRegistry
from trusts.conditions import PermissionConditionError


def _note_models():
    User = get_user_model()

    class Note(models.Model):
        title = models.CharField(max_length=40)
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        status = models.CharField(max_length=20, default='open')

        class Meta:
            app_label = 'trusts_tests'

    return Note


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


_IMPORT_ORDER_SCRIPT = """
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
root = %r
if root not in sys.path:
    sys.path.insert(0, root)

import django
django.setup()

if %r:
    import trusts.conditions._ir  # noqa: F401
import trusts.core
from trusts.conditions._ir import RegistryConditionLookup

registry = trusts.core.TrustsRegistry()
assert registry.condition_lookup is not None
assert isinstance(registry.condition_lookup, RegistryConditionLookup)
assert registry.condition_lookup.conditions is registry.conditions
print('ok')
"""


class DefaultLookupBindTest(TestCase):
    def test_apps_registers_meta_option_without_ir(self):
        from django.db.models import options as model_options

        import trusts.apps as apps_mod

        self.assertIn('permission_conditions', model_options.DEFAULT_NAMES)
        self.assertFalse(hasattr(apps_mod, 'RegistryConditionLookup'))

    def test_construct_self_binds_private_adapter_zero_sql(self):
        with self.assertNumQueries(0):
            registry = TrustsRegistry()
            registry.freeze()
        self.assertIsInstance(registry.condition_lookup, RegistryConditionLookup)
        self.assertIs(registry.condition_lookup.conditions, registry.conditions)
        self.assertTrue(registry.frozen)

    def test_handles_stay_isolated(self):
        left = TrustsRegistry()
        right = TrustsRegistry()
        self.assertIsNot(left.condition_lookup, right.condition_lookup)
        self.assertIsNot(left.conditions, right.conditions)
        self.assertIs(left.condition_lookup.conditions, left.conditions)
        self.assertIs(right.condition_lookup.conditions, right.conditions)

    def test_explicit_unbind_and_partial_bind_do_not_mutate(self):
        registry = TrustsRegistry()
        bound = registry.condition_lookup
        with self.assertNumQueries(0):
            registry.set_condition_lookup(None)
        self.assertIsNone(registry.condition_lookup)

        class OnlyRecord(object):
            def record_for(self, model, cond_code):
                return None

        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                registry.set_condition_lookup(OnlyRecord())
        self.assertIsNone(registry.condition_lookup)
        with self.assertNumQueries(0):
            registry.set_condition_lookup(bound)
        self.assertIs(registry.condition_lookup, bound)

    def _import_order(self, ir_first):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        script = _IMPORT_ORDER_SCRIPT % (root, ir_first)
        env = os.environ.copy()
        env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
        env['PYTHONPATH'] = os.pathsep.join(
            [root] + ([env['PYTHONPATH']] if env.get('PYTHONPATH') else [])
        )
        proc = subprocess.run(
            [sys.executable, '-c', script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('ok', proc.stdout)

    def test_core_then_construct_is_not_circular(self):
        self._import_order(ir_first=False)

    def test_ir_then_core_construct_is_not_circular(self):
        self._import_order(ir_first=True)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class DefaultLookupCompileTest(TransactionTestCase):
    def test_named_condition_compiles_without_consumer_bind(self):
        Note = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-151', 'alice-151@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            locked = Note.objects.create(
                title='drop', owner=alice, status='locked',
            )
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                registry.register_permission_condition(
                    Note, 'open', lambda u, p, o: o.status != 'locked',
                )
            lookup = registry.condition_lookup
            self.assertIsInstance(lookup, RegistryConditionLookup)
            record = lookup.record_for(Note, 'open')
            self.assertIsNotNone(record)
            q = lookup.compile_q(Note, 'trusts_tests.change_note:open', alice)
            listed = set(Note.objects.filter(q).values_list('pk', flat=True))
            self.assertEqual(listed, {keep.pk})
            self.assertNotIn(locked.pk, listed)
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'open', alice, 'trusts_tests.change_note', keep,
                )
            )
            self.assertFalse(
                registry.evaluate_permission_condition(
                    Note, 'open', alice, 'trusts_tests.change_note', locked,
                )
            )

    def test_unknown_unbind_and_unbound_record_fail_closed(self):
        Note = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-151u', 'alice-151u@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice)
            registry = TrustsRegistry()
            lookup = registry.condition_lookup
            self.assertIsNone(lookup.record_for(Note, 'missing'))
            with self.assertRaises(AttributeError) as missing:
                lookup.compile_q(
                    Note, 'trusts_tests.change_note:missing', alice,
                )
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(PermissionConditionError) as typo:
                registry.register_permission_condition(
                    Note, 'typo', lambda u, p, o: u == o.nope,
                )
            self.assertIn('nope', str(typo.exception))
            self.assertIsNone(
                registry.get_permission_condition_record(Note, 'typo'),
            )
            empty = ConditionRecord(model=Note)
            registry.conditions._records[(Note._meta.label, 'empty')] = empty
            with self.assertRaises(PermissionConditionError) as unbound:
                registry.evaluate_permission_condition(
                    Note, 'empty', alice, 'trusts_tests.change_note', note,
                )
            self.assertIn('unbound', str(unbound.exception))
            registry.set_condition_lookup(None)
            self.assertIsNone(registry.condition_lookup)
