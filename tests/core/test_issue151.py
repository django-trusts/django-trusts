from tests.support import built_catalog, configured_catalog, unbound_named_filters
"""#151 C1: construct-time self-bind of Core's private condition lookup.

Library-only proofs. Applications register builders; they do not import
``trusts.plan.conditions`` or call ``set_filter_lookup``.
"""

import os
import subprocess
import sys
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document
from trusts.apps import TrustsImplementationConfig
from trusts.conditions import (
    PermissionConditionError,
    permission_condition_code,
    permission_has_condition,
)
from trusts.plan.conditions import ConditionRecord, FrozenConditionLookup
from trusts.compile.factory import RegistryFactory
from trusts.errors import TrustsConfigurationError


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
        registry = RegistryFactory()
        self.assertIsNone(registry.filter_lookup)
        built = built_catalog(registry)
        self.assertIsInstance(built.filter_lookup, FrozenConditionLookup)
        self.assertFalse(hasattr(built.filter_lookup, 'conditions'))

    def test_handles_do_not_share_lookup_or_store(self):
        left = RegistryFactory()
        right = RegistryFactory()
        self.assertIsNot(left.conditions, right.conditions)
        self.assertIsNone(left.filter_lookup)
        self.assertIsNone(right.filter_lookup)

    def test_build_and_ready_do_not_bind_or_rebind(self):
        import inspect

        registry = RegistryFactory()
        built = built_catalog(registry)
        self.assertIsInstance(built.filter_lookup, FrozenConditionLookup)
        self.assertIsNone(registry.filter_lookup)
        self.assertFalse(hasattr(built.filter_lookup, 'conditions'))
        source = inspect.getsource(RegistryFactory.build)
        self.assertNotIn('set_filter_lookup', source)
        self.assertIn('FrozenConditionLookup', source)
        self.assertNotIn(
            'set_filter_lookup',
            inspect.getsource(TrustsImplementationConfig.ready),
        )
        self.assertNotIn(
            'RegistryConditionLookup',
            inspect.getsource(RegistryFactory.build),
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

    def test_companion_pin_is_exact_zero_candidate(self):
        z_methods = '833866b9a096ac8a31e8bc60424e01a02f05389c'
        stale_r5a = '462c83b59edfb51011b4373e8214b2daaab7f500'
        stale_38 = 'c7dc4f11f728ad3c4c22249e471daa4bf9849404'
        stale_191 = '517307170f954f187da78c56e236ec1779c46e29'
        stale_181 = 'f50946f7112702a41bd63a3e044b44a0d4ec3297'
        stale = '841004af49687c31c466ed03dbfd4f8ce9c7f153'
        prior_merged_zero = '2e3cccedb92b4cf85e9d6a3cd2d51821aad1d716'
        pairing = {
            'ci': (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(),
            'wheels': (ROOT / 'scripts' / 'verify-companion-wheels.py').read_text(),
            'runner': (ROOT / 'scripts' / 'run-z1-pair-tests.py').read_text(),
        }
        self.assertIn(z_methods, pairing['ci'])
        self.assertIn(z_methods, pairing['wheels'])
        self.assertIn('COMPANION_ZERO_SHA: %s' % z_methods, pairing['ci'])
        self.assertIn("ZERO_HEAD = '%s'" % z_methods, pairing['wheels'])
        for name, text in pairing.items():
            self.assertNotIn(stale, text, name)
            self.assertNotIn(stale_r5a, text, name)
            self.assertNotIn(stale_38, text, name)
            self.assertNotIn(stale_181, text, name)
            self.assertNotIn(stale_191, text, name)
            self.assertNotIn(prior_merged_zero, text, name)
        self.assertNotIn('OMIT_ZERO_UNBOUND_DEFAULT', pairing['runner'])
        self.assertNotIn(
            'test_unbound_is_none_and_bind_is_zero_sql',
            pairing['runner'],
        )

    def test_host_docs_do_not_import_or_bind_ir_lookup(self):
        apps_text = (ROOT / 'tests' / 'myapp' / 'apps.py').read_text()
        readme = (ROOT / 'README.md').read_text()
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        for text in (apps_text, readme, rst):
            self.assertNotIn('RegistryConditionLookup', text)
            self.assertNotIn('trusts.conditions._ir', text)
            self.assertNotIn('set_filter_lookup', text)


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

    def test_rewrites_import_does_not_load_the_factory(self):
        source = (ROOT / 'trusts' / 'plan' / 'rewrites.py').read_text()
        self.assertNotIn('trusts.compile.factory', source)
        stdout = self._run_isolated(
            'from django.conf import settings\n'
            'settings.configure(\n'
            '    SECRET_KEY="rewrites-import",\n'
            '    USE_TZ=True,\n'
            '    INSTALLED_APPS=[\n'
            '        "django.contrib.contenttypes",\n'
            '        "django.contrib.auth",\n'
            '    ],\n'
            '    DATABASES={"default": {\n'
            '        "ENGINE": "django.db.backends.sqlite3",\n'
            '        "NAME": ":memory:",\n'
            '    }},\n'
            ')\n'
            'import django\n'
            'django.setup()\n'
            'import sys\n'
            'import trusts.plan.rewrites\n'
            'assert "trusts.compile.factory" not in sys.modules\n'
            'from trusts.plan.rewrites import bind_once\n'
            'assert bind_once is trusts.plan.rewrites.bind_once\n'
            'assert "trusts.compile.factory" not in sys.modules\n'
            'print("rewrites-without-factory")\n'
        )
        self.assertIn('rewrites-without-factory', stdout)


class LiveEnsureSelfBindTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_live_ensure_registry_is_self_bound_without_host_wiring(self):
        catalog = configured_catalog(DOCUMENT_BACKEND)
        found = {
            (model, code)
            for model, code, record in catalog.iter_permission_conditions()
        }
        self.assertIn((Document, 'non_confidential'), found)


class OverrideUnbindAndFailClosedTest(KernelHostRequiredMixin, TestCase):
    def test_explicit_unbind_and_partial_bind_do_not_mutate_wrongly(self):
        registry = RegistryFactory()
        frozen = FrozenConditionLookup(())
        self.assertIsNone(registry.filter_lookup)

        class OnlyRecord(object):
            def record_for(self, model, cond_code):
                return None

        with self.assertRaises(TrustsConfigurationError):
            registry.set_filter_lookup(OnlyRecord())
        self.assertIsNone(registry.filter_lookup)

        registry.set_filter_lookup(frozen)
        self.assertIs(registry.filter_lookup, frozen)
        registry.set_filter_lookup(None)
        self.assertIsNone(registry.filter_lookup)
        registry.set_filter_lookup(frozen)
        self.assertIs(registry.filter_lookup, frozen)

    def test_unknown_condition_fail_closes_through_supported_backend_path(self):
        backend = DocumentBackend()
        document = Document(title='probe')
        user = get_user_model()(username='probe-151')
        self.assertFalse(backend.has_perm(
            user, 'myapp.change_document:missing', document,
        ))

    def test_explicit_unbind_fail_closes_named_condition_overlay(self):
        backend = DocumentBackend()
        document = Document(title='unbind')
        user = get_user_model()(username='unbind-151')
        with unbound_named_filters(DocumentBackend):
            with self.assertRaises(AttributeError) as ctx:
                backend.has_perm(
                    user, 'myapp.change_document:non_confidential', document,
                )
            self.assertIn('not associate', str(ctx.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedConditionCompilationTest(TransactionTestCase):
    def test_zero_sql_construction_registration_and_finalization(self):
        Note = _note_model()
        with self.assertNumQueries(0):
            registry = RegistryFactory()
            self.assertIsNone(registry.filter_lookup)
            registry.register_permission_condition(
                Note, 'owned', lambda u, p, o: u == o.owner,
            )
            built = built_catalog(registry)
        self.assertIsInstance(built.filter_lookup, FrozenConditionLookup)
        self.assertIsNone(registry.filter_lookup)
        self.assertFalse(hasattr(built.filter_lookup, 'conditions'))
        self.assertIs(
            built.get_permission_condition_record(Note, 'owned'),
            registry.conditions.get_permission_condition_record(Note, 'owned'),
        )
        self.assertIsNotNone(
            registry.conditions.get_permission_condition_record(Note, 'owned'),
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
            registry = RegistryFactory()
            with self.assertNumQueries(0):
                registry.register_permission_condition(
                    Note, 'owned', lambda u, p, o: u == o.owner,
                )
            built = built_catalog(registry)
            lookup = built.filter_lookup
            self.assertIsInstance(lookup, FrozenConditionLookup)
            record = lookup.record_for(Note, 'owned')
            self.assertIsNotNone(record)
            self.assertIs(
                record,
                registry.conditions.get_permission_condition_record(Note, 'owned'),
            )
            perm = 'trusts_tests.change_note:owned'
            compiled = lookup.compile_q(Note, perm, alice)
            stored = registry.conditions.compile_registered_condition_q(Note, perm, alice)
            self.assertEqual(str(compiled), str(stored))
            listed = set(Note.objects.filter(compiled).values_list('pk', flat=True))
            self.assertEqual(listed, {keep.pk})
            self.assertNotIn(drop.pk, listed)
            self.assertTrue(
                registry.conditions.evaluate_permission_condition(
                    Note, 'owned', alice, 'trusts_tests.change_note', keep,
                )
            )
            self.assertFalse(
                registry.conditions.evaluate_permission_condition(
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
            registry = RegistryFactory()
            lookup = FrozenConditionLookup(())
            self.assertIsNone(lookup.record_for(Note, 'missing'))
            with self.assertRaises(AttributeError) as missing:
                registry.conditions.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:missing', alice,
                )
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(TypeError):
                registry.register_permission_condition(
                    Note, 'typo', 'not-a-builder',
                )
            self.assertIsNone(
                registry.conditions.get_permission_condition_record(Note, 'typo'),
            )
            with self.assertRaises(PermissionConditionError):
                registry.register_permission_condition(
                    Note, 'typo', lambda u, p, o: u == o.nope,
                )
            self.assertIsNone(
                registry.conditions.get_permission_condition_record(Note, 'typo'),
            )
            registry.conditions._records[(Note._meta.label, 'empty')] = (
                ConditionRecord(model=Note)
            )
            with self.assertRaises(PermissionConditionError) as unbound:
                registry.conditions.evaluate_permission_condition(
                    Note, 'empty', alice, 'trusts_tests.change_note', note,
                )
            self.assertIn('unbound', str(unbound.exception))
