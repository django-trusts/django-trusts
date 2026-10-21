from tests.support import built_catalog, configured_catalog, unbound_named_filters, compiler
"""#151 C1: the catalog's condition lookup is the frozen rows.

Library-only proofs. Applications register builders; they do not import
``trusts.plan.conditions``.
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
from trusts.conditions import (
    PermissionConditionError,
    permission_condition_code,
    permission_has_condition,
)
from trusts.plan.conditions import ConditionRecord, FrozenConditionLookup
from trusts.compile.catalogs import Catalog
from trusts.compile.factory import Compiler


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

    def test_handles_do_not_share_lookup_or_store(self):
        left = compiler()
        right = compiler()
        self.assertIsNot(left.conditions, right.conditions)
        self.assertIsNot(
            built_catalog(left).filter_lookup,
            built_catalog(right).filter_lookup,
        )

    def test_build_freezes_a_lookup_the_factory_does_not_keep(self):
        registry = compiler()
        built = built_catalog(registry)
        self.assertIsInstance(built.filter_lookup, FrozenConditionLookup)
        self.assertFalse(hasattr(built.filter_lookup, 'conditions'))
        self.assertFalse(hasattr(registry, 'filter_lookup'))


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
    def test_catalog_uses_the_shapes_lookup(self):
        registry = compiler()
        shape = registry.compile()
        self.assertIsInstance(shape.filter_lookup, FrozenConditionLookup)
        self.assertIsNone(shape.filter_lookup.record_for(Document, 'missing'))
        self.assertFalse(hasattr(shape.filter_lookup, 'conditions'))
        self.assertIsNot(registry.compile().filter_lookup, shape.filter_lookup)

    def test_unknown_condition_fail_closes_through_supported_backend_path(self):
        backend = DocumentBackend()
        document = Document(title='probe')
        user = get_user_model()(username='probe-151')
        self.assertFalse(backend.has_perm(
            user, 'myapp.change_document:missing', document,
        ))

    def test_missing_named_condition_denies(self):
        backend = DocumentBackend()
        document = Document(title='unbind')
        user = get_user_model()(username='unbind-151')
        with unbound_named_filters(DocumentBackend):
            self.assertFalse(DocumentBackend().has_perm(
                user, 'myapp.change_document:non_confidential', document,
            ))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedConditionCompilationTest(TransactionTestCase):
    def test_zero_sql_construction_registration_and_finalization(self):
        Note = _note_model()
        with self.assertNumQueries(0):
            registry = compiler()
            registry.add_named_filter(
                Note, 'owned', lambda u, p, o: u == o.owner,
            )
            built = built_catalog(registry)
        self.assertIsInstance(built.filter_lookup, FrozenConditionLookup)
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
            registry = compiler()
            with self.assertNumQueries(0):
                registry.add_named_filter(
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
            compiled = lookup.compile_q(Note, perm, alice, get_user_model())
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
            registry = compiler()
            lookup = FrozenConditionLookup(())
            self.assertIsNone(lookup.record_for(Note, 'missing'))
            with self.assertRaises(AttributeError) as missing:
                registry.conditions.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:missing', alice,
                )
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(TypeError):
                registry.add_named_filter(
                    Note, 'typo', 'not-a-builder',
                )
            self.assertIsNone(
                registry.conditions.get_permission_condition_record(Note, 'typo'),
            )
            with self.assertRaises(PermissionConditionError):
                registry.add_named_filter(
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
