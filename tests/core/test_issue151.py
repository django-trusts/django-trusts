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
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document
from trusts.errors import PermissionConditionError


ROOT = Path(__file__).resolve().parents[2]


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
        left.add_named_filter(
            Document, 'own', lambda u, p, o: o.title == 'keep',
        )
        right.add_named_filter(
            Document, 'own', lambda u, p, o: o.title == 'drop',
        )
        self.assertIsNot(
            built_catalog(left).named_filters,
            built_catalog(right).named_filters,
        )

    def test_build_freezes_a_lookup_the_factory_does_not_keep(self):
        registry = compiler()
        built = built_catalog(registry)
        again = built_catalog(registry)
        self.assertIsNot(built.named_filters, again.named_filters)
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
        self.assertNotIn(
            (Document._meta.label, 'missing'), shape.named_filters,
        )
        self.assertIsNot(registry.compile().named_filters, shape.named_filters)

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
        found = {
            code for model, code, _tree in built.iter_permission_conditions()
            if model is Note
        }
        self.assertIn('owned', found)

    def test_core_only_named_condition_compiles_through_supported_calls(self):
        Note = _note_model()
        User = get_user_model()

        class NoteGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _IsolatedTables(Note, NoteGrant):
            alice = User.objects.create_user(
                'alice-151', 'alice-151@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-151', 'bob-151@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice)
            drop = Note.objects.create(title='drop', owner=bob)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Note),
                codename='change_note',
                name='Can change note',
            )
            for holder in (alice, bob):
                for row in (keep, drop):
                    NoteGrant.objects.create(
                        note=row, user=holder, permission=change,
                    )
            registry = compiler()
            registry.register(
                trust=NoteGrant,
                user='user',
                permission='permission',
                content='note',
            )
            with self.assertNumQueries(0):
                registry.add_named_filter(
                    Note, 'owned', lambda u, p, o: u == o.owner,
                )
            built = built_catalog(registry)
            code = 'trusts_tests.change_note:owned'
            self.assertTrue(built.has_perm(alice, code, keep))
            self.assertFalse(built.has_perm(alice, code, drop))
            self.assertTrue(built.has_perm(bob, code, drop))
            self.assertFalse(built.has_perm(bob, code, keep))
            self.assertEqual(
                set(built.permitted_users(keep, code).values_list(
                    'pk', flat=True,
                )),
                {alice.pk},
            )

    def test_unknown_and_malformed_fail_closed(self):
        Note = _note_model()
        User = get_user_model()

        class NoteGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _IsolatedTables(Note, NoteGrant):
            alice = User.objects.create_user(
                'alice-151u', 'alice-151u@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Note),
                codename='change_note',
                name='Can change note',
            )
            NoteGrant.objects.create(note=keep, user=alice, permission=change)
            registry = compiler()
            with self.assertRaises(TypeError):
                registry.add_named_filter(Note, 'typo', 'not-a-builder')
            with self.assertRaises(PermissionConditionError):
                registry.add_named_filter(
                    Note, 'typo', lambda u, p, o: u == o.nope,
                )
            registry.add_named_filter(
                Note, 'typo', lambda u, p, o: u == o.owner,
            )
            registry.register(
                trust=NoteGrant,
                user='user',
                permission='permission',
                content='note',
            )
            built = built_catalog(registry)
            self.assertTrue(built.has_perm(
                alice, 'trusts_tests.change_note', keep,
            ))
            self.assertFalse(built.has_perm(
                alice, 'trusts_tests.change_note:missing', keep,
            ))
            self.assertTrue(built.has_perm(
                alice, 'trusts_tests.change_note:typo', keep,
            ))
