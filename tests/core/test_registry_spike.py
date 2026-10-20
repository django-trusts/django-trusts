"""A catalog is built whole from one frozen shape.

``RegistryFactory`` stays the registration front end. ``build()``
returns the shape. ``built_catalog`` asks that shape.
"""

import ast
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection, models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.compile.factory import RegistryFactory
from trusts.compile.nodes import Along, Ref
from trusts.plan.conditions import ConditionRegistry
from trusts.plan.recursions import GrantReach
from tests.support import built_catalog


def _sql(expr, model):
    query = model._default_manager.annotate(hit=expr).query
    compiler = query.get_compiler(using=connection.alias)
    return compiler.as_sql()


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RegistryInjectionSpikeTest(SimpleTestCase):
    def test_registry_module_does_not_import_compile(self):
        import trusts.plan.registry as registry_module

        tree = ast.parse(Path(registry_module.__file__).read_text())
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        for name in imported:
            self.assertFalse(
                name == 'trusts.compile' or name.startswith('trusts.compile.'),
                name,
            )
        self.assertTrue(registry_module.__file__.endswith('registry.py'))

    def test_direct_trusts_registry_still_registers(self):
        Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        record = _register_document(registry, DocumentGrant)
        self.assertEqual(registry.records, (record,))
        self.assertIs(built_catalog(registry).plan_for(Document).records[0], record)

    def test_injected_plan_matches_live_registry(self):
        Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        _register_document(registry, DocumentGrant)
        shape = registry.build()
        self.assertIsInstance(shape.conditions, tuple)
        self.assertNotIsInstance(shape.conditions, ConditionRegistry)
        self.assertIsNot(shape.filter_lookup, registry.filter_lookup)
        self.assertEqual(shape.records, registry.records)
        self.assertEqual(shape.delegations, registry.delegations)

        live = built_catalog(registry).plan_for(Document)
        built = built_catalog(registry).plan_for(Document)
        self.assertEqual(built.records, live.records)
        self.assertIs(built.records[0], live.records[0])
        self.assertEqual(built.delegations, live.delegations)
        self.assertIs(built.permission_model, live.permission_model)
        self.assertIs(built.content_identity, live.content_identity)
        # Rule fragments are computed inside each registry from the
        # same user-condition data, so compare SQL, not identity.
        self.assertEqual(
            _sql(built.user_rules, get_user_model()),
            _sql(live.user_rules, get_user_model()),
        )
        self.assertEqual(built.user_override_q, live.user_override_q)

        User = get_user_model()
        user = User(pk=1)
        permission = Permission(pk=2)
        self.assertEqual(
            _sql(built.content_exists(user, permission), Document),
            _sql(live.content_exists(user, permission), Document),
        )

    def test_injected_grant_reach_matches_along_plan(self):
        Folder, FolderGrant = _folder_models()
        registry = RegistryFactory()
        root = Ref(FolderGrant)
        registry.register(
            content=root.folder,
            user=root.user,
            permission=root.permission,
            along=Along(root.folder.parent, 2),
        )
        live = built_catalog(registry).plan_for(Folder)
        built = built_catalog(registry).plan_for(Folder)
        self.assertIsNotNone(built.records[0].along)
        User = get_user_model()
        user = User(pk=1)
        permission = Permission(pk=2)
        live_expr = live.content_exists(user, permission)
        built_expr = built.content_exists(user, permission)
        self.assertIsInstance(live_expr, GrantReach)
        self.assertIs(type(built_expr), type(live_expr))
        self.assertIs(built_expr.record, live_expr.record)
        self.assertEqual(
            built_expr.seed_query.get_compiler(using=connection.alias).as_sql(),
            live_expr.seed_query.get_compiler(using=connection.alias).as_sql(),
        )


def _document_models():
    class Document(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Document, DocumentGrant


def _folder_models():
    class Folder(models.Model):
        parent = models.ForeignKey(
            'self', null=True, related_name='children',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class FolderGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Folder, FolderGrant


def _register_document(registry, grant):
    root = Ref(grant)
    return registry.register(
        content=root.document,
        user=root.user,
        permission=root.permission,
    )
