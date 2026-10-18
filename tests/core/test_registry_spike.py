"""Spike: a frozen registry built whole from lowered values.

``TrustsRegistry`` stays the registration front end. ``FrozenRegistry``
takes records, delegations, the shared condition store, stored user
conditions, and the user override as data. It does not import
``trusts.core``. Core imports the frozen class.
"""

import ast
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection, models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.compile.nodes import Along
from trusts.plan.recursions import GrantReach
from trusts.core import (
    Ref,
    TrustsRegistry,
)
from trusts.plan.registry import FrozenRegistry


def _sql(expr, model):
    query = model._default_manager.annotate(hit=expr).query
    compiler = query.get_compiler(using=connection.alias)
    return compiler.as_sql()


def _frozen_from(registry):
    return FrozenRegistry(
        records=registry.records,
        delegations=registry.delegations,
        conditions=registry.conditions,
        user_conditions=registry._stored_user_conditions(),
        user_override=registry._user_override,
        condition_lookup=registry.condition_lookup,
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FrozenRegistryInjectionSpikeTest(SimpleTestCase):
    def test_module_does_not_import_core_or_compile(self):
        import trusts.compile.factory as factory_module
        import trusts.core as core
        import trusts.plan.registry as registry_module

        for module in (registry_module, factory_module):
            tree = ast.parse(Path(module.__file__).read_text())
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            for name in imported:
                self.assertFalse(
                    name == 'trusts.core' or name.startswith('trusts.core.'),
                    '%s imports %s' % (module.__name__, name),
                )
                if module is registry_module:
                    self.assertFalse(
                        name == 'trusts.compile'
                        or name.startswith('trusts.compile.'),
                        name,
                    )
        self.assertIs(core._FrozenRegistry, FrozenRegistry)
        self.assertTrue(registry_module.__file__.endswith('registry.py'))

    def test_direct_trusts_registry_still_registers(self):
        Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        record = _register_document(registry, DocumentGrant)
        self.assertEqual(registry.records, (record,))
        self.assertIs(registry.plan_for(Document).records[0], record)

    def test_injected_plan_matches_live_registry(self):
        Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        _register_document(registry, DocumentGrant)
        frozen = _frozen_from(registry)
        self.assertIs(frozen.conditions, registry.conditions)
        self.assertIs(frozen.condition_lookup, registry.condition_lookup)
        self.assertEqual(frozen.records, registry.records)
        self.assertEqual(frozen.delegations, registry.delegations)

        live = registry.plan_for(Document)
        built = frozen.plan_for(Document)
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
        registry = TrustsRegistry()
        root = Ref(FolderGrant)
        registry.register(
            content=root.folder,
            user=root.user,
            permission=root.permission,
            along=Along(root.folder.parent, 2),
        )
        frozen = _frozen_from(registry)
        live = registry.plan_for(Folder)
        built = frozen.plan_for(Folder)
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
