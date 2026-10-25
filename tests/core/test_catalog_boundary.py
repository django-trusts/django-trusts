"""The catalog does not build itself, and it does not import the factory."""

import ast
import dataclasses
import inspect
from types import MappingProxyType

from django.test import SimpleTestCase

import trusts.apps as apps_module
import trusts.backends as backends
import trusts.compile.catalogs as catalogs
import trusts.compile.compilers as compilers
import trusts.decorators as decorators
import trusts.inspect.checks as checks
import trusts.inspect.snapshot as snapshot
import trusts.models as models
from tests.support import compiler


def _imported_modules(module):
    tree = ast.parse(inspect.getsource(module))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
    return found


class CatalogFactoryBoundaryTest(SimpleTestCase):
    def test_import_direction(self):
        catalog_imports = _imported_modules(catalogs)
        compiler_imports = _imported_modules(compilers)
        self.assertNotIn('trusts.compile.compilers', catalog_imports)
        self.assertNotIn('trusts.plan.rewrites', catalog_imports)
        self.assertFalse(any(name.endswith('.compilers') for name in catalog_imports))
        self.assertIn('trusts.compile.catalogs', compiler_imports)
        for module in (backends, snapshot):
            found = _imported_modules(module)
            self.assertFalse(any(name.startswith('trusts.plan') for name in found))
        for module in (checks, snapshot):
            self.assertFalse(any(
                name.startswith('trusts.compile') for name in _imported_modules(module)
            ))
        for module in (models, decorators, checks, snapshot):
            found = _imported_modules(module)
            self.assertNotIn('trusts.compile.compilers', found)
            self.assertFalse(any(name.endswith('.compilers') for name in found))
        self.assertNotIn('trusts.backends', _imported_modules(snapshot))
        app_imports = _imported_modules(apps_module)
        self.assertFalse(any(
            name == 'trusts' or name.startswith('trusts.')
            for name in app_imports
        ))

    def test_catalog_methods_do_not_assign_fields(self):
        tree = ast.parse(inspect.getsource(catalogs.Catalog))
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if isinstance(node, ast.Assign):
                    targets.extend(node.targets)
                elif node.target is not None:
                    targets.append(node.target)
            elif isinstance(node, ast.AugAssign):
                targets.append(node.target)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == '__setattr__':
                    self.fail('Catalog calls __setattr__')
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == 'self'
                ):
                    self.fail('Catalog assigns self.%s' % target.attr)

    def test_compile_stores_finished_fields(self):
        catalog = compiler().compile()
        self.assertIsInstance(catalog.named_filters, MappingProxyType)
        self.assertIsInstance(catalog.plans, MappingProxyType)
        self.assertIsInstance(catalog.questions, tuple)
        self.assertIsInstance(catalog.prepared_conditions, MappingProxyType)
        self.assertFalse(hasattr(catalog, 'compile_condition'))
        with self.assertRaises(TypeError):
            catalog.prepared_conditions['extra'] = None
        with self.assertRaises(TypeError):
            catalog.named_filters['extra'] = None
        with self.assertRaises(TypeError):
            catalog.plans[None] = None
        with self.assertRaises(dataclasses.FrozenInstanceError):
            catalog.questions = ()
        again = compiler().compile()
        self.assertIsNot(again, catalog)
        self.assertEqual(catalog.questions, ())
