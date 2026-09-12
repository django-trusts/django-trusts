"""#103 / #111: generic mixin lives only on ``trusts.backends``.

``trusts.core_backends`` is gone. Historical ``TrustModelBackend`` and
TrustGroup SQL live only on ``trusts.zero.backends``.
"""

import ast
import importlib
import inspect

from django.test import SimpleTestCase

from trusts.backends import TrustModelBackendMixin
from trusts.core import PlanQueryCompiler


class BackendsMixinBoundaryTest(SimpleTestCase):
    def test_canonical_mixin_import_and_plan_compiler(self):
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertFalse(
            TrustModelBackendMixin.query_compiler.historical_fallback,
        )

    def test_core_backends_module_is_gone(self):
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('trusts.core_backends')

    def test_historical_backend_path_is_gone(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))
        with self.assertRaises(ImportError):
            from trusts.backends import TrustModelBackend  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.backends import HistoricalGroupQueryCompiler  # noqa: F401

    def test_backends_has_no_trustgroup_dependency(self):
        import trusts.backends as backends

        self.assertFalse(hasattr(backends, 'HistoricalGroupQueryCompiler'))
        self.assertFalse(hasattr(backends, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends, 'historical_group_grant_exists'))
        self.assertFalse(hasattr(backends, 'TrustGroup'))
        self.assertNotIn('TrustGroup', backends.__dict__)

        tree = ast.parse(inspect.getsource(backends))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.name)
                    if node.module:
                        imported.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
        self.assertNotIn('historical_group_grant_exists', imported)
        self.assertNotIn('group_local_grant_exists', imported)
        self.assertNotIn('trust_grant_q', imported)
        self.assertNotIn('HistoricalGroupQueryCompiler', imported)
        self.assertNotIn('TrustGroup', imported)
        self.assertNotIn('kernel_config', imported)
        self.assertNotIn('get_permission_model', imported)
        self.assertNotIn('get_entity_model', imported)

    def test_zero_ui_surfaces_are_gone_from_core(self):
        import importlib

        for name in (
            'trusts.authorization',
            'trusts.views',
            'trusts.urls',
            'trusts.admin',
        ):
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)
