"""#103 / #111: generic ``trusts.core_backends`` boundary after cutover.

Canonical mixin import plus a deprecated same-object alias on
``trusts.backends``. Historical ``TrustModelBackend`` and TrustGroup
SQL are gone from core. Runtime mixin behavior is unchanged.
"""

import ast
import inspect

from django.test import SimpleTestCase

from trusts.core import PlanQueryCompiler
from trusts.core_backends import TrustModelBackendMixin


class CoreBackendsBoundaryTest(SimpleTestCase):
    def test_canonical_mixin_import_and_plan_compiler(self):
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertFalse(
            TrustModelBackendMixin.query_compiler.historical_fallback,
        )

    def test_backends_mixin_is_core_backends_mixin(self):
        from trusts.backends import (
            TrustModelBackendMixin as AliasMixin,
        )
        self.assertIs(AliasMixin, TrustModelBackendMixin)

    def test_historical_backend_path_is_gone(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))
        with self.assertRaises(ImportError):
            from trusts.backends import TrustModelBackend  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.backends import HistoricalGroupQueryCompiler  # noqa: F401

    def test_core_backends_has_no_trustgroup_dependency(self):
        import trusts.core_backends as core_backends

        self.assertFalse(hasattr(core_backends, 'HistoricalGroupQueryCompiler'))
        self.assertFalse(hasattr(core_backends, 'TrustModelBackend'))
        self.assertFalse(hasattr(core_backends, 'historical_group_grant_exists'))
        self.assertFalse(hasattr(core_backends, 'TrustGroup'))
        self.assertNotIn('TrustGroup', core_backends.__dict__)

        tree = ast.parse(inspect.getsource(core_backends))
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
