"""#103 step 1: generic core_backends mixin boundary.

Kernel proofs: the mixin lives on ``trusts.core_backends``, the old
import is the exact same object, historical backend/compiler stay on
``trusts.backends``, and ``core_backends`` has no TrustGroup SQL or
model dependency.
"""

import ast
from pathlib import Path

from django.test import SimpleTestCase

from trusts.backends import (
    HistoricalGroupQueryCompiler,
    TrustModelBackend,
    TrustModelBackendMixin as BackendsMixin,
)
from trusts.core import PlanQueryCompiler
from trusts.core_backends import TrustModelBackendMixin as CoreMixin
import trusts.core_backends as core_backends


def _imported_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            for alias in node.names:
                names.add(alias.name)
    return names


def _used_names(tree):
    return {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
    } | {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }


class CoreBackendsBoundaryTest(SimpleTestCase):
    def test_backends_mixin_is_core_backends_mixin(self):
        from trusts.backends import TrustModelBackendMixin
        self.assertIs(BackendsMixin, CoreMixin)
        self.assertIs(TrustModelBackendMixin, CoreMixin)

    def test_mixin_keeps_plan_compiler_and_historical_backend_keeps_group(self):
        self.assertIsInstance(CoreMixin.query_compiler, PlanQueryCompiler)
        self.assertIsInstance(
            TrustModelBackend.query_compiler,
            HistoricalGroupQueryCompiler,
        )
        self.assertIsNot(
            TrustModelBackend.query_compiler,
            CoreMixin.query_compiler,
        )
        self.assertTrue(issubclass(TrustModelBackend, CoreMixin))

    def test_core_backends_has_no_trustgroup_dependency(self):
        source = Path(core_backends.__file__).read_text()
        tree = ast.parse(source)
        imported = _imported_names(tree)
        used = _used_names(tree)
        self.assertNotIn('historical_group_grant_exists', imported)
        self.assertNotIn('historical_group_grant_exists', used)
        self.assertNotIn('group_local_grant_exists', imported)
        self.assertNotIn('group_local_grant_exists', used)
        self.assertNotIn('HistoricalGroupQueryCompiler', imported)
        self.assertNotIn('HistoricalGroupQueryCompiler', used)
        self.assertNotIn('TrustGroup', used)
        self.assertFalse(hasattr(core_backends, 'historical_group_grant_exists'))
        self.assertFalse(hasattr(core_backends, 'HistoricalGroupQueryCompiler'))
