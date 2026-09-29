"""Suite membership and the single runtime gate.

Kernel and pair labels stay ``tests.core.test_issue147``. The
slice modules below are what that label loads.
"""

import inspect
from pathlib import Path

from django.test import SimpleTestCase

from trusts.core import RelationPlan


class PolicyLockImportTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE

        self.assertIn('tests.core.test_issue147', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue147', PAIR_KERNEL_SUITE)

    def test_authorization_modules_call_only_the_shared_gate(self):
        import trusts.backends as backends
        import trusts.core as core
        import trusts.decorators as decorators
        import trusts.query as query

        gated = {
            backends: 1,
            query: 2,
            decorators: 1,
            core: 5,
        }
        for module, count in gated.items():
            source = Path(module.__file__).read_text(encoding='utf-8')
            self.assertEqual(
                source.count('ensure_policy_lockfile_verified('), count,
                module.__name__,
            )
            self.assertNotIn('build_policy_manifest', source)
            self.assertNotIn('read_canonical_policy', source)
        backend_source = Path(backends.__file__).read_text(encoding='utf-8')
        self.assertEqual(backend_source.count('self._gate_policy_lock()'), 3)
        for module in (backends, query, decorators):
            source = Path(module.__file__).read_text(encoding='utf-8')
            self.assertNotIn('canonicalize(', source)
        plan = inspect.getsource(RelationPlan.common_permissions)
        self.assertNotIn('ensure_policy_lockfile_verified', plan)
        checks = Path(core.__file__).resolve().parents[1] / 'trusts' / 'checks.py'
        self.assertNotIn(
            'ensure_policy_lockfile_verified',
            checks.read_text(encoding='utf-8'),
        )

    def test_slice_modules_name_the_audit_layout(self):
        import importlib

        from tests.core.test_issue147 import SLICE_MODULES

        self.assertEqual(
            SLICE_MODULES,
            (
                'tests.core.test_issue147.test_c1_snapshot',
                'tests.core.test_issue147.test_unsupported_family',
                'tests.core.test_issue147.test_c2_canonical',
                'tests.core.test_issue147.test_c3_commands',
                'tests.core.test_issue147.test_c4a_runtime',
                'tests.core.test_issue147.test_c4b_isolation',
                'tests.core.test_issue147.test_suite_wiring',
            ),
        )
        unsupported = importlib.import_module(
            'tests.core.test_issue147.test_unsupported_family',
        )
        self.assertTrue(hasattr(
            unsupported.UnsupportedFamilyFailClosedTest,
            'test_unsupported_family_fails_closed_for_the_whole_snapshot',
        ))

