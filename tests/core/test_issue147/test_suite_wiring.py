"""Suite membership and the removed request-time lockfile gate."""

from pathlib import Path

from django.test import SimpleTestCase


class PolicyLockImportTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE

        self.assertIn('tests.core.test_issue147', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue147', PAIR_KERNEL_SUITE)

    def test_request_time_lockfile_gate_is_removed(self):
        import trusts.backends as backends
        import trusts.core as core
        import trusts.decorators as decorators
        import trusts.inspect.commands as policy_command_impl
        import trusts.inspect.snapshot as policy_snapshot
        import trusts.query as query

        self.assertFalse(hasattr(policy_snapshot, 'ensure_policy_lockfile_verified'))
        self.assertFalse(hasattr(policy_snapshot, '_policy_lock_verification_state'))
        for module in (backends, core, decorators, query):
            source = Path(module.__file__).read_text(encoding='utf-8')
            self.assertNotIn('ensure_policy_lockfile_verified', source)
        lock_source = Path(policy_snapshot.__file__).read_text(encoding='utf-8')
        self.assertNotIn('ensure_policy_lockfile_verified', lock_source)
        self.assertNotIn('probe_along_capabilities', lock_source)
        self.assertNotIn('INACTIVE', lock_source)
        self.assertNotIn('VERIFIED', lock_source)
        backend_source = Path(backends.__file__).read_text(encoding='utf-8')
        self.assertNotIn('_gate_policy_lock', backend_source)
