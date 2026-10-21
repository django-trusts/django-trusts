"""Suite membership and the removed request-time lockfile gate."""

from pathlib import Path

from django.test import SimpleTestCase

import trusts.models as models_mod


class PolicyLockImportTest(SimpleTestCase):

    def test_request_time_lockfile_gate_is_removed(self):
        import trusts.backends as backends
        import trusts.decorators as decorators
        import trusts.inspect.commands as policy_command_impl
        import trusts.inspect.snapshot as policy_snapshot

        self.assertFalse(hasattr(policy_snapshot, 'ensure_policy_lockfile_verified'))
        self.assertFalse(hasattr(policy_snapshot, '_policy_lock_verification_state'))
        for module in (backends, decorators, models_mod):
            source = Path(module.__file__).read_text(encoding='utf-8')
            self.assertNotIn('ensure_policy_lockfile_verified', source)
        lock_source = Path(policy_snapshot.__file__).read_text(encoding='utf-8')
        self.assertNotIn('ensure_policy_lockfile_verified', lock_source)
        self.assertNotIn('probe_along_capabilities', lock_source)
        self.assertNotIn('INACTIVE', lock_source)
        self.assertNotIn('VERIFIED', lock_source)
        backend_source = Path(backends.__file__).read_text(encoding='utf-8')
        self.assertNotIn('_gate_policy_lock', backend_source)
