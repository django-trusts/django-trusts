"""C4b. Late registration and fresh-process isolation of sticky state."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import (
    SimpleTestCase,
    override_settings,
)

from trusts.core import (
    BackendHandle,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import (
    CONVENTIONAL_LOCKFILE_NAME,
    build_policy_manifest,
    canonicalize,
    ensure_policy_lockfile_verified,
    generate_policy_lockfile,
    _policy_lock_verification_state,
    _reset_policy_lock_verification,
)

from tests.core.test_issue147.support import (
    _forbid_sql,
    _fresh_lock_process,
    _registry_surface,
    _same_type_compiler,
)


class PolicyLockIsolationTest(SimpleTestCase):
    """C4b isolation. Late registration and fresh-process memory.

    The installed configured handles are the snapshot membership.
    Backend class names are not hard-coded, so the same proofs run
    under kernel settings and the Zero pair.
    """

    def setUp(self):
        _reset_policy_lock_verification()

    def tearDown(self):
        _reset_policy_lock_verification()

    def _assert_fresh_start(self, data):
        self.assertEqual(data['before'], 'UNCHECKED')
        self.assertEqual(data['sql'], 0)

    def test_late_register_and_named_filter_do_not_change_verified_snapshot(self):
        from trusts.apps import configured_implementation_handles

        handles = configured_implementation_handles()
        self.assertTrue(handles)
        invoked = []

        def boom(*args, **kwargs):
            invoked.append((args, kwargs))
            raise AssertionError('late builder invoked')

        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with _forbid_sql():
                    ensure_policy_lockfile_verified(*handles)
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')
                recorded = path.read_bytes()
                surfaces = tuple(_registry_surface(handle) for handle in handles)
                for handle in handles:
                    self.assertTrue(handle.registry.frozen)
                with _forbid_sql():
                    self.assertEqual(canonicalize(build_policy_manifest()), recorded)
                user = get_user_model()
                with _forbid_sql():
                    for handle in handles:
                        with self.assertRaises(TrustsConfigurationError) as ctx:
                            handle.register(
                                trust=user,
                                user=boom,
                                permission=boom,
                                content=boom,
                                condition=boom,
                            )
                        self.assertIn('frozen', str(ctx.exception))
                        with self.assertRaises(TrustsConfigurationError) as ctx:
                            handle.add_named_filter(user, 'c4b_late', boom)
                        self.assertIn('frozen', str(ctx.exception))
                self.assertEqual(invoked, [])
                self.assertEqual(
                    tuple(_registry_surface(handle) for handle in handles),
                    surfaces,
                )
                with _forbid_sql():
                    self.assertEqual(
                        canonicalize(build_policy_manifest()), recorded,
                    )
                self.assertEqual(path.read_bytes(), recorded)
                sample = handles[0]
                fresh = BackendHandle(
                    path=sample.path,
                    registry=sample.registry,
                    compiler=_same_type_compiler(sample.compiler),
                )
                other = BackendHandle(
                    path=sample.path,
                    registry=TrustsRegistry(),
                    compiler=_same_type_compiler(sample.compiler),
                )
                other.registry.freeze()
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ), _forbid_sql():
                    ensure_policy_lockfile_verified(fresh)
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        ensure_policy_lockfile_verified(other)
                self.assertIn('registry', str(ctx.exception))
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')

    def test_fresh_process_does_not_inherit_verified_state(self):
        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')
                document = json.loads(path.read_text(encoding='utf-8'))
                document['schema_version'] = document['schema_version'] + 1
                path.write_text(json.dumps(document), encoding='utf-8')
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ), _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')
                checked = _fresh_lock_process('verify-explicit', lock=path)
                self._assert_fresh_start(checked)
                self.assertEqual(checked['after'], 'FAILED')
                self.assertIsNotNone(checked['error'])
                self.assertIn('schema_version', checked['error'])
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')

    def test_fresh_process_does_not_inherit_inactive_state(self):
        with tempfile.TemporaryDirectory() as base_s:
            project = Path(base_s)
            lock = project / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(
                BASE_DIR=str(project), TRUSTS_POLICY_LOCKFILE=None,
            ):
                with _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')
                self.assertFalse(lock.exists())
                generated = _fresh_lock_process('generate', lock=lock)
                self._assert_fresh_start(generated)
                self.assertIsNone(generated['error'])
                self.assertEqual(generated['after'], 'UNCHECKED')
                self.assertTrue(lock.is_file())
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ), _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')
                checked = _fresh_lock_process(
                    'verify-conventional', base=project,
                )
                self._assert_fresh_start(checked)
                self.assertIsNone(checked['error'], checked)
                self.assertEqual(checked['after'], 'VERIFIED')
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')

    def test_sticky_failure_is_reraise_without_reread_and_fresh_process_rechecks(self):
        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            path.write_text('{', encoding='utf-8')
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified()
                self.assertIn('JSON', str(ctx.exception))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
                generated = _fresh_lock_process('generate', lock=path)
                self._assert_fresh_start(generated)
                self.assertIsNone(generated['error'], generated)
                self.assertEqual(generated['after'], 'UNCHECKED')
                self.assertIn(b'"schema_version": 1', path.read_bytes())
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ), _forbid_sql():
                    with self.assertRaises(TrustsConfigurationError) as again:
                        ensure_policy_lockfile_verified()
                self.assertIs(again.exception, ctx.exception)
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
                checked = _fresh_lock_process('verify-explicit', lock=path)
                self._assert_fresh_start(checked)
                self.assertIsNone(checked['error'], checked)
                self.assertEqual(checked['after'], 'VERIFIED')
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
