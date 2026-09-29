"""C4a. Process-local runtime verification before authorization results."""

import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import (
    AnonymousUser,
    Permission,
)
from django.http import Http404
from django.test import (
    RequestFactory,
    SimpleTestCase,
    override_settings,
)

from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    common_permissions,
    filter_authorized_scopes,
    granted,
    instance_match,
)
from trusts.policy_lock import (
    CONVENTIONAL_LOCKFILE_NAME,
    PolicyLockDrift,
    build_policy_manifest,
    canonicalize,
    check_policy_lockfile,
    ensure_policy_lockfile_verified,
    generate_policy_lockfile,
    _policy_lock_verification_state,
    _reset_policy_lock_verification,
)

from tests.core.test_issue147 import PortableOtherCompiler
from tests.core.test_issue147.support import (
    _RuntimeManager,
    _active_backend,
    _active_owner,
    _authorization_view,
    _candidate_queryset,
    _engine,
    _forbid_sql,
    _same_type_compiler,
)


class PolicyLockRuntimeGateTest(SimpleTestCase):
    """C4a runtime gate. Sticky, zero-SQL, and handle membership.

    Uses the installed implementation so the same cases run under
    kernel-only settings and the Zero pair. Owner membership is unchanged.
    """

    def setUp(self):
        _reset_policy_lock_verification()

    def tearDown(self):
        _reset_policy_lock_verification()

    def _assert_policy_lock_blocked(self, func):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            func()
        self.assertIn('Policy lock', str(ctx.exception))

    def test_conventional_absence_is_sticky_inactive(self):
        backend = _active_backend()
        with tempfile.TemporaryDirectory() as base_s:
            project = Path(base_s)
            with override_settings(BASE_DIR=str(project), TRUSTS_POLICY_LOCKFILE=None):
                with patch(
                    'trusts.policy_lock.build_policy_manifest',
                    side_effect=AssertionError('built'),
                ):
                    ensure_policy_lockfile_verified()
                    self.assertFalse(backend.has_perm(None, 'auth.change_user'))
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')
                lock = project / CONVENTIONAL_LOCKFILE_NAME
                lock.write_bytes(b'{}')
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ):
                    self.assertEqual(backend.get_all_permissions(None), set())
                    self.assertEqual(backend.get_group_permissions(None), set())
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')
                self.assertEqual(lock.read_bytes(), b'{}')

    def test_no_usable_base_dir_stays_inactive_after_a_file_appears(self):
        backend = _active_backend()
        with tempfile.TemporaryDirectory() as base_s:
            project = Path(base_s)
            lock = project / 'explicit.lock.json'
            with override_settings(BASE_DIR=None, TRUSTS_POLICY_LOCKFILE=None):
                ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')
            generate_policy_lockfile(override=str(lock))
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(lock)):
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ):
                    self.assertFalse(backend.has_perm(None, 'auth.change_user'))
                self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')

    def test_explicit_failures_stick_until_restart(self):
        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified()
                self.assertIn('missing', str(ctx.exception))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
                generate_policy_lockfile(override=str(path))
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ):
                    with self.assertRaises(TrustsConfigurationError) as again:
                        ensure_policy_lockfile_verified()
                self.assertIn('missing', str(again.exception))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')

            _reset_policy_lock_verification()
            path.write_text('{', encoding='utf-8')
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified()
                self.assertIn('JSON', str(ctx.exception))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
                path.write_bytes(canonicalize(build_policy_manifest()))
                with self.assertRaises(TrustsConfigurationError) as again:
                    ensure_policy_lockfile_verified()
                self.assertIn('JSON', str(again.exception))

            _reset_policy_lock_verification()
            generate_policy_lockfile(override=str(path))
            drifted = json.loads(path.read_text(encoding='utf-8'))
            for handle in drifted['handles']:
                handle['renderer']['profile'] = (
                    'django_generic_unsupported_along'
                )
                handle['renderer']['along'] = 'unsupported'
            path.write_text(json.dumps(drifted), encoding='utf-8')
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with self.assertRaises(PolicyLockDrift) as ctx:
                    check_policy_lockfile()
                self.assertEqual(_policy_lock_verification_state(), 'UNCHECKED')
                self.assertIn('profile', str(ctx.exception))
                with self.assertRaises(PolicyLockDrift) as runtime:
                    ensure_policy_lockfile_verified()
                self.assertIn('profile', str(runtime.exception))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')
                path.write_bytes(canonicalize(build_policy_manifest()))
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ):
                    with self.assertRaises(PolicyLockDrift):
                        ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')

    def test_verified_match_is_sticky_and_zero_sql(self):
        import trusts.policy_lock as policy_lock

        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            order = []
            real_frozen = policy_lock._frozen_configured_handles
            real_compare = policy_lock._compare_lock_bytes

            def frozen():
                order.append('freeze')
                handles = real_frozen()
                for handle in handles:
                    self.assertTrue(handle.registry.frozen)
                return handles

            def compare(lock_path, raw, handles):
                order.append('compare')
                self.assertEqual(order, ['freeze', 'compare'])
                return real_compare(lock_path, raw, handles)

            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                with patch.object(
                    policy_lock, '_frozen_configured_handles', frozen,
                ), patch.object(
                    policy_lock, '_compare_lock_bytes', compare,
                ), _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(order, ['freeze', 'compare'])
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')
                path.unlink()
                with patch(
                    'trusts.policy_lock._read_lock_bytes',
                    side_effect=AssertionError('reread'),
                ), _forbid_sql():
                    ensure_policy_lockfile_verified()
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')

    def test_every_result_path_is_gated_before_an_early_result(self):
        backend = _active_backend()
        user = get_user_model()()
        perm = Permission()
        queryset = _candidate_queryset()
        content = get_user_model()
        stray = BackendHandle(
            path='tests.policy.runtime-stray',
            registry=TrustsRegistry(),
            compiler=PlanQueryCompiler(),
        )
        request = RequestFactory().get('/')
        request.user = AnonymousUser()
        view = _authorization_view()
        with tempfile.TemporaryDirectory() as base_s:
            missing = Path(base_s) / 'missing.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(missing)):
                with patch(
                    'trusts.backends.is_active_principal',
                    side_effect=AssertionError('principal'),
                ):
                    self._assert_policy_lock_blocked(
                        lambda: backend.has_perm(user, 'auth.change_user'),
                    )
                    self._assert_policy_lock_blocked(
                        lambda: backend.get_all_permissions(user),
                    )
                    self._assert_policy_lock_blocked(
                        lambda: backend.get_group_permissions(user),
                    )
                with patch(
                    'trusts.core.granted',
                    side_effect=AssertionError('granted'),
                ):
                    self._assert_policy_lock_blocked(
                        lambda: queryset.authorized(user, perm),
                    )
                    self._assert_policy_lock_blocked(
                        lambda: _RuntimeManager().authorized(user, perm),
                    )
                with patch(
                    'trusts.core._compile_granted',
                    side_effect=AssertionError('compiled'),
                ):
                    self._assert_policy_lock_blocked(
                        lambda: granted((), queryset, user, perm),
                    )
                    self._assert_policy_lock_blocked(
                        lambda: all_match((), queryset, user, perm),
                    )
                    self._assert_policy_lock_blocked(
                        lambda: instance_match(stray, object(), user, perm),
                    )
                with patch(
                    'trusts.core._compile_common_permissions',
                    side_effect=AssertionError('common'),
                ):
                    self._assert_policy_lock_blocked(
                        lambda: common_permissions((), queryset, user),
                    )
                with patch(
                    'trusts.core._require_instance',
                    side_effect=AssertionError('scopes'),
                ):
                    self._assert_policy_lock_blocked(
                        lambda: filter_authorized_scopes(
                            queryset, user, perm, content=content,
                        ),
                    )
                self._assert_policy_lock_blocked(lambda: view(request))
                self.assertEqual(_policy_lock_verification_state(), 'FAILED')

    def test_inactive_early_results_keep_previous_behavior(self):
        backend = _active_backend()
        user = get_user_model()()
        perm = Permission()
        queryset = _candidate_queryset()
        content = get_user_model()
        request = RequestFactory().get('/')
        request.user = AnonymousUser()
        view = _authorization_view()
        stray = BackendHandle(
            path='tests.policy.runtime-stray',
            registry=TrustsRegistry(),
            compiler=PlanQueryCompiler(),
        )
        with override_settings(BASE_DIR=None, TRUSTS_POLICY_LOCKFILE=None):
            with _forbid_sql():
                self.assertFalse(backend.has_perm(user, 'auth.change_user'))
                self.assertEqual(backend.get_all_permissions(user), set())
                self.assertEqual(backend.get_group_permissions(user), set())
                with patch(
                    'trusts.core._compile_granted', return_value=None,
                ) as compiled:
                    self.assertIsNone(granted((), queryset, user, perm))
                    self.assertIsNone(all_match((), queryset, user, perm))
                    self.assertIsNone(
                        instance_match(stray, object(), user, perm),
                    )
                self.assertEqual(compiled.call_count, 3)
                with patch(
                    'trusts.core._compile_common_permissions',
                    return_value=None,
                ) as common:
                    self.assertIsNone(common_permissions((), queryset, user))
                self.assertEqual(common.call_count, 1)
                scoped = filter_authorized_scopes(
                    queryset, user, perm, content=content,
                )
                self.assertIn('QuerySet', type(scoped).__name__)
                with patch(
                    'trusts.core._compile_granted', return_value=None,
                ):
                    authorized = queryset.authorized(user, perm)
                self.assertIn('QuerySet', type(authorized).__name__)
                with self.assertRaises(Http404):
                    view(request)
            self.assertEqual(_policy_lock_verification_state(), 'INACTIVE')

    def test_membership_rejects_strangers_and_accepts_a_rewrapped_handle(self):
        user = get_user_model()()
        perm = Permission()
        queryset = _candidate_queryset()
        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                owner = _active_owner()
                configured = owner.configured_backend()
                again = owner.configured_backend()
                fresh = BackendHandle(
                    path=configured.path,
                    registry=configured.registry,
                    compiler=_same_type_compiler(configured.compiler),
                )
                self.assertIsNot(configured, again)
                self.assertIsNot(fresh, configured)
                self.assertIsNot(fresh.compiler, configured.compiler)
                ensure_policy_lockfile_verified(configured, again, fresh)
                document = json.loads(path.read_text(encoding='utf-8'))
                self._assert_no_runtime_identity(document)
                with patch(
                    'trusts.core._compile_granted', return_value=None,
                ):
                    self.assertIsNone(granted((fresh,), queryset, user, perm))

                other = BackendHandle(
                    path=configured.path,
                    registry=TrustsRegistry(),
                    compiler=_same_type_compiler(configured.compiler),
                )
                other.registry.freeze()
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified(other)
                self.assertIn('registry', str(ctx.exception))
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    granted((other,), queryset, user, perm)
                self.assertIn('registry', str(ctx.exception))

                stray = BackendHandle(
                    path='tests.policy.not-in-snapshot',
                    registry=TrustsRegistry(),
                    compiler=PlanQueryCompiler(),
                )
                stray.registry.freeze()
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified(stray)
                self.assertIn('unconfigured', str(ctx.exception))
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    granted((stray,), queryset, user, perm)
                self.assertIn('unconfigured', str(ctx.exception))

                wrong_compiler = BackendHandle(
                    path=configured.path,
                    registry=configured.registry,
                    compiler=PortableOtherCompiler(),
                )
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    ensure_policy_lockfile_verified(wrong_compiler)
                self.assertIn('compiler', str(ctx.exception))
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')

    def test_family_and_renderer_profile_bind_the_verified_handle(self):
        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                owner = _active_owner()
                handle = owner.configured_backend()
                ensure_policy_lockfile_verified(handle)
                had_instance = '_authorization_family' in owner.__dict__
                previous = owner._authorization_family
                owner._authorization_family = 'ordered_fold'
                try:
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        ensure_policy_lockfile_verified(handle)
                    self.assertIn('family', str(ctx.exception))
                    self.assertEqual(
                        _policy_lock_verification_state(), 'VERIFIED',
                    )
                finally:
                    if had_instance:
                        owner._authorization_family = previous
                    else:
                        del owner._authorization_family
                ensure_policy_lockfile_verified(handle)
                with _engine('django.db.backends.postgresql'):
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        ensure_policy_lockfile_verified(handle)
                    self.assertIn('renderer profile', str(ctx.exception))
                    self.assertEqual(
                        _policy_lock_verification_state(), 'VERIFIED',
                    )
                ensure_policy_lockfile_verified(handle)

    def test_generate_and_system_checks_do_not_verify(self):
        from django.core import checks as django_checks

        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(path)):
                written = generate_policy_lockfile()
                self.assertEqual(written, path)
                self.assertEqual(_policy_lock_verification_state(), 'UNCHECKED')
                match = check_policy_lockfile()
                self.assertEqual(match.status, 'match')
                self.assertEqual(_policy_lock_verification_state(), 'UNCHECKED')
                django_checks.run_checks()
                self.assertEqual(_policy_lock_verification_state(), 'UNCHECKED')

    def test_apps_not_ready_stay_unchecked_and_do_not_freeze(self):
        from django.apps import apps as django_apps

        with patch.object(django_apps, 'ready', False), patch(
            'trusts.policy_lock._frozen_configured_handles',
            side_effect=AssertionError('froze'),
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                ensure_policy_lockfile_verified()
            self.assertIn('ready', str(ctx.exception))
        self.assertEqual(_policy_lock_verification_state(), 'UNCHECKED')

    def test_concurrent_verification_sticks_once(self):
        from django.conf import settings
        from trusts.apps import configured_implementation_handles

        with tempfile.TemporaryDirectory() as base_s:
            path = Path(base_s) / 'policy.lock.json'
            generate_policy_lockfile(override=str(path))
            _reset_policy_lock_verification()
            handles = configured_implementation_handles()
            previous = getattr(settings, 'TRUSTS_POLICY_LOCKFILE', None)
            settings.TRUSTS_POLICY_LOCKFILE = str(path)
            barrier = threading.Barrier(4)
            errors = []

            def worker():
                try:
                    barrier.wait(timeout=10)
                    ensure_policy_lockfile_verified(*handles)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            try:
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=30)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(_policy_lock_verification_state(), 'VERIFIED')
            finally:
                if previous is None:
                    try:
                        del settings.TRUSTS_POLICY_LOCKFILE
                    except AttributeError:
                        settings.TRUSTS_POLICY_LOCKFILE = None
                else:
                    settings.TRUSTS_POLICY_LOCKFILE = previous

    def _assert_no_runtime_identity(self, node):
        if isinstance(node, dict):
            self.assertNotIn('registry', node)
            self.assertNotIn('owner', node)
            self.assertNotIn('compiler_type', node)
            for value in node.values():
                self._assert_no_runtime_identity(value)
        elif isinstance(node, list):
            for item in node:
                self._assert_no_runtime_identity(item)
