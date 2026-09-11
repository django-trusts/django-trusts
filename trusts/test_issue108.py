"""#108 Step I: implementation-owned registry bridge.

Additive helper / resolvers plus mixin dual-resolve. Kernel AppConfig,
``kernel_config()``, historical backend, and ``core_backends`` identity
stay. Isolated ``Apps`` registries must not donate onto the live kernel.
"""

import types
from pathlib import Path
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.backends import HostTrustModelBackend, MixinOnlyBackend
from trusts.apps import (
    AppConfig,
    TrustsImplementationConfig,
    implementation_configs,
    implementation_for_class,
    implementation_for_path,
    kernel_config,
)
from trusts.backends import (
    HistoricalGroupQueryCompiler,
    TrustModelBackend,
    TrustModelBackendMixin as BackendsMixin,
)
from trusts.core import PlanQueryCompiler, TrustsConfigurationError, TrustsRegistry
from trusts.core_backends import TrustModelBackendMixin


CONCRETE = 'trusts.backends.TrustModelBackend'
HOST = 'tests.backends.HostTrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
ALIASED = 'tests.backends.AliasedTrustModelBackend'


class _Apps(object):
    """Minimal Apps stand-in: ``get_app_configs()`` plus a ready flag."""

    def __init__(self, configs, ready=False):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return list(self._configs)


def _module(name):
    return types.ModuleType(name)


def _owner(name, label, *paths):
    class Owner(TrustsImplementationConfig):
        pass

    Owner.__name__ = name.rsplit('.', 1)[-1]
    Owner.name = name
    Owner.label = label
    Owner.path = str(Path(__file__).resolve().parent)
    Owner.trusts_backend_paths = paths
    return Owner(name, _module(name))


def _bind(configs, ready=False):
    apps = _Apps(configs, ready=ready)
    for config in configs:
        config.apps = apps
    return apps


class ImplementationHelperImportTest(SimpleTestCase):
    def test_generic_declarations_import_without_implementation(self):
        self.assertTrue(issubclass(TrustsImplementationConfig, object))
        self.assertEqual(implementation_configs(), ())
        self.assertIs(BackendsMixin, TrustModelBackendMixin)
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertIsInstance(
            TrustModelBackend.query_compiler, HistoricalGroupQueryCompiler,
        )
        self.assertIs(type(kernel_config()), AppConfig)
        self.assertTrue(AppConfig.default)
        self.assertFalse(TrustsImplementationConfig.default)
        self.assertIs(kernel_config(), kernel_config())
        self.assertEqual(kernel_config().label, 'trusts_core')

    def test_resolver_requires_owner_on_kernel_only_registry(self):
        with self.assertRaises(TrustsConfigurationError) as path_ctx:
            implementation_for_path(CONCRETE)
        self.assertEqual(path_ctx.exception.reason, 'missing_implementation')
        with self.assertRaises(TrustsConfigurationError) as class_ctx:
            implementation_for_class(TrustModelBackend)
        self.assertEqual(class_ctx.exception.reason, 'missing_implementation')

    def test_owner_absent_mixin_still_uses_transitional_kernel(self):
        live = kernel_config()
        with patch('trusts.apps.kernel_config', wraps=kernel_config) as kernel:
            self.assertIs(TrustModelBackend()._trusts_config(), live)
            kernel.assert_called()


class ImplementationRegistryIsolationTest(SimpleTestCase):
    def test_registration_is_isolated_per_apps_registry(self):
        live_kernel = kernel_config()
        owner = _owner('tests.impl_host', 'impl_host', HOST)
        isolated = _bind([owner])
        owner.ready()
        handle = owner.configured_backend(HOST)
        self.assertIsInstance(handle.registry, TrustsRegistry)
        self.assertEqual(handle.registry.records, ())
        self.assertIsNot(handle.registry, live_kernel.registry)
        self.assertEqual(implementation_configs(), ())
        self.assertEqual(implementation_configs(isolated), (owner,))
        self.assertIs(
            implementation_for_path(HOST, apps_registry=isolated), owner,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST)
        self.assertEqual(ctx.exception.reason, 'missing_implementation')
        self.assertIs(kernel_config(), live_kernel)

    def test_ready_and_check_reentry_are_idempotent(self):
        owner = _owner('tests.impl_host', 'impl_host', HOST)
        _bind([owner])
        owner.ready()
        first = owner.registries[HOST]
        stored = dict(owner.registries)
        owner.ready()
        import trusts.checks  # noqa: F401
        self.assertIs(owner.registries[HOST], first)
        self.assertEqual(owner.registries, stored)
        self.assertIs(owner.configured_backend(HOST).registry, first)

    def test_empty_owned_paths_fail_at_startup(self):
        owner = _owner('tests.impl_empty', 'impl_empty')
        _bind([owner])
        with self.assertRaises(ImproperlyConfigured):
            owner.ready()
        self.assertEqual(owner.registries, {})


class ExactPathRoutingTest(SimpleTestCase):
    def test_multiple_owners_route_by_exact_path_independent_of_order(self):
        first = _owner('tests.impl_host', 'impl_host', HOST)
        second = _owner('tests.impl_mixin', 'impl_mixin', MIXIN)
        host_first = _bind([first, second])
        mixin_first = _bind([second, first])
        self.assertIs(
            implementation_for_path(HOST, apps_registry=host_first), first,
        )
        self.assertIs(
            implementation_for_path(HOST, apps_registry=mixin_first), first,
        )
        self.assertIs(
            implementation_for_path(MIXIN, apps_registry=host_first), second,
        )
        self.assertIs(
            implementation_for_path(MIXIN, apps_registry=mixin_first), second,
        )
        self.assertIs(
            implementation_for_class(
                HostTrustModelBackend, apps_registry=mixin_first,
            ),
            first,
        )
        self.assertIs(
            implementation_for_class(
                MixinOnlyBackend, apps_registry=host_first,
            ),
            second,
        )
        self.assertEqual(
            [type(c).__name__ for c in implementation_configs(host_first)],
            ['impl_host', 'impl_mixin'],
        )
        self.assertEqual(
            [type(c).__name__ for c in implementation_configs(mixin_first)],
            ['impl_mixin', 'impl_host'],
        )

    def test_donation_writes_the_owning_registry(self):
        owner = _owner('tests.impl_host', 'impl_host', HOST)
        other = _owner('tests.impl_mixin', 'impl_mixin', MIXIN)
        isolated = _bind([other, owner])
        owner.ready()
        other.ready()
        resolved = implementation_for_path(HOST, apps_registry=isolated)
        self.assertIs(resolved, owner)
        handle = resolved.configured_backend(HOST)
        self.assertIs(handle.registry, owner.registries[HOST])
        self.assertIsNot(handle.registry, other.registries[MIXIN])
        self.assertEqual(handle.path, HOST)


class FailLoudOwnershipTest(SimpleTestCase):
    def test_missing_owner_fails_before_authorization(self):
        owner = _owner('tests.impl_mixin', 'impl_mixin', MIXIN)
        isolated = _bind([owner])
        owner.ready()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST, apps_registry=isolated)
        self.assertEqual(ctx.exception.reason, 'missing_implementation')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_class(
                HostTrustModelBackend, apps_registry=isolated,
            )
        self.assertEqual(ctx.exception.reason, 'missing_implementation')

    def test_duplicate_owner_fails_at_startup_and_resolve(self):
        first = _owner('tests.impl_a', 'impl_a', HOST)
        second = _owner('tests.impl_b', 'impl_b', HOST)
        isolated = _bind([first, second])
        with self.assertRaises(TrustsConfigurationError) as ctx:
            first.ready()
        self.assertEqual(ctx.exception.reason, 'duplicate_implementation')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST, apps_registry=isolated)
        self.assertEqual(ctx.exception.reason, 'duplicate_implementation')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_class(
                HostTrustModelBackend, apps_registry=isolated,
            )
        self.assertEqual(ctx.exception.reason, 'duplicate_implementation')

    def test_ambiguous_owned_paths_fail_at_startup(self):
        owner = _owner('tests.impl_alias', 'impl_alias', CONCRETE, ALIASED)
        _bind([owner])
        with self.assertRaises(TrustsConfigurationError) as ctx:
            owner.ready()
        self.assertEqual(ctx.exception.reason, 'ambiguous_path')
        isolated = _bind([owner])
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_class(
                TrustModelBackend, apps_registry=isolated,
            )
        self.assertEqual(ctx.exception.reason, 'ambiguous_path')

    def test_class_path_identity_mismatch_fails_before_authorization(self):
        owner = _owner('tests.impl_mismatch', 'impl_mismatch', HOST)

        def _wrong_path(cls):
            return MIXIN

        owner.path_for_class = _wrong_path
        isolated = _bind([owner])
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST, apps_registry=isolated)
        self.assertEqual(ctx.exception.reason, 'identity_mismatch')


class MixinDualResolveTest(SimpleTestCase):
    def test_owner_present_never_consults_kernel_fallback(self):
        owner = _owner('tests.impl_host', 'impl_host', HOST)
        _bind([owner])
        owner.ready()
        backend = HostTrustModelBackend()
        with patch(
            'trusts.apps.implementation_configs', return_value=(owner,),
        ):
            with patch('trusts.apps.kernel_config') as kernel:
                self.assertIs(backend._trusts_config(), owner)
                self.assertIs(
                    backend._own_handle().registry, owner.registries[HOST],
                )
                kernel.assert_not_called()

    def test_owner_absent_legacy_still_uses_kernel_config(self):
        live = kernel_config()
        backend = TrustModelBackend()
        with patch('trusts.apps.implementation_configs', return_value=()):
            with patch('trusts.apps.kernel_config', wraps=kernel_config) as kernel:
                self.assertIs(backend._trusts_config(), live)
                kernel.assert_called()
        self.assertIs(backend._own_handle().registry, live.registry)

    def test_duplicate_owner_fails_from_mixin_before_sql(self):
        first = _owner('tests.impl_a', 'impl_a', HOST)
        second = _owner('tests.impl_b', 'impl_b', HOST)
        backend = HostTrustModelBackend()
        with patch(
            'trusts.apps.implementation_configs', return_value=(first, second),
        ):
            with patch('trusts.apps.kernel_config') as kernel:
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    backend._trusts_config()
                self.assertEqual(ctx.exception.reason, 'duplicate_implementation')
                kernel.assert_not_called()

    def test_historical_and_core_backends_identity_preserved(self):
        self.assertIs(BackendsMixin, TrustModelBackendMixin)
        self.assertTrue(issubclass(TrustModelBackend, TrustModelBackendMixin))
        self.assertTrue(
            TrustModelBackend.query_compiler.historical_fallback,
        )
        self.assertFalse(
            TrustModelBackendMixin.query_compiler.historical_fallback,
        )
