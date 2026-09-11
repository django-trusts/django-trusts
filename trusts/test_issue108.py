"""#108 / #111: implementation-owned registry after the kernel cutover.

Helper + owner resolvers stay. ``kernel_config()`` is a tombstone.
Mixin identity stays. Historical core backend is gone.
"""

from unittest.mock import patch

from django.apps import AppConfig as DjangoAppConfig
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from tests.apps import TestsConfig, live_config
from tests.backends import HostTrustModelBackend, MixinOnlyBackend
from tests.kernel_host.apps import HOST_BACKEND
from trusts.apps import (
    AppConfig,
    TrustsImplementationConfig,
    _listed_mixin_paths,
    implementation_configs,
    implementation_for_class,
    implementation_for_path,
    kernel_config,
)
from trusts.backends import TrustModelBackendMixin
from trusts.core import TrustsConfigurationError, TrustsRegistry


HOST = 'tests.backends.HostTrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
ALIASED = 'tests.backends.AliasedTrustModelBackend'


class HostImplConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_host'
    trusts_backend_paths = (HOST,)


class MixinImplConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_mixin'
    trusts_backend_paths = (MIXIN,)


class EmptyImplConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_empty'
    trusts_backend_paths = ()


class DuplicatePathImplConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_dup_path'
    trusts_backend_paths = (HOST, HOST)


class _AppsView(object):
    def __init__(self, configs, ready=True):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return tuple(self._configs)

    def is_installed(self, name):
        return False


def _bind(config_cls, configs=None, ready=True):
    config = config_cls('tests', tests_module)
    view = _AppsView(
        configs if configs is not None else [config],
        ready=ready,
    )
    config.apps = view
    if configs is None:
        view._configs = [config]
    return config


class ImplementationHelperSurfaceTest(SimpleTestCase):
    def test_kernel_is_not_an_implementation_config(self):
        self.assertFalse(issubclass(AppConfig, TrustsImplementationConfig))
        self.assertFalse(TrustsImplementationConfig.default)
        self.assertTrue(AppConfig.default)
        self.assertIsInstance(live_config(), TrustsImplementationConfig)
        self.assertIn(live_config(), implementation_configs())

    def test_helper_and_resolvers_import(self):
        self.assertTrue(issubclass(TrustsImplementationConfig, DjangoAppConfig))
        self.assertTrue(callable(implementation_for_path))
        self.assertTrue(callable(implementation_for_class))
        self.assertTrue(callable(implementation_configs))

    def test_mixin_lives_only_on_trusts_backends(self):
        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )

    def test_historical_backend_no_longer_imports(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))

    def test_generic_declarations_import_without_calling_tombstone(self):
        from trusts.core import Ref, TrustsRegistry, filter_authorized_scopes
        from trusts.query import AuthorizedManager, AuthorizedQuerySet

        with patch('trusts.apps.kernel_config', wraps=kernel_config) as wrapped:
            self.assertTrue(callable(filter_authorized_scopes))
            self.assertTrue(issubclass(AuthorizedQuerySet, object))
            self.assertTrue(issubclass(AuthorizedManager, object))
            registry = TrustsRegistry()
            self.assertEqual(registry.records, ())
            self.assertIsNotNone(Ref)
            wrapped.assert_not_called()


class ImplementationRoutingTest(SimpleTestCase):
    def test_exact_path_routing_is_independent_of_app_order(self):
        host = _bind(HostImplConfig)
        mixin = _bind(MixinImplConfig)
        for order in ((host, mixin), (mixin, host)):
            view = _AppsView(order)
            host.apps = view
            mixin.apps = view
            self.assertIs(implementation_for_path(HOST, view), host)
            self.assertIs(implementation_for_path(MIXIN, view), mixin)
            self.assertIs(
                implementation_for_class(HostTrustModelBackend, view), host,
            )
            self.assertIs(
                implementation_for_class(MixinOnlyBackend, view), mixin,
            )

    def test_missing_owner_fails_loud_before_sql(self):
        view = _AppsView([])
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST, view)
        self.assertIn('No implementation owns', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_class(HostTrustModelBackend, view)
        self.assertIn('no implementation owner', str(ctx.exception))
        self.assertIsNone(
            implementation_for_class(
                HostTrustModelBackend, view, required=False,
            )
        )

    def test_duplicate_owner_fails_loud(self):
        first = _bind(HostImplConfig)
        second = _bind(HostImplConfig)
        view = _AppsView([first, second])
        first.apps = view
        second.apps = view
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(HOST, view)
        self.assertIn('multiple implementation owners', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            implementation_for_class(HostTrustModelBackend, view)

    def test_class_path_identity_mismatch_fails_loud(self):
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                _listed_mixin_paths()
            self.assertIn('multiple paths', str(ctx.exception))


class ImplementationReadyTest(SimpleTestCase):
    def test_empty_owned_paths_fail_at_startup(self):
        config = _bind(EmptyImplConfig)
        with self.assertRaises(ImproperlyConfigured) as ctx:
            config.ready()
        self.assertIn('trusts_backend_paths', str(ctx.exception))

    def test_repeated_owned_path_fails_at_startup(self):
        config = _bind(DuplicatePathImplConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                config.ready()
        self.assertIn('must not repeat', str(ctx.exception))

    def test_owned_path_missing_from_settings_fails_at_startup(self):
        config = _bind(HostImplConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                config.ready()
        self.assertIn('not listed in AUTHENTICATION_BACKENDS', str(ctx.exception))

    def test_duplicate_owner_fails_at_startup(self):
        first = _bind(HostImplConfig)
        second = _bind(HostImplConfig)
        view = _AppsView([first, second], ready=False)
        first.apps = view
        second.apps = view
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                first.ready()
        self.assertIn('multiple implementation owners', str(ctx.exception))

    def test_ready_is_idempotent_and_does_not_replace_registries(self):
        config = _bind(HostImplConfig, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            config.ready()
            first = config.registries[HOST]
            holder = config.registries
            config.ready()
            self.assertIs(config.registries, holder)
            self.assertIs(config.registries[HOST], first)

    def test_donation_uses_implementation_for_path(self):
        config = _bind(HostImplConfig, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            config.ready()
            owner = implementation_for_path(HOST, config.apps)
            self.assertIs(owner, config)
            handle = owner.configured_backend(HOST)
            before = handle.registry.records
            handle.registry.register  # surface exists
            self.assertIs(handle.registry, config.registries[HOST])
            self.assertEqual(handle.registry.records, before)


class MixinOwnerResolveTest(SimpleTestCase):
    def test_owner_absent_is_configuration_error_not_tombstone(self):
        backend = MixinOnlyBackend()
        with patch('trusts.apps.implementation_configs', return_value=()):
            with patch('trusts.apps.kernel_config', wraps=kernel_config) as wrapped:
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    backend._trusts_config()
                self.assertIn('no implementation owner', str(ctx.exception))
                wrapped.assert_not_called()

    def test_owner_present_never_consults_kernel(self):
        owner = _bind(HostImplConfig, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            owner.ready()
            backend = HostTrustModelBackend()
            with patch(
                'trusts.apps.implementation_configs',
                return_value=(owner,),
            ):
                with patch('trusts.apps.kernel_config') as kernel:
                    config = backend._trusts_config()
                    self.assertIs(config, owner)
                    kernel.assert_not_called()
                    handle = backend._own_handle()
                    self.assertEqual(handle.path, HOST)
                    self.assertIs(handle.registry, owner.registries[HOST])

    def test_duplicate_owner_does_not_fall_back_to_kernel(self):
        first = _bind(HostImplConfig)
        second = _bind(HostImplConfig)
        backend = HostTrustModelBackend()
        with patch(
            'trusts.apps.implementation_configs',
            return_value=(first, second),
        ):
            with patch('trusts.apps.kernel_config') as kernel:
                with self.assertRaises(TrustsConfigurationError):
                    backend._trusts_config()
                kernel.assert_not_called()

    def test_live_host_is_the_kernel_suite_owner(self):
        from django.conf import settings

        if HOST_BACKEND not in (getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()):
            self.skipTest('kernel-only host path is not listed on the IIa pair')
        owner = live_config()
        self.assertEqual(implementation_for_path(HOST_BACKEND), owner)
        self.assertIs(
            implementation_for_class(HostTrustModelBackend), owner,
        )


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedImplementationStoreTest(SimpleTestCase):
    def test_implementation_registry_does_not_touch_live_owner(self):
        live = live_config()
        before = dict(live.registries)
        before_records = {
            path: registry.records for path, registry in before.items()
        }
        impl = _bind(HostImplConfig, ready=False)
        impl.apps = self.isolated_apps
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            view = _AppsView([impl], ready=False)
            impl.apps = view
            impl.ready()
            isolated = impl.registries[HOST]
            self.assertIsInstance(isolated, TrustsRegistry)
        self.assertEqual(
            {path: registry.records for path, registry in live.registries.items()},
            before_records,
        )
        for path, registry in before.items():
            self.assertIs(live.registries[path], registry)

    def test_isolate_apps_without_implementation_does_not_donate(self):
        live = live_config()
        before = live.registry.records
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        impl = HostImplConfig('tests', tests_module)
        impl.apps = self.isolated_apps
        self.assertEqual(implementation_configs(self.isolated_apps), ())
        self.assertEqual(live.registry.records, before)
