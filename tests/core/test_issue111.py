"""#111: library cutover. Core is ``1.0.0.dev3``.

Core ships no AppConfig, no Django app label, and no ``kernel_config()``.
Historical concrete imports fail. Supported owners resolve through
``TrustsImplementationConfig``. The generic mixin lives only on
``trusts.backends``; ``trusts.core_backends`` is gone.
"""

from unittest.mock import patch

from django.apps import apps
from django.test import SimpleTestCase, override_settings

import tests as tests_module
from tests.apps import live_config
from tests.backends import HostTrustModelBackend, MixinOnlyBackend
from tests.kernel_host.apps import HOST_BACKEND, KernelHostConfig
from trusts.apps import (
    TrustsImplementationConfig,
    configured_implementation_handles,
    implementation_configs,
    implementation_for_class,
    implementation_for_path,
)
from trusts.backends import TrustModelBackendMixin
from trusts.core import TrustsConfigurationError


MIXIN = 'tests.backends.MixinOnlyBackend'


class MixinImplConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_mixin_111'
    trusts_backend_paths = (MIXIN,)


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


class LibraryIdentityTest(SimpleTestCase):
    def test_kernel_config_and_appconfig_are_gone(self):
        import trusts.apps as apps_mod

        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertFalse(hasattr(apps_mod, 'KERNEL_CONFIG_TOMBSTONE'))
        self.assertFalse(hasattr(apps_mod, 'AppConfig'))
        labels = {config.label for config in apps.get_app_configs()}
        names = {config.name for config in apps.get_app_configs()}
        self.assertNotIn('trusts', labels)
        self.assertNotIn('trusts_core', labels)
        self.assertNotIn('trusts', names)
        with self.assertRaises(LookupError):
            apps.get_app_config('trusts')
        with self.assertRaises(LookupError):
            apps.get_app_config('trusts_core')


class HistoricalImportCutoverTest(SimpleTestCase):
    def test_models_module_is_inert(self):
        import trusts.models as models_mod

        self.assertFalse(hasattr(models_mod, 'Trust'))
        self.assertFalse(hasattr(models_mod, 'Content'))
        self.assertNotIn('Trust', dir(models_mod))
        with self.assertRaises(ImportError):
            from trusts.models import Trust  # noqa: F401
        with self.assertRaises(AttributeError):
            getattr(models_mod, 'Trust')

    def test_historical_backend_imports_fail(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))
        with self.assertRaises(ImportError):
            from trusts.backends import TrustModelBackend  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.backends import HistoricalGroupQueryCompiler  # noqa: F401

    def test_mixin_lives_only_on_trusts_backends(self):
        import importlib

        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('trusts.core_backends')
        from trusts.core import PlanQueryCompiler

        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertFalse(
            TrustModelBackendMixin.query_compiler.historical_fallback,
        )

    def test_core_is_not_an_installed_implementation(self):
        self.assertIsInstance(live_config(), TrustsImplementationConfig)
        self.assertIs(type(live_config()), KernelHostConfig)
        self.assertNotIn(
            'trusts',
            {config.name for config in apps.get_app_configs()},
        )


class OwnerResolutionTest(SimpleTestCase):
    def test_live_host_owner_resolves(self):
        owner = live_config()
        self.assertIsInstance(owner, TrustsImplementationConfig)
        handle = owner.configured_backend(HOST_BACKEND)
        self.assertEqual(handle.path, HOST_BACKEND)
        backend = HostTrustModelBackend()
        self.assertIs(backend._trusts_config(), owner)
        configured_implementation_handles()
        implementation_for_path(HOST_BACKEND)
        implementation_for_class(HostTrustModelBackend)
        self.assertIn(owner, implementation_configs())

    def test_authorized_and_filter_scopes_use_owners(self):
        from trusts.core import filter_authorized_scopes
        from trusts.query import AuthorizedQuerySet

        handles = configured_implementation_handles()
        self.assertTrue(handles)
        self.assertEqual(handles[0].path, HOST_BACKEND)
        self.assertTrue(issubclass(AuthorizedQuerySet, object))
        self.assertTrue(callable(filter_authorized_scopes))

    def test_missing_owner_is_configuration_error(self):
        backend = MixinOnlyBackend()
        with patch('trusts.apps.implementation_configs', return_value=()):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                backend._trusts_config()
            self.assertIn('no implementation owner', str(ctx.exception))

    def test_owner_present_resolves(self):
        owner = _bind(MixinImplConfig, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            owner.ready()
            backend = MixinOnlyBackend()
            with patch(
                'trusts.apps.implementation_configs',
                return_value=(owner,),
            ):
                self.assertIs(backend._trusts_config(), owner)
