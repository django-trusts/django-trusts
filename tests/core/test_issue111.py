"""#111: library cutover. Core is ``1.0.0.dev3``.

Core ships no AppConfig, no Django app label, and no ``kernel_config()``.
Historical concrete imports fail. Supported owners subclass
``TrustsConfigMixin``. The generic mixin lives only on
``trusts.backends``; ``trusts.core_backends`` is gone.
"""


from django.apps import apps
from django.core.checks import run_checks
from django.test import SimpleTestCase, override_settings

import tests as tests_module
from tests.kernel_host.apps import HOST_BACKEND, KernelHostConfig
from tests.kernel_host.backends import HostTrustModelBackend
from tests.support import configured_catalog
from trusts.apps import TrustsConfigMixin, installed_catalogs
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import filter_by_permitted_content
from trusts.models import AuthorizedQuerySet


MIXIN = 'tests.backends.MixinOnlyBackend'


class MixinImplConfig(TrustsConfigMixin):
    name = 'tests'
    label = 'trusts_impl_mixin_111'


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


class HistoricalImportCutoverTest(SimpleTestCase):


    def test_mixin_lives_only_on_trusts_backends(self):
        import importlib

        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('trusts.core_backends')
        from trusts.plan.relations import PlanQueryCompiler

        catalog = apps.get_app_config('trusts_kernel_host').get_catalog()
        self.assertIsInstance(catalog.compiler, PlanQueryCompiler)
        self.assertFalse(catalog.compiler.historical_fallback)

    def test_core_is_not_an_installed_implementation(self):
        host = apps.get_app_config('trusts_kernel_host')
        self.assertIs(type(host), KernelHostConfig)
        self.assertIsInstance(host, TrustsConfigMixin)
        self.assertNotIn(
            'trusts',
            {config.name for config in apps.get_app_configs()},
        )


class OwnerResolutionTest(SimpleTestCase):
    def test_live_host_owner_resolves(self):
        owner = apps.get_app_config('trusts_kernel_host')
        self.assertIsInstance(owner, TrustsConfigMixin)
        handle = configured_catalog(HOST_BACKEND)
        self.assertEqual(handle.path, owner.catalog_path())
        backend = HostTrustModelBackend()
        self.assertIs(backend.get_catalog(), handle)
        self.assertIn(handle, installed_catalogs())

    def test_authorized_and_filter_scopes_use_owners(self):
        registries = installed_catalogs()
        self.assertTrue(registries)
        self.assertEqual(
            registries[0].path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )
        self.assertTrue(issubclass(AuthorizedQuerySet, object))
        self.assertTrue(callable(filter_by_permitted_content))

    def test_missing_owner_is_configuration_error(self):
        outside = 'tests.gh_permissions.backends.OutsideBackend'
        with override_settings(AUTHENTICATION_BACKENDS=(HOST_BACKEND, outside)):
            messages = [
                message for message in run_checks()
                if getattr(message, 'id', None) == 'trusts.E012'
            ]
        self.assertEqual(
            [message.msg for message in messages],
            ['App gh_permissions must extend TrustsConfigMixin.'],
        )

    def test_owner_present_resolves(self):
        backend = HostTrustModelBackend()
        catalog = backend.get_catalog()
        self.assertEqual(
            catalog.path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )
        self.assertIs(catalog, HostTrustModelBackend().catalog)
