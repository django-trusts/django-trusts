"""#67: registry ownership and first-contribution idempotence.

Category ``.permitted()`` runtime stays on Zero ``tests/legacy/``.
"""

import types
from unittest.mock import patch

from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import TestsConfig, live_config
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND, KernelHostConfig
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.models import Document
import tests as tests_module
from trusts.core import TrustsRegistry


class TrustsRegistryOwnershipTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_package_registry_is_created_in_init_not_replaced_by_ready(self):
        live = live_config()
        self.assertIsInstance(live, KernelHostConfig)
        self.assertIsInstance(live.registry, TrustsRegistry)
        first = live.registry
        live.ready()
        self.assertIs(live.registry, first)

    def test_reader_obtains_registry_via_app_config_not_package_root(self):
        import trusts

        live = live_config().registry
        self.assertIsInstance(live, TrustsRegistry)
        self.assertIsNone(getattr(trusts, 'registry', None))
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RelationPlan', None))

    def test_isolated_core_registries_stay_independent(self):
        live = live_config().registry
        isolated = TrustsRegistry()
        self.assertIsNot(isolated, live)
        self.assertEqual(isolated.records, ())

    def test_core_module_has_no_historical_import_or_global(self):
        import trusts.core as core

        forbidden = {
            'Trust',
            'Content',
            'Junction',
            'TrustUserPermission',
            'TrustGroupPermission',
            'Group',
            'Role',
            'Category',
        }
        self.assertFalse(forbidden.intersection(vars(core)))
        imported = {
            value.__name__
            for value in vars(core).values()
            if isinstance(value, types.ModuleType)
        }
        self.assertTrue(
            all(
                name == 'trusts.core' or not name.startswith('trusts.')
                for name in imported
            ),
            imported,
        )

    def test_trusts_does_not_import_or_discover_tests_category(self):
        import trusts.apps as trusts_apps
        import trusts.core as core
        import trusts.models as trusts_models

        for module in (trusts_apps, core, trusts_models):
            self.assertNotIn('Category', vars(module))
            self.assertNotIn('Ticket', vars(module))


class ContributorIdempotenceTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_reenter_same_document_contributor_ready_is_noop(self):
        from django.apps import apps

        contributor = apps.get_app_config('myapp')
        self.assertIsInstance(contributor, DocumentConfig)
        registry = contributor.configured_backend().registry
        self.assertIs(contributor._document_grant_registry_id, registry)
        before = registry.records
        with patch.object(registry, 'register', wraps=registry.register) as register:
            contributor.ready()
        register.assert_not_called()
        self.assertEqual(registry.records, before)
        self.assertTrue(registry.plan_for(Document).records)

    def test_host_ready_does_not_replace_or_donate_document(self):
        host = live_config()
        self.assertEqual(host._configured_trusts_paths(), (HOST_BACKEND,))
        before = host.registry.records
        host.ready()
        self.assertEqual(host.registry.records, before)
        self.assertFalse(host.registry.plan_for(Document).records)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateToLiveRegistryTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = live_config().registry
        before = live.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertIsNone(getattr(contributor, '_document_grant_registry_id', None))
        self.assertEqual(live.records, before)
        self.assertNotIn(DOCUMENT_BACKEND, live_config().registries)
