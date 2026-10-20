"""#67: registry ownership and first-contribution idempotence.

Category ``.permitted()`` runtime stays on Zero ``tests/legacy/``.
"""

from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import configured_catalog, TestsConfig, live_config
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from trusts.apps import TrustsImplementationConfig
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.models import Document
import tests as tests_module
from trusts.installed import catalogs
from trusts.compile.factory import RegistryFactory


class TrustsRegistryOwnershipTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_package_registry_is_created_in_init_not_replaced_by_ready(self):
        # The built object is sealed onto the backend class, not
        # constructed in AppConfig.__init__. A second ready() must not
        # replace it. The path dict stays empty unless a test writes it.
        from tests.backends import HostTrustModelBackend
        from trusts.plan.registry import Registry

        live = live_config()
        self.assertIsInstance(live, TrustsImplementationConfig)
        catalog = catalogs[HostTrustModelBackend]
        self.assertIsInstance(catalog.policy(), Registry)
        first = catalog.policy()
        live.ready()
        self.assertIs(catalogs[HostTrustModelBackend].policy(), first)
        self.assertFalse(hasattr(live, 'registries'))

    def test_reader_obtains_registry_via_app_config_not_package_root(self):
        import trusts

        from tests.backends import HostTrustModelBackend
        from trusts.plan.registry import Registry

        live = catalogs[HostTrustModelBackend].policy()
        self.assertIsInstance(live, Registry)
        self.assertIsNone(getattr(trusts, 'registry', None))
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RelationPlan', None))

    def test_isolated_core_registries_stay_independent(self):
        from tests.backends import HostTrustModelBackend

        live = catalogs[HostTrustModelBackend].policy()
        isolated = RegistryFactory()
        self.assertIsNot(isolated, live)
        self.assertEqual(isolated.records, ())

    def test_trusts_does_not_import_or_discover_tests_category(self):
        import trusts.apps as trusts_apps
        import trusts.models as trusts_models

        for module in (trusts_apps, trusts_models):
            self.assertNotIn('Category', vars(module))
            self.assertNotIn('Ticket', vars(module))


class ContributorIdempotenceTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_reenter_same_document_contributor_ready_is_noop(self):
        from django.apps import apps

        from tests.myapp.backends import DocumentBackend

        contributor = apps.get_app_config('myapp')
        self.assertIsInstance(contributor, DocumentConfig)
        recorder = DocumentBackend().get_registry()
        built = configured_catalog(DOCUMENT_BACKEND)
        self.assertTrue(recorder.frozen)
        before = built.records
        contributor.ready()
        self.assertEqual(built.records, before)
        self.assertTrue(built.plan_for(Document).records)

    def test_host_ready_does_not_replace_or_donate_document(self):
        host = live_config()
        self.assertEqual(configured_catalog(HOST_BACKEND).path, HOST_BACKEND)
        from tests.backends import HostTrustModelBackend
        registry = catalogs[HostTrustModelBackend].policy()
        before = registry.records
        host.ready()
        self.assertEqual(registry.records, before)
        self.assertFalse(registry.plan_for(Document).records)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateToLiveRegistryTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        from tests.backends import HostTrustModelBackend
        live = catalogs[HostTrustModelBackend].policy()
        before = live.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertIsNone(getattr(contributor, '_document_grant_registry_id', None))
        self.assertEqual(live.records, before)
        self.assertFalse(hasattr(live_config(), 'registries'))
