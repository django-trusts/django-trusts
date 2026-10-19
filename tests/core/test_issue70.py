"""#70: second-owner contribution idempotence (Document path).

Trust-as-content ``.permitted()`` stays on Zero ``tests/legacy/``.
"""

from django.apps import apps
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import (
    configured_catalog, isolate_live_registry, live_config, override_apps_ready,
)
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.models import Document, DocumentGrant
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import RegistryFactory


class DocumentContributionIdempotenceTest(KernelHostRequiredMixin, SimpleTestCase):
    def setUp(self):
        super().setUp()
        from tests.myapp.backends import DocumentBackend
        from trusts.apps import catalogs

        self.contributor = apps.get_app_config('myapp')
        self.assertIsInstance(self.contributor, DocumentConfig)
        self._document_cls = DocumentBackend
        self.saved_catalog = catalogs.get(DocumentBackend)
        self.live_registry = configured_catalog(self.contributor).registry
        self.saved_sentinel = self.contributor._document_grant_registry_id

    def tearDown(self):
        from trusts.apps import catalogs

        if self.saved_catalog is None:
            catalogs.pop(self._document_cls, None)
        else:
            catalogs[self._document_cls] = self.saved_catalog
        self.contributor._document_grant_registry_id = self.saved_sentinel

    def test_reenter_same_contributor_ready_is_noop(self):
        before = self.live_registry.records
        self.contributor.ready()
        self.assertEqual(self.live_registry.records, before)

    def test_ready_does_not_replace_registry(self):
        first = configured_catalog(self.contributor).registry
        self.contributor.ready()
        self.assertIs(configured_catalog(self.contributor).registry, first)

    def test_new_registry_receives_declaration_again(self):
        from tests.myapp.backends import DocumentBackend

        isolated = RegistryFactory()
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        recorder = DocumentBackend().get_registry()
        self.contributor._document_grant_registry_id = None
        with override_apps_ready(False, self.contributor.apps):
            self.contributor.ready()
        self.assertIs(self.contributor._document_grant_registry_id, recorder)
        self.assertTrue(recorder.frozen)
        self.assertEqual(isolated.records, ())
        self.assertTrue(self.live_registry.plan_for(Document).records)

    def test_conflicting_contribution_fails_closed_without_sentinel(self):
        from tests.myapp.backends import DocumentBackend

        isolated = RegistryFactory()
        j = Ref(DocumentGrant)
        isolated.register(
            content=j.document,
            user=j.permission,
            permission=j.user,
        )
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        recorder = DocumentBackend().get_registry()
        before = self.live_registry.records
        self.contributor._document_grant_registry_id = None
        with override_apps_ready(False, self.contributor.apps):
            self.contributor.ready()
        self.assertIs(self.contributor._document_grant_registry_id, recorder)
        self.assertEqual(len(isolated.records), 1)
        self.assertEqual(self.live_registry.records, before)


@isolate_apps(
    'tests',
    'tests.myapp',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateDocumentContributionTest(
    KernelHostRequiredMixin, SimpleTestCase,
):
    def test_isolate_apps_tests_config_does_not_touch_live_document_registry(self):
        from tests.apps import TestsConfig
        import tests as tests_module

        live = configured_catalog(apps.get_app_config('myapp')).registry
        before = live.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_document_grant_registry_id', None))
        self.assertEqual(live.records, before)
