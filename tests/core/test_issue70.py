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
        from trusts.backends import catalogs

        self.contributor = apps.get_app_config('myapp')
        self.assertIsInstance(self.contributor, DocumentConfig)
        self._document_cls = DocumentBackend
        self.saved_catalog = catalogs.get(DocumentBackend)
        self.live_catalog = configured_catalog(DOCUMENT_BACKEND)

    def tearDown(self):
        from trusts.backends import catalogs

        if self.saved_catalog is None:
            catalogs.pop(self._document_cls, None)
        else:
            catalogs[self._document_cls] = self.saved_catalog

    def test_reenter_same_contributor_ready_is_noop(self):
        before = self.live_catalog.records
        self.contributor.ready()
        self.assertEqual(self.live_catalog.records, before)

    def test_ready_does_not_replace_registry(self):
        first = configured_catalog(DOCUMENT_BACKEND)
        self.contributor.ready()
        self.assertIs(configured_catalog(DOCUMENT_BACKEND), first)

    def test_frozen_recorder_is_not_rewritten(self):
        from tests.myapp.backends import DocumentBackend

        isolated = RegistryFactory()
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        recorder = DocumentBackend().get_registry()
        self.contributor.ready()
        self.assertTrue(recorder.frozen)
        self.assertEqual(isolated.records, ())
        self.assertTrue(self.live_catalog.plan_for(Document).records)

    def test_conflicting_contribution_does_not_reach_the_frozen_recorder(self):
        isolated = RegistryFactory()
        j = Ref(DocumentGrant)
        isolated.register(
            content=j.document,
            user=j.permission,
            permission=j.user,
        )
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        before = self.live_catalog.records
        self.contributor.ready()
        self.assertEqual(len(isolated.records), 1)
        self.assertEqual(self.live_catalog.records, before)


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

        live = configured_catalog(DOCUMENT_BACKEND)
        before = live.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_document_grant_registry_id', None))
        self.assertEqual(live.records, before)
