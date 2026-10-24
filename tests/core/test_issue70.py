"""#70: second-owner contribution idempotence (Document path).

Trust-as-content ``.permitted()`` stays on Zero ``tests/legacy/``.
"""

from django.apps import apps
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.support import (
    configured_catalog,
    isolate_live_registry,
    compiler,
)
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.models import Document, DocumentGrant
from trusts.compile.nodes import Ref


class DocumentContributionIdempotenceTest(KernelHostRequiredMixin, SimpleTestCase):
    def setUp(self):
        super().setUp()
        from tests.myapp.backends import DocumentBackend
        from tests.support import config_for_class

        self.contributor = apps.get_app_config('myapp')
        self.assertIsInstance(self.contributor, DocumentConfig)
        self._document_config = config_for_class(DocumentBackend)
        self.saved_catalog = self._document_config.catalog
        self.live_catalog = configured_catalog(DOCUMENT_BACKEND)

    def tearDown(self):
        self._document_config.catalog = self.saved_catalog

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
        from trusts.errors import TrustsConfigurationError

        isolated = compiler()
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        self.contributor.ready()
        self.assertEqual(isolated.records, ())
        self.assertTrue(self.live_catalog.plan_for(Document).records)
        with self.assertRaises(TrustsConfigurationError):
            DocumentBackend().get_registry().register(
                trust=DocumentGrant, user='user', permission='permission',
                content='document',
            )

    def test_conflicting_contribution_does_not_reach_the_frozen_recorder(self):
        isolated = compiler()
        j = Ref(DocumentGrant)
        isolated.register_relation(
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
