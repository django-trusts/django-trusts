"""#70: second-owner contribution idempotence (Document path).

Trust-as-content ``.permitted()`` stays on Zero ``tests/legacy/``.
"""

from unittest.mock import patch

from django.apps import apps
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import isolate_live_registry, live_config, override_apps_ready
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND, DocumentConfig
from tests.myapp.models import Document, DocumentGrant
from trusts.core import Ref, TrustsConfigurationError, TrustsRegistry


class DocumentContributionIdempotenceTest(KernelHostRequiredMixin, SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.contributor = apps.get_app_config('myapp')
        self.assertIsInstance(self.contributor, DocumentConfig)
        self.saved_registries = dict(self.contributor.registries)
        self.live_registry = self.contributor.configured_backend().registry
        self.saved_sentinel = self.contributor._document_grant_registry_id

    def tearDown(self):
        self.contributor.registries.clear()
        self.contributor.registries.update(self.saved_registries)
        self.contributor._document_grant_registry_id = self.saved_sentinel

    def test_reenter_same_contributor_ready_is_noop(self):
        before = self.live_registry.records
        with patch.object(
            self.live_registry, 'register', wraps=self.live_registry.register,
        ) as register:
            self.contributor.ready()
        register.assert_not_called()
        self.assertEqual(self.live_registry.records, before)

    def test_ready_does_not_replace_registry(self):
        first = self.contributor.configured_backend().registry
        self.contributor.ready()
        self.assertIs(self.contributor.configured_backend().registry, first)

    def test_new_registry_receives_declaration_again(self):
        isolated = TrustsRegistry()
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        self.contributor._document_grant_registry_id = None
        with override_apps_ready(False, self.contributor.apps):
            self.contributor.ready()
        self.assertIs(self.contributor._document_grant_registry_id, isolated)
        self.assertEqual(len(isolated.plan_for(Document).records), 1)
        self.assertIs(isolated.records[0].root, DocumentGrant)

    def test_conflicting_contribution_fails_closed_without_sentinel(self):
        isolated = TrustsRegistry()
        j = Ref(DocumentGrant)
        isolated.register(
            content=j.document,
            user=j.permission,
            permission=j.user,
        )
        isolate_live_registry(self.contributor, isolated, DOCUMENT_BACKEND)
        self.contributor._document_grant_registry_id = None
        with override_apps_ready(False, self.contributor.apps):
            with self.assertRaises(TrustsConfigurationError):
                self.contributor.ready()
        self.assertIsNone(self.contributor._document_grant_registry_id)
        self.assertEqual(len(isolated.records), 1)


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

        live = apps.get_app_config('myapp').configured_backend().registry
        before = live.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_document_grant_registry_id', None))
        self.assertEqual(live.records, before)
