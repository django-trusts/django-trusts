"""#72: isolate-apps / host-path contribution isolation.

Ticket ``.permitted()`` stays on Zero ``tests/legacy/``.
"""

from django.apps import apps
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import TestsConfig, live_config
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.models import Document
import tests as tests_module
from trusts.core import TrustsRegistry


class IsolatedHostDoesNotReceiveDocumentContributionTest(
    KernelHostRequiredMixin, SimpleTestCase,
):
    def test_host_registry_stays_empty_of_document_terminal(self):
        host = live_config()
        self.assertEqual(host._configured_trusts_paths(), (HOST_BACKEND,))
        self.assertFalse(host.registry.plan_for(Document).records)
        before = host.registry.records
        host.ready()
        self.assertEqual(host.registry.records, before)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateTicketContributionTest(
    KernelHostRequiredMixin, SimpleTestCase,
):
    def test_tests_config_ready_on_isolate_does_not_touch_live(self):
        live_host = live_config().registry
        live_doc = apps.get_app_config('myapp').configured_backend().registry
        before_host = live_host.records
        before_doc = live_doc.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_ticket_registry_id', None))
        self.assertEqual(live_host.records, before_host)
        self.assertEqual(live_doc.records, before_doc)
        self.assertIsInstance(TrustsRegistry(), TrustsRegistry)
