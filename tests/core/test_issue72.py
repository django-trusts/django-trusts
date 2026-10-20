"""#72: isolate-apps / host-path contribution isolation.

Ticket ``.permitted()`` stays on Zero ``tests/legacy/``.
"""

from django.apps import apps
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.apps import TestsConfig
from tests.support import configured_catalog
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.models import Document
import tests as tests_module
from trusts.compile.factory import Compiler


class IsolatedHostDoesNotReceiveDocumentContributionTest(
    KernelHostRequiredMixin, SimpleTestCase,
):
    def test_host_compiler_stays_empty_of_document_terminal(self):
        host = apps.get_app_config('trusts_kernel_host')
        self.assertEqual(
            configured_catalog(HOST_BACKEND).path, host.catalog_path(),
        )
        compiler = configured_catalog(HOST_BACKEND)
        self.assertFalse(compiler.plan_for(Document).records)
        before = compiler.records
        host.ready()
        self.assertEqual(compiler.records, before)


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
        live_host = configured_catalog(HOST_BACKEND)
        from tests.myapp.apps import DOCUMENT_BACKEND
        live_doc = configured_catalog(DOCUMENT_BACKEND)
        before_host = live_host.records
        before_doc = live_doc.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_ticket_registry_id', None))
        self.assertEqual(live_host.records, before_host)
        self.assertEqual(live_doc.records, before_doc)
        self.assertIsInstance(Compiler(), Compiler)
