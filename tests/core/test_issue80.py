"""#80: any-plan-records gate on isolated handles.

``filter_by_user_content_perm`` / NewTeamForm on Trust stay on Zero.
"""

from django.contrib.auth.models import Group
from django.test import SimpleTestCase

from tests.models import Organization
from tests.myapp.models import Document, DocumentGrant
from trusts.compile.nodes import Ref
from trusts.compile.factory import RegistryFactory
from tests.support import built_registries
from trusts.plan.aggregates import any_plan_records


def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


class AnyPlanRecordsGateRuleTest(SimpleTestCase):
    def test_any_path_establishes_support_empty_and_other_terminals_do_not(self):
        empty = RegistryFactory()
        filled = RegistryFactory()
        _contribute_document(filled)
        self.assertFalse(any_plan_records((), Document))
        self.assertFalse(any_plan_records(built_registries((empty,)), Document))
        self.assertTrue(any_plan_records(built_registries((empty, filled)), Document))
        self.assertTrue(any_plan_records(built_registries((filled, empty)), Document))
        self.assertTrue(any_plan_records(built_registries((filled,)), Document))
        self.assertFalse(any_plan_records(built_registries((filled,)), Organization))
        self.assertFalse(any_plan_records(built_registries((filled,)), Group))
