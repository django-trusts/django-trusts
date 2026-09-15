"""#80: any-plan-records gate on isolated handles.

``filter_by_user_content_perm`` / NewTeamForm on Trust stay on Zero.
"""

from django.contrib.auth.models import Group
from django.test import SimpleTestCase

from tests.models import Organization
from tests.myapp.models import Document, DocumentGrant
from trusts.core import Ref, TrustsRegistry, any_plan_records


class _Handle(object):
    def __init__(self, registry):
        self.registry = registry
        self.compiler = object()


def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


class AnyPlanRecordsGateRuleTest(SimpleTestCase):
    def test_any_path_establishes_support_empty_and_other_terminals_do_not(self):
        empty = TrustsRegistry()
        filled = TrustsRegistry()
        _contribute_document(filled)
        unused = _Handle(empty)
        supporting = _Handle(filled)
        self.assertFalse(any_plan_records((), Document))
        self.assertFalse(any_plan_records((unused,), Document))
        self.assertTrue(any_plan_records((unused, supporting), Document))
        self.assertTrue(any_plan_records((supporting, unused), Document))
        self.assertTrue(any_plan_records((supporting,), Document))
        self.assertFalse(any_plan_records((supporting,), Organization))
        self.assertFalse(any_plan_records((supporting,), Group))
