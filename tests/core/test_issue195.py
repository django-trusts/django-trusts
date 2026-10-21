"""#195 C2: Core is relationship-only after OrderedFold deletion."""
from pathlib import Path

from django.test import SimpleTestCase

from trusts.plan.relations import PlanQueryCompiler, QueryCompiler


ROOT = Path(__file__).resolve().parents[2]


class CoreOrderedFoldDeletedTest(SimpleTestCase):

    def test_engine_module_is_gone(self):
        with self.assertRaises(ModuleNotFoundError):
            __import__('trusts.ordered_fold')
        self.assertFalse((ROOT / 'trusts' / 'ordered_fold.py').exists())


class RelationshipOnlyCompilerTest(SimpleTestCase):

    def test_applies_and_any_plan_records_ignore_strategy(self):
        compiler = PlanQueryCompiler()
        protocol = QueryCompiler()
        empty = type('Plan', (), {'records': (), 'delegations': (), 'strategy': object()})()
        filled = type('Plan', (), {'records': (object(),), 'delegations': ()})()
        self.assertFalse(compiler.applies(empty))
        self.assertFalse(protocol.applies(empty))
        self.assertTrue(compiler.applies(filled))
        self.assertTrue(protocol.applies(filled))
