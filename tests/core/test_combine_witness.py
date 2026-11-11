"""The compiler that built a plan is the compiler that combines its rows.

``group_exists`` slices the same plan. It keeps that compiler, so a
replacement for OR runs on the group slice too. A plan constructed
without a compiler still uses the default OR.
"""

from dataclasses import replace

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from tests.myapp.models import Document, DocumentGrant
from tests.support import built_catalog, compiler
from trusts.plan.relations import PlanQueryCompiler


class _MarkingCompiler(PlanQueryCompiler):
    def __init__(self):
        self.compilers = []

    def combine(self, plan, witnesses):
        self.compilers.append(plan.query_compiler)
        return None


def _saved_permission():
    """A migrated auth permission. Creating one for Document leaves a
    content-type id in the cache after the test transaction rolls back.
    """
    return Permission.objects.get(
        content_type__app_label='auth',
        content_type__model='user',
        codename='add_user',
    )


class CompilerCarriedOnEveryPlanTest(TestCase):
    def test_content_and_group_slice_use_the_plans_compiler(self):
        marker = _MarkingCompiler()
        registry = compiler(query_compiler=marker)
        registry.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        plan = built_catalog(registry).plan_for(Document)
        user = get_user_model().objects.create_user(
            'combine-witness', password='x',
        )
        permission = _saved_permission()
        self.assertIs(plan.content_exists(user, permission), None)
        self.assertEqual(marker.compilers, [marker])

        grouped = replace(
            plan,
            records=(replace(plan.records[0], via_group=True),),
            query_compiler=marker,
        )
        marker.compilers.clear()
        self.assertIs(marker.group_exists(grouped, Document(), user, permission), None)
        self.assertEqual(marker.compilers, [marker])

    def test_default_compiler_still_ors_one_registration(self):
        registry = compiler()
        registry.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        plan = built_catalog(registry).plan_for(Document)
        user = get_user_model().objects.create_user(
            'combine-default', password='x',
        )
        permission = _saved_permission()
        predicate = plan.content_exists(user, permission)
        self.assertIsNotNone(predicate)
        self.assertIs(plan.query_compiler.__class__, PlanQueryCompiler)
