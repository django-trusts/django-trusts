"""Other public queryset APIs do not add one bind row (#300).

``QuerySet.extra(select)`` is not an ``OuterRef`` target.
``extra(tables)`` quotes its argument, so a ``(SELECT %s AS col)``
string is an identifier and its ``%s`` is not a parameter.
``FilteredRelation`` can bind a condition once on one real join, and a
second join repeats it. ``union()`` cannot be filtered afterwards.
Django 6.1.2 has no CTE queryset API. Policy SQL is unchanged.
"""

import django.db.models as models
from django.db import connection
from django.db.models import Exists, FilteredRelation, IntegerField, OuterRef, Q, Value
from django.db.utils import NotSupportedError
from django.test import SimpleTestCase

from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE


def _sql(qs):
    return qs.query.sql_with_params()


class ExtraSelectSuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue300_extra', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue300_extra', PAIR_KERNEL_SUITE)


class ExtraSelectTest(SimpleTestCase):
    def test_extra_select_is_not_an_outerref_target(self):
        inner = Document.objects.filter(pk=OuterRef('bound_user'))
        with self.assertRaises(Exception) as caught:
            Document.objects.extra(
                select={'bound_user': '%s'},
                select_params=[7],
            ).filter(Exists(inner))
        self.assertIn('bound_user', str(caught.exception))

    def test_extra_tables_quotes_a_derived_table(self):
        fragment = '(SELECT %s AS user_id) AS trusts_bind'
        sql, params = _sql(Document.objects.extra(
            tables=[fragment],
            select_params=[7],
        ))
        self.assertIn(connection.ops.quote_name(fragment), sql)
        self.assertNotIn('FROM (SELECT', sql)
        self.assertEqual(params, ())

    def test_filtered_relation_binds_once_per_join(self):
        one = Document.objects.alias(
            rel=FilteredRelation(
                'documentgrant',
                condition=Q(documentgrant__id=Value(
                    7, output_field=IntegerField(),
                )),
            ),
        ).filter(rel__id__isnull=False)
        sql, params = _sql(one)
        self.assertIn('INNER JOIN', sql)
        self.assertNotIn('CROSS JOIN', sql)
        self.assertEqual(params.count(7), 1)

        two = Document.objects.alias(
            rel=FilteredRelation(
                'documentgrant',
                condition=Q(documentgrant__id=Value(
                    7, output_field=IntegerField(),
                )),
            ),
            rel2=FilteredRelation(
                'documentaltgrant',
                condition=Q(documentaltgrant__id=Value(
                    7, output_field=IntegerField(),
                )),
            ),
        ).filter(rel__id__isnull=False, rel2__id__isnull=False)
        sql, params = _sql(two)
        self.assertEqual(params.count(7), 2)
        self.assertEqual(sql.count('%s'), len(params))

    def test_union_cannot_be_filtered(self):
        combined = Document.objects.all().union(Document.objects.all())
        with self.assertRaises(NotSupportedError):
            combined.filter(pk=1)

    def test_django_has_no_cte_queryset_api(self):
        self.assertFalse(hasattr(models, 'CTE'))
        self.assertFalse(hasattr(models, 'With'))
        self.assertFalse(any(
            name.startswith('with_') or name == 'cte'
            for name in dir(Document.objects)
        ))
