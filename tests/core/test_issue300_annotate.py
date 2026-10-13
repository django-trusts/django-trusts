"""``QuerySet.annotate(Value)`` does not bind an inquiry value once (#300).

Django 6.1.2 puts the ``Value`` in the SELECT list and still compiles it
again for every ``OuterRef``. A list query with two references therefore
has three placeholders. ``QuerySet.exists()`` clears the annotation mask,
drops that SELECT alias, and leaves the inlined copies. Policy SQL is
unchanged: a SELECT alias is not in scope for a nested ``WHERE``, so
this module does not touch ``trusts``.
"""

from django.db.models import Exists, IntegerField, OuterRef, Value
from django.db.models.expressions import RawSQL
from django.test import SimpleTestCase

from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE


def _sql(qs):
    return qs.query.sql_with_params()


class AnnotateValueSuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue300_annotate', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue300_annotate', PAIR_KERNEL_SUITE)


class AnnotateValueOuterRefTest(SimpleTestCase):
    def test_annotate_selects_the_value_and_inlines_it_again(self):
        inner = Document.objects.filter(pk=OuterRef('bound_user'))
        outer = Document.objects.annotate(
            bound_user=Value(7, output_field=IntegerField()),
        ).filter(Exists(inner), Exists(inner))
        sql, params = _sql(outer)
        self.assertIn('AS "bound_user"', sql)
        self.assertNotIn('CROSS JOIN', sql)
        self.assertEqual(params.count(7), 3)
        self.assertEqual(sql.count('%s'), len(params))

    def test_exists_drops_the_select_alias_and_still_inlines(self):
        inner = Document.objects.filter(pk=OuterRef('bound_user'))
        query = Document.objects.annotate(
            bound_user=Value(7, output_field=IntegerField()),
        ).filter(Exists(inner), Exists(inner)).query.exists()
        sql, params = query.sql_with_params()
        self.assertNotIn('bound_user', sql)
        self.assertEqual(params.count(7), 2)
        self.assertEqual(sql.count('%s'), len(params))

    def test_rawsql_names_the_alias_without_reusing_its_placeholder(self):
        sql, params = _sql(Document.objects.annotate(
            bound_user=Value(7, output_field=IntegerField()),
        ).filter(pk__in=RawSQL(
            '(SELECT id FROM myapp_document WHERE id = bound_user)',
            [],
        )))
        self.assertIn('AS "bound_user"', sql)
        self.assertIn('id = bound_user', sql)
        self.assertEqual(params.count(7), 1)
        self.assertEqual(sql.count('%s'), len(params))
