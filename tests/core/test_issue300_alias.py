"""``QuerySet.alias(Value)`` does not bind an inquiry value once (#300).

Django 6.1.2 resolves ``OuterRef`` to the outer annotation and compiles
that expression again. A ``Value`` therefore becomes a new placeholder
at every reference. ``alias()`` also has to run before ``filter(Exists)``,
cannot sit on the outermost comparison, and cannot reuse a concrete
field name. Policy SQL is unchanged: these calls cannot compile an
inquiry, so this module does not touch ``trusts``.
"""

from django.db.models import CharField, Exists, IntegerField, OuterRef, Value
from django.test import SimpleTestCase

from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE


def _sql(qs):
    return qs.query.sql_with_params()


class AliasValueSuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue300_alias', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue300_alias', PAIR_KERNEL_SUITE)


class AliasValueOuterRefTest(SimpleTestCase):
    def test_alias_inlines_each_reference(self):
        inner = Document.objects.filter(
            pk=OuterRef('bound_user'),
            title=OuterRef('bound_app'),
        )
        outer = Document.objects.alias(
            bound_user=Value(7, output_field=IntegerField()),
            bound_app=Value('myapp', output_field=CharField()),
        ).filter(
            Exists(inner) | Exists(inner) | Exists(
                Document.objects.filter(pk=OuterRef('bound_user')),
            ),
        )
        sql, params = _sql(outer)
        self.assertNotIn('bound_user', sql)
        self.assertNotIn('CROSS JOIN', sql)
        self.assertEqual(params.count(7), 3)
        self.assertEqual(params.count('myapp'), 2)
        self.assertEqual(sql.count('%s'), len(params))

    def test_alias_after_exists_cannot_see_the_name(self):
        inner = Document.objects.filter(pk=OuterRef('bound_user'))
        with self.assertRaises(Exception) as caught:
            Document.objects.filter(Exists(inner)).alias(
                bound_user=Value(7, output_field=IntegerField()),
            )
        self.assertIn('bound_user', str(caught.exception))

    def test_outer_query_cannot_compile_its_own_outerref(self):
        qs = Document.objects.alias(
            bound_user=Value(7, output_field=IntegerField()),
        ).filter(pk=OuterRef('bound_user'))
        with self.assertRaises(ValueError) as caught:
            qs.query.sql_with_params()
        self.assertIn('subquery', str(caught.exception))

    def test_alias_name_cannot_match_a_concrete_field(self):
        with self.assertRaises(ValueError) as caught:
            Document.objects.alias(
                id=Value(7, output_field=IntegerField()),
            )
        self.assertIn('conflicts with a field', str(caught.exception))
