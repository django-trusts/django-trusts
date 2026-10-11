"""Deterministic policy-lock SQL line breaks (issue #291)."""

from django.test import SimpleTestCase

from trusts.core import TrustsConfigurationError
from trusts.policy_sql_format import (
    _tokenize_policy_sql,
    format_policy_sql,
)


def _texts(sql):
    return [text for text, _spaced in _tokenize_policy_sql(sql)]


class PolicySqlFormatTest(SimpleTestCase):
    def test_breaks_are_between_tokens_and_byte_stable(self):
        raw = (
            'SELECT DISTINCT "t"."id" FROM "t" '
            'LEFT OUTER JOIN "u" ON ("t"."id" = "u"."id") '
            'WHERE ("t"."id" = %s AND "u"."id" IS NOT NULL) '
            'UNION ALL '
            'SELECT "t"."id" FROM "t" WHERE NOT EXISTS('
            'SELECT %s AS "a" FROM "t" "U0" WHERE "U0"."id" = %s LIMIT 1)'
        )
        formatted = format_policy_sql(raw)
        self.assertEqual(formatted, (
            'SELECT DISTINCT "t"."id"\n'
            'FROM "t"\n'
            'LEFT OUTER JOIN "u" ON ("t"."id" = "u"."id")\n'
            'WHERE ("t"."id" = %s\n'
            '    AND "u"."id" IS NOT NULL\n'
            ')\n'
            'UNION ALL\n'
            'SELECT "t"."id"\n'
            'FROM "t"\n'
            'WHERE NOT EXISTS(\n'
            '  SELECT %s AS "a"\n'
            '  FROM "t" "U0"\n'
            '  WHERE "U0"."id" = %s\n'
            '  LIMIT 1\n'
            ')'
        ))
        self.assertEqual(_texts(raw), _texts(formatted))
        self.assertEqual(formatted, format_policy_sql(formatted))
        self.assertFalse(formatted.endswith('\n'))

    def test_with_recursive_and_cycle_stay_outside_quotes(self):
        raw = (
            'WITH RECURSIVE "gen"("ident", "depth") AS ('
            'SELECT "seed_rows"."ident", 0 FROM ('
            'SELECT DISTINCT "U0"."folder_id" AS "ident" '
            'FROM "documents_foldergrant" "U0" '
            'INNER JOIN "auth_permission" "U1" '
            'ON ("U0"."permission_id" = "U1"."id") '
            'WHERE ("U0"."permission_id" = %s '
            'AND "U0"."folder_id" IS NOT NULL)'
            ') AS "seed_rows" '
            'UNION ALL '
            'SELECT "child"."id", "g"."depth" + 1 '
            'FROM "gen" AS "g" '
            'JOIN "documents_folder" AS "child" '
            'ON "child"."parent_id" = "g"."ident" '
            'WHERE "g"."depth" < %s AND "child"."id" IS NOT NULL'
            ') CYCLE "ident" SET "is_cycle" USING "path" '
            'SELECT DISTINCT "s"."id" FROM "gen" '
            'JOIN "documents_folder" AS "s" '
            'ON "s"."id" = "gen"."ident"'
        )
        formatted = format_policy_sql(raw)
        self.assertIn(
            'CYCLE "ident" SET "is_cycle" USING "path"', formatted,
        )
        self.assertIn('\n  UNION ALL\n', formatted)
        self.assertIn('\n  SELECT "seed_rows"."ident", 0\n', formatted)
        self.assertEqual(_texts(raw), _texts(formatted))
        self.assertEqual(formatted, format_policy_sql(formatted))
        exists = 'SELECT 1 FROM "t" WHERE EXISTS(SELECT 1) OR "t"."id" = %s'
        formatted_exists = format_policy_sql(exists)
        self.assertIn('\nWHERE\nEXISTS(\n', formatted_exists)
        self.assertIn('\n  OR "t"."id" = %s', formatted_exists)
        self.assertEqual(_texts(exists), _texts(formatted_exists))

    def test_quoted_keywords_and_literals_are_not_split(self):
        raw = (
            'SELECT "FROM" FROM (SELECT \'AND OR FROM\' AS "FROM") AS "t" '
            'WHERE "FROM" = %s AND \'it\'\'s\' = %s'
        )
        formatted = format_policy_sql(raw)
        self.assertIn('SELECT "FROM"\nFROM (', formatted)
        self.assertIn("SELECT 'AND OR FROM' AS \"FROM\"", formatted)
        self.assertIn("'it''s'", formatted)
        self.assertEqual(_texts(raw), _texts(formatted))
        backtick = 'SELECT `FROM` FROM `t` WHERE `a``b` = %s'
        self.assertIn('`a``b`', format_policy_sql(backtick))
        self.assertEqual(_texts(backtick), _texts(format_policy_sql(backtick)))
        bracket = 'SELECT [FROM] FROM [t] WHERE [weird]]name] = %s'
        formatted_bracket = format_policy_sql(bracket)
        self.assertIn('[weird]]name]', formatted_bracket)
        self.assertIn('[FROM]', formatted_bracket.splitlines()[0])
        self.assertEqual(_texts(bracket), _texts(formatted_bracket))

    def test_comments_placeholders_numbers_and_other_joins(self):
        commented = (
            'SELECT 1 -- FROM JOIN\n'
            'FROM "t" /* AND OR */ WHERE 1 = 1'
        )
        formatted = format_policy_sql(commented)
        self.assertIn('SELECT 1 -- FROM JOIN\nFROM "t" /* AND OR */', formatted)
        self.assertEqual(_texts(commented), _texts(formatted))
        block = 'SELECT 1 /* FROM\nJOIN */ FROM "t"'
        formatted_block = format_policy_sql(block)
        self.assertIn('/* FROM\nJOIN */', formatted_block)
        self.assertEqual(_texts(block), _texts(formatted_block))
        clauses = (
            'SELECT "t"."id" FROM "t" GROUP BY "t"."id" '
            'HAVING "t"."id" = %s ORDER BY "t"."id" ASC LIMIT 1 OFFSET 0'
        )
        self.assertEqual(format_policy_sql(clauses), (
            'SELECT "t"."id"\n'
            'FROM "t"\n'
            'GROUP BY "t"."id"\n'
            'HAVING "t"."id" = %s\n'
            'ORDER BY "t"."id" ASC\n'
            'LIMIT 1\n'
            'OFFSET 0'
        ))
        joins = (
            'SELECT 1 FROM "t" CROSS JOIN "u" NATURAL JOIN "v" '
            'RIGHT JOIN "w" ON (1 = 1) '
            'FULL OUTER JOIN "x" ON (1 = 1) '
            'RIGHT OUTER JOIN "y" ON (1 = 1)'
        )
        formatted_joins = format_policy_sql(joins)
        self.assertIn('\nCROSS JOIN "u"\n', formatted_joins)
        self.assertIn('\nNATURAL JOIN "v"\n', formatted_joins)
        self.assertIn('\nRIGHT JOIN "w"', formatted_joins)
        self.assertIn('\nFULL OUTER JOIN "x"', formatted_joins)
        self.assertIn('\nRIGHT OUTER JOIN "y"', formatted_joins)
        numeric = (
            'SELECT 1.5e+2, 10.25, 2e10, 1 <= 2, 1e+ FROM "t" '
            'WHERE %% = %(user_id)s -- tail'
        )
        formatted_numeric = format_policy_sql(numeric)
        self.assertIn('1.5e+2', formatted_numeric)
        self.assertIn('%%', formatted_numeric)
        self.assertIn('%(user_id)s', formatted_numeric)
        self.assertEqual(_texts(numeric), _texts(formatted_numeric))
        self.assertEqual(format_policy_sql(''), '')
        self.assertEqual(format_policy_sql('   \n'), '')
        self.assertEqual(format_policy_sql('SELECT 1)'), 'SELECT 1)')

    def test_malformed_sql_fails_closed(self):
        with self.assertRaises(TrustsConfigurationError):
            format_policy_sql(None)
        for raw in (
            "SELECT 'open",
            'SELECT "open',
            'SELECT `open',
            'SELECT [open',
            'SELECT 1 /* open',
            'SELECT %(open',
            'SELECT %q',
            'SELECT @',
        ):
            with self.assertRaises(TrustsConfigurationError):
                format_policy_sql(raw)
