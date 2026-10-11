"""Fail-closed policy-lock SQL line breaks (issue #291)."""

from unittest.mock import patch

from django.test import SimpleTestCase

from trusts.core import TrustsConfigurationError
from trusts.policy_sql_format import (
    _format_policy_sql,
    _tokenize_policy_sql,
)


def _texts(sql):
    return [text for text, _spaced in _tokenize_policy_sql(sql)]


def _rejected(test, sql, token):
    with test.assertRaises(TrustsConfigurationError) as caught:
        _format_policy_sql(sql)
    message = str(caught.exception)
    test.assertIn(repr(token), message)
    test.assertIn(repr(sql), message)
    return message


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
        formatted = _format_policy_sql(raw)
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
        self.assertEqual(formatted, _format_policy_sql(formatted))
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
        formatted = _format_policy_sql(raw)
        self.assertIn(
            'CYCLE "ident" SET "is_cycle" USING "path"', formatted,
        )
        self.assertIn('\n  UNION ALL\n', formatted)
        self.assertIn('\n  SELECT "seed_rows"."ident", 0\n', formatted)
        self.assertEqual(_texts(raw), _texts(formatted))
        self.assertEqual(formatted, _format_policy_sql(formatted))
        exists = 'SELECT 1 FROM "t" WHERE EXISTS(SELECT 1) OR "t"."id" = %s'
        formatted_exists = _format_policy_sql(exists)
        self.assertIn('\nWHERE\nEXISTS(\n', formatted_exists)
        self.assertIn('\n  OR "t"."id" = %s', formatted_exists)
        self.assertEqual(_texts(exists), _texts(formatted_exists))

    def test_quoted_keywords_and_literals_are_not_split(self):
        raw = (
            'SELECT "FROM" FROM (SELECT \'AND OR FROM\' AS "FROM") AS "t" '
            'WHERE "FROM" = %s AND \'it\'\'s\' = %s'
        )
        formatted = _format_policy_sql(raw)
        self.assertIn('SELECT "FROM"\nFROM (', formatted)
        self.assertIn("SELECT 'AND OR FROM' AS \"FROM\"", formatted)
        self.assertIn("'it''s'", formatted)
        self.assertEqual(_texts(raw), _texts(formatted))
        backtick = 'SELECT `FROM` FROM `t` WHERE `a``b` = %s'
        self.assertIn('`a``b`', _format_policy_sql(backtick))
        self.assertEqual(_texts(backtick), _texts(_format_policy_sql(backtick)))

    def test_placeholders_numbers_comparisons_and_joins(self):
        clauses = (
            'SELECT "t"."id" FROM "t" GROUP BY "t"."id" '
            'HAVING "t"."id" = %s ORDER BY "t"."id" ASC LIMIT 1 OFFSET 0'
        )
        self.assertEqual(_format_policy_sql(clauses), (
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
        formatted_joins = _format_policy_sql(joins)
        self.assertIn('\nCROSS JOIN "u"\n', formatted_joins)
        self.assertIn('\nNATURAL JOIN "v"\n', formatted_joins)
        self.assertIn('\nRIGHT JOIN "w"', formatted_joins)
        self.assertIn('\nFULL OUTER JOIN "x"', formatted_joins)
        self.assertIn('\nRIGHT OUTER JOIN "y"', formatted_joins)
        numeric = (
            'SELECT 1.5e+2, 10.25, 2e10 FROM "t" '
            'WHERE "a" > %s AND "a" >= ? AND "a" < %s AND "a" <= %s'
        )
        formatted_numeric = _format_policy_sql(numeric)
        self.assertIn('1.5e+2', formatted_numeric)
        self.assertIn('?', formatted_numeric)
        self.assertEqual(_texts(numeric), _texts(formatted_numeric))
        self.assertEqual(_format_policy_sql(''), '')
        self.assertEqual(_format_policy_sql('   \n'), '')
        self.assertEqual(_format_policy_sql('SELECT 1)'), 'SELECT 1)')
        ordered = 'SELECT "t"."id" FROM "t" ORDER BY "t"."id" DESC'
        self.assertIn('\nORDER BY "t"."id" DESC', _format_policy_sql(ordered))

    def test_line_comment_is_rejected(self):
        raw = 'SELECT 1 -- keep newline\n+ 2'
        message = _rejected(self, raw, '-- keep newline')
        self.assertIn('line comment', message)
        self.assertNotIn('+ 2', message.split(' in query ', 1)[0])

    def test_block_comment_is_rejected(self):
        raw = 'SELECT 1 /* AND OR */ FROM "t"'
        message = _rejected(self, raw, '/* AND OR */')
        self.assertIn('block comment', message)
        with self.assertRaises(TrustsConfigurationError):
            _format_policy_sql('SELECT 1 /* open')

    def test_hash_comment_is_rejected(self):
        raw = 'SELECT 1 # note'
        message = _rejected(self, raw, '# note')
        self.assertIn('hash comment', message)

    def test_dollar_quoted_string_is_rejected(self):
        raw = 'SELECT $$AND$$'
        message = _rejected(self, raw, '$$AND$$')
        self.assertIn('dollar-quoted string', message)
        tagged = 'SELECT $tag$AND$tag$'
        message = _rejected(self, tagged, '$tag$AND$tag$')
        self.assertIn('dollar-quoted string', message)
        unclosed = 'SELECT $$AND'
        message = _rejected(self, unclosed, '$$AND')
        self.assertIn('dollar-quoted string', message)
        open_tag = 'SELECT $tag$AND'
        message = _rejected(self, open_tag, '$tag$AND')
        self.assertIn('dollar-quoted string', message)

    def test_e_string_is_rejected(self):
        raw = "SELECT E'AND'"
        message = _rejected(self, raw, "E'AND'")
        self.assertIn('E-string', message)
        unclosed = "SELECT E'open"
        message = _rejected(self, unclosed, unclosed)
        self.assertIn('E-string', message)

    def test_backslash_escape_is_rejected(self):
        raw = "SELECT 'a\\b'"
        message = _rejected(self, raw, '\\b')
        self.assertIn('backslash escape', message)
        bare = 'SELECT \\x'
        message = _rejected(self, bare, '\\x')
        self.assertIn('backslash escape', message)

    def test_unknown_operator_is_rejected(self):
        raw = "SELECT 'a' ~ 'b'"
        message = _rejected(self, raw, '~')
        self.assertIn('operator', message)
        regex = "SELECT \"title\" ~* 'A'"
        starred = _rejected(self, regex, '~*')
        self.assertIn('operator', starred)
        glued = 'SELECT 1 +~ 2'
        message = _rejected(self, glued, '+~')
        self.assertIn('operator', message)
        with self.assertRaises(TrustsConfigurationError):
            _format_policy_sql('SELECT 1 +-- comment')

    def test_other_unrecognized_tokens_are_rejected(self):
        for raw, token in (
            ('SELECT [FROM]', '[FROM]'),
            ('SELECT [open', '[open'),
            ('SELECT @', '@'),
            ('SELECT %q', '%q'),
            ('SELECT %(name)s', '%(name)s'),
            ('SELECT $1', '$1'),
            ('SELECT definitely_not_a_keyword', 'definitely_not_a_keyword'),
            ('SELECT %(open', '%(open'),
            ('SELECT ?~', '?~'),
            ('SELECT 1e+', '1e+'),
        ):
            _rejected(self, raw, token)

    def test_round_trip_failure_names_the_query(self):
        raw = 'SELECT 1'
        with patch(
            'trusts.policy_sql_format._emit', return_value='SELECT 1 FROM',
        ):
            message = _rejected(self, raw, raw)
        self.assertIn('token stream', message)
        with patch(
            'trusts.policy_sql_format._emit', return_value='SELECT 1 -- gone',
        ):
            message = _rejected(self, raw, raw)
        self.assertIn('token stream', message)

    def test_malformed_sql_fails_closed(self):
        with self.assertRaises(TrustsConfigurationError):
            _format_policy_sql(None)
        for raw in (
            "SELECT 'open",
            'SELECT "open',
            'SELECT `open',
        ):
            with self.assertRaises(TrustsConfigurationError) as caught:
                _format_policy_sql(raw)
            self.assertIn(repr(raw), str(caught.exception))
