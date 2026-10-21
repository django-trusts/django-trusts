"""Fail-closed policy-lock SQL line breaks (issue #291)."""


from django.test import SimpleTestCase

from trusts.errors import TrustsConfigurationError
from trusts.inspect.format import (
    _emit,
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
            'WHERE NOT EXISTS (\n'
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
        self.assertIn('\nWHERE\nEXISTS (\n', formatted_exists)
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

    def test_parenthesized_exists_opens_and_closes_on_one_line(self):
        raw = (
            'SELECT 1 WHERE ("t"."id" = %s AND (EXISTS('
            'SELECT %s AS "a" FROM "t" WHERE "t"."id" = %s LIMIT 1)))'
        )
        formatted = _format_policy_sql(raw)
        self.assertIn('\n    AND ( EXISTS (\n', formatted)
        self.assertIn('\n    ) ) )', formatted)
        self.assertNotIn('AND (\n', formatted)
        self.assertEqual(_texts(raw), _texts(formatted))
        self.assertEqual(formatted, _format_policy_sql(formatted))
        disjunction = (
            'SELECT 1 WHERE ("t"."id" = %s OR (EXISTS('
            'SELECT %s AS "a" FROM "t" LIMIT 1)))'
        )
        formatted_or = _format_policy_sql(disjunction)
        self.assertIn('\n    OR ( EXISTS (\n', formatted_or)
        self.assertIn('\n    ) ) )', formatted_or)
        self.assertEqual(_texts(disjunction), _texts(formatted_or))
        siblings = (
            'SELECT 1 WHERE ("t"."id" = %s AND (EXISTS('
            'SELECT %s AS "a" FROM "t" LIMIT 1) OR EXISTS('
            'SELECT %s AS "a" FROM "u" LIMIT 1)))'
        )
        formatted_siblings = _format_policy_sql(siblings)
        self.assertIn('\n    AND ( EXISTS (\n', formatted_siblings)
        self.assertIn('\n    )\n    OR EXISTS (\n', formatted_siblings)
        self.assertIn('\n    ) ) )', formatted_siblings)
        self.assertNotIn('EXISTS(', formatted_siblings)
        self.assertEqual(_texts(siblings), _texts(formatted_siblings))
        self.assertEqual(
            formatted_siblings, _format_policy_sql(formatted_siblings),
        )
        # A comparison stays on the connective's line, two spaces in.
        compared = 'SELECT 1 WHERE "t"."id" = %s AND "t"."id" = %s OR "u"."id" = %s'
        self.assertIn(
            '\n  AND "t"."id" = %s\n  OR "u"."id" = %s',
            _format_policy_sql(compared),
        )
        bare = (
            'SELECT 1 WHERE (EXISTS(SELECT %s AS "a" FROM "t" LIMIT 1) '
            'OR EXISTS(SELECT %s AS "a" FROM "u" LIMIT 1))'
        )
        formatted_bare = _format_policy_sql(bare)
        self.assertIn('\n  EXISTS (\n', formatted_bare)
        self.assertIn('\n  )\n  OR EXISTS (\n', formatted_bare)
        self.assertIn('\n  ) )', formatted_bare)
        self.assertNotIn('EXISTS(', formatted_bare)
        self.assertEqual(_texts(bare), _texts(formatted_bare))
        wrapped = (
            'SELECT 1 WHERE (EXISTS(SELECT %s AS "a" FROM "t" LIMIT 1) '
            'OR (EXISTS(SELECT %s AS "a" FROM "u" LIMIT 1)))'
        )
        formatted_wrapped = _format_policy_sql(wrapped)
        self.assertIn('\n  OR ( EXISTS (\n', formatted_wrapped)
        self.assertNotIn('\n    OR ( EXISTS (', formatted_wrapped)
        self.assertEqual(_texts(wrapped), _texts(formatted_wrapped))
        negated = (
            'SELECT 1 WHERE ("t"."id" = %s AND NOT EXISTS('
            'SELECT %s AS "a" FROM "t" LIMIT 1))'
        )
        formatted_negated = _format_policy_sql(negated)
        self.assertIn('\n  AND NOT EXISTS (\n', formatted_negated)
        self.assertIn('\n    SELECT %s AS "a"\n', formatted_negated)
        self.assertEqual(_texts(negated), _texts(formatted_negated))
        leading_not = (
            'SELECT 1 WHERE (NOT EXISTS(SELECT %s AS "a" FROM "t" LIMIT 1) '
            'OR EXISTS(SELECT %s AS "a" FROM "u" LIMIT 1))'
        )
        formatted_leading = _format_policy_sql(leading_not)
        self.assertIn('\n  NOT EXISTS (\n', formatted_leading)
        self.assertIn('\n  OR EXISTS (\n', formatted_leading)
        self.assertNotIn('EXISTS(', formatted_leading)
        self.assertEqual(_texts(leading_not), _texts(formatted_leading))

    def test_adjacent_string_literals_are_rejected(self):
        raw = "SELECT 'a'\n'b'"
        collapsed = "SELECT 'a' 'b'"
        # A space and a newline produce the same token texts, and emitting
        # the newline form collapses it to that space. Token equality
        # would accept the change.
        self.assertEqual(_texts(raw), _texts(collapsed))
        emitted = _emit(_tokenize_policy_sql(raw))
        self.assertEqual(emitted, collapsed)
        self.assertEqual(_texts(raw), _texts(emitted))
        message = _rejected(self, raw, "'a' 'b'")
        self.assertIn('adjacent string literals', message)
        self.assertIn(repr(raw), message)
        spaced = _rejected(self, collapsed, "'a' 'b'")
        self.assertIn('adjacent string literals', spaced)
        continued = "SELECT 'a'\n'b'\n'c'"
        self.assertEqual(_texts(continued), ["SELECT", "'a'", "'b'", "'c'"])
        _rejected(self, continued, "'a' 'b'")

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
