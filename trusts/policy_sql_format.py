"""Internal line breaks for policy-lock SQL.

The formatter accepts only tokens that Django's SQLite, PostgreSQL, and
MySQL compilers and ``along=`` SQL emit for policy queries, plus the
PostgreSQL literal forms and the MySQL ``#`` comment that must stay
byte-identical. Anything else raises. Breaks are inserted only between
accepted tokens. The formatted text must tokenize back to that same
stream. No formatter library is involved. Schema version 1 is unchanged.
"""

from __future__ import annotations

from trusts.core import TrustsConfigurationError

# Unquoted words the compilers and ``along=`` SQL emit. Any other bare
# word is rejected. Quoted identifiers are a separate token class.
_KEYWORDS = frozenset((
    'ALL', 'AND', 'AS', 'ASC', 'BY', 'CROSS', 'CYCLE', 'DESC', 'DISTINCT',
    'EXISTS', 'FROM', 'FULL', 'GROUP', 'HAVING', 'IN', 'INNER', 'IS', 'JOIN',
    'LEFT', 'LIMIT', 'NATURAL', 'NOT', 'NULL', 'OFFSET', 'ON', 'OR', 'ORDER',
    'OUTER', 'RECURSIVE', 'RIGHT', 'SELECT', 'SET', 'UNION', 'USING', 'WHERE',
    'WITH',
))
# Clause and boolean keywords that start a new line. ``AND`` and ``OR``
# are the boolean connectives of the group that contains them. ``JOIN``
# and its leading modifier (``LEFT OUTER``, ``INNER``, ...) share one line.
_CLAUSE_WORDS = frozenset((
    'FROM', 'WHERE', 'UNION', 'EXISTS', 'ORDER', 'GROUP', 'HAVING',
    'LIMIT', 'OFFSET', 'CYCLE', 'SELECT', 'WITH',
    'INNER', 'CROSS', 'NATURAL',
))
_JOIN_MODIFIERS = frozenset((
    'INNER', 'CROSS', 'NATURAL', 'LEFT', 'RIGHT', 'FULL', 'OUTER',
))
# Longest match first. These are the symbol operators in the three
# compilers' comparison lookups and in the ``along=`` depth expression.
_OPERATORS = ('<=', '>=', '=', '<', '>', '+')
_STRUCTURAL = frozenset('(),.')


def _format_policy_sql(sql, *, vendor=None):
    """Return ``sql`` with predictable breaks between accepted tokens.

    ``vendor`` is Django's connection vendor (``postgresql``, ``mysql``,
    or ``sqlite``). Whitespace between tokens is a single space, or a
    newline and indent at a break, except where the backend's literal or
    comment rules require the original bytes. Spacing that Django omitted,
    such as ``EXISTS(``, stays omitted. PostgreSQL dollar quotes, ``E''``
    strings, and newline-continued string literals stay one byte-identical
    token. A MySQL ``#`` comment keeps the newline that ends it.
    PostgreSQL ``#``, ``#>``, and ``#>>`` stay operators. Anything else
    unrecognized raises ``TrustsConfigurationError`` and names the query
    and the token. The formatted token stream must match the original
    stream, with those literals and comments byte-identical, or formatting
    raises instead of emitting changed SQL.
    """
    if not isinstance(sql, str):
        raise TrustsConfigurationError(
            'Policy SQL formatter expected text, not %s.'
            % type(sql).__name__
        )
    tokens = _tokenize_policy_sql(sql, vendor)
    if not tokens:
        return ''
    formatted = _emit(tokens)
    try:
        again = _tokenize_policy_sql(formatted, vendor)
    except TrustsConfigurationError:
        _reject_round_trip(sql)
    if [text for text, _spaced in tokens] != [text for text, _spaced in again]:
        _reject_round_trip(sql)
    return formatted


def _reject(sql, token, kind):
    raise TrustsConfigurationError(
        'Policy SQL formatter rejected %s %r in query %r.'
        % (kind, token, sql)
    )


def _reject_round_trip(sql):
    raise TrustsConfigurationError(
        'Policy SQL formatter could not preserve the token stream of query %r.'
        % (sql,)
    )


def _tokenize_policy_sql(sql, vendor=None):
    """Return ``(text, spaced)`` pairs. ``spaced`` is whitespace before."""
    tokens = []
    length = len(sql)
    index = 0
    while index < length:
        start = index
        while index < length and sql[index] in ' \t\r\n':
            index += 1
        if index >= length:
            break
        spaced = bool(tokens) and index > start
        token, index = _one_token(sql, index, vendor)
        if vendor == 'postgresql' and _is_pg_literal(token):
            token, index = _continue_pg_literals(sql, index, token)
        tokens.append((token, spaced))
    return tokens


def _one_token(sql, index, vendor):
    char = sql[index]
    if char == '-' and sql.startswith('--', index):
        _reject(sql, _until_newline(sql, index), 'line comment')
    if char == '/' and sql.startswith('/*', index):
        end = sql.find('*/', index + 2)
        if end == -1:
            _reject(sql, sql[index:], 'block comment')
        _reject(sql, sql[index:end + 2], 'block comment')
    if char == '#':
        if vendor == 'mysql':
            return _mysql_hash_comment(sql, index)
        if vendor == 'postgresql':
            return _postgres_hash_operator(sql, index)
        _reject(sql, _until_newline(sql, index), 'hash comment')
    if char == '\\':
        nxt = sql[index + 1] if index + 1 < len(sql) else ''
        _reject(sql, '\\' + nxt, 'backslash escape')
    if char == '$':
        if vendor == 'postgresql':
            return _dollar_literal(sql, index)
        _reject_dollar(sql, index)
    if char in 'eE' and index + 1 < len(sql) and sql[index + 1] == "'":
        if vendor == 'postgresql':
            return _e_string(sql, index)
        _reject_e_string(sql, index)
    if char == '"':
        return _quoted(sql, index, '"', 'identifier')
    if char == '`':
        return _quoted(sql, index, '`', 'identifier')
    if char == "'":
        return _quoted(sql, index, "'", 'string')
    if char == '[':
        end = sql.find(']', index + 1)
        if end == -1:
            _reject(sql, sql[index:], 'token')
        _reject(sql, sql[index:end + 1], 'token')
    if char == '%':
        if sql.startswith('%s', index):
            return '%s', index + 2
        _reject(sql, _unrecognized_percent(sql, index), 'placeholder')
    if char == '?':
        if index + 1 < len(sql) and _is_operator_char(sql[index + 1]):
            _reject(sql, _operator_run(sql, index), 'operator')
        return '?', index + 1
    if char.isalpha() or char == '_':
        end = index + 1
        while end < len(sql) and (sql[end].isalnum() or sql[end] == '_'):
            end += 1
        word = sql[index:end]
        if word.upper() not in _KEYWORDS:
            _reject(sql, word, 'keyword')
        return word, end
    if char.isdigit():
        return _number(sql, index)
    if char in _STRUCTURAL:
        return char, index + 1
    return _operator(sql, index)


def _is_pg_literal(token):
    if token.startswith(("'", '$')):
        return True
    return len(token) >= 2 and token[0] in 'eE' and token[1] == "'"


def _continue_pg_literals(sql, index, token):
    """Keep newline-separated PostgreSQL literals in one byte-identical token."""
    length = len(sql)
    while True:
        end = index
        while end < length and sql[end] in ' \t\r\n':
            end += 1
        gap = sql[index:end]
        if '\n' not in gap or end >= length:
            return token, index
        if not _pg_literal_starts(sql, end):
            return token, index
        nxt, index = _one_token(sql, end, 'postgresql')
        token += gap + nxt


def _pg_literal_starts(sql, index):
    char = sql[index]
    if char == "'":
        return True
    if char in 'eE' and index + 1 < len(sql) and sql[index + 1] == "'":
        return True
    if char != '$':
        return False
    if sql.startswith('$$', index):
        return True
    tag_end = index + 1
    while tag_end < len(sql) and (sql[tag_end].isalnum() or sql[tag_end] == '_'):
        tag_end += 1
    return (
        tag_end > index + 1
        and tag_end < len(sql)
        and sql[tag_end] == '$'
    )


def _mysql_hash_comment(sql, index):
    """A MySQL ``#`` comment includes the newline that terminates it."""
    end = sql.find('\n', index)
    if end == -1:
        return sql[index:], len(sql)
    return sql[index:end + 1], end + 1


def _postgres_hash_operator(sql, index):
    """PostgreSQL ``#``, ``#>``, and ``#>>``. A longer run is rejected."""
    if sql.startswith('#>>', index):
        operator = '#>>'
    elif sql.startswith('#>', index):
        operator = '#>'
    else:
        operator = '#'
    end = index + len(operator)
    if end < len(sql) and _is_operator_char(sql[end]):
        _reject(sql, _operator_run(sql, index), 'operator')
    return operator, end


def _dollar_literal(sql, index):
    """One PostgreSQL dollar quote, bytes unchanged, including its body."""
    if sql.startswith('$$', index):
        end = sql.find('$$', index + 2)
        if end == -1:
            _reject(sql, sql[index:], 'dollar-quoted string')
        return sql[index:end + 2], end + 2
    tag_end = index + 1
    while tag_end < len(sql) and (sql[tag_end].isalnum() or sql[tag_end] == '_'):
        tag_end += 1
    if (
        tag_end > index + 1
        and tag_end < len(sql)
        and sql[tag_end] == '$'
    ):
        closer = sql[index:tag_end + 1]
        end = sql.find(closer, tag_end + 1)
        if end == -1:
            _reject(sql, sql[index:], 'dollar-quoted string')
        return sql[index:end + len(closer)], end + len(closer)
    end = index + 1
    while end < len(sql) and (sql[end].isalnum() or sql[end] in '_$'):
        end += 1
    _reject(sql, sql[index:end], 'token')


def _e_string(sql, index):
    """One PostgreSQL ``E''`` string. Backslash escapes do not end it."""
    end = index + 2
    length = len(sql)
    while end < length:
        if sql[end] == '\\':
            if end + 1 >= length:
                _reject(sql, sql[index:], 'E-string')
            end += 2
            continue
        if sql[end] == "'":
            if end + 1 < length and sql[end + 1] == "'":
                end += 2
                continue
            return sql[index:end + 1], end + 1
        end += 1
    _reject(sql, sql[index:], 'E-string')


def _until_newline(sql, index):
    end = sql.find('\n', index)
    if end == -1:
        return sql[index:]
    return sql[index:end]


def _reject_dollar(sql, index):
    if sql.startswith('$$', index):
        end = sql.find('$$', index + 2)
        if end == -1:
            _reject(sql, sql[index:], 'dollar-quoted string')
        _reject(sql, sql[index:end + 2], 'dollar-quoted string')
    tag_end = index + 1
    while tag_end < len(sql) and (sql[tag_end].isalnum() or sql[tag_end] == '_'):
        tag_end += 1
    if (
        tag_end > index + 1
        and tag_end < len(sql)
        and sql[tag_end] == '$'
    ):
        closer = sql[index:tag_end + 1]
        end = sql.find(closer, tag_end + 1)
        if end == -1:
            _reject(sql, sql[index:], 'dollar-quoted string')
        _reject(sql, sql[index:end + len(closer)], 'dollar-quoted string')
    end = index + 1
    while end < len(sql) and (sql[end].isalnum() or sql[end] in '_$'):
        end += 1
    _reject(sql, sql[index:end], 'token')


def _reject_e_string(sql, index):
    try:
        _text, end = _quoted(sql, index + 1, "'", 'string')
    except TrustsConfigurationError:
        _reject(sql, sql[index:], 'E-string')
    _reject(sql, sql[index:end], 'E-string')


def _unrecognized_percent(sql, index):
    if sql.startswith('%(', index):
        end = sql.find(')s', index + 2)
        if end != -1:
            return sql[index:end + 2]
        end = index + 2
        while end < len(sql) and sql[end] not in ' \t\r\n':
            end += 1
        return sql[index:end]
    end = index + 1
    while end < len(sql) and (sql[end].isalnum() or sql[end] in '%_'):
        end += 1
    return sql[index:end]


def _quoted(sql, index, quote, kind):
    end = index + 1
    length = len(sql)
    while end < length:
        if sql[end] == '\\':
            nxt = sql[end + 1] if end + 1 < length else ''
            _reject(sql, '\\' + nxt, 'backslash escape')
        if sql[end] == quote:
            if end + 1 < length and sql[end + 1] == quote:
                end += 2
                continue
            return sql[index:end + 1], end + 1
        end += 1
    _reject(sql, sql[index:], 'unclosed %s' % kind)


def _is_operator_char(char):
    if char.isalnum() or char == '_' or char.isspace():
        return False
    return char not in '\'"`$%?(),.'


def _operator_run(sql, index):
    end = index + 1
    length = len(sql)
    while end < length and _is_operator_char(sql[end]):
        if sql.startswith(('--', '/*'), end):
            break
        end += 1
    return sql[index:end]


def _operator(sql, index):
    for operator in _OPERATORS:
        if not sql.startswith(operator, index):
            continue
        end = index + len(operator)
        if end < len(sql) and _is_operator_char(sql[end]):
            _reject(sql, _operator_run(sql, index), 'operator')
        return operator, end
    _reject(sql, _operator_run(sql, index), 'operator')


def _number(sql, index):
    end = index + 1
    length = len(sql)
    while end < length and sql[end].isdigit():
        end += 1
    if (
        end < length and sql[end] == '.'
        and end + 1 < length and sql[end + 1].isdigit()
    ):
        end += 2
        while end < length and sql[end].isdigit():
            end += 1
    if end < length and sql[end] in 'eE':
        exponent = end + 1
        if exponent < length and sql[exponent] in '+-':
            exponent += 1
        if exponent >= length or not sql[exponent].isdigit():
            _reject(sql, sql[index:exponent], 'number')
        end = exponent + 1
        while end < length and sql[end].isdigit():
            end += 1
    return sql[index:end], end


def _bare_upper(text):
    """Uppercase an unquoted keyword. Operators and quotes are not words."""
    if not text or not (text[0].isalpha() or text[0] == '_'):
        return None
    return text.upper()


def _wants_break(bare, prev_bare, next_bare, line_open):
    """Return ``(break, extra_indent)`` for one bare word."""
    if not line_open or bare is None:
        return False, 0
    if bare == 'JOIN' and prev_bare in _JOIN_MODIFIERS:
        return False, 0
    if bare == 'OUTER' and prev_bare in ('LEFT', 'RIGHT', 'FULL'):
        return False, 0
    if bare == 'ALL' and prev_bare == 'UNION':
        return False, 0
    if bare == 'BY' and prev_bare in ('ORDER', 'GROUP'):
        return False, 0
    if bare == 'EXISTS' and prev_bare == 'NOT':
        return False, 0
    if bare in ('AND', 'OR'):
        return True, 2
    if bare in ('LEFT', 'RIGHT', 'FULL') and next_bare in ('OUTER', 'JOIN'):
        return True, 0
    if bare == 'JOIN' or bare in _CLAUSE_WORDS:
        return True, 0
    return False, 0


def _emit(tokens):
    lines = []
    parts = []
    depth = 0
    stack = [False]
    prev_bare = None

    def line_open():
        return any(not char.isspace() for char in ''.join(parts))

    def newline(extra):
        nonlocal parts
        text = ''.join(parts).rstrip(' \t')
        # A MySQL ``#`` comment already ends with its terminating newline.
        # One line break is enough; a second would be an empty line.
        if text.endswith('\n'):
            text = text[:-1]
        lines.append(text)
        stack[depth] = True
        parts = [' ' * (depth * 2 + extra)]

    def emit(text, spaced):
        if spaced and line_open():
            parts.append(' ')
        parts.append(text)

    for index, (text, spaced) in enumerate(tokens):
        if text == '(':
            emit('(', spaced)
            depth += 1
            stack.append(False)
            prev_bare = None
            continue
        if text == ')':
            if depth == 0:
                emit(')', spaced)
            else:
                inner = stack.pop()
                depth -= 1
                if inner:
                    if line_open():
                        lines.append(''.join(parts).rstrip(' \t'))
                        stack[depth] = True
                    parts = [' ' * (depth * 2)]
                    emit(')', False)
                else:
                    emit(')', spaced)
            prev_bare = None
            continue
        bare = _bare_upper(text)
        next_bare = None
        if index + 1 < len(tokens):
            next_bare = _bare_upper(tokens[index + 1][0])
        should, extra = _wants_break(bare, prev_bare, next_bare, line_open())
        if should:
            newline(extra)
            spaced = False
        emit(text, spaced)
        prev_bare = bare
    if line_open():
        lines.append(''.join(parts).rstrip(' \t'))
    return '\n'.join(lines)
