"""Deterministic line breaks for policy-lock SQL.

Core tokenizes the compiled statement and inserts breaks only between
tokens. Quoted identifiers, string literals, and comments stay intact.
The same tokens always produce the same bytes. No formatter library is
involved. Schema version 1 is unchanged: ``trusts.E009`` compares this
text, and the token sequence is the statement Django compiled.
"""

from __future__ import annotations

from trusts.core import TrustsConfigurationError

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
_TWO_CHAR = frozenset(('<=', '>=', '<>', '!=', '||', '::'))
_ONE_CHAR = frozenset('=<>+-*/(),.;?')


def format_policy_sql(sql):
    """Return ``sql`` with predictable breaks between tokens.

    Whitespace between tokens is a single space, or a newline and indent
    at a break. Spacing that Django omitted, such as ``EXISTS(``, stays
    omitted. The result has no trailing newline.
    """
    if not isinstance(sql, str):
        raise TrustsConfigurationError(
            'Policy SQL formatter expected text, not %s.'
            % type(sql).__name__
        )
    tokens = _tokenize_policy_sql(sql)
    if not tokens:
        return ''
    return _emit(tokens)


def _tokenize_policy_sql(sql):
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
        token, index = _one_token(sql, index)
        tokens.append((token, spaced))
    return tokens


def _one_token(sql, index):
    char = sql[index]
    if char == '"':
        return _quoted(sql, index, '"')
    if char == "'":
        return _quoted(sql, index, "'")
    if char == '`':
        return _quoted(sql, index, '`')
    if char == '[':
        return _bracket(sql, index)
    if char == '-' and sql.startswith('--', index):
        end = sql.find('\n', index)
        if end == -1:
            end = len(sql)
        return sql[index:end], end
    if char == '/' and sql.startswith('/*', index):
        end = sql.find('*/', index + 2)
        if end == -1:
            raise TrustsConfigurationError(
                'Policy SQL formatter found an unclosed comment.'
            )
        return sql[index:end + 2], end + 2
    if char == '%':
        return _placeholder(sql, index)
    if sql.startswith(tuple(_TWO_CHAR), index):
        return sql[index:index + 2], index + 2
    if char in _ONE_CHAR:
        return char, index + 1
    if char.isalpha() or char == '_':
        end = index + 1
        while end < len(sql) and (sql[end].isalnum() or sql[end] == '_'):
            end += 1
        return sql[index:end], end
    if char.isdigit():
        return _number(sql, index)
    raise TrustsConfigurationError(
        'Policy SQL formatter found an unsupported character %r.' % (char,)
    )


def _quoted(sql, index, quote):
    end = index + 1
    length = len(sql)
    while end < length:
        if sql[end] == quote:
            if end + 1 < length and sql[end + 1] == quote:
                end += 2
                continue
            return sql[index:end + 1], end + 1
        end += 1
    raise TrustsConfigurationError(
        'Policy SQL formatter found an unclosed quote.'
    )


def _bracket(sql, index):
    end = index + 1
    length = len(sql)
    while end < length:
        if sql[end] == ']':
            if end + 1 < length and sql[end + 1] == ']':
                end += 2
                continue
            return sql[index:end + 1], end + 1
        end += 1
    raise TrustsConfigurationError(
        'Policy SQL formatter found an unclosed quote.'
    )


def _placeholder(sql, index):
    if sql.startswith('%%', index):
        return '%%', index + 2
    if sql.startswith('%s', index):
        return '%s', index + 2
    if sql.startswith('%(', index):
        end = sql.find(')s', index + 2)
        if end == -1:
            raise TrustsConfigurationError(
                'Policy SQL formatter found an unclosed placeholder.'
            )
        return sql[index:end + 2], end + 2
    raise TrustsConfigurationError(
        'Policy SQL formatter found an unsupported placeholder.'
    )


def _number(sql, index):
    end = index
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
        if exponent < length and sql[exponent].isdigit():
            end = exponent + 1
            while end < length and sql[end].isdigit():
                end += 1
    return sql[index:end], end


def _bare_upper(text):
    """Uppercase an unquoted word. Operators and quotes are not words."""
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
        lines.append(''.join(parts).rstrip())
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
                        lines.append(''.join(parts).rstrip())
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
        lines.append(''.join(parts).rstrip())
    return '\n'.join(lines)
