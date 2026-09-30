"""Compose lockfile SQL from exact fragments of the compiled statements.

Internal to the schema-1 renderer. Not a public API and not a reverse
mapping. ``trusts.E009`` does not parse the document; it compares
rendered bytes. This module checks, before those bytes are returned,
that every structured operation expands to the SQL the compiler
produced.

A fragment is closed SQL. An operation template may name a fragment
with ``{{fragment-id}}`` only when that fragment's text, aliases
included, occurs once in the compiled statement and that fragment's
parameters occupy the same contiguous span. Anything else is stored as
the full compiled statement. There is no placeholder whose expansion
is guessed.

The aggregate statement is captured by a compiler installed on this
thread's connection for that one call. Django's ``SQLCompiler`` class
is not modified.
"""

from __future__ import annotations

import re
import threading

from trusts.core import TrustsConfigurationError, _compile_granted

_PLACEHOLDER_RE = re.compile(r'\{\{([^{}]+)\}\}')
_AGGREGATE_LOCK = threading.Lock()

_INSTANCE = 'has_perm_permission_instance'
_CODE = 'has_perm_permission_code'
_AND = 'authorized_and_named_filter'
_OR = 'or_group_authorized'
_QUERYSET = 'queryset_has_perm'
_QUERYSET_CODE = 'queryset_has_perm_permission_code'


def _build_backend_composition(handle, alias, records, trusts, named_filters):
    """Return the backend ``composition`` mapping, or None.

    ``None`` when the backend has no trusts. Named filters then stay
    standalone rows and are not composed with a grant. The mapping is
    verified before it is returned.
    """
    if not records:
        return None
    if len(records) != len(trusts):
        raise TrustsConfigurationError(
            'Composition received trusts that do not match the registry.'
        )
    filters = _named_filters(handle, alias, named_filters)
    fragments = {}
    order = []
    operations = []
    for group in _content_groups(records, trusts):
        _append_group(
            operations, fragments, order, group, filters, handle, alias,
        )
    composition = {
        'fragments': [fragments[item] for item in order],
        'operations': operations,
    }
    _verify_composition(composition)
    return composition


def _verify_composition(composition):
    """Raise unless every structured operation expands losslessly.

    Also rejects duplicate ids, a reference to an unknown fragment, a
    placeholder that is not the fragment's exact token, a fragment that
    is not closed SQL, and a reference cycle.
    """
    if not isinstance(composition, dict):
        raise TrustsConfigurationError(
            'Composition section must be a mapping.'
        )
    fragments = _index_fragments(composition.get('fragments'))
    _reject_fragment_cycles(fragments)
    seen_ops = set()
    for operation in composition.get('operations') or ():
        if not isinstance(operation, dict):
            raise TrustsConfigurationError(
                'Composition operation must be a mapping.'
            )
        operation_id = operation.get('id')
        if operation_id in seen_ops:
            raise TrustsConfigurationError(
                'Composition operation id %r collides.' % (operation_id,)
            )
        seen_ops.add(operation_id)
        representation = operation.get('representation')
        if representation == 'full_sql':
            _reject_placeholders(
                operation.get('sql') or '',
                'full SQL for %s' % operation_id,
            )
            continue
        if representation != 'structured':
            raise TrustsConfigurationError(
                'Composition operation %s has representation %r.'
                % (operation_id, representation)
            )
        expanded = operation.get('expanded') or {}
        sql, params = _expand_structured(operation, fragments)
        if sql != expanded.get('sql') or params != expanded.get('params'):
            raise TrustsConfigurationError(
                'Composition template for %s does not expand to the '
                'compiled statement.' % operation_id
            )


def _index_fragments(rows):
    if not isinstance(rows, list):
        raise TrustsConfigurationError(
            'Composition fragments must be a list.'
        )
    fragments = {}
    for row in rows:
        if not isinstance(row, dict):
            raise TrustsConfigurationError(
                'Composition fragment must be a mapping.'
            )
        fragment_id = row.get('id')
        if not isinstance(fragment_id, str) or fragment_id == '':
            raise TrustsConfigurationError(
                'Composition fragment is missing an id.'
            )
        if fragment_id in fragments:
            raise TrustsConfigurationError(
                'Composition fragment id %r collides.' % (fragment_id,)
            )
        fragments[fragment_id] = row
    return fragments


def _reject_fragment_cycles(fragments):
    graph = {}
    for fragment_id, row in fragments.items():
        refs = _placeholder_ids(row.get('sql') or '')
        if refs:
            graph[fragment_id] = refs
    visiting = set()
    visited = set()

    def walk(fragment_id):
        if fragment_id in visiting:
            raise TrustsConfigurationError(
                'Composition reference cycle at fragment %s.'
                % fragment_id
            )
        if fragment_id in visited:
            return
        refs = graph.get(fragment_id)
        if not refs:
            return
        visiting.add(fragment_id)
        for ref in refs:
            if ref not in fragments:
                raise TrustsConfigurationError(
                    'Composition fragment %s references missing '
                    'fragment %s.' % (fragment_id, ref)
                )
            walk(ref)
        visiting.remove(fragment_id)
        visited.add(fragment_id)

    for fragment_id in graph:
        walk(fragment_id)
    for fragment_id in graph:
        raise TrustsConfigurationError(
            'Composition fragment %s is not closed SQL.' % fragment_id
        )


def _expand_structured(operation, fragments):
    template = operation.get('sql')
    if not isinstance(template, str):
        raise TrustsConfigurationError(
            'Composition operation %s is missing SQL.' % operation.get('id')
        )
    refs = operation.get('refs')
    if not isinstance(refs, list) or not refs:
        raise TrustsConfigurationError(
            'Composition operation %s is missing references.'
            % operation.get('id')
        )
    remaining_params = list(operation.get('params') or ())
    remaining = template
    parts = []
    built = []
    seen = set()
    for ref in refs:
        if not isinstance(ref, dict):
            raise TrustsConfigurationError(
                'Composition reference on %s must be a mapping.'
                % operation.get('id')
            )
        fragment_id = ref.get('fragment')
        placeholder = ref.get('placeholder')
        expected = '{{%s}}' % fragment_id
        if placeholder != expected or fragment_id in seen:
            raise TrustsConfigurationError(
                'Composition placeholder %r is not an exact reference '
                'to %r.' % (placeholder, fragment_id)
            )
        seen.add(fragment_id)
        fragment = fragments.get(fragment_id)
        if fragment is None:
            raise TrustsConfigurationError(
                'Composition operation %s references missing fragment %s.'
                % (operation.get('id'), fragment_id)
            )
        if remaining.count(placeholder) != 1:
            raise TrustsConfigurationError(
                'Placeholder %s must occur once.' % placeholder
            )
        index = remaining.find(placeholder)
        before = remaining[:index]
        count = before.count('%s')
        if count > len(remaining_params):
            raise TrustsConfigurationError(
                'Composition operation %s parameters do not cover the '
                'template.' % operation.get('id')
            )
        built.extend(remaining_params[:count])
        remaining_params = remaining_params[count:]
        parts.append(before)
        parts.append(fragment['sql'])
        built.extend(list(fragment.get('params') or ()))
        remaining = remaining[index + len(placeholder):]
    if _placeholder_ids(remaining):
        raise TrustsConfigurationError(
            'Composition operation %s has a placeholder without a '
            'reference.' % operation.get('id')
        )
    count = remaining.count('%s')
    if count != len(remaining_params):
        raise TrustsConfigurationError(
            'Composition operation %s parameters do not match the '
            'template.' % operation.get('id')
        )
    built.extend(remaining_params)
    parts.append(remaining)
    return ''.join(parts), built


def _append_group(operations, fragments, order, group, filters, handle, alias):
    model = group['model']
    label = group['label']
    records = tuple(item['record'] for item in group['items'])
    user = _group_sentinel(records, 'user', label, alias)
    permission = _group_sentinel(records, 'permission', label, alias)
    extracted = [_grant_fragment(item) for item in group['items']]
    # Every grant in the group must be an exact fragment. A partial
    # reference would leave the other grant as unmarked SQL.
    if all(fragment is not None for fragment in extracted):
        pieces = extracted
    else:
        pieces = []
    model_filters = [
        row for row in filters if row['model_cls'] is model
    ]
    instance = _content_sentinel(model, alias)
    manager = _content_manager(model)
    granted = _compile_granted(
        (handle,), instance, user, permission, kind='complete',
    )
    if granted is None:
        raise TrustsConfigurationError(
            'Composition found no grant for %s.' % label
        )
    exists_sql, exists_params = _compile_exists(
        manager.filter(pk=instance.pk).filter(granted),
        alias, records,
    )
    _append_operation(
        operations, fragments, order,
        '%s:%s' % (_INSTANCE, label),
        _INSTANCE,
        exists_sql,
        exists_params,
        pieces,
    )
    code = _permission_code(model)
    binding = _permission_binding(code, model)
    granted_code = _compile_granted(
        (handle,), instance, user, binding, kind='complete',
    )
    if granted_code is None:
        raise TrustsConfigurationError(
            'Composition found no permission-code grant for %s.' % label
        )
    code_sql, code_params = _compile_exists(
        manager.filter(pk=instance.pk).filter(granted_code),
        alias, records,
    )
    _append_operation(
        operations, fragments, order,
        '%s:%s' % (_CODE, label),
        _CODE,
        code_sql,
        code_params,
        pieces,
    )
    for row in model_filters:
        combined = manager.filter(granted & row['q']).distinct()
        sql, params = _compile(
            combined, alias, records, expr=row['expr'],
        )
        if pieces and row['fragment'] is not None:
            and_pieces = list(pieces)
            and_pieces.append(row['fragment'])
        else:
            and_pieces = []
        _append_operation(
            operations, fragments, order,
            '%s:%s:%s' % (_AND, row['model'], row['code']),
            _AND,
            sql,
            params,
            and_pieces,
        )
    if len(group['items']) > 1:
        listed = manager.all()
        granted_all = _compile_granted(
            (handle,), listed, user, permission, kind='complete',
        )
        if granted_all is None:
            raise TrustsConfigurationError(
                'Composition found no or-group grant for %s.' % label
            )
        sql, params = _compile(
            listed.filter(granted_all).distinct(), alias, records, expr=None,
        )
        _append_operation(
            operations, fragments, order,
            '%s:%s' % (_OR, label),
            _OR,
            sql,
            params,
            pieces,
        )
    listed = manager.all()
    granted_list = _compile_granted(
        (handle,), listed, user, permission, kind='complete',
    )
    if granted_list is None:
        raise TrustsConfigurationError(
            'Composition found no queryset grant for %s.' % label
        )
    query = _aggregate_query(listed, granted_list, alias)
    sql, params = _compile(_Query(query), alias, records, expr=None)
    _append_operation(
        operations, fragments, order,
        '%s:%s' % (_QUERYSET, label),
        _QUERYSET,
        sql,
        params,
        pieces,
    )
    granted_code_list = _compile_granted(
        (handle,), listed, user, binding, kind='complete',
    )
    if granted_code_list is None:
        raise TrustsConfigurationError(
            'Composition found no queryset permission-code grant for %s.'
            % label
        )
    query = _aggregate_query(listed, granted_code_list, alias)
    sql, params = _compile(_Query(query), alias, records, expr=None)
    _append_operation(
        operations, fragments, order,
        '%s:%s' % (_QUERYSET_CODE, label),
        _QUERYSET_CODE,
        sql,
        params,
        pieces,
    )


def _append_operation(
    operations, fragments, order, operation_id, kind, sql, params, pieces,
):
    if any(row['id'] == operation_id for row in operations):
        raise TrustsConfigurationError(
            'Composition operation id %r collides.' % (operation_id,)
        )
    if '{{' in sql:
        raise TrustsConfigurationError(
            'Compiled SQL for %s contains a composition token.'
            % operation_id
        )
    factored = _factor(sql, params, pieces)
    if factored is None:
        operations.append({
            'id': operation_id,
            'kind': kind,
            'representation': 'full_sql',
            'sql': sql,
            'params': params,
        })
        return
    template, owned, refs = factored
    for piece in pieces:
        _remember_fragment(fragments, order, piece)
    operations.append({
        'id': operation_id,
        'kind': kind,
        'representation': 'structured',
        'sql': template,
        'params': owned,
        'refs': refs,
        'expanded': {
            'sql': sql,
            'params': params,
        },
    })


def _remember_fragment(fragments, order, piece):
    current = fragments.get(piece['id'])
    if current is None:
        fragments[piece['id']] = {
            'id': piece['id'],
            'kind': piece['kind'],
            'sql': piece['sql'],
            'params': piece['params'],
        }
        order.append(piece['id'])
        return
    if current['sql'] != piece['sql'] or current['params'] != piece['params']:
        raise TrustsConfigurationError(
            'Composition fragment id %r collides.' % (piece['id'],)
        )


def _factor(sql, params, pieces):
    """Return ``(template, owned_params, refs)`` or None.

    ``None`` unless every piece occurs exactly once in the statement
    still being scanned, and its parameters are the contiguous slice at
    that span, in piece order. A second copy is left as raw SQL rather
    than referenced, so the operation stays ``full_sql``.
    """
    if not pieces:
        return None
    remaining_sql = sql
    remaining_params = list(params)
    parts = []
    owned = []
    refs = []
    seen = set()
    for piece in pieces:
        frag_sql = piece['sql']
        placeholder = '{{%s}}' % piece['id']
        if (
            piece['id'] in seen
            or not _safe_placeholder(piece['id'], placeholder, frag_sql)
        ):
            return None
        seen.add(piece['id'])
        if remaining_sql.count(frag_sql) != 1:
            return None
        index = remaining_sql.find(frag_sql)
        before = remaining_sql[:index]
        count = before.count('%s')
        if count > len(remaining_params):
            return None
        owned.extend(remaining_params[:count])
        remaining_params = remaining_params[count:]
        width = len(piece['params'])
        if remaining_params[:width] != list(piece['params']):
            return None
        remaining_params = remaining_params[width:]
        parts.append(before)
        parts.append(placeholder)
        refs.append({
            'placeholder': placeholder,
            'fragment': piece['id'],
        })
        remaining_sql = remaining_sql[index + len(frag_sql):]
    if remaining_sql.count('%s') != len(remaining_params):
        return None
    if _placeholder_ids(''.join(parts) + remaining_sql) != [
        ref['fragment'] for ref in refs
    ]:
        return None
    owned.extend(remaining_params)
    parts.append(remaining_sql)
    return ''.join(parts), owned, refs


def _safe_placeholder(fragment_id, placeholder, frag_sql):
    if (
        not isinstance(fragment_id, str)
        or fragment_id == ''
        or '{' in fragment_id
        or '}' in fragment_id
        or '%s' in fragment_id
        or '%s' in placeholder
        or placeholder in frag_sql
        or '{{' in frag_sql
    ):
        return False
    return True


def _content_groups(records, trusts):
    from trusts.policy_lock import _model_label

    groups = []
    index = {}
    for record, trust in zip(records, trusts):
        label = _model_label(record.content_model)
        slot = index.get(label)
        if slot is None:
            index[label] = len(groups)
            groups.append({
                'label': label,
                'model': record.content_model,
                'items': [],
            })
            slot = index[label]
        groups[slot]['items'].append({
            'record': record,
            'id': trust['id'],
            'sql': trust['sql'],
            'params': trust['params'],
        })
    return groups


def _grant_fragment(item):
    body = _single_exists_body(item['sql'])
    if body is None or item['sql'].count(body) != 1:
        return None
    index = item['sql'].find(body)
    before = item['sql'][:index].count('%s')
    width = body.count('%s')
    params = list(item['params'])
    if item['sql'].count('%s') != len(params):
        return None
    if before + width > len(params):
        return None
    fragment_id = 'grant:%s' % item['id']
    if not _safe_placeholder(fragment_id, '{{%s}}' % fragment_id, body):
        return None
    return {
        'id': fragment_id,
        'kind': 'grant_exists',
        'sql': body,
        'params': params[before:before + width],
    }


def _named_filters(handle, alias, named_filters):
    from trusts.conditions._ir import compile_expression_q
    from trusts.policy_lock import (
        _any_sentinel_permission,
        _any_sentinel_user,
        _model_label,
    )

    registry = getattr(handle, 'registry', None)
    iterator = getattr(registry, 'iter_permission_conditions', None)
    if not callable(iterator):
        if named_filters:
            raise TrustsConfigurationError(
                'Composition cannot see named filters on %s.'
                % getattr(handle, 'path', None)
            )
        return []
    user = _any_sentinel_user(alias)
    permission = _any_sentinel_permission(alias)
    rows = []
    projected = list(named_filters)
    for index, (model, code, record) in enumerate(iterator()):
        if index >= len(projected):
            raise TrustsConfigurationError(
                'Composition named filters do not match the lockfile rows.'
            )
        row = projected[index]
        label = _model_label(model)
        if row.get('model') != label or row.get('code') != code:
            raise TrustsConfigurationError(
                'Composition named filters do not match the lockfile rows.'
            )
        expr = getattr(record, 'expr', None)
        compiled = compile_expression_q(expr, model, user, permission)
        rows.append({
            'model': label,
            'model_cls': model,
            'code': code,
            'expr': expr,
            'q': compiled,
            'fragment': _predicate_fragment(row),
        })
    if len(rows) != len(projected):
        raise TrustsConfigurationError(
            'Composition named filters do not match the lockfile rows.'
        )
    return rows


def _predicate_fragment(row):
    sql = row['sql']
    params = list(row['params'])
    marker = ' WHERE '
    where = sql.find(marker)
    if where < 0:
        return None
    predicate = sql[where + len(marker):]
    if predicate.count('%s') != len(params) or sql.count('%s') != len(params):
        return None
    fragment_id = 'predicate:%s:%s' % (row['model'], row['code'])
    if not _safe_placeholder(fragment_id, '{{%s}}' % fragment_id, predicate):
        return None
    return {
        'id': fragment_id,
        'kind': 'named_filter_predicate',
        'sql': predicate,
        'params': params,
    }


def _compile_exists(queryset, alias, records):
    return _compile(_Query(queryset.query.exists()), alias, records, expr=None)


def _compile(queryset, alias, records, *, expr):
    from trusts.policy_lock import _compile_queryset

    return _compile_queryset(
        queryset, alias, record=records[0], expr=expr, records=records,
    )


def _aggregate_query(queryset, granted_q, alias):
    """Return the ``all_match`` aggregate query without keeping its rows.

    The capturing compiler is installed only on this alias's connection
    for the call, then the connection is restored. A lock keeps two
    renders from swapping that alias at the same time. Django's
    compiler class is left alone, so other connections keep the
    original execute method.
    """
    from django.db import connections
    from django.db.models import Count

    real = connections[alias]
    captured = {}

    class _CapturingOps(object):
        def compiler(self, compiler_name):
            base = real.ops.compiler(compiler_name)

            class _CapturingCompiler(base):
                def execute_sql(self, *args, **kwargs):
                    del args, kwargs
                    captured['query'] = self.query.clone()
                    return (0, 1)

            _CapturingCompiler.__name__ = 'Capturing%s' % base.__name__
            return _CapturingCompiler

        def __getattr__(self, name):
            return getattr(real.ops, name)

    class _CapturingConnection(object):
        def __init__(self):
            self.ops = _CapturingOps()

        def __getattr__(self, name):
            return getattr(real, name)

    with _AGGREGATE_LOCK:
        connections[alias] = _CapturingConnection()
        try:
            queryset.aggregate(
                total=Count('pk', distinct=True),
                lacking=Count('pk', distinct=True, filter=~granted_q),
            )
        finally:
            connections[alias] = real
    if 'query' not in captured:
        raise TrustsConfigurationError(
            'Composition did not capture queryset has_perm SQL.'
        )
    return captured['query']


def _single_exists_body(sql):
    bodies = _exists_bodies(sql)
    if len(bodies) != 1:
        return None
    return bodies[0]


def _exists_bodies(sql):
    bodies = []
    needle = 'EXISTS('
    start = 0
    while True:
        found = sql.find(needle, start)
        if found < 0:
            return bodies
        index = found + len(needle)
        depth = 1
        while index < len(sql) and depth:
            char = sql[index]
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            index += 1
        if depth:
            raise TrustsConfigurationError(
                'Composition found an unclosed EXISTS.'
            )
        bodies.append(sql[found + len(needle):index - 1])
        start = index


def _placeholder_ids(sql):
    return _PLACEHOLDER_RE.findall(sql)


def _reject_placeholders(sql, where):
    found = _placeholder_ids(sql)
    if found:
        raise TrustsConfigurationError(
            'Composition %s contains placeholder %s.'
            % (where, found[0])
        )


def _group_sentinel(records, role, label, alias):
    """Unsaved user or permission whose model and target the group shares."""
    from trusts.policy_lock import _sentinel

    first = records[0]
    model = getattr(first, '%s_model' % role)._meta.concrete_model
    target = getattr(first, '%s_target' % role)
    for record in records[1:]:
        other = getattr(record, '%s_model' % role)._meta.concrete_model
        if other is not model or getattr(record, '%s_target' % role) != target:
            raise TrustsConfigurationError(
                'Composition on %s requires one %s model and target.'
                % (label, role)
            )
    return _sentinel(model, target, alias=alias)


def _content_manager(model):
    """Default manager of the concrete model.

    A model may rename or omit ``objects``. Instance checks use
    ``concrete_model._default_manager``; composition querysets do too.
    """
    return model._meta.concrete_model._default_manager


def _content_sentinel(model, alias):
    from trusts.policy_lock import _sentinel

    pk = model._meta.pk
    return _sentinel(model, pk.attname, alias=alias)


def _permission_code(model):
    meta = model._meta
    return '%s.change_%s' % (meta.app_label, meta.model_name)


def _permission_binding(code, model):
    from trusts.backends import _permission_binding

    return _permission_binding(code, model)


class _Query(object):
    def __init__(self, query):
        self.query = query
