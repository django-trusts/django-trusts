"""Record compiled SQL for composed authorization operations.

Internal to the schema-1 renderer. Not a public API and not a reverse
mapping. ``trusts.E009`` does not parse the document; it compares
rendered bytes. Each operation stores the statement Django compiled
and the parameters in that statement's order. There is no fragment,
placeholder, or second copy.

The aggregate statement is captured by a compiler installed on this
thread's connection for that one call. Django's ``SQLCompiler`` class
is not modified, and the runtime query shape is not changed to make a
span reusable.
"""

from __future__ import annotations

import threading

from trusts.core import TrustsConfigurationError, _compile_granted

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
    standalone rows.
    """
    if not records:
        return None
    if len(records) != len(trusts):
        raise TrustsConfigurationError(
            'Composition received trusts that do not match the registry.'
        )
    filters = _named_filters(handle, alias, named_filters)
    operations = []
    for group in _content_groups(records):
        _append_group(operations, group, filters, handle, alias)
    return {'operations': operations}


def _append_group(operations, group, filters, handle, alias):
    model = group['model']
    label = group['label']
    records = tuple(group['items'])
    user = _group_sentinel(records, 'user', label, alias)
    permission = _group_sentinel(records, 'permission', label, alias)
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
        operations,
        '%s:%s' % (_INSTANCE, label),
        exists_sql,
        exists_params,
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
        operations,
        '%s:%s' % (_CODE, label),
        code_sql,
        code_params,
    )
    for row in model_filters:
        combined = manager.filter(granted & row['q']).distinct()
        sql, params = _compile(
            combined, alias, records, expr=row['expr'],
        )
        _append_operation(
            operations,
            '%s:%s:%s' % (_AND, row['model'], row['code']),
            sql,
            params,
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
            operations,
            '%s:%s' % (_OR, label),
            sql,
            params,
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
        operations,
        '%s:%s' % (_QUERYSET, label),
        sql,
        params,
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
        operations,
        '%s:%s' % (_QUERYSET_CODE, label),
        sql,
        params,
    )


def _append_operation(operations, operation_id, sql, params):
    if any(row['id'] == operation_id for row in operations):
        raise TrustsConfigurationError(
            'Composition operation id %r collides.' % (operation_id,)
        )
    operations.append({
        'id': operation_id,
        'sql': sql,
        'params': params,
    })


def _content_groups(records):
    from trusts.policy_lock import _model_label

    groups = []
    index = {}
    for record in records:
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
        groups[slot]['items'].append(record)
    return groups


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
        })
    if len(rows) != len(projected):
        raise TrustsConfigurationError(
            'Composition named filters do not match the lockfile rows.'
        )
    return rows


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
