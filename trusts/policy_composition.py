"""Composition evidence for schema-1 policy SQL. Not the lockfile.

``render_policy_sql_bytes`` records each trust's ``.authorized()``
statement and each named filter's statement. Runtime ``has_perm``,
filter-to-grant AND, multi-trust OR, and queryset ``all_match`` are
different statements. This module compiles those statements and writes
a separate canonical YAML document that shows:

* the expanded SQL the compiler actually produced;
* a structured form when a lockfile fragment is an exact substring and
  its parameters sit contiguously at that position;
* full SQL when alias renaming or a different permission bind makes
  that fragment unusable.

``trusts.E009`` does not read this document. Named-filter rows stay
full SELECTs; a composition reference points at the filter predicate,
not at that SELECT.
"""

from __future__ import annotations

from django.contrib.auth.models import Permission
from django.db.models import Count
from django.db.models.sql.compiler import SQLCompiler

from trusts.backends import _permission_binding
from trusts.core import TrustsConfigurationError, _compile_granted
from trusts.policy_lock import (
    SCHEMA_VERSION,
    _compile_queryset,
    _model_label,
    _sentinel,
    resolve_policy_database,
)
from trusts.policy_yaml import PolicyYamlError, dump_policy_yaml

_RULES = (
    'A reference is valid only when the fragment SQL, aliases included, '
    'occurs in the expanded statement and that fragment\'s parameters '
    'occupy the same contiguous span.',
    'Expansion replaces each placeholder with the fragment SQL and '
    'splices the fragment parameters at that position. Parameters that '
    'sit outside the fragment stay in template order.',
    'Outer aliases or a different permission bind that change the '
    'fragment text require the full statement. There is no token whose '
    'expansion is guessed.',
    'The lockfile named-filter row is the full SELECT. Filter-to-grant '
    'composition references only that statement\'s WHERE predicate.',
    'Instance has_perm is a candidate primary-key predicate plus grant '
    'EXISTS, not IN (<< .authorized() subquery >>). .authorized() is a '
    'content SELECT.',
)


def render_composition_evidence_bytes(*, alias=None, handles=None):
    """Return canonical YAML evidence bytes. Not lockfile bytes."""
    resolved = resolve_policy_database(alias)
    if handles is None:
        from trusts.apps import configured_implementation_handles

        handles = configured_implementation_handles()
    try:
        document = build_composition_document(tuple(handles), resolved)
        verify_composition_document(document)
        return dump_policy_yaml(document)
    except PolicyYamlError as exc:
        raise TrustsConfigurationError(str(exc)) from exc


def build_composition_document(handles, alias):
    """Compile composition shapes for ``handles`` on ``alias``."""
    from django.conf import settings

    engine = (settings.DATABASES.get(alias) or {}).get('ENGINE')
    if not isinstance(engine, str) or engine == '':
        raise TrustsConfigurationError(
            'Policy SQL render alias %r has no DATABASES ENGINE.' % (alias,)
        )
    user = _any_user(alias)
    permission = _any_permission(alias)
    backends = []
    for handle in handles:
        backends.append(_project_handle(handle, alias, user, permission))
    return {
        'schema_version': SCHEMA_VERSION,
        'lockfile': False,
        'role': 'composition-evidence',
        'first_drop': ['trust.authorized', 'named_filter'],
        'rules': list(_RULES),
        'database': {'engine': engine},
        'backends': backends,
    }


def verify_composition_document(document):
    """Fail unless every structured operation expands to its full SQL."""
    for backend in document['backends']:
        fragments = {row['id']: row for row in backend['fragments']}
        for operation in backend['operations']:
            structured = operation.get('structured')
            if structured is None:
                continue
            expanded = operation['expanded']
            sql = _substitute(structured['sql'], structured['refs'], fragments)
            if sql != expanded['sql']:
                raise TrustsConfigurationError(
                    'Composition template for %s does not expand to the '
                    'compiled statement.' % operation['id']
                )
            _assert_param_span(
                expanded['sql'], expanded['params'], structured['refs'],
                fragments,
            )


def _project_handle(handle, alias, user, permission):
    path = getattr(handle, 'path', None)
    registry = getattr(handle, 'registry', None)
    if not isinstance(path, str) or registry is None:
        raise TrustsConfigurationError(
            'Composition evidence requires a path and registry.'
        )
    from trusts.policy_lock import _assign_ids, _compile_authorized

    records = tuple(getattr(registry, 'records', ()) or ())
    trust_ids = _assign_ids(records)
    fragments = []
    operations = []
    grant_ids = []
    for record, trust_id in zip(records, trust_ids):
        sql, params = _compile_authorized(record, alias)
        body = _single_exists_body(sql)
        if body is None or sql.count(body) != 1:
            raise TrustsConfigurationError(
                'Composition evidence could not isolate the grant EXISTS '
                'for %s.' % trust_id
            )
        _assert_span(sql, params, body, params)
        fragment_id = 'grant:%s' % trust_id
        grant_ids.append(fragment_id)
        fragments.append({
            'id': fragment_id,
            'kind': 'grant_exists',
            'denotes': (
                'EXISTS body of this trust\'s .authorized() statement, '
                'including aliases and parameter order.'
            ),
            'sql': body,
            'params': params,
        })
        operations.append(_full_operation(
            'authorized:%s' % trust_id,
            'trust.authorized',
            True,
            'Lockfile row. Full content SELECT for this trust.',
            sql,
            params,
        ))
    filters = _named_filters(registry, alias)
    for row in filters:
        fragment_id = 'predicate:%s:%s' % (row['model'], row['code'])
        fragments.append({
            'id': fragment_id,
            'kind': 'named_filter_predicate',
            'denotes': (
                'WHERE predicate of the named-filter SELECT. Not that '
                'SELECT and not a grant.'
            ),
            'sql': row['predicate'],
            'params': row['params'],
        })
        operations.append(_full_operation(
            'named_filter:%s:%s' % (row['model'], row['code']),
            'named_filter',
            True,
            'Lockfile row. Standalone named-filter SELECT, not combined '
            'with a grant.',
            row['sql'],
            row['params'],
        ))
    if records:
        content_model = records[0].content_model
        if any(record.content_model is not content_model for record in records):
            raise TrustsConfigurationError(
                'Composition evidence on %s requires one content model.'
                % path
            )
        _append_runtime_operations(
            operations, fragments, grant_ids, filters, handle, alias, user,
            permission, content_model, records,
        )
    return {
        'path': path,
        'fragments': fragments,
        'operations': operations,
    }


def _append_runtime_operations(
    operations, fragments, grant_ids, filters, handle, alias, user,
    permission, content_model, records,
):
    by_id = {row['id']: row for row in fragments}
    record = records[0]
    instance = _content_sentinel(content_model, alias)
    granted = _compile_granted(
        (handle,), instance, user, permission, kind='complete',
    )
    if granted is None:
        raise TrustsConfigurationError(
            'Composition evidence found no grant for %s.' % _model_label(
                content_model,
            )
        )
    exists_sql, exists_params = _compile_exists(
        content_model.objects.filter(pk=instance.pk).filter(granted),
        alias, record, None,
    )
    _append_factored(
        operations,
        'has_perm_permission_instance',
        'has_perm_permission_instance',
        False,
        'Candidate primary-key predicate plus grant EXISTS. Reuses the '
        'grant fragment only when that text matches. This is not the '
        '.authorized() SELECT and not IN (authorized subquery). '
        'Parameter order is the exists() probe, the candidate '
        'primary-key sentinel, then the fragment parameters.',
        exists_sql,
        exists_params,
        [by_id[item] for item in grant_ids],
    )
    code = _permission_code(content_model)
    binding = _permission_binding(code, content_model)
    granted_code = _compile_granted(
        (handle,), instance, user, binding, kind='complete',
    )
    code_sql, code_params = _compile_exists(
        content_model.objects.filter(pk=instance.pk).filter(granted_code),
        alias, record, None,
    )
    _append_factored(
        operations,
        'has_perm_permission_code',
        'has_perm_permission_code',
        False,
        'Permission-code has_perm binds permission through a codename '
        'subquery. Full SQL when that changes the grant text or aliases.',
        code_sql,
        code_params,
        [by_id[item] for item in grant_ids],
    )
    for row in filters:
        if row['model_cls'] is not content_model:
            continue
        combined = content_model.objects.filter(granted & row['q']).distinct()
        sql, params = _compile_queryset(
            combined, alias, record=record, expr=row['expr'],
        )
        pieces = [by_id[item] for item in grant_ids]
        pieces.append(by_id['predicate:%s:%s' % (row['model'], row['code'])])
        _append_factored(
            operations,
            'authorized_and_named_filter:%s' % row['code'],
            'authorized_and_named_filter',
            False,
            'Runtime AND of the grant EXISTS with the named-filter '
            'predicate. The named-filter SELECT stays a separate '
            'lockfile row.',
            sql,
            params,
            pieces,
        )
    if len(records) > 1:
        listed = content_model.objects.all()
        granted_all = _compile_granted(
            (handle,), listed, user, permission, kind='complete',
        )
        sql, params = _compile_queryset(
            listed.filter(granted_all).distinct(), alias, record=record,
            expr=None,
        )
        _append_factored(
            operations,
            'or_group_authorized',
            'or_group_authorized',
            False,
            'Runtime OR of per-trust grant EXISTS bodies. The lockfile '
            'keeps each trust statement separate and records or_group '
            'instead of this combined statement.',
            sql,
            params,
            [by_id[item] for item in grant_ids],
        )
    _append_queryset_has_perm(
        operations, by_id, grant_ids, handle, alias, user, permission,
        content_model, record,
    )


def _append_queryset_has_perm(
    operations, by_id, grant_ids, handle, alias, user, permission,
    content_model, record,
):
    listed = content_model.objects.all()
    granted = _compile_granted(
        (handle,), listed, user, permission, kind='complete',
    )
    query = _aggregate_query(listed, granted)
    sql, params = _compile_queryset(
        _Query(query), alias, record=record, expr=None,
    )
    _append_factored(
        operations,
        'queryset_has_perm',
        'queryset_has_perm',
        False,
        'all_match COUNT/FILTER statement. The grant EXISTS is nested '
        'under NOT. The outer aggregate is not the .authorized() SELECT.',
        sql,
        params,
        [by_id[item] for item in grant_ids],
    )


def _append_factored(
    operations, operation_id, kind, enters_lockfile, reason, sql, params,
    pieces,
):
    template, refs = _template_for(sql, params, pieces)
    if template is None:
        operation = _full_operation(
            operation_id, kind, enters_lockfile, reason, sql, params,
        )
        bodies = _exists_bodies(sql)
        if bodies and pieces:
            operation['locked_fragments'] = [piece['id'] for piece in pieces]
            operation['expanded_exists'] = [{'sql': body} for body in bodies]
        operations.append(operation)
        return
    operations.append({
        'id': operation_id,
        'kind': kind,
        'enters_lockfile': enters_lockfile,
        'representation': 'structured',
        'reason': reason,
        'structured': {
            'sql': template,
            'refs': refs,
        },
        'expanded': {
            'sql': sql,
            'params': params,
        },
    })


def _full_operation(operation_id, kind, enters_lockfile, reason, sql, params):
    return {
        'id': operation_id,
        'kind': kind,
        'enters_lockfile': enters_lockfile,
        'representation': 'full_sql',
        'reason': reason,
        'expanded': {
            'sql': sql,
            'params': params,
        },
    }


def _template_for(sql, params, pieces):
    """Return ``(template, refs)`` when every piece is an exact span."""
    remaining_sql = sql
    remaining_params = list(params)
    parts = []
    refs = []
    for piece in pieces:
        frag_sql = piece['sql']
        index = remaining_sql.find(frag_sql)
        if index < 0:
            return None, None
        before = remaining_sql[:index]
        count = before.count('%s')
        remaining_params = remaining_params[count:]
        width = len(piece['params'])
        if remaining_params[:width] != piece['params']:
            return None, None
        remaining_params = remaining_params[width:]
        placeholder = '{{%s}}' % piece['id']
        if '%s' in placeholder or placeholder in frag_sql:
            raise TrustsConfigurationError(
                'Composition placeholder %s is not safe.' % placeholder
            )
        parts.append(before)
        parts.append(placeholder)
        refs.append({
            'placeholder': placeholder,
            'fragment': piece['id'],
        })
        remaining_sql = remaining_sql[index + len(frag_sql):]
    if remaining_sql.count('%s') != len(remaining_params):
        return None, None
    parts.append(remaining_sql)
    return ''.join(parts), refs


def _assert_param_span(sql, params, refs, fragments):
    remaining_sql = sql
    remaining = list(params)
    built = []
    for ref in refs:
        frag = fragments[ref['fragment']]
        index = remaining_sql.find(frag['sql'])
        if index < 0:
            raise TrustsConfigurationError(
                'Expanded SQL lost fragment %s.' % ref['fragment']
            )
        before = remaining_sql[:index]
        count = before.count('%s')
        built.extend(remaining[:count])
        remaining = remaining[count:]
        width = len(frag['params'])
        if remaining[:width] != frag['params']:
            raise TrustsConfigurationError(
                'Fragment %s parameters are not a contiguous span.'
                % ref['fragment']
            )
        built.extend(remaining[:width])
        remaining = remaining[width:]
        remaining_sql = remaining_sql[index + len(frag['sql']):]
    count = remaining_sql.count('%s')
    built.extend(remaining[:count])
    remaining = remaining[count:]
    if remaining or built != params:
        raise TrustsConfigurationError(
            'Composition parameter expansion does not match compiler order.'
        )


def _substitute(template, refs, fragments):
    sql = template
    for ref in refs:
        placeholder = ref['placeholder']
        frag_sql = fragments[ref['fragment']]['sql']
        if sql.count(placeholder) != 1:
            raise TrustsConfigurationError(
                'Placeholder %s must occur once.' % placeholder
            )
        sql = sql.replace(placeholder, frag_sql, 1)
    return sql


def _named_filters(registry, alias):
    from trusts.conditions._ir import compile_expression_q
    from trusts.policy_lock import _any_sentinel_permission, _any_sentinel_user

    rows = []
    iterator = getattr(registry, 'iter_permission_conditions', None)
    if not callable(iterator):
        return rows
    user = _any_sentinel_user(alias)
    permission = _any_sentinel_permission(alias)
    for model, code, record in iterator():
        expr = getattr(record, 'expr', None)
        compiled = compile_expression_q(expr, model, user, permission)
        queryset = model.objects.filter(compiled)
        sql, params = _compile_queryset(
            queryset, alias, record=None, expr=expr,
        )
        marker = ' WHERE '
        where = sql.find(marker)
        if where < 0:
            raise TrustsConfigurationError(
                'Named filter %s SQL has no WHERE clause.' % code
            )
        predicate = sql[where + len(marker):]
        if predicate.count('%s') != len(params):
            raise TrustsConfigurationError(
                'Named filter %s predicate does not own every parameter.'
                % code
            )
        rows.append({
            'model': _model_label(model),
            'model_cls': model,
            'code': code,
            'expr': expr,
            'q': compiled,
            'sql': sql,
            'predicate': predicate,
            'params': params,
        })
    return rows


def _compile_exists(queryset, alias, record, expr):
    exists_query = queryset.query.exists()
    return _compile_queryset(
        _Query(exists_query), alias, record=record, expr=expr,
    )


def _aggregate_query(queryset, granted_q):
    """Return the ``all_match`` aggregate query without executing it."""
    captured = {}

    def execute_sql(self, *args, **kwargs):
        del args, kwargs
        captured['query'] = self.query.clone()
        return (0, 1)

    original = SQLCompiler.execute_sql
    SQLCompiler.execute_sql = execute_sql
    try:
        queryset.aggregate(
            total=Count('pk', distinct=True),
            lacking=Count('pk', distinct=True, filter=~granted_q),
        )
    finally:
        SQLCompiler.execute_sql = original
    if 'query' not in captured:
        raise TrustsConfigurationError(
            'Composition evidence did not capture queryset has_perm SQL.'
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
                'Composition evidence found an unclosed EXISTS.'
            )
        bodies.append(sql[found + len(needle):index - 1])
        start = index


def _assert_span(sql, params, fragment, fragment_params):
    index = sql.find(fragment)
    if index < 0:
        raise TrustsConfigurationError(
            'Grant fragment is not in the authorized statement.'
        )
    before = sql[:index].count('%s')
    width = len(fragment_params)
    if params[before:before + width] != fragment_params:
        raise TrustsConfigurationError(
            'Grant fragment parameters are not a contiguous span.'
        )


def _content_sentinel(model, alias):
    pk = model._meta.pk
    return _sentinel(model, pk.attname, alias=alias)


def _any_user(alias):
    from django.contrib.auth import get_user_model

    user_model = get_user_model()
    return _sentinel(user_model, user_model._meta.pk.attname, alias=alias)


def _any_permission(alias):
    return _sentinel(Permission, Permission._meta.pk.attname, alias=alias)


def _permission_code(model):
    meta = model._meta
    return '%s.change_%s' % (meta.app_label, meta.model_name)


class _Query(object):
    def __init__(self, query):
        self.query = query
