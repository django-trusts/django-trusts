"""SQL-first authorization policy export and lockfile check.

``trusts_policy_sql`` renders schema version 1 as canonical YAML: one
``.authorized()`` statement per registered trust, standalone
named-filter SQL, and ``or_group`` when two trusts on a backend share a
content model. The same document records composed operations. A
reference is emitted only when the fragment SQL and its parameters are
an exact contiguous span of the compiler output. Otherwise the
operation stores that output in full. The alias is not stored.
``trusts.E009`` compares those bytes to the committed file. It is the
only lockfile enforcement.
"""

from __future__ import annotations

import contextvars
import datetime
import errno
import math
import os
import stat
import tempfile
import threading
import uuid
from decimal import Decimal
from pathlib import Path

from django.core import checks as django_checks
from django.db.models.expressions import Value
from django.db.models.lookups import Lookup

from trusts.core import (
    RelationPlan,
    TrustsConfigurationError,
    _compile_granted,
)
from trusts.policy_yaml import (
    PolicyYamlError,
    dump_policy_yaml,
    _load_policy_yaml,
)

SCHEMA_VERSION = 1
CHECK_ID_POLICY_LOCK = 'trusts.E009'
CONVENTIONAL_LOCKFILE_NAME = 'trusts-policy.lock.yaml'

_INTEGER_SENTINEL_TYPES = frozenset((
    'AutoField',
    'BigAutoField',
    'SmallAutoField',
    'IntegerField',
    'BigIntegerField',
    'SmallIntegerField',
    'PositiveIntegerField',
    'PositiveBigIntegerField',
    'PositiveSmallIntegerField',
))
_TEXT_SENTINEL_TYPES = frozenset((
    'CharField',
    'TextField',
    'SlugField',
    'EmailField',
    'URLField',
    'FileField',
    'FilePathField',
    'GenericIPAddressField',
))

# Set only while this task is compiling an export. Classification runs
# on compilers built for that connection proxy, and only when this
# context var is set, so another thread's SQLCompiler.compile is the
# Django method.
_export_scope = contextvars.ContextVar(
    'trusts_policy_sql_export', default=None,
)
_classifying_classes = {}
_classifying_class_lock = threading.Lock()
_ctx = threading.local()


class PolicyLockLocation(object):
    """Exact lockfile path plus how presence was classified.

    ``path`` is absolute. ``explicit`` is true when the path came from
    ``TRUSTS_POLICY_LOCKFILE`` or a command override. ``state`` is
    ``absent``, ``present``, ``missing_parent``, ``not_a_directory``, or
    ``permission``. Classification inspects this path and its immediate
    parent only.
    """

    __slots__ = ('path', 'explicit', 'state')

    def __init__(self, path, explicit, state):
        self.path = path
        self.explicit = explicit
        self.state = state

    def __repr__(self):
        return '<PolicyLockLocation %s explicit=%s %s>' % (
            self.state, self.explicit, self.path,
        )


class _Symbol(object):
    """One classified placeholder. Not a runtime value."""

    __slots__ = ('payload',)

    def __init__(self, payload):
        self.payload = payload

    def __repr__(self):
        return '<Symbol %r>' % (self.payload,)

    def __hash__(self):
        return hash(id(self))

    def __eq__(self, other):
        return self is other


def resolve_policy_database(override=None):
    """Return the database alias used to render policy SQL.

    ``override`` is the ``--database`` value for one command process.
    Otherwise ``settings.TRUSTS_POLICY_DATABASE`` is used. Unset or
    ``None`` selects Django's ``default`` alias. A non-empty
    ``DATABASES`` key selects that alias. Any other value is a
    configuration error. The alias is not written into the document.
    """
    from django.conf import settings
    from django.db.utils import DEFAULT_DB_ALIAS

    if override is not None:
        alias = override
    elif not settings.configured:
        alias = DEFAULT_DB_ALIAS
    else:
        alias = getattr(settings, 'TRUSTS_POLICY_DATABASE', None)
        if alias is None:
            alias = DEFAULT_DB_ALIAS
    databases = {}
    if settings.configured:
        databases = getattr(settings, 'DATABASES', None) or {}
    if (
        isinstance(alias, bool)
        or not isinstance(alias, str)
        or alias == ''
        or alias not in databases
    ):
        raise TrustsConfigurationError(
            'TRUSTS_POLICY_DATABASE must be unset or a configured '
            'DATABASES alias, not %r.' % (alias,)
        )
    return alias


def render_policy_sql_bytes(*, alias=None, handles=None):
    """Return the schema-1 policy SQL document as UTF-8 bytes.

    ``alias`` overrides ``TRUSTS_POLICY_DATABASE`` for this call only.
    ``handles`` defaults to the configured implementation handles.
    Compilation uses ``as_sql()`` / ``sql_with_params()`` and does not
    execute the exported statements. Composed operations are checked
    before the bytes are returned: a structured reference that does not
    expand to the compiler SQL and parameter order raises, and no
    partial document is returned.
    """
    resolved = resolve_policy_database(alias)
    if handles is None:
        from trusts.apps import configured_implementation_handles

        handles = configured_implementation_handles()
    document = _build_document(tuple(handles), resolved)
    return _dump_document(document)


def write_policy_lock(payload, *, override=None):
    """Write ``payload`` to the resolved lockfile path.

    Parent directories are not created. The payload is the same byte
    string printed to stdout. This does not compare an existing file.
    """
    if not isinstance(payload, bytes):
        raise TypeError(
            'Policy lock payload must be bytes, not %s.'
            % type(payload).__name__
        )
    location = resolve_lockfile_path(override=override)
    _require_writable_parent(location)
    if location.state == 'present' and _lockfile_is_directory(location.path):
        raise TrustsConfigurationError(
            'Policy lock path is a directory: %s.' % location.path
        )
    _atomic_write(location.path, payload)
    return location.path


def resolve_lockfile_path(*, override=None):
    """Return the lockfile location. Never consults the process CWD.

    ``override`` is an explicit path. When it is omitted, a set
    ``settings.TRUSTS_POLICY_LOCKFILE`` (anything other than ``None``)
    is the explicit path. Otherwise the conventional path is
    ``settings.BASE_DIR / "trusts-policy.lock.yaml"`` when ``BASE_DIR``
    is an absolute path string or ``Path``. A missing or relative
    ``BASE_DIR`` is not usable and requires an explicit absolute path.
    Relative explicit paths fail closed. This function does not create
    directories, read the file, or issue SQL.
    """
    if override is not None:
        path = _absolute_lock_path(override)
        explicit = True
    else:
        configured = _configured_lock_override()
        if configured is not None:
            path = _absolute_lock_path(configured)
            explicit = True
        else:
            base = _usable_base_dir()
            if base is None:
                raise TrustsConfigurationError(
                    'Policy lock requires an absolute TRUSTS_POLICY_LOCKFILE '
                    'when BASE_DIR is unset or not absolute. The process '
                    'working directory is not used.'
                )
            path = base / CONVENTIONAL_LOCKFILE_NAME
            explicit = False
    return PolicyLockLocation(path, explicit, _classify_lockfile(path))


def _build_document(handles, alias):
    from django.conf import settings

    engine = (settings.DATABASES.get(alias) or {}).get('ENGINE')
    if not isinstance(engine, str) or engine == '':
        raise TrustsConfigurationError(
            'Policy SQL render alias %r has no DATABASES ENGINE.' % (alias,)
        )
    projected = []
    for handle in handles:
        projected.append(_project_backend(handle, alias))
    projected.sort(key=lambda row: row['path'])
    paths = [row['path'] for row in projected]
    if len(paths) != len(set(paths)):
        raise TrustsConfigurationError(
            'Policy SQL render found duplicate backend paths.'
        )
    return {
        'schema_version': SCHEMA_VERSION,
        'database': {'engine': engine},
        'backends': projected,
    }


def _project_backend(handle, alias):
    path = getattr(handle, 'path', None)
    if not isinstance(path, str) or path == '':
        raise TrustsConfigurationError(
            'Policy SQL render handle is missing a configured path: %r.'
            % (path,)
        )
    from trusts.apps import _handle_authorization_family

    family = _handle_authorization_family(handle)
    if family != 'relationship':
        raise TrustsConfigurationError(
            'Policy SQL render only serializes family %r; backend path '
            '%r has unsupported family %r.'
            % ('relationship', path, family)
        )
    registry = getattr(handle, 'registry', None)
    if registry is None:
        raise TrustsConfigurationError(
            'Policy SQL render requires a registry for backend path %r.'
            % (path,)
        )
    records = tuple(getattr(registry, 'records', ()) or ())
    ids = _assign_ids(records)
    content_labels = [_model_label(record.content_model) for record in records]
    grouped = {
        label for label in content_labels if content_labels.count(label) > 1
    }
    trusts = []
    grants = []
    for record, trust_id, content_label in zip(records, ids, content_labels):
        sql, params = _compile_authorized(record, alias)
        row = {
            'id': trust_id,
            'root': _model_label(record.root),
            'user': _relation(record, 'user'),
            'permission': _relation(record, 'permission'),
            'content': _relation(record, 'content'),
        }
        if content_label in grouped:
            row['or_group'] = content_label
        row['sql'] = sql
        row['params'] = params
        trusts.append(row)
        grants.append({
            'id': trust_id,
            'record': record,
            'content_model': record.content_model,
            'content_label': content_label,
            'sql': sql,
            'params': params,
        })
    filters = _named_filter_details(registry, alias)
    fragments, operations = _compose_backend(handle, alias, grants, filters)
    return {
        'path': path,
        'trusts': trusts,
        'named_filters': [
            {
                'model': row['model'],
                'code': row['code'],
                'sql': row['sql'],
                'params': row['params'],
            }
            for row in filters
        ],
        'fragments': fragments,
        'operations': operations,
    }


def _relation(record, role):
    return {
        'path': getattr(record, '%s_field' % role),
        'model': _model_label(getattr(record, '%s_model' % role)),
        'target': getattr(record, '%s_target' % role),
    }


def _assign_ids(records):
    bases = [_base_id(record) for record in records]
    totals = {}
    for base in bases:
        totals[base] = totals.get(base, 0) + 1
    seen = {}
    labels = []
    for base in bases:
        seen[base] = seen.get(base, 0) + 1
        number = seen[base]
        if totals[base] == 1 or number == 1:
            labels.append(base)
        else:
            labels.append('%s#%s' % (base, number))
    return labels


def _base_id(record):
    label = '%s:%s' % (_model_label(record.root), record.content_field)
    if getattr(record, 'condition', None) is not None:
        label += '+cond'
    along = getattr(record, 'along', None)
    if along is not None:
        label += '+along:%s:%s' % (
            getattr(along, 'shape', None),
            getattr(along, 'bound', None),
        )
    return label


def _named_filter_details(registry, alias):
    rows = []
    iterator = getattr(registry, 'iter_permission_conditions', None)
    if not callable(iterator):
        return rows
    for model, code, record in iterator():
        model_label = _model_label(model)
        if not isinstance(code, str) or code == '':
            raise TrustsConfigurationError(
                'Named filter on %s has a non-portable code %r.'
                % (model_label, code)
            )
        expr = getattr(record, 'expr', None)
        sql, params = _compile_named_filter(model, expr, alias)
        rows.append({
            'model': model_label,
            'model_cls': model,
            'code': code,
            'expr': expr,
            'sql': sql,
            'params': params,
        })
    return rows


_GRANT_DENOTES = (
    'EXISTS body of this trust\'s .authorized() statement, including '
    'aliases and parameter order.'
)
_PREDICATE_DENOTES = (
    'WHERE predicate of the named-filter SELECT. Not that SELECT and '
    'not a grant.'
)
_REASON_INSTANCE = (
    'Candidate primary-key predicate plus grant EXISTS. Reuses the '
    'grant fragment only when that text matches. This is not the '
    '.authorized() SELECT and not IN (authorized subquery). '
    'Parameter order is the exists() probe, the candidate '
    'primary-key sentinel, then the fragment parameters.'
)
_REASON_CODE = (
    'Permission-code has_perm binds permission through a codename '
    'subquery. The codename, app label, and model constants are the '
    'inspection probe change_<model>, not a declared permission. '
    'Full SQL when that bind changes the grant text or aliases.'
)
_REASON_AND = (
    'Runtime AND of the grant EXISTS with the named-filter predicate. '
    'The named-filter SELECT stays a separate lockfile row.'
)
_REASON_OR = (
    'Runtime OR of per-trust grant EXISTS bodies. The lockfile keeps '
    'each trust statement separate and records or_group instead of '
    'this combined statement.'
)
_REASON_QUERYSET = (
    'all_match COUNT/FILTER statement. The grant EXISTS is nested '
    'under NOT. The outer aggregate is not the .authorized() SELECT.'
)


def _compose_backend(handle, alias, grants, filters):
    """Return ``(fragments, operations)`` for one backend.

    Fragments are leaves: grant EXISTS bodies in trust order, then
    named-filter WHERE predicates in ``add_named_filter`` order. An
    operation template may name those fragments. It is stored only when
    each fragment's SQL occurs exactly once, in order, and that
    fragment's parameters occupy the same contiguous span. Expansion
    replaces each ``{{fragment-id}}`` with that SQL and splices the
    fragment parameters at that position. Parameters outside every
    fragment stay in compiler order. A cycle, a missing reference, or a
    duplicate fragment id fails the render. Alias correlation that
    changes the fragment text stores the compiler statement in full.
    """
    fragments = []
    seen = set()
    for grant in grants:
        body = _grant_fragment_span(grant['sql'], grant['params'])
        if body is None:
            continue
        sql, params = body
        _add_fragment(fragments, seen, {
            'id': 'grant:%s' % grant['id'],
            'kind': 'grant_exists',
            'denotes': _GRANT_DENOTES,
            'sql': sql,
            'params': params,
        })
    for row in filters:
        predicate = _predicate_span(row['sql'], row['params'])
        if predicate is None:
            continue
        sql, params = predicate
        _add_fragment(fragments, seen, {
            'id': 'predicate:%s:%s' % (row['model'], row['code']),
            'kind': 'named_filter_predicate',
            'denotes': _PREDICATE_DENOTES,
            'sql': sql,
            'params': params,
        })
    by_id = {row['id']: row for row in fragments}
    operations = []
    operation_ids = set()
    for group in _content_groups(grants):
        _append_group_operations(
            operations, operation_ids, by_id, group, filters, handle, alias,
        )
    _verify_composed_operations(fragments, operations)
    return fragments, operations


def _content_groups(grants):
    groups = []
    index = {}
    for grant in grants:
        label = grant['content_label']
        slot = index.get(label)
        if slot is None:
            index[label] = len(groups)
            groups.append({
                'label': label,
                'model': grant['content_model'],
                'grants': [],
            })
            slot = index[label]
        groups[slot]['grants'].append(grant)
    return groups


def _add_fragment(fragments, seen, row):
    fragment_id = row['id']
    if not isinstance(fragment_id, str) or fragment_id == '':
        raise TrustsConfigurationError(
            'Composition fragment id must be a non-empty string.'
        )
    if any(char in fragment_id for char in '{}%\r\n'):
        raise TrustsConfigurationError(
            'Composition fragment id %r collides with reference syntax.'
            % (fragment_id,)
        )
    if fragment_id in seen:
        raise TrustsConfigurationError(
            'Duplicate composition fragment %s.' % fragment_id
        )
    if '{{' in row['sql']:
        raise TrustsConfigurationError(
            'Composition cycle: fragment %s contains a reference token. '
            'Fragments are leaves.' % fragment_id
        )
    seen.add(fragment_id)
    fragments.append(row)


def _append_group_operations(
    operations, operation_ids, by_id, group, filters, handle, alias,
):
    records = [grant['record'] for grant in group['grants']]
    _require_one_terminal(records, group['label'])
    record = records[0]
    content_model = group['model']
    user = _sentinel(record.user_model, record.user_target, alias=alias)
    permission = _sentinel(
        record.permission_model, record.permission_target, alias=alias,
    )
    pieces = _group_pieces(by_id, group['grants'])
    granted = _compile_granted(
        (handle,), _content_sentinel(content_model, alias), user,
        permission, kind='complete',
    )
    if granted is None:
        raise TrustsConfigurationError(
            'Policy SQL render found no grant for %s.' % group['label']
        )
    instance = _content_sentinel(content_model, alias)
    exists_sql, exists_params = _compile_exists(
        content_model._default_manager.using(alias).filter(
            pk=instance.pk,
        ).filter(granted),
        alias, record, None, records,
    )
    _append_factored(
        operations, operation_ids,
        'has_perm_permission_instance:%s' % group['label'],
        'has_perm_permission_instance',
        _REASON_INSTANCE,
        exists_sql, exists_params, pieces,
    )
    from trusts.backends import _permission_binding

    binding = _permission_binding(
        _permission_probe(content_model), content_model,
    )
    granted_code = _compile_granted(
        (handle,), instance, user, binding, kind='complete',
    )
    if granted_code is None:
        raise TrustsConfigurationError(
            'Policy SQL render found no permission-code grant for %s.'
            % group['label']
        )
    code_sql, code_params = _compile_exists(
        content_model._default_manager.using(alias).filter(
            pk=instance.pk,
        ).filter(granted_code),
        alias, record, None, records,
    )
    _append_factored(
        operations, operation_ids,
        'has_perm_permission_code:%s' % group['label'],
        'has_perm_permission_code',
        _REASON_CODE,
        code_sql, code_params, pieces,
    )
    for row in filters:
        if row['model_cls'] is not content_model:
            continue
        from trusts.conditions._ir import compile_expression_q

        compiled = compile_expression_q(
            row['expr'], content_model, user, permission,
        )
        combined = content_model._default_manager.using(alias).filter(
            granted & compiled,
        ).distinct()
        sql, params = _compile_queryset(
            combined, alias, record=record, expr=row['expr'],
            records=tuple(records),
        )
        and_pieces = list(pieces)
        predicate_id = 'predicate:%s:%s' % (row['model'], row['code'])
        predicate = by_id.get(predicate_id)
        if predicate is not None:
            and_pieces.append(predicate)
        elif pieces:
            # A grant reference without the predicate would describe a
            # different composition than the one compiled. Store full SQL.
            and_pieces = []
        _append_factored(
            operations, operation_ids,
            'authorized_and_named_filter:%s:%s' % (
                row['model'], row['code'],
            ),
            'authorized_and_named_filter',
            _REASON_AND,
            sql, params, and_pieces,
        )
    if len(records) > 1:
        listed = content_model._default_manager.using(alias).all()
        granted_all = _compile_granted(
            (handle,), listed, user, permission, kind='complete',
        )
        if granted_all is None:
            raise TrustsConfigurationError(
                'Policy SQL render found no OR grant for %s.'
                % group['label']
            )
        sql, params = _compile_queryset(
            listed.filter(granted_all).distinct(), alias, record=record,
            expr=None, records=tuple(records),
        )
        _append_factored(
            operations, operation_ids,
            'or_group_authorized:%s' % group['label'],
            'or_group_authorized',
            _REASON_OR,
            sql, params, pieces,
        )
    listed = content_model._default_manager.using(alias).all()
    granted_rows = _compile_granted(
        (handle,), listed, user, permission, kind='complete',
    )
    if granted_rows is None:
        raise TrustsConfigurationError(
            'Policy SQL render found no queryset grant for %s.'
            % group['label']
        )
    query = _capture_aggregate_query(listed, granted_rows, alias)
    sql, params = _compile_queryset(
        _ComposedQuery(query), alias, record=record, expr=None,
        records=tuple(records),
    )
    _append_factored(
        operations, operation_ids,
        'queryset_has_perm:%s' % group['label'],
        'queryset_has_perm',
        _REASON_QUERYSET,
        sql, params, pieces,
    )


def _require_one_terminal(records, label):
    user_models = {
        record.user_model._meta.concrete_model for record in records
    }
    permission_models = {
        record.permission_model._meta.concrete_model for record in records
    }
    if len(user_models) != 1 or len(permission_models) != 1:
        raise TrustsConfigurationError(
            'Composed policy SQL for %s requires one user model and one '
            'permission model.' % label
        )


def _group_pieces(by_id, grants):
    pieces = []
    for grant in grants:
        row = by_id.get('grant:%s' % grant['id'])
        if row is None:
            return []
        pieces.append(row)
    return pieces


def _append_factored(
    operations, operation_ids, operation_id, kind, reason, sql, params,
    pieces,
):
    if operation_id in operation_ids:
        raise TrustsConfigurationError(
            'Duplicate composition operation %s.' % operation_id
        )
    operation_ids.add(operation_id)
    template, refs = _template_for(sql, params, pieces)
    if template is None:
        operation = _full_operation(
            operation_id, kind, reason, sql, params,
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


def _full_operation(operation_id, kind, reason, sql, params):
    return {
        'id': operation_id,
        'kind': kind,
        'representation': 'full_sql',
        'reason': reason,
        'expanded': {
            'sql': sql,
            'params': params,
        },
    }


def _template_for(sql, params, pieces):
    """Return ``(template, refs)`` when every piece is an exact span."""
    if not pieces:
        return None, None
    if '{{' in sql:
        return None, None
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
        if (
            '%s' in placeholder
            or placeholder in frag_sql
            or placeholder in sql
        ):
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


def _verify_composed_operations(fragments, operations):
    """Fail unless every structured operation expands to its compiler SQL.

    Fragment parameters must occupy one contiguous span of the expanded
    parameter list, in reference order. Parameters outside those spans
    stay in the compiler's order. A missing reference or a second use
    of the same placeholder fails the render.
    """
    by_id = {}
    for row in fragments:
        if row['id'] in by_id:
            raise TrustsConfigurationError(
                'Duplicate composition fragment %s.' % row['id']
            )
        if '{{' in row['sql']:
            raise TrustsConfigurationError(
                'Composition cycle: fragment %s contains a reference '
                'token. Fragments are leaves.' % row['id']
            )
        by_id[row['id']] = row
    seen_ops = set()
    for operation in operations:
        if operation['id'] in seen_ops:
            raise TrustsConfigurationError(
                'Duplicate composition operation %s.' % operation['id']
            )
        seen_ops.add(operation['id'])
        structured = operation.get('structured')
        if structured is None:
            continue
        expanded = operation['expanded']
        sql = _substitute(structured['sql'], structured['refs'], by_id)
        if sql != expanded['sql']:
            raise TrustsConfigurationError(
                'Composition template for %s does not expand to the '
                'compiled statement.' % operation['id']
            )
        _assert_param_span(
            expanded['sql'], expanded['params'], structured['refs'], by_id,
        )


def _assert_param_span(sql, params, refs, fragments):
    remaining_sql = sql
    remaining = list(params)
    built = []
    for ref in refs:
        frag = fragments.get(ref['fragment'])
        if frag is None:
            raise TrustsConfigurationError(
                'Missing composition reference %s.' % ref['fragment']
            )
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
    if remaining or built != list(params):
        raise TrustsConfigurationError(
            'Composition parameter expansion does not match compiler order.'
        )


def _substitute(template, refs, fragments):
    sql = template
    for ref in refs:
        placeholder = ref['placeholder']
        expected = '{{%s}}' % ref['fragment']
        if placeholder != expected:
            raise TrustsConfigurationError(
                'Composition placeholder %s does not name %s.'
                % (placeholder, ref['fragment'])
            )
        frag = fragments.get(ref['fragment'])
        if frag is None:
            raise TrustsConfigurationError(
                'Missing composition reference %s.' % ref['fragment']
            )
        frag_sql = frag['sql']
        if '{{' in frag_sql:
            raise TrustsConfigurationError(
                'Composition cycle: fragment %s contains a reference '
                'token. Fragments are leaves.' % ref['fragment']
            )
        if sql.count(placeholder) != 1:
            raise TrustsConfigurationError(
                'Placeholder %s must occur once.' % placeholder
            )
        sql = sql.replace(placeholder, frag_sql, 1)
    if '{{' in sql:
        raise TrustsConfigurationError(
            'Composition template left an unresolved reference.'
        )
    return sql


def _grant_fragment_span(sql, params):
    bodies = _exists_bodies(sql)
    if len(bodies) != 1:
        return None
    body = bodies[0]
    if body == '' or sql.count(body) != 1 or '{{' in body:
        return None
    index = sql.find(body)
    before = sql[:index].count('%s')
    width = body.count('%s')
    if sql.count('%s') != len(params) or before + width > len(params):
        return None
    return body, list(params[before:before + width])


def _predicate_span(sql, params):
    marker = ' WHERE '
    where = sql.find(marker)
    if where < 0:
        return None
    predicate = sql[where + len(marker):]
    if predicate == '' or sql.count(predicate) != 1 or '{{' in predicate:
        return None
    before = sql[:where + len(marker)].count('%s')
    width = predicate.count('%s')
    if before + width != len(params) or sql.count('%s') != len(params):
        return None
    return predicate, list(params[before:before + width])


def _compile_exists(queryset, alias, record, expr, records):
    exists_query = queryset.query.exists(limit=True)
    return _compile_queryset(
        _ComposedQuery(exists_query), alias, record=record, expr=expr,
        records=tuple(records),
    )


def _capture_aggregate_query(queryset, granted_q, alias):
    """Return the ``all_match`` aggregate query without executing it.

    ``QuerySet.aggregate`` compiles through ``Query.get_aggregation``
    and then asks that compiler to execute. A capturing compiler is
    installed on this thread's connection for that call and the
    connection is restored before anything else compiles. The Django
    compiler class is not modified.
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
            'Policy SQL render did not capture queryset has_perm SQL.'
        )
    return captured['query']


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
                'Policy SQL render found an unclosed EXISTS.'
            )
        bodies.append(sql[found + len(needle):index - 1])
        start = index


def _content_sentinel(model, alias):
    pk = model._meta.pk
    return _sentinel(model, pk.attname, alias=alias)


def _permission_probe(model):
    meta = model._meta
    return '%s.change_%s' % (meta.app_label, meta.model_name)


class _ComposedQuery(object):
    def __init__(self, query):
        self.query = query


def _compile_authorized(record, alias):
    user = _sentinel(record.user_model, record.user_target, alias=alias)
    permission = _sentinel(
        record.permission_model, record.permission_target, alias=alias,
    )
    plan = RelationPlan(
        records=(record,),
        permission_model=record.permission_model,
    )
    queryset = plan.filter_content(
        record.content_model._default_manager.all(),
        user,
        permission,
    )
    return _compile_queryset(queryset, alias, record=record, expr=None)


def _compile_named_filter(model, expr, alias):
    from trusts.conditions._ir import compile_expression_q

    compiled = compile_expression_q(
        expr, model,
        _any_sentinel_user(alias),
        _any_sentinel_permission(alias),
    )
    queryset = model._default_manager.filter(compiled)
    return _compile_queryset(queryset, alias, record=None, expr=expr)


def _any_sentinel_user(alias):
    from django.contrib.auth import get_user_model

    user_model = get_user_model()
    return _sentinel(user_model, user_model._meta.pk.attname, alias=alias)


def _any_sentinel_permission(alias):
    from django.contrib.auth.models import Permission

    return _sentinel(Permission, Permission._meta.pk.attname, alias=alias)


def _sentinel(model, target_attname, *, alias):
    """Unsaved instance whose PK and target field preparation succeeds.

    The value is deterministic for a concrete field and is never written.
    Django rejects related lookups whose primary key is unset, so the PK
    is populated even when the comparison target is a different column.
    """
    instance = model()
    pk_field = model._meta.pk
    setattr(instance, pk_field.attname, _sentinel_value(pk_field, alias))
    if target_attname and target_attname != pk_field.attname:
        target = _concrete_target_field(model, target_attname)
        setattr(instance, target.attname, _sentinel_value(target, alias))
    return instance


def _concrete_target_field(model, attname):
    field = model._meta.get_field(attname)
    concrete = getattr(field, 'attname', None)
    if concrete == attname and not getattr(field, 'is_relation', False):
        return field
    for candidate in model._meta.concrete_fields:
        if candidate.attname == attname:
            return candidate
    return field


def _sentinel_value(field, alias):
    """Deterministic Python value ``field`` preparation accepts."""
    internal = field.get_internal_type()
    if internal in _INTEGER_SENTINEL_TYPES:
        return 1
    if internal == 'BooleanField':
        return True
    if internal == 'UUIDField':
        return uuid.UUID(int=1)
    if internal in _TEXT_SENTINEL_TYPES:
        return _text_sentinel(field)
    if internal == 'DecimalField':
        return Decimal('1')
    if internal == 'FloatField':
        return 1.0
    if internal == 'BinaryField':
        return b'\x01'
    if internal == 'DateField':
        return datetime.date(2000, 1, 1)
    if internal == 'DateTimeField':
        return _datetime_sentinel()
    if internal == 'TimeField':
        return datetime.time(0, 0)
    if internal == 'DurationField':
        return datetime.timedelta(seconds=1)
    if internal == 'JSONField':
        return {'sentinel': 1}
    return _fallback_sentinel(field, alias)


def _text_sentinel(field):
    internal = field.get_internal_type()
    if internal == 'EmailField':
        value = 's@e.test'
    elif internal == 'URLField':
        value = 'https://e.test/'
    elif internal == 'GenericIPAddressField':
        value = '127.0.0.1'
    else:
        value = '1'
    max_length = getattr(field, 'max_length', None)
    if (
        isinstance(max_length, int)
        and max_length >= 0
        and len(value) > max_length
    ):
        if max_length == 0:
            return ''
        return '1'[:max_length]
    return value


def _datetime_sentinel():
    from django.conf import settings

    if getattr(settings, 'USE_TZ', False):
        return datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    return datetime.datetime(2000, 1, 1)


def _fallback_sentinel(field, alias):
    from django.db import connections

    connection = connections[alias]
    candidates = (
        1,
        '1',
        True,
        1.0,
        Decimal('1'),
        b'\x01',
        uuid.UUID(int=1),
        datetime.date(2000, 1, 1),
        _datetime_sentinel(),
        datetime.time(0, 0),
        datetime.timedelta(seconds=1),
    )
    for candidate in candidates:
        try:
            field.get_db_prep_value(
                field.get_prep_value(candidate), connection, prepared=True,
            )
        except Exception:
            continue
        return candidate
    model = getattr(field, 'model', None)
    label = model._meta.label if model is not None else '?'
    raise TrustsConfigurationError(
        'Policy SQL render could not build an unsaved sentinel for %s.%s '
        '(%s).' % (label, field.attname, field.get_internal_type())
    )


def _compile_queryset(queryset, alias, *, record, expr, records=None):
    from django.db import connections

    _ctx.record = record
    _ctx.records = tuple(records) if records else None
    _ctx.filter_queues = None if expr is None else _filter_queues(expr)
    token = _export_scope.set(object())
    try:
        compiler = queryset.query.get_compiler(
            connection=_ExportConnection(connections[alias]),
        )
        sql, params = compiler.as_sql()
    finally:
        _export_scope.reset(token)
        _ctx.record = None
        _ctx.records = None
        _ctx.filter_queues = None
    if not isinstance(sql, str):
        raise TrustsConfigurationError(
            'Policy SQL render produced a non-text statement.'
        )
    return sql, _symbols_from_params(params)


@django_checks.register()
def check_policy_sql_lockfile(app_configs, **kwargs):
    """Compare the rendered policy SQL document to the lockfile.

    Untagged, so plain ``manage.py check`` runs it and tag-selected
    runs that omit untagged checks do not. A missing conventional file
    reports nothing, even when ``TRUSTS_POLICY_DATABASE`` is invalid:
    the check does not apply until that file is present or an explicit
    path is configured. When the check applies, a bad database alias,
    an explicit missing or unreadable file, and a byte mismatch report
    ``trusts.E009``. This is not a request-time authorization gate.
    """
    del app_configs, kwargs
    try:
        message = _lockfile_check_message()
    except TrustsConfigurationError as exc:
        message = str(exc)
    if message is None:
        return []
    return [django_checks.Error(
        message,
        hint=(
            'Silencing trusts.E009 removes the only lockfile enforcement. '
            'Regenerate the file with trusts_policy_sql --lock after '
            'reviewing the SQL.'
        ),
        obj=None,
        id=CHECK_ID_POLICY_LOCK,
    )]


def _lockfile_check_message():
    """Return an E009 message, or None when the check does not apply.

    Conventional absence is decided before the database alias is
    resolved. An invalid ``TRUSTS_POLICY_DATABASE`` is reported only
    when a conventional file is present or an explicit path is
    configured.
    """
    try:
        location = resolve_lockfile_path()
    except TrustsConfigurationError as exc:
        if _configured_lock_override() is None:
            return None
        resolve_policy_database(None)
        return str(exc)
    if not _lockfile_enforcement_applies(location):
        return None
    resolve_policy_database(None)
    action = _presence_action(location, writing=False)
    if action == 'inactive':
        return None
    raw = _read_lock_bytes(location)
    if raw is None:
        return None
    live = render_policy_sql_bytes()
    if raw == live:
        return None
    return 'Policy lock bytes differ: %s.' % location.path


def _lockfile_enforcement_applies(location):
    """True when this location is in the lockfile check's scope.

    An explicit path always applies. A conventional path applies only
    when the file is present (or cannot be classified as absence).
    """
    if location.explicit:
        return True
    return location.state not in (
        'absent', 'missing_parent', 'not_a_directory',
    )


def _filter_queues(expr):
    from trusts.conditions import _ir

    queues = {}

    def add(path, symbol):
        queues.setdefault(path, []).append(symbol)

    def walk(node):
        if isinstance(node, (_ir.And, _ir.Or)):
            walk(node.left)
            walk(node.right)
            return
        if isinstance(node, (_ir.Eq, _ir.Ne)):
            pair = _comparison_symbol(node)
            if pair is not None:
                add(pair[0], pair[1])

    if expr is not None:
        walk(expr)
    return queues


def _comparison_symbol(node):
    from trusts.conditions import _ir

    left = node.left
    right = node.right
    object_ref = None
    other = None
    for side in (left, right):
        if isinstance(side, _ir.Ref) and side.source == 'object':
            if object_ref is None:
                object_ref = side
            else:
                return None
        else:
            other = side
    if object_ref is None or other is None:
        return None
    if isinstance(other, _ir.Ref) and other.source == 'object':
        return None
    path = '__'.join(object_ref.path)
    if isinstance(other, _ir.Const):
        return path, {'const': _json_const(other.value)}
    if isinstance(other, _ir.Ref) and other.source == 'principal':
        if other.path:
            bind = 'user.%s' % '__'.join(other.path)
        else:
            bind = 'user.id'
        return path, {'bind': bind}
    if isinstance(other, _ir.Ref) and other.source == 'permission':
        return path, {'bind': 'permission.id'}
    return None


class _ExportOps(object):
    """Database operations that build export-scoped compilers only."""

    def __init__(self, ops):
        self._ops = ops

    def compiler(self, compiler_name):
        return _classifying_compiler(self._ops.compiler(compiler_name))

    def __getattr__(self, name):
        return getattr(self._ops, name)


class _ExportConnection(object):
    """Connection proxy whose compilers classify export placeholders.

    The real connection object is not mutated, and ``SQLCompiler.compile``
    is not replaced. Nested subquery compilers receive this same proxy,
    so they classify too. Other threads keep using Django's compiler.
    """

    def __init__(self, connection):
        self._connection = connection
        self.ops = _ExportOps(connection.ops)

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def __setattr__(self, name, value):
        if name in ('_connection', 'ops'):
            object.__setattr__(self, name, value)
            return
        setattr(self._connection, name, value)


def _classifying_compiler(base):
    cached = _classifying_classes.get(base)
    if cached is not None:
        return cached
    with _classifying_class_lock:
        cached = _classifying_classes.get(base)
        if cached is not None:
            return cached

        class ClassifyingCompiler(base):
            def compile(self, node):
                if _export_scope.get() is None:
                    return super().compile(node)
                sql, params = super().compile(node)
                return _classify_compiled(node, sql, params)

        ClassifyingCompiler.__name__ = 'Classifying%s' % base.__name__
        _classifying_classes[base] = ClassifyingCompiler
        return ClassifyingCompiler


def _classify_compiled(node, sql, params):
    if isinstance(params, tuple):
        params = list(params)
    else:
        params = list(params or ())
    tagged = []
    for param in params:
        if isinstance(param, _Symbol):
            tagged.append(param)
            continue
        symbol = _symbol_for_new_param(node)
        if symbol is None:
            raise TrustsConfigurationError(
                'Policy SQL render could not classify a %s placeholder.'
                % type(node).__name__
            )
        tagged.append(_Symbol(symbol))
    return sql, tagged


def _symbol_for_new_param(node):
    if isinstance(node, Value):
        return {'const': _json_const(node.value)}
    if not isinstance(node, Lookup):
        return None
    queued = _queued_filter_symbol(node)
    if queued is not None:
        return queued
    record = getattr(_ctx, 'record', None)
    if record is not None:
        bind = _bind_name(node, record)
        if bind is not None:
            return {'bind': bind}
    rhs = getattr(node, 'rhs', None)
    if rhs is not None and not hasattr(rhs, 'as_sql'):
        return {'const': _json_const(rhs)}
    return None


def _queued_filter_symbol(node):
    queues = getattr(_ctx, 'filter_queues', None)
    if not queues:
        return None
    path = _lookup_field_name(node)
    pending = queues.get(path) if path else None
    if not pending:
        return None
    return pending.pop(0)


def _bind_name(node, record):
    grouped = getattr(_ctx, 'records', None)
    if grouped:
        names = []
        for item in grouped:
            name = _bind_name_one(node, item)
            if name is not None and name not in names:
                names.append(name)
        if len(names) > 1:
            raise TrustsConfigurationError(
                'Policy SQL render found conflicting binds %s for one '
                'lookup.' % (names,)
            )
        if len(names) == 1:
            return names[0]
        return None
    if record is None:
        return None
    return _bind_name_one(node, record)


def _bind_name_one(node, record):
    target = getattr(getattr(node, 'lhs', None), 'target', None)
    if target is None:
        return None
    remote = getattr(target, 'remote_field', None)
    model = getattr(remote, 'model', None) if remote is not None else None
    if model is None:
        return None
    concrete = model._meta.concrete_model
    if concrete is record.user_model._meta.concrete_model:
        return 'user.%s' % record.user_target
    if concrete is record.permission_model._meta.concrete_model:
        return 'permission.%s' % record.permission_target
    return None


def _lookup_field_name(node):
    """Field name that matches a condition path for this lookup.

    Relation lookups compile against the remote target column. The
    output field keeps the relation name (``owner``), which is the path
    stored on the condition. Scalar lookups use that same output field.
    """
    lhs = getattr(node, 'lhs', None)
    for attr in ('output_field', 'target'):
        field = getattr(lhs, attr, None)
        name = getattr(field, 'name', None)
        if isinstance(name, str) and name != '':
            return name
    return None


def _symbols_from_params(params):
    symbols = []
    for param in params:
        if not isinstance(param, _Symbol):
            raise TrustsConfigurationError(
                'Policy SQL render left an unclassified placeholder.'
            )
        symbols.append(param.payload)
    return symbols


def _json_const(value):
    """In-document value for one condition constant.

    ``null``, booleans, strings, integers, and finite floats stay bare
    scalars. ``1`` and ``1.0`` stay distinct, and ``-0.0`` keeps its
    sign. Bytes, ``Decimal``, ``UUID``, dates, times, datetimes,
    timedeltas, non-finite floats, and ``ModelIdentity`` use a tagged
    mapping (``type`` plus fields). The YAML codec writes those
    mappings as ordinary mappings and quotes every string inside them,
    so YAML 1.1 does not reinterpret dates, bool words, or decimals.
    """
    from trusts.conditions._ir import ModelIdentity

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {'type': 'float', 'value': 'NaN'}
        if math.isinf(value):
            return {
                'type': 'float',
                'value': 'Infinity' if value > 0 else '-Infinity',
            }
        return value
    if isinstance(value, bytes):
        return {'type': 'bytes', 'hex': value.hex()}
    if isinstance(value, Decimal):
        if value.is_nan():
            text = 'NaN'
        elif not value.is_finite():
            text = 'Infinity' if value > 0 else '-Infinity'
        else:
            text = str(value)
        return {'type': 'decimal', 'value': text}
    if isinstance(value, uuid.UUID):
        return {'type': 'uuid', 'value': str(value)}
    if isinstance(value, datetime.datetime):
        return {'type': 'datetime', 'value': value.isoformat()}
    if isinstance(value, datetime.date):
        return {'type': 'date', 'value': value.isoformat()}
    if isinstance(value, datetime.time):
        return {'type': 'time', 'value': value.isoformat()}
    if isinstance(value, datetime.timedelta):
        return {
            'type': 'timedelta',
            'days': value.days,
            'seconds': value.seconds,
            'microseconds': value.microseconds,
        }
    if isinstance(value, ModelIdentity):
        return {
            'type': 'model',
            'app_label': value.app_label,
            'model': value.model_name,
            'pk': _json_const(value.pk),
        }
    raise TrustsConfigurationError(
        'Policy SQL render cannot record constant %r (%s).'
        % (value, type(value).__name__)
    )


def _const_from_json(value):
    """Inverse of :func:`_json_const` for one recorded constant value."""
    from trusts.conditions._ir import ModelIdentity

    if isinstance(value, dict):
        kind = value.get('type')
        if kind == 'float':
            return float(value['value'])
        if kind == 'bytes':
            return bytes.fromhex(value['hex'])
        if kind == 'decimal':
            return Decimal(value['value'])
        if kind == 'uuid':
            return uuid.UUID(value['value'])
        if kind == 'date':
            return datetime.date.fromisoformat(value['value'])
        if kind == 'time':
            return datetime.time.fromisoformat(value['value'])
        if kind == 'datetime':
            return datetime.datetime.fromisoformat(value['value'])
        if kind == 'timedelta':
            return datetime.timedelta(
                days=value['days'],
                seconds=value['seconds'],
                microseconds=value['microseconds'],
            )
        if kind == 'model':
            return ModelIdentity(
                value['app_label'],
                value['model'],
                _const_from_json(value['pk']),
            )
        raise TrustsConfigurationError(
            'Policy SQL render found an unknown constant tag %r.' % (kind,)
        )
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return value
    raise TrustsConfigurationError(
        'Policy SQL render cannot restore constant %r (%s).'
        % (value, type(value).__name__)
    )


def _model_label(model):
    meta = getattr(model, '_meta', None)
    label = getattr(meta, 'label', None)
    if not isinstance(label, str) or label == '':
        raise TrustsConfigurationError(
            'Policy SQL render expected a model, not %r.' % (model,)
        )
    return label


def _dump_document(document):
    try:
        return dump_policy_yaml(document)
    except PolicyYamlError as exc:
        raise TrustsConfigurationError(str(exc)) from exc


def _load_policy_sql_document(payload):
    """Private diagnostic helper for a schema-1 policy document.

    Not a supported public API and not a two-directional mapping
    contract. Tests use it for coding completeness. ``trusts.E009``
    does not call this. Equality is raw bytes against
    :func:`render_policy_sql_bytes`.

    :func:`_load_policy_yaml` parses the payload, re-dumps it with the
    canonical writer, and rejects the input unless the bytes are
    identical.
    """
    try:
        document = _load_policy_yaml(payload)
    except PolicyYamlError as exc:
        raise TrustsConfigurationError(str(exc)) from exc
    if not isinstance(document, dict):
        raise TrustsConfigurationError(
            'Policy SQL document must be a mapping.'
        )
    return document


def _configured_lock_override():
    from django.conf import settings

    if not settings.configured:
        return None
    return getattr(settings, 'TRUSTS_POLICY_LOCKFILE', None)


def _usable_base_dir():
    from django.conf import settings

    if not settings.configured:
        return None
    base = getattr(settings, 'BASE_DIR', None)
    if base is None or isinstance(base, bool):
        return None
    if not isinstance(base, (str, os.PathLike)):
        return None
    text = os.fspath(base)
    if not isinstance(text, str) or text == '':
        return None
    path = Path(text)
    if not path.is_absolute():
        return None
    return path


def _absolute_lock_path(value):
    if isinstance(value, bool) or not isinstance(value, (str, os.PathLike)):
        raise TrustsConfigurationError(
            'Policy lock path must be an absolute path, not %s. It is not '
            'resolved against the process working directory.'
            % type(value).__name__
        )
    text = os.fspath(value)
    if not isinstance(text, str):
        raise TrustsConfigurationError(
            'Policy lock path must be an absolute path, not %s. It is not '
            'resolved against the process working directory.'
            % type(text).__name__
        )
    if not Path(text).is_absolute():
        raise TrustsConfigurationError(
            'Policy lock path must be absolute, not %r. It is not resolved '
            'against the process working directory.' % (text,)
        )
    return Path(text)


def _classify_lockfile(path):
    """Classify ``path`` without searching parents for a lockfile."""
    parent = path.parent
    try:
        parent_mode = os.stat(parent).st_mode
    except FileNotFoundError:
        return 'missing_parent'
    except PermissionError:
        return 'permission'
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return 'permission'
        raise
    if not stat.S_ISDIR(parent_mode):
        return 'not_a_directory'
    try:
        os.lstat(path)
    except FileNotFoundError:
        return 'absent'
    except PermissionError:
        return 'permission'
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return 'permission'
        raise
    return 'present'


def _presence_action(location, *, writing):
    """Map presence to inactive, create, or present. Fail closed otherwise."""
    state = location.state
    path = location.path
    if state == 'permission':
        raise TrustsConfigurationError(
            'Policy lock permission denied: %s.' % path
        )
    if state == 'missing_parent':
        if location.explicit or writing:
            raise TrustsConfigurationError(
                'Policy lock parent directory is missing: %s.' % path.parent
            )
        return 'inactive'
    if state == 'not_a_directory':
        if location.explicit or writing:
            raise TrustsConfigurationError(
                'Policy lock parent is not a directory: %s.' % path.parent
            )
        return 'inactive'
    if state == 'absent':
        if writing:
            return 'create'
        if location.explicit:
            raise TrustsConfigurationError(
                'Policy lock file is missing: %s.' % path
            )
        return 'inactive'
    if state == 'present':
        return 'present'
    raise TrustsConfigurationError(
        'Policy lock path state %r is unsupported.' % (state,)
    )


def _require_writable_parent(location):
    action = _presence_action(location, writing=True)
    if action not in ('create', 'present'):
        raise TrustsConfigurationError(
            'Policy lock path %s cannot be written (state %s).'
            % (location.path, location.state)
        )
    return action


def _lockfile_is_directory(path):
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode)


def _read_lock_bytes(location):
    """Return lockfile bytes, or None if a conventional file vanished.

    A directory path, permission failure, and an explicit missing file
    fail closed. A conventional file that disappears between classify
    and read is absence, not drift. This does not search parent
    directories and does not issue SQL.
    """
    if _lockfile_is_directory(location.path):
        raise TrustsConfigurationError(
            'Policy lock path is a directory: %s.' % location.path
        )
    try:
        return location.path.read_bytes()
    except PermissionError as exc:
        raise TrustsConfigurationError(
            'Policy lock permission denied: %s.' % location.path
        ) from exc
    except FileNotFoundError:
        if location.explicit:
            raise TrustsConfigurationError(
                'Policy lock file is missing: %s.' % location.path
            )
        return None


def _atomic_write(path, payload):
    """Replace ``path`` via a temp file in the same directory. No CWD."""
    parent = path.parent
    fd = None
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix='.trusts-policy.',
            suffix='.tmp',
            dir=os.fspath(parent),
        )
        with os.fdopen(fd, 'wb') as handle:
            fd = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, os.fspath(path))
        tmp_name = None
    except PermissionError as exc:
        raise TrustsConfigurationError(
            'Policy lock permission denied: %s.' % path
        ) from exc
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise TrustsConfigurationError(
                'Policy lock permission denied: %s.' % path
            ) from exc
        if exc.errno in (errno.EISDIR, errno.ENOTDIR):
            raise TrustsConfigurationError(
                'Policy lock path is a directory: %s.' % path
            ) from exc
        raise TrustsConfigurationError(
            'Policy lock could not be written: %s.' % (exc,)
        ) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
