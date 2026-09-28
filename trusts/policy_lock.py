"""Finalized authorization-policy snapshot (lockfile C1, issue #147).

Projects frozen relationship registries into an immutable snapshot and a
detached JSON-ready document. Registration fingerprints and readable
labels are derived here. Runtime verification, lockfile read/write,
``int_dec`` constant decoding, and commutative named-filter boolean
normalization are later slices and are not performed.

The portable document never contains runtime object identity, source
locations, or database credentials. Callers cannot select a database
alias: the renderer profile is always Django's ``DEFAULT_DB_ALIAS``
resolved through ``django.db.connections``, with zero SQL.
"""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType

from trusts.core import (
    All,
    Equal,
    PermissionIn,
    Ref,
    TrustsConfigurationError,
)

SCHEMA_VERSION = 1
COMPILER_VERSION = 1

RELATIONSHIP_FAMILY = 'relationship'
SQLITE_JSON1_RCTE_PROFILE = 'django_sqlite3_json1_rcte'
GENERIC_UNSUPPORTED_ALONG_PROFILE = 'django_generic_unsupported_along'
PROFILE_VERSION = 1
ALONG_SUPPORTED = 'supported'
ALONG_UNSUPPORTED = 'unsupported'
_DUMMY_ENGINE = 'django.db.backends.dummy'
_IEEE_SAFE_INT = 2**53 - 1

_REGISTRATION_KEYS = (
    'kind',
    'root',
    'user',
    'user_model',
    'user_target',
    'permission',
    'permission_model',
    'permission_target',
    'content',
    'content_model',
    'content_target',
    'condition',
    'along',
)

_ALONG_KEYS = (
    'bound',
    'shape',
    'walk_path',
    'walk_model',
    'walk_ident',
    'suffix_path',
    'ident_family',
    'parent_attname',
    'edge_model',
    'edge_parent_attname',
    'edge_child_attname',
    'rewrite_attname',
)

class PolicyManifest(object):
    """Frozen snapshot. Not the lockfile document and not a live registry.

    Use :func:`manifest_to_json_data` for a detached JSON-ready copy.
    Attribute assignment is rejected. The stored value is a read-only
    tree of strings, numbers, booleans, ``None``, tuples, and mapping
    proxies — never ``RegisteredRelation``, ``AlongWalk``, or ``Expr``.
    """

    __slots__ = ('_document',)

    def __init__(self, document):
        object.__setattr__(self, '_document', _freeze(document))

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('PolicyManifest is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('PolicyManifest is immutable.')

    def __eq__(self, other):
        if not isinstance(other, PolicyManifest):
            return NotImplemented
        return self._document == other._document

    def __repr__(self):
        return '<PolicyManifest schema=%s handles=%s>' % (
            self._document['schema_version'],
            len(self._document['handles']),
        )


def build_policy_manifest(handles=None, *, alias=None):
    """Project finalized handles into an immutable policy snapshot.

    ``handles`` defaults to every configured implementation handle, in
    owner-then-path discovery order. The returned document sorts handles
    by configured path. ``alias`` is not a selection channel: any
    supplied value is ignored, including a real non-default database
    alias. The recorded renderer is always Django's default connection.

    An unfrozen registry, a missing or duplicate implementation owner,
    an unsupported authorization family, an Along registration on a
    renderer whose ``along`` is not ``supported``, or a non-portable
    named-filter constant fails closed. Ownership is the exact
    configured implementation for the path, not the authorization
    helper's permissive family fallback. This function does not freeze
    registries, open a connection, or probe the server.
    """
    del alias  # Caller-selected aliases never choose the verify target.
    if handles is None:
        from trusts.apps import configured_implementation_handles

        handles = configured_implementation_handles()
    renderer = _resolve_default_renderer()
    projected = [
        _project_handle(handle, renderer) for handle in handles
    ]
    projected.sort(key=_handle_sort_key)
    return PolicyManifest({
        'schema_version': SCHEMA_VERSION,
        'compiler_version': COMPILER_VERSION,
        'handles': projected,
    })


def fingerprint_registration(payload):
    """Return ``sha256:`` plus the lowercase hex of the canonical payload.

    ``payload`` is the registration semantic object (kind, paths, models,
    targets, condition, along).     Derived ``fingerprint`` and ``label``
    keys are accepted and ignored. Every other unexpected key is
    rejected, recursively, at the registration, closed-condition, and
    Along levels. Each closed-condition op is checked for its required
    keys before those keys are read: ``all`` requires ``predicates``,
    ``equal`` requires ``left`` and ``right``, and ``permission_in``
    requires ``refs``. A missing key is a configuration error. Path
    components must already be strings; they are not coerced. Key order
    does not affect the digest. Closed ``all`` / ``equal`` /
    ``permission_in`` nodes are normalized so commutative order is not
    identity.
    """
    if isinstance(payload, MappingProxyType):
        payload = dict(payload)
    if not isinstance(payload, dict):
        raise TypeError(
            'fingerprint_registration payload must be a dict, not %s.'
            % type(payload).__name__
        )
    ordered = _canonicalize_registration(payload)
    return _digest(_canonical_bytes(ordered))


def manifest_to_json_data(manifest):
    """Return a detached JSON-ready dict.

    The result shares no mutable containers with ``manifest`` or with
    any live registry object. A later mutation of the returned value
    does not change the snapshot or a second conversion.
    """
    if not isinstance(manifest, PolicyManifest):
        raise TypeError(
            'manifest_to_json_data expected a PolicyManifest, not %s.'
            % type(manifest).__name__
        )
    return _thaw(manifest._document)


def _digest(payload_bytes):
    return 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()


def _canonical_bytes(obj):
    """Quiet UTF-8 form used as the registration fingerprint input.

    Same serializer the lockfile generator will use for the document
    (indent 2, schema key order, trailing LF). Full-file quiet
    regeneration and the nonsemantic ``diagnostics`` reader stay in a
    later slice; this helper only feeds fingerprints.
    """
    text = json.dumps(
        obj,
        ensure_ascii=False,
        indent=2,
        separators=(',', ': '),
        sort_keys=False,
    )
    if not text.endswith('\n'):
        text += '\n'
    return text.encode('utf-8')


def _resolve_default_renderer():
    """Project the default Django connection without connecting."""
    from django.core.exceptions import ImproperlyConfigured
    from django.db import connections
    from django.db.utils import DEFAULT_DB_ALIAS, ConnectionDoesNotExist

    from trusts.core import along_connection_supported

    alias = DEFAULT_DB_ALIAS
    if not isinstance(alias, str) or alias == '':
        raise TrustsConfigurationError(
            'Django DEFAULT_DB_ALIAS is missing or malformed: %r.'
            % (alias,)
        )
    try:
        connection = connections[alias]
    except (ConnectionDoesNotExist, ImproperlyConfigured, KeyError) as exc:
        raise TrustsConfigurationError(
            'Policy lock cannot resolve Django default database alias '
            '%r: %s' % (alias, exc)
        ) from exc
    settings_dict = getattr(connection, 'settings_dict', None)
    if not isinstance(settings_dict, dict):
        raise TrustsConfigurationError(
            'Policy lock renderer alias %r has a malformed settings_dict, '
            'not %s.' % (alias, type(settings_dict).__name__)
        )
    engine = settings_dict.get('ENGINE')
    if (
        not isinstance(engine, str)
        or engine == ''
        or engine == _DUMMY_ENGINE
    ):
        raise TrustsConfigurationError(
            'Policy lock renderer alias %r has a missing or malformed '
            'ENGINE: %r.' % (alias, engine)
        )
    if along_connection_supported(connection):
        profile = SQLITE_JSON1_RCTE_PROFILE
        along = ALONG_SUPPORTED
    else:
        profile = GENERIC_UNSUPPORTED_ALONG_PROFILE
        along = ALONG_UNSUPPORTED
    return {
        'alias': alias,
        'engine': engine,
        'profile': profile,
        'profile_version': PROFILE_VERSION,
        'along': along,
    }


def _project_handle(handle, renderer):
    path = getattr(handle, 'path', None)
    if not isinstance(path, str) or path == '':
        raise TrustsConfigurationError(
            'Policy snapshot handle is missing a configured path: %r.'
            % (path,)
        )
    family = _family_for_path(path)
    if family != RELATIONSHIP_FAMILY:
        raise TrustsConfigurationError(
            'Core lockfile v1 only serializes family %r; backend path %r '
            'has unsupported family %r.'
            % (RELATIONSHIP_FAMILY, path, family)
        )
    registry = getattr(handle, 'registry', None)
    if registry is None or not getattr(registry, 'frozen', False):
        raise TrustsConfigurationError(
            'Policy snapshot requires a frozen registry for backend '
            'path %r.' % (path,)
        )
    compiler = _compiler_identity(getattr(handle, 'compiler', None), path)
    registrations = _project_registrations(registry, path)
    named_filters = _project_named_filters(registry)
    if renderer['along'] != ALONG_SUPPORTED and any(
        row['along'] is not None for row in registrations
    ):
        raise TrustsConfigurationError(
            'Along registration on %r cannot execute: renderer alias %r '
            'engine %r profile %r reports along %r. Core lockfile '
            'snapshot does not open a connection or probe the server.'
            % (
                path,
                renderer['alias'],
                renderer['engine'],
                renderer['profile'],
                renderer['along'],
            )
        )
    return {
        'path': path,
        'family': family,
        'compiler': compiler,
        'renderer': dict(renderer),
        'registrations': registrations,
        'named_filters': named_filters,
    }


def _family_for_path(path):
    """Exact configured owner/family for a lockfile snapshot.

    ``_handle_authorization_family`` turns a missing owner and a
    duplicate-owner error into ``"relationship"`` so isolated
    authorization tests keep working. A manifest must not. This
    resolver calls ``implementation_for_path`` and fails closed.
    """
    from trusts.apps import implementation_for_path

    try:
        config = implementation_for_path(path)
    except TrustsConfigurationError as exc:
        raise TrustsConfigurationError(
            'Policy snapshot cannot bind an exact owner for backend '
            'path %r: %s' % (path, exc)
        ) from exc
    family = getattr(config, '_authorization_family', None)
    if not isinstance(family, str) or family == '':
        raise TrustsConfigurationError(
            'Policy snapshot backend path %r has a missing or malformed '
            'authorization family: %r.' % (path, family)
        )
    return family


def _compiler_identity(compiler, path):
    """Importable module-qualified class identity that round-trips.

    Local and dynamic classes (``<locals>``, ``type()`` results that
    are not module attributes) are rejected. The returned string is
    suitable for ``import_string`` in another process.
    """
    from django.utils.module_loading import import_string

    if isinstance(compiler, type):
        cls = compiler
    elif compiler is not None:
        cls = type(compiler)
    else:
        cls = None
    module = getattr(cls, '__module__', None) if cls is not None else None
    qualname = getattr(cls, '__qualname__', None) if cls is not None else None
    identity = None
    if isinstance(module, str) and isinstance(qualname, str):
        identity = '%s.%s' % (module, qualname)
    portable = (
        isinstance(module, str)
        and isinstance(qualname, str)
        and module not in ('', 'builtins', '__main__')
        and qualname != ''
        and '<' not in qualname
        and '>' not in qualname
    )
    if portable:
        try:
            resolved = import_string(identity)
        except Exception as exc:
            raise TrustsConfigurationError(
                'Policy snapshot backend %r compiler %r is not a portable '
                'importable type identity (got %r): %s'
                % (path, compiler, identity, exc)
            ) from exc
        if resolved is cls:
            return identity
    raise TrustsConfigurationError(
        'Policy snapshot backend %r compiler %r is not a portable '
        'importable type identity (got %r).'
        % (path, compiler, identity)
    )


def _project_registrations(registry, path):
    payloads = []
    for record in registry.records:
        payloads.append(_registration_payload(record, path))
    fingerprints = [fingerprint_registration(payload) for payload in payloads]
    labels = _labels(payloads, fingerprints)
    rows = []
    for fingerprint, label, payload in zip(fingerprints, labels, payloads):
        row = {'fingerprint': fingerprint, 'label': label}
        row.update(payload)
        rows.append(row)
    rows.sort(key=lambda row: row['fingerprint'])
    return rows


def _registration_payload(record, path):
    root = getattr(record, 'root', None)
    root_label = _model_label(root, 'registration root on %r' % (path,))
    condition = _project_condition(
        getattr(record, 'condition', None), root_label,
    )
    along = _project_along(getattr(record, 'along', None), root_label)
    return _canonicalize_registration({
        'kind': 'any_path',
        'root': root_label,
        'user': _path_list(record, 'user_path', root_label),
        'user_model': _model_label(
            getattr(record, 'user_model', None),
            'user model on %s' % root_label,
        ),
        'user_target': _target(record, 'user_target', root_label),
        'permission': _path_list(record, 'permission_path', root_label),
        'permission_model': _model_label(
            getattr(record, 'permission_model', None),
            'permission model on %s' % root_label,
        ),
        'permission_target': _target(record, 'permission_target', root_label),
        'content': _path_list(record, 'content_path', root_label),
        'content_model': _model_label(
            getattr(record, 'content_model', None),
            'content model on %s' % root_label,
        ),
        'content_target': _target(record, 'content_target', root_label),
        'condition': condition,
        'along': along,
    })


def _path_list(record, attr, root_label):
    value = getattr(record, attr, None)
    if not isinstance(value, tuple) or not all(isinstance(part, str) for part in value):
        raise TrustsConfigurationError(
            'Registration on %s has a non-portable %s: %r.'
            % (root_label, attr, value)
        )
    if not value:
        raise TrustsConfigurationError(
            'Registration on %s has an empty %s.' % (root_label, attr)
        )
    return list(value)


def _target(record, attr, root_label):
    value = getattr(record, attr, None)
    if not isinstance(value, str) or value == '':
        raise TrustsConfigurationError(
            'Registration on %s has a non-portable %s: %r.'
            % (root_label, attr, value)
        )
    return value


def _model_label(model, what):
    meta = getattr(model, '_meta', None)
    label = getattr(meta, 'label', None)
    if not isinstance(label, str) or label == '':
        raise TrustsConfigurationError(
            'Policy snapshot %s is not a model: %r.' % (what, model)
        )
    return label


def _project_condition(condition, root_label):
    if condition is None:
        return None
    return _canonicalize_condition(_condition_node(condition, root_label))


def _condition_node(condition, root_label):
    if isinstance(condition, All):
        return {
            'op': 'all',
            'predicates': [
                _condition_node(predicate, root_label)
                for predicate in condition.predicates
            ],
        }
    if isinstance(condition, Equal):
        return {
            'op': 'equal',
            'left': _condition_ref_path(condition.left, root_label),
            'right': _condition_ref_path(condition.right, root_label),
        }
    if isinstance(condition, PermissionIn):
        return {
            'op': 'permission_in',
            'refs': [
                _condition_ref_path(ref, root_label) for ref in condition.refs
            ],
        }
    raise TrustsConfigurationError(
        'Registration on %s has unsupported closed condition %s.'
        % (root_label, type(condition).__name__)
    )


def _condition_ref_path(ref, root_label):
    if isinstance(ref, Ref):
        return list(ref._path)
    path = getattr(ref, '_path', None)
    if isinstance(path, tuple):
        return list(path)
    raise TrustsConfigurationError(
        'Registration on %s has a non-portable condition ref %r.'
        % (root_label, ref)
    )


def _project_along(along, root_label):
    if along is None:
        return None
    walk_path = tuple(getattr(along, 'walk_path', ()) or ())
    suffix_path = tuple(getattr(along, 'suffix_path', ()) or ())
    walk_field = getattr(along, 'walk_field', None)
    suffix_field = getattr(along, 'suffix_field', None)
    expected_walk = '__'.join(walk_path)
    expected_suffix = '__'.join(suffix_path)
    if walk_field != expected_walk or suffix_field != expected_suffix:
        raise TrustsConfigurationError(
            'Along on %s stores walk/suffix lookups %r/%r that do not '
            'match path-derived %r/%r.'
            % (
                root_label, walk_field, suffix_field,
                expected_walk, expected_suffix,
            )
        )
    edge_model = getattr(along, 'edge_model', None)
    return _canonicalize_along({
        'bound': getattr(along, 'bound', None),
        'shape': getattr(along, 'shape', None),
        'walk_path': list(walk_path),
        'walk_model': _model_label(
            getattr(along, 'walk_model', None),
            'Along walk model on %s' % root_label,
        ),
        'walk_ident': getattr(along, 'walk_ident', None),
        'suffix_path': list(suffix_path),
        'ident_family': getattr(along, 'ident_family', None),
        'parent_attname': getattr(along, 'parent_attname', None),
        'edge_model': (
            None if edge_model is None else _model_label(
                edge_model, 'Along edge model on %s' % root_label,
            )
        ),
        'edge_parent_attname': getattr(along, 'edge_parent_attname', None),
        'edge_child_attname': getattr(along, 'edge_child_attname', None),
        'rewrite_attname': getattr(along, 'rewrite_attname', None),
    })


def _labels(payloads, fingerprints):
    bases = [_base_label(payload) for payload in payloads]
    counts = {}
    for base in bases:
        counts[base] = counts.get(base, 0) + 1
    labels = []
    for base, fingerprint in zip(bases, fingerprints):
        if counts[base] > 1:
            hex_digest = fingerprint.split(':', 1)[1]
            labels.append('%s#%s' % (base, hex_digest[:8]))
        else:
            labels.append(base)
    return labels


def _base_label(payload):
    lookup = '__'.join(payload['content'])
    label = '%s:%s' % (payload['root'], lookup)
    if payload['condition'] is not None:
        label += '+cond'
    along = payload['along']
    if along is not None:
        label += '+along:%s:%s' % (along['shape'], along['bound'])
    return label


def _project_named_filters(registry):
    """Project model-scoped named filters.

    Expr encoding covers the v1 portable constant allowlist already
    decided for null, bool, IEEE-safe int, and str. Floats, model
    primary keys, and other IR constants fail closed. ``int_dec`` and
    commutative ``and`` / ``or`` flattening are not applied here.
    """
    rows = []
    iterator = getattr(registry, 'iter_permission_conditions', None)
    if not callable(iterator):
        return rows
    for model, code, record in iterator():
        model_label = _model_label(model, 'named filter model')
        if not isinstance(code, str) or code == '':
            raise TrustsConfigurationError(
                'Named filter on %s has a non-portable code %r.'
                % (model_label, code)
            )
        expr = _canonicalize_expr(
            _project_expr(
                getattr(record, 'expr', None),
                where='%s:%s' % (model_label, code),
            )
        )
        payload = {'model': model_label, 'code': code, 'expr': expr}
        rows.append({
            'model': model_label,
            'code': code,
            'fingerprint': _digest(_canonical_bytes(payload)),
            'expr': expr,
        })
    rows.sort(key=lambda row: (row['model'], row['code']))
    return rows


def _project_expr(node, *, where):
    from trusts.conditions import _ir

    if isinstance(node, _ir.Ref):
        if node.source not in ('principal', 'permission', 'object'):
            raise TrustsConfigurationError(
                'Named filter %s has unknown ref source %r.'
                % (where, node.source)
            )
        if not all(isinstance(part, str) for part in node.path):
            raise TrustsConfigurationError(
                'Named filter %s has a non-portable ref path.' % (where,)
            )
        return {'ref': node.source, 'path': list(node.path)}
    if isinstance(node, _ir.Const):
        kind, value = _portable_constant(node.value, where)
        return {'const': {'type': kind, 'value': value}}
    if isinstance(node, (_ir.Eq, _ir.Ne, _ir.And, _ir.Or)):
        op = {
            _ir.Eq: 'eq',
            _ir.Ne: 'ne',
            _ir.And: 'and',
            _ir.Or: 'or',
        }[type(node)]
        return {
            'op': op,
            'left': _project_expr(node.left, where=where),
            'right': _project_expr(node.right, where=where),
        }
    raise TrustsConfigurationError(
        'Named filter %s has non-portable expression %s.'
        % (where, type(node).__name__)
    )


def _portable_constant(value, where):
    if value is None:
        return 'null', None
    if isinstance(value, bool):
        return 'bool', bool(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _IEEE_SAFE_INT:
            raise TrustsConfigurationError(
                'Named filter %s integer %r is outside the IEEE-safe JSON '
                'integer range. int_dec encoding is not part of lockfile C1.'
                % (where, value)
            )
        return 'int', value
    if isinstance(value, str):
        return 'str', value
    raise TrustsConfigurationError(
        'Named filter %s constant type %s is not portable in lockfile v1.'
        % (where, type(value).__name__)
    )


_DERIVED_REGISTRATION_KEYS = ('fingerprint', 'label')


def _as_dict(value):
    if isinstance(value, MappingProxyType):
        return dict(value)
    if isinstance(value, dict):
        return value
    return None


def _unexpected_keys(mapping, allowed):
    allowed_set = set(allowed)
    return sorted(
        (key for key in mapping if key not in allowed_set),
        key=repr,
    )


def _reject_unexpected(mapping, allowed, what):
    unknown = _unexpected_keys(mapping, allowed)
    if unknown:
        raise TrustsConfigurationError(
            '%s has unexpected field(s) %s.'
            % (what, ', '.join(repr(key) for key in unknown))
        )


def _require_present(mapping, required, op):
    """Reject a closed-condition variant before its keys are indexed."""
    missing = [key for key in required if key not in mapping]
    if missing:
        raise TrustsConfigurationError(
            'Closed condition op %r is missing %s.'
            % (op, ', '.join(missing))
        )


def _require_text(value, what):
    if not isinstance(value, str) or value == '':
        raise TrustsConfigurationError(
            '%s must be a non-empty string, not %r.' % (what, value)
        )
    return value


def _require_string_path(value, what, *, allow_empty=False):
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise TrustsConfigurationError(
            '%s must be a list of strings, not %s.'
            % (what, type(value).__name__)
        )
    if not value and not allow_empty:
        raise TrustsConfigurationError('%s is empty.' % (what,))
    parts = []
    for part in value:
        if isinstance(part, bool) or not isinstance(part, str) or part == '':
            raise TrustsConfigurationError(
                '%s has a non-string component %r.' % (what, part)
            )
        parts.append(part)
    return parts


def _optional_text(value, what):
    if value is None:
        return None
    return _require_text(value, what)


def _canonicalize_registration(payload):
    mapping = _as_dict(payload)
    if mapping is None:
        raise TrustsConfigurationError(
            'Registration fingerprint payload must be an object, not %s.'
            % type(payload).__name__
        )
    _reject_unexpected(
        mapping,
        _REGISTRATION_KEYS + _DERIVED_REGISTRATION_KEYS,
        'Registration fingerprint payload',
    )
    for key in _DERIVED_REGISTRATION_KEYS:
        if key in mapping and not isinstance(mapping[key], str):
            raise TrustsConfigurationError(
                'Registration fingerprint payload field %s must be a '
                'string, not %s.' % (key, type(mapping[key]).__name__)
            )
    missing = [key for key in _REGISTRATION_KEYS if key not in mapping]
    if missing:
        raise TrustsConfigurationError(
            'Registration fingerprint payload is missing %s.'
            % ', '.join(missing)
        )
    ordered = {key: mapping[key] for key in _REGISTRATION_KEYS}
    if ordered['kind'] != 'any_path':
        raise TrustsConfigurationError(
            'Registration fingerprint kind must be %r, not %r.'
            % ('any_path', ordered['kind'])
        )
    for key in (
        'root', 'user_model', 'user_target',
        'permission_model', 'permission_target',
        'content_model', 'content_target',
    ):
        ordered[key] = _require_text(ordered[key], 'Registration %s' % key)
    for key in ('user', 'permission', 'content'):
        ordered[key] = _require_string_path(ordered[key], 'Registration %s' % key)
    ordered['condition'] = _canonicalize_condition(ordered['condition'])
    ordered['along'] = _canonicalize_along(ordered['along'])
    return ordered


def _canonicalize_condition(condition):
    if condition is None:
        return None
    mapping = _as_dict(condition)
    if mapping is None or 'op' not in mapping:
        raise TrustsConfigurationError(
            'Closed condition is not portable lockfile IR: %r.' % (condition,)
        )
    op = mapping['op']
    if op == 'all':
        _reject_unexpected(mapping, ('op', 'predicates'), 'Closed condition')
        _require_present(mapping, ('predicates',), op)
        predicates_in = mapping['predicates']
        if (
            isinstance(predicates_in, (str, bytes))
            or not isinstance(predicates_in, (list, tuple))
            or not predicates_in
        ):
            raise TrustsConfigurationError(
                'Closed condition predicates must be a non-empty list, '
                'not %r.' % (predicates_in,)
            )
        predicates = [
            _canonicalize_condition(item) for item in predicates_in
        ]
        predicates.sort(key=_json_sort_key)
        return {'op': 'all', 'predicates': predicates}
    if op == 'equal':
        _reject_unexpected(mapping, ('op', 'left', 'right'), 'Closed condition')
        _require_present(mapping, ('left', 'right'), op)
        left = _require_string_path(mapping['left'], 'Equal left')
        right = _require_string_path(mapping['right'], 'Equal right')
        if tuple(left) > tuple(right):
            left, right = right, left
        return {'op': 'equal', 'left': left, 'right': right}
    if op == 'permission_in':
        _reject_unexpected(mapping, ('op', 'refs'), 'Closed condition')
        _require_present(mapping, ('refs',), op)
        refs_in = mapping['refs']
        if (
            isinstance(refs_in, (str, bytes))
            or not isinstance(refs_in, (list, tuple))
            or not refs_in
        ):
            raise TrustsConfigurationError(
                'permission_in refs must be a non-empty list, not %r.'
                % (refs_in,)
            )
        refs = [
            _require_string_path(ref, 'permission_in ref') for ref in refs_in
        ]
        refs.sort(key=tuple)
        return {'op': 'permission_in', 'refs': refs}
    raise TrustsConfigurationError(
        'Unsupported closed condition op %r.' % (op,)
    )


def _canonicalize_along(along):
    if along is None:
        return None
    mapping = _as_dict(along)
    if mapping is None:
        raise TrustsConfigurationError(
            'Along fingerprint payload is not an object: %r.' % (along,)
        )
    _reject_unexpected(mapping, _ALONG_KEYS, 'Along fingerprint payload')
    missing = [key for key in _ALONG_KEYS if key not in mapping]
    if missing:
        raise TrustsConfigurationError(
            'Along fingerprint payload is missing %s.' % ', '.join(missing)
        )
    ordered = {key: mapping[key] for key in _ALONG_KEYS}
    bound = ordered['bound']
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise TrustsConfigurationError(
            'Along bound is not a portable integer: %r.' % (bound,)
        )
    ordered['shape'] = _require_text(ordered['shape'], 'Along shape')
    for key in ('walk_ident', 'ident_family', 'walk_model'):
        ordered[key] = _require_text(ordered[key], 'Along %s' % key)
    for key in (
        'parent_attname', 'edge_model', 'edge_parent_attname',
        'edge_child_attname', 'rewrite_attname',
    ):
        ordered[key] = _optional_text(ordered[key], 'Along %s' % key)
    ordered['walk_path'] = _require_string_path(
        ordered['walk_path'], 'Along walk_path',
    )
    ordered['suffix_path'] = _require_string_path(
        ordered['suffix_path'], 'Along suffix_path', allow_empty=True,
    )
    return ordered


def _canonicalize_expr(expr):
    if not isinstance(expr, dict):
        raise TrustsConfigurationError(
            'Named-filter expr is not an object: %r.' % (expr,)
        )
    if 'ref' in expr:
        return {
            'ref': expr['ref'],
            'path': [str(part) for part in expr['path']],
        }
    if 'const' in expr:
        const = expr['const']
        return {
            'const': {
                'type': const['type'],
                'value': const['value'],
            },
        }
    return {
        'op': expr['op'],
        'left': _canonicalize_expr(expr['left']),
        'right': _canonicalize_expr(expr['right']),
    }


def _json_sort_key(node):
    return json.dumps(
        node, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    )


def _handle_sort_key(handle):
    return (
        handle['path'],
        handle['compiler'],
        tuple(row['fingerprint'] for row in handle['registrations']),
        tuple(
            (row['model'], row['code'], row['fingerprint'])
            for row in handle['named_filters']
        ),
    )


def _freeze(value):
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        raise TrustsConfigurationError(
            'Policy snapshot cannot freeze a float.'
        )
    if isinstance(value, MappingProxyType):
        return MappingProxyType({
            key: _freeze(item) for key, item in value.items()
        })
    if isinstance(value, dict):
        return MappingProxyType({
            key: _freeze(item) for key, item in value.items()
        })
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise TrustsConfigurationError(
        'Policy snapshot cannot freeze %s.' % type(value).__name__
    )


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


__all__ = (
    'ALONG_SUPPORTED',
    'ALONG_UNSUPPORTED',
    'COMPILER_VERSION',
    'GENERIC_UNSUPPORTED_ALONG_PROFILE',
    'PROFILE_VERSION',
    'PolicyManifest',
    'RELATIONSHIP_FAMILY',
    'SCHEMA_VERSION',
    'SQLITE_JSON1_RCTE_PROFILE',
    'build_policy_manifest',
    'fingerprint_registration',
    'manifest_to_json_data',
)
