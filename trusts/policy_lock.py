"""Finalized authorization-policy snapshot (lockfile C1–C2, issue #147).

Projects frozen relationship registries into an immutable snapshot and a
detached JSON-ready document. Registration fingerprints and readable
labels are derived here. C2 adds the quiet UTF-8/LF serializer and the
strict canonical reader: ``schema_version`` / ``compiler_version``,
named-filter IR with commutative ``and`` / ``or``, the v1 constant
allowlist, and ``int`` versus canonical ``int_dec``.

The portable document never contains runtime object identity, source
locations, or database credentials. Callers cannot select a database
alias: the renderer profile is always Django's ``DEFAULT_DB_ALIAS``
resolved through ``django.db.connections``, with zero SQL. Management
commands, path selection, and runtime gating are later slices and are
not performed.
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
    does not change the snapshot or a second conversion. The dict is
    the semantic document: it has no ``diagnostics`` key.
    """
    if not isinstance(manifest, PolicyManifest):
        raise TypeError(
            'manifest_to_json_data expected a PolicyManifest, not %s.'
            % type(manifest).__name__
        )
    return _thaw(manifest._document)


def canonicalize(source):
    """Return quiet UTF-8/LF canonical policy bytes.

    A :class:`PolicyManifest` is encoded from its detached semantic
    document. Bytes, ``str``, or a JSON object are strict-read first
    (:func:`read_canonical_policy`), so regeneration drops top-level
    ``diagnostics`` and rejects unknown fields, cross-shape integers,
    and noncanonical ``int_dec`` spellings. The generator form is
    UTF-8, no BOM, LF-only, two-space indent, schema key order, and a
    trailing newline. This function does not touch the database.
    """
    if isinstance(source, PolicyManifest):
        document = read_canonical_policy(manifest_to_json_data(source))
    else:
        document = read_canonical_policy(source)
    return _canonical_bytes(document)


def read_canonical_policy(source):
    """Strict-read a lockfile document and return the semantic dict.

    ``source`` is UTF-8 bytes, text, or a JSON object. Top-level
    ``diagnostics`` is the only nonsemantic key: it is dropped and is
    not present on the result. Every other unknown field fails closed,
    recursively, at each semantic schema level. ``schema_version`` and
    ``compiler_version`` must be integer ``1``. Named-filter ``and`` /
    ``or`` are flattened and sorted. Integer constants must already be
    the canonical ``int`` or ``int_dec`` shape; this reader does not
    rewrite cross-shape or noncanonical spellings. No SQL.
    """
    if isinstance(source, PolicyManifest):
        raise TypeError(
            'read_canonical_policy expected UTF-8 bytes, str, or dict, '
            'not PolicyManifest. Use manifest_to_json_data or canonicalize.'
        )
    return _canonicalize_document(_load_json_source(source))


def _digest(payload_bytes):
    return 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()


def _canonical_bytes(obj):
    """Quiet UTF-8/LF serializer for fingerprints and the lockfile.

    ``indent`` 2, ``separators=(',', ': ')``, schema key order (the
    caller builds ordered objects; keys are not re-sorted), no BOM,
    trailing LF. ``ensure_ascii=False`` so non-ASCII constants stay
    UTF-8. ``diagnostics`` is never added here.
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
    """Project model-scoped named filters into public lockfile IR.

    Constants are the v1 allowlist: null, bool, str, and integers.
    IEEE-safe integers (``abs(n) <= 2**53 - 1``, bool excluded) use
    ``int``. Integers outside that range use canonical ``int_dec``
    decimal text. Floats, ``ModelIdentity``, and every other constant
    fail closed. Commutative ``and`` / ``or`` flatten to a sorted
    ``args`` list so operand order is not identity.
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
            return 'int_dec', _canonical_int_dec_text(value)
        return 'int', value
    if isinstance(value, str):
        return 'str', value
    raise TrustsConfigurationError(
        'Named filter %s constant type %s is not portable in lockfile v1.'
        % (where, type(value).__name__)
    )


def _canonical_int_dec_text(value):
    """Canonical base-10 text: optional leading ``-``, digits, no ``+``.

    ``value`` is a Python ``int`` that is already outside the IEEE-safe
    range. ``str(int)`` has no leading zeroes and no leading ``+``.
    """
    if value < 0:
        return '-' + str(-value)
    return str(value)


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


_DOCUMENT_KEYS = ('schema_version', 'compiler_version', 'handles')
_HANDLE_KEYS = (
    'path', 'family', 'compiler', 'renderer', 'registrations', 'named_filters',
)
_RENDERER_KEYS = (
    'alias', 'engine', 'profile', 'profile_version', 'along',
)
_NAMED_FILTER_KEYS = ('model', 'code', 'fingerprint', 'expr')
_CMP_OPS = ('eq', 'ne')
_BOOL_OPS = ('and', 'or')
_PROFILES = (
    SQLITE_JSON1_RCTE_PROFILE,
    GENERIC_UNSUPPORTED_ALONG_PROFILE,
)
_REF_SOURCES = ('principal', 'permission', 'object')
_CONST_TYPES = ('null', 'bool', 'str', 'int', 'int_dec')


def _canonicalize_expr(expr, where='Named-filter expr'):
    """Public lockfile IR for one named-filter expression.

    ``eq`` / ``ne`` stay ordered pairs. ``and`` / ``or`` accept either
    the private binary ``left`` / ``right`` shape or an ``args`` list,
    then flatten nested same-op nodes and sort the children. Constants
    are strict: cross-shape and noncanonical ``int_dec`` fail closed.
    """
    mapping = _as_dict(expr)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s must be an object, not %s.' % (where, type(expr).__name__)
        )
    markers = [key for key in ('ref', 'const', 'op') if key in mapping]
    if len(markers) != 1:
        raise TrustsConfigurationError(
            '%s must contain exactly one of ref, const, or op.' % (where,)
        )
    kind = markers[0]
    if kind == 'ref':
        _reject_unexpected(mapping, ('ref', 'path'), where)
        _missing_keys(mapping, ('ref', 'path'), where)
        source = mapping['ref']
        if source not in _REF_SOURCES:
            raise TrustsConfigurationError(
                '%s has unknown ref source %r.' % (where, source)
            )
        return {
            'ref': source,
            'path': _require_string_path(
                mapping['path'], '%s path' % where, allow_empty=True,
            ),
        }
    if kind == 'const':
        _reject_unexpected(mapping, ('const',), where)
        _missing_keys(mapping, ('const',), where)
        return {'const': _canonicalize_const(mapping['const'], where)}
    op = mapping['op']
    if op in _CMP_OPS:
        _reject_unexpected(mapping, ('op', 'left', 'right'), where)
        _missing_keys(mapping, ('left', 'right'), where)
        return {
            'op': op,
            'left': _canonicalize_expr(mapping['left'], '%s left' % where),
            'right': _canonicalize_expr(mapping['right'], '%s right' % where),
        }
    if op in _BOOL_OPS:
        return _canonicalize_bool_expr(mapping, op, where)
    raise TrustsConfigurationError(
        '%s has unsupported op %r.' % (where, op)
    )


def _canonicalize_bool_expr(mapping, op, where):
    has_args = 'args' in mapping
    has_binary = 'left' in mapping or 'right' in mapping
    if has_args and has_binary:
        raise TrustsConfigurationError(
            '%s %s cannot use both args and left/right.' % (where, op)
        )
    if has_args:
        _reject_unexpected(mapping, ('op', 'args'), where)
        raw_children = mapping['args']
        if (
            isinstance(raw_children, (str, bytes))
            or not isinstance(raw_children, (list, tuple))
        ):
            raise TrustsConfigurationError(
                '%s %s args must be a list, not %s.'
                % (where, op, type(raw_children).__name__)
            )
        children = [
            _canonicalize_expr(item, '%s arg %s' % (where, index))
            for index, item in enumerate(raw_children)
        ]
    elif has_binary:
        _reject_unexpected(mapping, ('op', 'left', 'right'), where)
        _missing_keys(mapping, ('left', 'right'), where)
        children = [
            _canonicalize_expr(mapping['left'], '%s left' % where),
            _canonicalize_expr(mapping['right'], '%s right' % where),
        ]
    else:
        raise TrustsConfigurationError(
            '%s %s is missing args.' % (where, op)
        )
    flat = []
    for child in children:
        if child.get('op') == op:
            flat.extend(child['args'])
        else:
            flat.append(child)
    if len(flat) < 2:
        raise TrustsConfigurationError(
            '%s %s requires at least two expressions.' % (where, op)
        )
    flat.sort(key=_json_sort_key)
    return {'op': op, 'args': flat}


def _canonicalize_const(const, where):
    mapping = _as_dict(const)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s constant must be an object, not %s.'
            % (where, type(const).__name__)
        )
    _reject_unexpected(mapping, ('type', 'value'), '%s constant' % where)
    _missing_keys(mapping, ('type', 'value'), '%s constant' % where)
    kind = mapping['type']
    value = mapping['value']
    if not isinstance(kind, str) or kind not in _CONST_TYPES:
        shown = kind if isinstance(kind, str) else type(kind).__name__
        raise TrustsConfigurationError(
            '%s constant type %s is not portable in lockfile v1.'
            % (where, shown)
        )
    if kind == 'null':
        if value is not None:
            raise TrustsConfigurationError(
                '%s null constant value must be null, not %s.'
                % (where, type(value).__name__)
            )
        return {'type': 'null', 'value': None}
    if kind == 'bool':
        if not isinstance(value, bool):
            raise TrustsConfigurationError(
                '%s bool constant value must be true or false, not %s.'
                % (where, type(value).__name__)
            )
        return {'type': 'bool', 'value': bool(value)}
    if kind == 'str':
        if not isinstance(value, str):
            raise TrustsConfigurationError(
                '%s str constant value must be a string, not %s.'
                % (where, type(value).__name__)
            )
        return {'type': 'str', 'value': value}
    if kind == 'int':
        return {'type': 'int', 'value': _require_ieee_int(value, where)}
    return {
        'type': 'int_dec',
        'value': _require_int_dec(value, where),
    }


def _require_ieee_int(value, where):
    """Accept only an IEEE-safe JSON integer. Bool and float are not int."""
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, float):
            raise TrustsConfigurationError(
                '%s constant type float is not portable in lockfile v1.'
                % (where,)
            )
        if isinstance(value, str):
            raise TrustsConfigurationError(
                '%s integer constant is cross-shape: type int requires a '
                'JSON number, not decimal text.' % (where,)
            )
        raise TrustsConfigurationError(
            '%s integer constant is cross-shape: type int does not accept '
            '%s.' % (where, type(value).__name__)
        )
    if abs(value) > _IEEE_SAFE_INT:
        raise TrustsConfigurationError(
            '%s integer constant is cross-shape: abs(n) > 2**53 - 1 must '
            'use int_dec, not int.' % (where,)
        )
    return value


def _require_int_dec(value, where):
    """Accept only canonical out-of-range decimal text. Do not rewrite."""
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        if isinstance(value, float):
            raise TrustsConfigurationError(
                '%s constant type float is not portable in lockfile v1.'
                % (where,)
            )
        raise TrustsConfigurationError(
            '%s integer constant is cross-shape: type int_dec requires '
            'canonical decimal text, not a JSON number.' % (where,)
        )
    if not isinstance(value, str):
        raise TrustsConfigurationError(
            '%s int_dec value must be decimal text, not %s.'
            % (where, type(value).__name__)
        )
    reason = _int_dec_spelling_error(value)
    if reason is not None:
        raise TrustsConfigurationError(
            '%s integer constant has noncanonical int_dec spelling %r '
            '(%s).' % (where, value, reason)
        )
    number = int(value)
    if abs(number) <= _IEEE_SAFE_INT:
        raise TrustsConfigurationError(
            '%s integer constant is cross-shape: IEEE-safe integers must '
            'use type int, not int_dec.' % (where,)
        )
    return value


def _int_dec_spelling_error(text):
    """Return a reason when ``text`` is not canonical ``int_dec`` text.

    Canonical form is an optional leading ``-`` and ASCII digits, with
    no ``+``, no leading zeroes, and no negative zero. ``None`` means
    the spelling is canonical. The IEEE range is checked separately.
    """
    if text == '':
        return 'empty'
    if text[0] == '+':
        return "leading '+'"
    negative = text[0] == '-'
    body = text[1:] if negative else text
    if body == '' or any(ch < '0' or ch > '9' for ch in body):
        return 'digits only'
    if body[0] == '0' and len(body) != 1:
        return 'leading zero'
    if negative and body == '0':
        return 'negative zero'
    return None


def _missing_keys(mapping, required, where):
    missing = [key for key in required if key not in mapping]
    if missing:
        raise TrustsConfigurationError(
            '%s is missing %s.' % (where, ', '.join(missing))
        )


def _require_exact_version(value, expected, what):
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise TrustsConfigurationError(
            'Policy document %s must be integer %s, not %r.'
            % (what, expected, value)
        )
    return expected


def _require_fingerprint(value, where):
    hexdigits = '0123456789abcdef'
    ok = (
        isinstance(value, str)
        and value.startswith('sha256:')
        and len(value) == 7 + 64
        and all(ch in hexdigits for ch in value[7:])
    )
    if not ok:
        raise TrustsConfigurationError(
            '%s fingerprint must be sha256: plus 64 lowercase hex digits, '
            'not %r.' % (where, value)
        )
    return value


def _require_list(value, what):
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise TrustsConfigurationError(
            '%s must be a list, not %s.' % (what, type(value).__name__)
        )
    return list(value)


def _load_json_source(source):
    if isinstance(source, str):
        text = source
    elif isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        if raw.startswith(b'\xef\xbb\xbf'):
            raise TrustsConfigurationError(
                'Policy document UTF-8 BOM is not accepted.'
            )
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise TrustsConfigurationError(
                'Policy document is not UTF-8: %s' % (exc,)
            ) from exc
    elif isinstance(source, (dict, MappingProxyType)):
        return _as_dict(source)
    else:
        raise TypeError(
            'read_canonical_policy expected UTF-8 bytes, str, or dict, not %s.'
            % type(source).__name__
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TrustsConfigurationError(
            'Policy document is not JSON: %s' % (exc,)
        ) from exc
    if isinstance(data, dict):
        return data
    raise TrustsConfigurationError(
        'Policy document must be a JSON object, not %s.'
        % type(data).__name__
    )


def _canonicalize_document(data):
    mapping = _as_dict(data)
    if mapping is None:
        raise TrustsConfigurationError(
            'Policy document must be a JSON object, not %s.'
            % type(data).__name__
        )
    _reject_unexpected(
        mapping, _DOCUMENT_KEYS + ('diagnostics',), 'Policy document',
    )
    _missing_keys(mapping, _DOCUMENT_KEYS, 'Policy document')
    schema_version = _require_exact_version(
        mapping['schema_version'], SCHEMA_VERSION, 'schema_version',
    )
    compiler_version = _require_exact_version(
        mapping['compiler_version'], COMPILER_VERSION, 'compiler_version',
    )
    handles_in = _require_list(mapping['handles'], 'Policy document handles')
    handles = [
        _canonicalize_handle(item, 'handles[%s]' % index)
        for index, item in enumerate(handles_in)
    ]
    handles.sort(key=_handle_sort_key)
    return {
        'schema_version': schema_version,
        'compiler_version': compiler_version,
        'handles': handles,
    }


def _canonicalize_handle(value, where):
    mapping = _as_dict(value)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s must be an object, not %s.' % (where, type(value).__name__)
        )
    _reject_unexpected(mapping, _HANDLE_KEYS, where)
    _missing_keys(mapping, _HANDLE_KEYS, where)
    family = _require_text(mapping['family'], '%s family' % where)
    if family != RELATIONSHIP_FAMILY:
        raise TrustsConfigurationError(
            '%s family %r is not supported by Core lockfile v1; only %r '
            'is serializable.' % (where, family, RELATIONSHIP_FAMILY)
        )
    registrations_in = _require_list(
        mapping['registrations'], '%s registrations' % where,
    )
    named_in = _require_list(
        mapping['named_filters'], '%s named_filters' % where,
    )
    registrations = [
        _canonicalize_document_registration(
            item, '%s.registrations[%s]' % (where, index),
        )
        for index, item in enumerate(registrations_in)
    ]
    registrations.sort(key=lambda row: row['fingerprint'])
    named_filters = [
        _canonicalize_named_filter(
            item, '%s.named_filters[%s]' % (where, index),
        )
        for index, item in enumerate(named_in)
    ]
    named_filters.sort(key=lambda row: (row['model'], row['code']))
    return {
        'path': _require_text(mapping['path'], '%s path' % where),
        'family': family,
        'compiler': _require_text(mapping['compiler'], '%s compiler' % where),
        'renderer': _canonicalize_renderer(
            mapping['renderer'], '%s.renderer' % where,
        ),
        'registrations': registrations,
        'named_filters': named_filters,
    }


def _canonicalize_renderer(value, where):
    mapping = _as_dict(value)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s must be an object, not %s.' % (where, type(value).__name__)
        )
    _reject_unexpected(mapping, _RENDERER_KEYS, where)
    _missing_keys(mapping, _RENDERER_KEYS, where)
    profile = _require_text(mapping['profile'], '%s profile' % where)
    if profile not in _PROFILES:
        raise TrustsConfigurationError(
            '%s profile %r is not a v1 lockfile renderer profile.'
            % (where, profile)
        )
    along = mapping['along']
    if along not in (ALONG_SUPPORTED, ALONG_UNSUPPORTED):
        raise TrustsConfigurationError(
            '%s along must be %r or %r, not %r.'
            % (where, ALONG_SUPPORTED, ALONG_UNSUPPORTED, along)
        )
    return {
        'alias': _require_text(mapping['alias'], '%s alias' % where),
        'engine': _require_text(mapping['engine'], '%s engine' % where),
        'profile': profile,
        'profile_version': _require_exact_version(
            mapping['profile_version'], PROFILE_VERSION, 'profile_version',
        ),
        'along': along,
    }


def _canonicalize_document_registration(value, where):
    mapping = _as_dict(value)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s must be an object, not %s.' % (where, type(value).__name__)
        )
    _reject_unexpected(
        mapping,
        _REGISTRATION_KEYS + _DERIVED_REGISTRATION_KEYS,
        where,
    )
    _missing_keys(
        mapping,
        _REGISTRATION_KEYS + _DERIVED_REGISTRATION_KEYS,
        where,
    )
    fingerprint = _require_fingerprint(mapping['fingerprint'], where)
    label = _require_text(mapping['label'], '%s label' % where)
    payload = _canonicalize_registration(mapping)
    row = {'fingerprint': fingerprint, 'label': label}
    row.update(payload)
    return row


def _canonicalize_named_filter(value, where):
    mapping = _as_dict(value)
    if mapping is None:
        raise TrustsConfigurationError(
            '%s must be an object, not %s.' % (where, type(value).__name__)
        )
    _reject_unexpected(mapping, _NAMED_FILTER_KEYS, where)
    _missing_keys(mapping, _NAMED_FILTER_KEYS, where)
    expr = _canonicalize_expr(mapping['expr'], '%s.expr' % where)
    return {
        'model': _require_text(mapping['model'], '%s model' % where),
        'code': _require_text(mapping['code'], '%s code' % where),
        'fingerprint': _require_fingerprint(mapping['fingerprint'], where),
        'expr': expr,
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
    'canonicalize',
    'fingerprint_registration',
    'manifest_to_json_data',
    'read_canonical_policy',
)
