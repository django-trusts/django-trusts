"""Private #131 C-unify path-filter IR, request-tuple boundary, and catalog.

Application code does not import this module. Path-filter builders receive
the root proxy ``r``; request-filter builders keep symbolic ``(u, p, o)``.
The two stores never consult each other.
"""

from __future__ import annotations

import hashlib
import json
import re

from django.db.models.base import ModelBase


FILTER_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')

_BOOLEAN_ERROR_MESSAGE = (
    "Python 'and'/'or'/'not' cannot be used in path filters "
    "because they cannot be overloaded; chained comparisons such as "
    "`0 < r.amount < 100` also truth-test a symbolic node. Use '&' and "
    "'|' for conjunction and disjunction, and '!=' instead of combining "
    "'not' with '=='. Membership uses .in_(), not Python 'in'."
)


def _is_model_class(value):
    return isinstance(value, ModelBase)


def _concrete_model(model):
    meta = getattr(model, '_meta', None)
    if meta is None:
        return model
    return meta.concrete_model


def _model_label(model):
    meta = getattr(getattr(model, '_meta', None), 'concrete_model', None)
    if meta is not None:
        return meta._meta.label
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _model_key(model):
    return _concrete_model(model)


class PathFilterBooleanError(Exception):
    """Raised when a path-filter node is truth-tested (``and`` / ``or`` / ``not``)."""


class PathFilterUnsupported(Exception):
    """Raised for operations outside the path-filter grammar."""


def _boolean_error():
    raise PathFilterBooleanError(_BOOLEAN_ERROR_MESSAGE)


def _unsupported(what):
    raise PathFilterUnsupported(
        '%s is not supported in path filters.' % what
    )


def validate_filter_name(name, *, role='filter'):
    """Require a declared/request filter name. Empty or malformed fail closed."""
    if not isinstance(name, str):
        raise TypeError(
            '%s name must be a string, not %r.' % (role, type(name).__name__,)
        )
    if not name or FILTER_NAME_RE.match(name) is None:
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError(
            '%s name %r is not a valid filter name '
            '(must match %s).' % (role, name, FILTER_NAME_RE.pattern)
        )
    return name


def validate_request_filter_tuple(value):
    """Validate a request ``filter=`` value before any iteration or coercion.

    Only a ``tuple`` whose members are strings proceeds. A bare ``str``,
    list, set, generator, or mapping is ``TypeError``. Do not
    ``tuple(value)`` a string into characters. Duplicate / empty /
    malformed names are ``TrustsConfigurationError``.
    """
    if not isinstance(value, tuple):
        raise TypeError(
            'filter must be a tuple of strings, not %r.'
            % (type(value).__name__,)
        )
    seen = []
    for name in value:
        if not isinstance(name, str):
            raise TypeError(
                'filter members must be strings, not %r.'
                % (type(name).__name__,)
            )
        validate_filter_name(name, role='request filter')
        if name in seen:
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'Duplicate request filter name %r.' % (name,)
            )
        seen.append(name)
    return value


def query_filter_identity(value):
    """Validate first, then sort for query/manifest identity.

    Diagnostics keep the supplied order (the validated tuple). Identity
    is the sorted tuple. No silent dedupe — duplicates already failed.
    """
    names = validate_request_filter_tuple(value)
    return tuple(sorted(names))


def validate_path_filter_attach(value):
    """Named-only path attach: omitted / ``None``, or exactly one ``str``.

    Callable, tuple, list, or mapping is ``TypeError`` (option B).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(
            'register(..., filter=) accepts exactly one filter name string, '
            'not %r.' % (type(value).__name__,)
        )
    return validate_filter_name(value, role='path filter')


class PathNode(object):
    """Private path-filter IR node. Not an application-facing import."""

    def __eq__(self, other):
        return PathEq(self, as_path_node(other))

    def __ne__(self, other):
        return PathNe(self, as_path_node(other))

    def __and__(self, other):
        return _path_bool(PathAnd, self, as_path_node(other), '&')

    def __or__(self, other):
        return _path_bool(PathOr, self, as_path_node(other), '|')

    def __rand__(self, other):
        return _path_bool(PathAnd, as_path_node(other), self, '&')

    def __ror__(self, other):
        return _path_bool(PathOr, as_path_node(other), self, '|')

    def __bool__(self):
        _boolean_error()

    def __call__(self, *args, **kwargs):
        _unsupported('Function or method calls')

    def __getitem__(self, key):
        _unsupported('Indexing')

    def __iter__(self):
        _unsupported('Iteration')

    def __contains__(self, item):
        _unsupported("'in' tests; use .in_()")

    def __hash__(self):
        return id(self)

    def in_(self, collection):
        _unsupported('.in_() on a predicate; call it on a field path')

    def to_tuple(self):
        raise NotImplementedError


class PathRef(PathNode):
    """Root-relative symbolic path built by attribute traversal on ``r``."""

    def __init__(self, root, path=()):
        if not _is_model_class(root):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'Path filter root must be a Django model class, not %r.'
                % (root,)
            )
        self.root = root
        self.path = tuple(path)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return PathRef(self.root, self.path + (name,))

    def __setattr__(self, name, value):
        if name in ('root', 'path'):
            object.__setattr__(self, name, value)
            return
        _unsupported('Assignment to symbolic fields')

    def __delattr__(self, name):
        _unsupported('Deletion of symbolic fields')

    def in_(self, collection):
        return PathIn(self, as_path_node(collection))

    def to_tuple(self):
        return ('ref', self.path)

    def __repr__(self):
        if not self.path:
            return 'r'
        return 'r.%s' % '.'.join(self.path)


class _PathPredicate(PathNode):
    """Predicate nodes compare structurally so stored IR can be equality-tested."""

    def __eq__(self, other):
        return type(self) is type(other) and self.to_tuple() == other.to_tuple()

    def __hash__(self):
        return hash((type(self), self.to_tuple()))

    def __ne__(self, other):
        if type(self) is type(other):
            return self.to_tuple() != other.to_tuple()
        return NotImplemented


class PathEq(_PathPredicate):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('eq', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r == %r)' % (self.left, self.right)


class PathNe(_PathPredicate):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('ne', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r != %r)' % (self.left, self.right)


class PathAnd(_PathPredicate):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('and', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r & %r)' % (self.left, self.right)


class PathOr(_PathPredicate):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('or', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r | %r)' % (self.left, self.right)


class PathIn(_PathPredicate):
    """Membership ``left.in_(right)``. Left is proved against ``permission=`` later."""

    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('in', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '%r.in_(%r)' % (self.left, self.right)


def is_path_predicate(node):
    return isinstance(node, (PathEq, PathNe, PathAnd, PathOr, PathIn))


def is_path_filter_node(node):
    return isinstance(node, PathNode) and is_path_predicate(node)


def as_path_node(value):
    if isinstance(value, PathNode):
        return value
    _unsupported('Constant of type %s' % type(value).__name__)


def _path_bool(cls, left, right, op):
    if not is_path_predicate(left) or not is_path_predicate(right):
        raise PathFilterUnsupported(
            "'%s' requires comparison operands (for example "
            "`(r.team.organization == r.repository.organization) %s "
            "r.operation.in_(r.team.operations)`)." % (op, op)
        )
    return cls(left, right)


def path_root_proxy(root_model):
    """Typed ``r`` for ``register_path_filter`` builders."""
    return PathRef(_concrete_model(root_model))


def _require_path_ref(node, role):
    from trusts.core import TrustsConfigurationError

    if not isinstance(node, PathRef):
        raise TrustsConfigurationError(
            '%s must be a root-relative path on r, not %r.' % (role, node)
        )
    return node


def _phase1_validate(node, root):
    """Resolve traversals. ``.in_()`` is locally compatible only. Zero SQL."""
    from trusts.core import (
        TrustsConfigurationError,
        _resolve_forward_singles,
        _resolve_permission_in_path,
    )

    if isinstance(node, (PathAnd, PathOr)):
        _phase1_validate(node.left, root)
        _phase1_validate(node.right, root)
        return
    if isinstance(node, (PathEq, PathNe)):
        left = _require_path_ref(node.left, 'path filter left')
        right = _require_path_ref(node.right, 'path filter right')
        if left.root is not root or right.root is not root:
            raise TrustsConfigurationError(
                'Path filter equality must stay on the declaration root %s.'
                % root._meta.label
            )
        _left_path, left_model, _left_field, left_target = (
            _resolve_forward_singles(root, left.path, 'path filter left')
        )
        _right_path, right_model, _right_field, right_target = (
            _resolve_forward_singles(root, right.path, 'path filter right')
        )
        if left_model is not right_model:
            raise TrustsConfigurationError(
                'Path filter equality paths must terminate on the same '
                'model; got %s and %s.'
                % (left_model._meta.label, right_model._meta.label)
            )
        if left_target != right_target:
            raise TrustsConfigurationError(
                'Path filter equality paths must share one resolved '
                'comparison field; got %s.%s and %s.%s.'
                % (
                    left_model._meta.label, left_target,
                    right_model._meta.label, right_target,
                )
            )
        return
    if isinstance(node, PathIn):
        left = _require_path_ref(node.left, 'in_ left')
        right = _require_path_ref(node.right, 'in_ right')
        if left.root is not root or right.root is not root:
            raise TrustsConfigurationError(
                'Path filter membership must stay on the declaration root %s.'
                % root._meta.label
            )
        _left_path, left_model, _left_field, left_target = (
            _resolve_forward_singles(root, left.path, 'in_ left')
        )
        pk_attname = getattr(left_model._meta.pk, 'attname', None)
        _resolve_permission_in_path(
            root, right.path, 'in_ right', left_model,
            permission_target=pk_attname,
        )
        return
    raise TrustsConfigurationError(
        'Path filter did not produce a comparison expression.'
    )


def invoke_path_filter_builder(builder, root_model, name):
    """Phase 1 invoke: one call with typed ``r``, then discard the callable."""
    from trusts.core import TrustsConfigurationError

    root = _concrete_model(root_model)
    r = path_root_proxy(root)
    try:
        result = builder(r)
    except (PathFilterBooleanError, PathFilterUnsupported, TrustsConfigurationError):
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            'Path filter builder %r on %s raised %s: %s'
            % (name, _model_label(root), type(exc).__name__, exc)
        ) from exc
    if isinstance(result, bool):
        raise TrustsConfigurationError(
            'Path filter builder %r on %s returned a boolean; return a '
            'comparison of r (for example `r.team.organization == '
            'r.repository.organization`).' % (name, _model_label(root))
        )
    if not is_path_filter_node(result):
        raise TrustsConfigurationError(
            'Path filter builder %r on %s did not return a path-filter '
            'predicate, got %r.' % (name, _model_label(root), result)
        )
    _phase1_validate(result, root)
    return result


def _walk_membership(node, visitor):
    if isinstance(node, (PathAnd, PathOr, PathEq, PathNe)):
        _walk_membership(node.left, visitor)
        _walk_membership(node.right, visitor)
        return
    if isinstance(node, PathIn):
        visitor(node)


def bind_path_filter_permission(expr, permission_path, permission_model,
                                permission_target):
    """Phase 2: every ``.in_()`` left path equals normalized ``permission=``.

    RHS target must equal that permission terminal. Mismatch raises;
    the caller stores nothing.
    """
    from trusts.core import TrustsConfigurationError, _resolve_permission_in_path

    permission_path = tuple(permission_path)
    mismatches = []

    def _check(node):
        left = node.left
        right = node.right
        if tuple(left.path) != permission_path:
            mismatches.append(
                'in_() left path %s != permission= %s'
                % (left.path, permission_path)
            )
            return
        try:
            _resolve_permission_in_path(
                left.root, right.path, 'in_ right', permission_model,
                permission_target=permission_target,
            )
        except TrustsConfigurationError as exc:
            mismatches.append(str(exc))

    _walk_membership(expr, _check)
    if mismatches:
        raise TrustsConfigurationError(
            'Path filter does not bind to permission path %s: %s'
            % (permission_path, '; '.join(mismatches))
        )
    return expr


def canonical_ir(node):
    """Stable IR blob for fingerprints. Name strings do not participate."""
    if node is None:
        return None
    to_tuple = getattr(node, 'to_tuple', None)
    if callable(to_tuple):
        return to_tuple()
    predicates = getattr(node, 'predicates', None)
    if predicates is not None:
        return ('all',) + tuple(canonical_ir(item) for item in predicates)
    refs = getattr(node, 'refs', None)
    if refs is not None:
        return ('permission_in',) + tuple(
            getattr(ref, '_path', getattr(ref, 'path', ref)) for ref in refs
        )
    left = getattr(node, 'left', None)
    right = getattr(node, 'right', None)
    if left is not None and right is not None:
        kind = type(node).__name__.lower()
        return (kind, canonical_ir(left), canonical_ir(right))
    path = getattr(node, '_path', getattr(node, 'path', None))
    if path is not None:
        return ('ref', tuple(path))
    return repr(node)


def ir_digest(node):
    """SHA-256 of the canonical IR. Not Python ``hash()``."""
    blob = json.dumps(canonical_ir(node), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()


def _along_identity(along):
    if along is None:
        return None
    return (
        along.bound,
        along.shape,
        tuple(along.walk_path),
        getattr(getattr(along.walk_model, '_meta', None), 'label', None),
        along.walk_ident,
        along.walk_field,
        tuple(along.suffix_path),
        along.suffix_field,
        along.ident_family,
        along.parent_attname,
        getattr(getattr(along.edge_model, '_meta', None), 'label', None),
        along.edge_parent_attname,
        along.edge_child_attname,
        along.rewrite_attname,
    )


def registration_fingerprint(record, *, strategy=None):
    """Canonical path-registration identity.

    Includes normalized root + three bindings + resolved path-filter IR
    + along / strategy. The path-filter **name** is diagnostic only and
    is not part of this digest.
    """
    payload = {
        'root': _model_label(getattr(record, 'root', None)),
        'user': tuple(getattr(record, 'user_path', ()) or ()),
        'permission': tuple(getattr(record, 'permission_path', ()) or ()),
        'content': tuple(getattr(record, 'content_path', ()) or ()),
        'along': _along_identity(getattr(record, 'along', None)),
        'filter_ir': canonical_ir(getattr(record, 'condition', None)),
        'strategy': None if strategy is None else getattr(
            strategy, 'content_model', strategy
        ) and _model_label(getattr(strategy, 'content_model', strategy)),
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()


class PathFilterRecord(object):
    """Named path-filter declaration: normalized IR only. Callable discarded."""

    __slots__ = ('root', 'name', 'expr', 'digest')

    def __init__(self, root, name, expr):
        self.root = root
        self.name = name
        self.expr = expr
        self.digest = ir_digest(expr)


class FilterCatalogEntry(object):
    """One declared named filter, including unused options."""

    __slots__ = ('kind', 'model_label', 'name', 'digest', 'consumed')

    def __init__(self, kind, model_label, name, digest, consumed):
        self.kind = kind
        self.model_label = model_label
        self.name = name
        self.digest = digest
        self.consumed = consumed

    def as_tuple(self):
        return (self.kind, self.model_label, self.name, self.digest, self.consumed)

    def __eq__(self, other):
        if not isinstance(other, FilterCatalogEntry):
            return NotImplemented
        return self.as_tuple() == other.as_tuple()

    def __repr__(self):
        return 'FilterCatalogEntry%s' % (self.as_tuple(),)


def build_filter_catalog(path_records, request_records, consumed_path_names):
    """List every declared named filter. Unused names still appear."""
    entries = []
    for record in path_records:
        key = (_model_key(record.root), record.name)
        entries.append(FilterCatalogEntry(
            'path',
            _model_label(record.root),
            record.name,
            record.digest,
            key in consumed_path_names,
        ))
    for model, name, record in request_records:
        digest = ir_digest(getattr(record, 'expr', None))
        entries.append(FilterCatalogEntry(
            'request',
            _model_label(model),
            name,
            digest,
            False,
        ))
    entries.sort(key=lambda item: (item.kind, item.model_label, item.name))
    return tuple(entries)
