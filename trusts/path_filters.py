"""Always-on named path filters: root proxy, private IR, r9 two-phase bind.

Lambdas are accepted only by ``register_path_filter``. ``register(...,
filter=)`` is a name. Builders are invoked once at declaration and
discarded.
"""

from __future__ import annotations

from dataclasses import dataclass

from trusts.request_filters import validate_filter_name


@dataclass(frozen=True)
class PFEqual:
    left: tuple
    right: tuple


@dataclass(frozen=True)
class PFNotEqual:
    left: tuple
    right: tuple


@dataclass(frozen=True)
class PFIn:
    left: tuple
    right: tuple


@dataclass(frozen=True)
class PFAnd:
    parts: tuple


@dataclass(frozen=True)
class PFOr:
    parts: tuple


@dataclass(frozen=True)
class PathFilterDecl:
    root: type
    name: str
    ir: object


def _raise_bool():
    from trusts.core import TrustsConfigurationError

    raise TrustsConfigurationError(
        'Python and / or cannot compose path filters; use & / |.'
    )


class _RootProxy:
    """Registration-time root-typed proxy ``r``."""

    __slots__ = ('_root', '_path')

    def __init__(self, root, path=()):
        object.__setattr__(self, '_root', root)
        object.__setattr__(self, '_path', tuple(path))

    def __setattr__(self, name, value):
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError('Path filter proxy is immutable.')

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return _RootProxy(self._root, self._path + (name,))

    def in_(self, collection):
        if not isinstance(collection, _RootProxy):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'in_() right-hand side must be a root-relative path, '
                'not %r.' % (type(collection).__name__,)
            )
        if self._root is not collection._root:
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'in_() operands must share one root model.'
            )
        if not self._path:
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'in_() left side must name a field path.'
            )
        return _Predicate(PFIn(self._path, collection._path))

    def __eq__(self, other):
        if not isinstance(other, _RootProxy):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '== operands must be root-relative paths.'
            )
        if self._root is not other._root:
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '== operands must share one root model.'
            )
        return _Predicate(PFEqual(self._path, other._path))

    def __ne__(self, other):
        if not isinstance(other, _RootProxy):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '!= operands must be root-relative paths.'
            )
        if self._root is not other._root:
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '!= operands must share one root model.'
            )
        return _Predicate(PFNotEqual(self._path, other._path))

    def __bool__(self):
        _raise_bool()

    def __and__(self, other):
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError(
            'Cannot & a bare path; compare or call in_() first.'
        )

    def __or__(self, other):
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError(
            'Cannot | a bare path; compare or call in_() first.'
        )

    def __contains__(self, other):
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError(
            'Python in is not a path-filter operator; use value.in_(collection).'
        )


class _Predicate:
    __slots__ = ('_ir',)

    def __init__(self, ir):
        object.__setattr__(self, '_ir', ir)

    def __setattr__(self, name, value):
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError('Path filter predicate is immutable.')

    def __and__(self, other):
        if not isinstance(other, _Predicate):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '& operands must be path-filter predicates.'
            )
        return _Predicate(PFAnd((self._ir, other._ir)))

    def __or__(self, other):
        if not isinstance(other, _Predicate):
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                '| operands must be path-filter predicates.'
            )
        return _Predicate(PFOr((self._ir, other._ir)))

    def __bool__(self):
        _raise_bool()

    def __eq__(self, other):
        return isinstance(other, _Predicate) and self._ir == other._ir

    def __hash__(self):
        return hash(self._ir)


def _walk_ir(node, visit):
    visit(node)
    if isinstance(node, (PFAnd, PFOr)):
        for part in node.parts:
            _walk_ir(part, visit)


def _validate_local_ir(root, ir):
    """Phase 1: local ``in_()`` / equality shape. No ``permission=`` yet."""
    from trusts.core import (
        TrustsConfigurationError,
        _resolve_forward_singles,
        _resolve_permission_in_path,
    )

    def visit(node):
        if isinstance(node, (PFEqual, PFNotEqual)):
            _resolve_forward_singles(root, node.left, 'filter left')
            _resolve_forward_singles(root, node.right, 'filter right')
            return
        if isinstance(node, PFIn):
            left_path, left_model, _lookup, left_target = (
                _resolve_forward_singles(root, node.left, 'in_ left')
            )
            _resolve_permission_in_path(
                root, node.right, 'in_ right', left_model,
                permission_target=left_target,
            )
            return
        if isinstance(node, (PFAnd, PFOr)):
            if not node.parts:
                raise TrustsConfigurationError(
                    'Path filter boolean node requires operands.'
                )
            return
        raise TrustsConfigurationError(
            'Unsupported path-filter IR node %r.' % (node,)
        )

    _walk_ir(ir, visit)
    return ir


def _bind_membership(root, ir, permission_path):
    """Phase 2: every ``in_()`` left path must equal ``permission=``."""
    from trusts.core import TrustsConfigurationError

    def visit(node):
        if isinstance(node, PFIn) and node.left != permission_path:
            raise TrustsConfigurationError(
                'Path filter in_() left path %r must equal the '
                'normalized permission= path %r.'
                % (node.left, permission_path)
            )

    _walk_ir(ir, visit)
    return ir


def _ir_to_condition(root, ir):
    """Lower private IR to ``All`` / ``Equal`` / ``permission_in`` when possible."""
    from trusts.core import (
        All,
        Equal,
        PathFilterCondition,
        Ref,
        permission_in,
    )

    def lower(node):
        if isinstance(node, PFEqual):
            return Equal(Ref(root, node.left), Ref(root, node.right))
        if isinstance(node, PFIn):
            return permission_in(Ref(root, node.right))
        if isinstance(node, PFAnd):
            parts = tuple(lower(part) for part in node.parts)
            if all(
                isinstance(part, (All, Equal, type(permission_in)))
                or part.__class__.__name__ in ('All', 'Equal', 'PermissionIn')
                for part in parts
            ):
                flat = []
                for part in parts:
                    if isinstance(part, All):
                        flat.extend(part.predicates)
                    else:
                        flat.append(part)
                return All(*flat)
            return PathFilterCondition(node)
        if isinstance(node, (PFNotEqual, PFOr)):
            return PathFilterCondition(node)
        return PathFilterCondition(node)

    return lower(ir)


def invoke_path_filter_builder(root, name, builder):
    """Invoke ``lambda r: ...`` once and return frozen local IR."""
    from trusts.core import TrustsConfigurationError

    if not callable(builder):
        raise TypeError(
            'register_path_filter builder must be callable, not %r.'
            % (type(builder).__name__,)
        )
    proxy = _RootProxy(root)
    try:
        result = builder(proxy)
    except Exception:
        raise
    if isinstance(result, _RootProxy):
        raise TrustsConfigurationError(
            'Path filter %r must return a predicate (==, !=, in_(), '
            '&, |), not a bare path.' % (name,)
        )
    if not isinstance(result, _Predicate):
        raise TrustsConfigurationError(
            'Path filter %r did not return a path-filter predicate, '
            'got %r.' % (name, result)
        )
    return _validate_local_ir(root, result._ir)


def register_path_filter(registry, root_model, name, builder):
    """Phase 1 store write. Duplicate names fail before invoke."""
    from trusts.core import TrustsConfigurationError, _is_model_class

    if getattr(registry, 'frozen', False):
        raise TrustsConfigurationError(
            'Cannot register a path filter on a frozen TrustsRegistry.'
        )
    if not _is_model_class(root_model):
        raise TrustsConfigurationError(
            'register_path_filter root must be a Django model class, '
            'not %r.' % (root_model,)
        )
    name = validate_filter_name(name, role='path filter')
    root = root_model._meta.concrete_model
    key = (root, name)
    store = registry._path_filters
    if key in store:
        raise TrustsConfigurationError(
            'Duplicate path filter %r on %s.' % (name, root._meta.label)
        )
    ir = invoke_path_filter_builder(root, name, builder)
    decl = PathFilterDecl(root=root, name=name, ir=ir)
    store[key] = decl
    return decl


def bind_named_path_filter(registry, root_model, name, permission_path):
    """Phase 2: resolve name and prove membership left == ``permission=``."""
    from trusts.core import TrustsConfigurationError, _is_model_class

    if not _is_model_class(root_model):
        raise TrustsConfigurationError(
            'register root must be a Django model class, not %r.'
            % (root_model,)
        )
    name = validate_filter_name(name, role='path filter')
    root = root_model._meta.concrete_model
    decl = registry._path_filters.get((root, name))
    if decl is None:
        raise TrustsConfigurationError(
            'Unknown path filter %r on %s.' % (name, root._meta.label)
        )
    _bind_membership(root, decl.ir, tuple(permission_path))
    return _ir_to_condition(root, decl.ir)


def registration_fingerprint(record):
    """Registration identity includes resolved path-filter IR, not the name."""
    return (
        record.root,
        record.content_path,
        record.user_path,
        record.permission_path,
        record.condition,
        record.along,
    )


def iter_path_filters(registry):
    """Yield ``(root, name, decl)`` in insertion order."""
    for (root, name), decl in registry._path_filters.items():
        yield root, name, decl
