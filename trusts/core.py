"""Isolated registration and common authorization-plan compiler.

``TrustsRegistry`` validates root-relative ``Ref`` paths through Django
model ``_meta`` and stores immutable records. More than one normalized
registration may share one permission-bearing root when they terminate
on different content models. The same registered records compile into
one correlated relation plan. Three projections change only the
terminal: permission enumeration, object authorization (SQL ``EXISTS``
membership over that enumeration), and authorized-content filtering.

Import from ``trusts.core``. This slice does not re-export a process-global
registry from ``trusts``. Generic compiler protocol, the default plan
compiler, ``any_plan_records()``, ``granted()``, ``all_match()``,
``common_permissions()``, and configuration/compiler exceptions live here.
"""

from dataclasses import dataclass
from functools import reduce
from operator import or_

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Count, Exists, Model, OuterRef, Q
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet


class TrustsConfigurationError(Exception):
    """Malformed or unsupported ``TrustsRegistry`` registration."""


class TrustsCompilerError(TrustsConfigurationError):
    """Configured Trusts backend is missing or has a malformed query compiler."""


class QueryCompiler(object):
    """Duck-typed compiler protocol. Not a registry or store."""

    historical_fallback = False

    def complete_exists(self, plan, candidates, user, permission):
        raise NotImplementedError

    def group_exists(self, plan, candidates, user, permission):
        raise NotImplementedError


class PlanQueryCompiler(object):
    """Immutable mixin default: registered plan only, no historical group."""

    historical_fallback = False

    def complete_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return plan.content_exists(user, permission)

    def group_exists(self, plan, candidates, user, permission):
        return None


def compiler_for_class(cls):
    """Resolve the class-owned compiler. Does not construct a backend instance."""
    compiler = getattr(cls, 'query_compiler', None)
    if compiler is None:
        raise TrustsCompilerError('%r is not query-capable' % (cls,))
    complete = getattr(compiler, 'complete_exists', None)
    group = getattr(compiler, 'group_exists', None)
    if not callable(complete) or not callable(group):
        raise TrustsCompilerError('%r is not query-capable' % (cls,))
    return compiler


def _as_q(predicate):
    if predicate is None:
        return None
    if isinstance(predicate, Q):
        return predicate
    return Q(predicate)


def _is_lookup_expression(value):
    """True for OuterRef / Subquery / other SQL expressions."""
    return hasattr(value, 'resolve_expression') and not isinstance(value, Model)


def _bind_terminal(value, role):
    """Accept a model instance or an unevaluated lookup expression."""
    if _is_lookup_expression(value):
        return value
    return _require_instance(value, role)


def candidate_queryset(content):
    """Instance or QuerySet → a queryset of candidate rows.

    An instance becomes ``Model.objects.filter(pk=pk)``. Does not evaluate.
    """
    if isinstance(content, QuerySet):
        return content
    if isinstance(content, Model):
        return content._meta.concrete_model._default_manager.filter(pk=content.pk)
    raise TrustsConfigurationError(
        'content must be a model instance or QuerySet, not %r.' % (content,)
    )


def _plan_for_permission(handle, candidates, user, permission):
    if isinstance(permission, Model):
        return handle.registry.plan_for(
            candidates, user=user, permission=permission,
        )
    return handle.registry.plan_for(candidates, user=user)


def any_plan_records(handles, content):
    """True when any handle registry has ``plan_for(content).records``.

    Aggregate **support** gate across configured Trusts paths. A
    declaration on one path establishes that the content terminal is
    known; it does not compile a grant and does not authorize through
    another path's compiler. Empty ``handles`` is False. Does not
    consult ``historical_fallback`` or historical model names.
    Construction issues no SQL.
    """
    for handle in handles:
        if handle.registry.plan_for(content).records:
            return True
    return False


def granted(handles, candidates, user, permission, *, kind='complete'):
    """OR each applicable handle compiler's complete (or group) predicate.

    Noun-blind: this builder does not know Trust, Group, Guardian, or
    ceiling. A valid compiler returning ``None`` is inapplicable and is
    omitted. Compiler exceptions propagate. An empty result is ``None``
    so the caller may use the transitional undeclared fallback.

    ``permission`` may be a permission instance or an unevaluated lookup
    (``Subquery`` / ``OuterRef``). Expressions are not passed to
    ``plan_for``; the plan is selected by content and user terminals.
    """
    parts = []
    for handle in handles:
        plan = _plan_for_permission(handle, candidates, user, permission)
        if kind == 'complete':
            fn = handle.compiler.complete_exists
        else:
            fn = handle.compiler.group_exists
        part = _as_q(fn(plan, candidates, user, permission))
        if part is None:
            continue
        parts.append(part)
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


def all_match(handles, candidates, user, permission, *, kind='complete', extra_q=None):
    """True iff candidates are nonempty and no row lacks the aggregate proof.

    One SQL. ``None`` when no handle applies so the caller may use the
    undeclared fallback. ``extra_q`` is an optional overlay (AND); it
    never creates a grant.
    """
    granted_q = granted(handles, candidates, user, permission, kind=kind)
    if granted_q is None:
        return None
    if extra_q is not None:
        granted_q = granted_q & extra_q
    qs = candidate_queryset(candidates)
    stats = qs.aggregate(
        total=Count('pk', distinct=True),
        lacking=Count('pk', distinct=True, filter=~granted_q),
    )
    return stats['total'] > 0 and stats['lacking'] == 0


def instance_match(handle, obj, user, permission, *, kind='complete', extra_q=None):
    """One grant EXISTS for ``obj`` through ``handle`` only.

    ``None`` when the handle is inapplicable. ``extra_q`` is an optional
    overlay (AND); it never creates a grant.
    """
    granted_q = granted((handle,), obj, user, permission, kind=kind)
    if granted_q is None:
        return None
    if extra_q is not None:
        granted_q = granted_q & extra_q
    return obj._meta.concrete_model._default_manager.filter(
        pk=obj.pk,
    ).filter(granted_q).exists()


def common_permissions(handles, candidates, user, *, kind='complete'):
    """Permission queryset held on every candidate via the aggregate proof.

    One SQL when evaluated. ``None`` when no handle applies so the caller
    may use the undeclared fallback. Uses nested ``OuterRef`` so the
    permission identity is the outer permission row, not the candidate.
    """
    qs = candidate_queryset(candidates)
    perm_expr = OuterRef(OuterRef('pk'))
    parts = []
    permission_model = None
    applicable = False
    for handle in handles:
        plan = handle.registry.plan_for(candidates, user=user)
        if plan.records:
            applicable = True
            if plan.permission_model is not None:
                if permission_model is None:
                    permission_model = plan.permission_model
                elif permission_model is not plan.permission_model:
                    raise TrustsConfigurationError(
                        'Applicable registrations must share one permission '
                        'model; got %s and %s.'
                        % (
                            permission_model._meta.label,
                            plan.permission_model._meta.label,
                        )
                    )
        if kind == 'complete':
            fn = handle.compiler.complete_exists
        else:
            fn = handle.compiler.group_exists
        part = _as_q(fn(plan, qs, user, perm_expr))
        if part is None:
            continue
        parts.append(part)
    if not applicable or permission_model is None:
        return None
    if not parts:
        return permission_model._default_manager.none()
    granted_q = parts[0] if len(parts) == 1 else reduce(or_, parts)
    return permission_model._default_manager.filter(
        Exists(qs),
    ).exclude(
        Exists(qs.filter(~granted_q)),
    ).distinct()


def _is_model_class(value):
    return isinstance(value, ModelBase)


def _generic_relation_types():
    """Load GFK types lazily so ``AppConfig.__init__`` can import this module.

    ``contenttypes.fields`` imports ``ContentType`` models and cannot run
    during ``Apps.populate`` phase 1.
    """
    try:
        from django.contrib.contenttypes.fields import (
            GenericForeignKey,
            GenericRelation,
        )
    except ImportError:  # pragma: no cover - contenttypes is a Django contrib app
        GenericForeignKey = type('GenericForeignKey', (), {})
        GenericRelation = type('GenericRelation', (), {})
    return GenericForeignKey, GenericRelation


def _classify_field(field):
    generic_foreign_key, generic_relation = _generic_relation_types()
    if isinstance(field, (generic_foreign_key, generic_relation)):
        return 'gfk'
    if not getattr(field, 'is_relation', False):
        return 'scalar'
    if getattr(field, 'many_to_many', False):
        return 'm2m'
    if getattr(field, 'one_to_one', False) and not getattr(field, 'concrete', False):
        return 'reverse_o2o'
    if getattr(field, 'one_to_many', False):
        return 'reverse_o2m'
    if getattr(field, 'auto_created', False) and not getattr(field, 'concrete', False):
        return 'reverse'
    related = getattr(field, 'related_model', None)
    if related is None:
        return 'gfk'
    return 'single'


def _path_text(path):
    return '.'.join(path)


def _lookup_text(path):
    return '__'.join(path)


def _materialize_related_model(field):
    """Resolve a still-string ``remote_field.model`` through the app registry.

    Isolated ``ForeignKey(settings.AUTH_USER_MODEL)`` fields keep a string
    until Django's lazy related-class hook runs. Path information needs the
    model class. ``apps.get_model`` is metadata only (zero SQL).
    """
    remote = getattr(field, 'remote_field', None)
    if remote is None:
        return
    model = getattr(remote, 'model', None)
    if _is_model_class(model):
        return
    related = getattr(field, 'related_model', None)
    if isinstance(related, str) or related is None:
        label = related if isinstance(related, str) else model
        if isinstance(label, str):
            try:
                related = django_apps.get_model(label)
            except (LookupError, ValueError):
                return
    if _is_model_class(related):
        try:
            remote.model = related
        except (AttributeError, TypeError):
            return


def _resolved_hop(field, role, path):
    """Resolve one hop from Django path information.

    Requires exactly one ``PathInfo`` and exactly one target field.
    Terminal model and outer comparison field come from that metadata.
    """
    _materialize_related_model(field)
    getter = getattr(field, 'get_path_info', None)
    if not callable(getter):
        raise TrustsConfigurationError(
            '%s path %r has no resolvable path information.'
            % (role, _path_text(path))
        )
    infos = getter()
    if infos is None:
        infos = ()
    infos = tuple(infos)
    if len(infos) != 1:
        raise TrustsConfigurationError(
            '%s path %r does not resolve to exactly one relation hop; '
            'composite and multi-join relations are not supported.'
            % (role, _path_text(path))
        )
    info = infos[0]
    target_fields = getattr(info, 'target_fields', None) or ()
    if len(target_fields) != 1:
        raise TrustsConfigurationError(
            '%s path %r exposes %s target fields; composite and '
            'multi-column correlation are not supported.'
            % (role, _path_text(path), len(target_fields))
        )
    to_opts = getattr(info, 'to_opts', None)
    related = None
    if to_opts is not None:
        related = getattr(to_opts, 'concrete_model', None) or getattr(
            to_opts, 'model', None
        )
    if not _is_model_class(related):
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, _path_text(path))
        )
    target = target_fields[0]
    attname = getattr(target, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
        )
    return related._meta.concrete_model, attname


_SUFFIX_KINDS = frozenset(('single', 'reverse_o2o', 'reverse_o2m'))
_SUFFIX_MAX = 2


def _resolve_path(root, path, role, *, trailing_reverse=False):
    """Validate a root-relative path and return lookup metadata.

    User and permission paths remain one direct single-valued hop.
    A content path may be that same direct hop, or one or more forward
    single-valued hops, then a reverse one-to-many gateway, then zero
    to two suffix hops. A suffix hop is a forward single-valued,
    reverse one-to-one, or reverse one-to-many relation.
    """
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )

    current = root
    related = None
    target_attname = None
    gateway_index = None
    n = len(path)

    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )

        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'm2m':
            raise TrustsConfigurationError(
                '%s path %r uses multi-valued field %r on %s; many-to-many '
                'and other multi-valued traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if trailing_reverse:
            if gateway_index is None:
                if kind == 'single':
                    pass
                elif kind == 'reverse_o2m' and index > 0:
                    gateway_index = index
                elif kind == 'reverse_o2o':
                    raise TrustsConfigurationError(
                        '%s path %r uses reverse one-to-one relation %r on '
                        '%s; reverse one-to-one is not a valid gateway.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
                elif kind in ('reverse_o2m', 'reverse'):
                    if not is_last:
                        raise TrustsConfigurationError(
                            '%s path %r uses reverse relation %r on %s '
                            'before the gateway; reverse relations require '
                            'a preceding forward hop.'
                            % (
                                role, _path_text(path), name,
                                current._meta.label,
                            )
                        )
                    raise TrustsConfigurationError(
                        '%s path %r uses reverse relation %r on %s; '
                        'multi-valued and reverse traversals are not '
                        'supported.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
                else:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
            else:
                suffix_depth = index - gateway_index
                if suffix_depth > _SUFFIX_MAX:
                    raise TrustsConfigurationError(
                        '%s path %r has more than two hops after the '
                        'reverse one-to-many gateway.'
                        % (role, _path_text(path))
                    )
                if kind not in _SUFFIX_KINDS:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s after '
                        'the gateway; suffix hops must be forward '
                        'single-valued, reverse one-to-one, or reverse '
                        'one-to-many.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
        elif kind in ('reverse_o2o', 'reverse_o2m', 'reverse'):
            if kind == 'reverse_o2o':
                raise TrustsConfigurationError(
                    '%s path %r uses reverse one-to-one relation %r on %s; '
                    'reverse one-to-one traversals are not supported.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s before '
                    'the final hop; reverse relations are only '
                    'supported as the final content hop.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        elif kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )

        related, target_attname = _resolved_hop(field, role, path)
        if not is_last:
            current = related

    if n != 1 and gateway_index is None:
        if trailing_reverse:
            raise TrustsConfigurationError(
                '%s path %r is not a direct single-valued relation or a '
                'forward path ending in one reverse one-to-many.'
                % (role, _path_text(path))
            )
        raise TrustsConfigurationError(
            '%s path %r is not a direct single-valued relation; only '
            'direct paths are supported.'
            % (role, _path_text(path))
        )
    return tuple(path), related, _lookup_text(path), target_attname


def _require_ref(value, role):
    if not isinstance(value, Ref):
        raise TrustsConfigurationError(
            '%s must be a root-relative Ref, not %r.' % (role, value)
        )
    return value


class Ref(object):
    """Root-relative path from one permission-bearing relation model.

    Build paths with attribute access::

        j = Ref(DocumentGrant)
        j.document  # path ('document',) on DocumentGrant

    Attribute access always builds a field ref, including names such as
    ``root`` and ``path``. Inspect the model and segments on the
    normalized ``RegisteredRelation``, not on ``Ref``.
    """

    __slots__ = ('_root', '_path')

    def __init__(self, root, path=()):
        if not _is_model_class(root):
            raise TrustsConfigurationError(
                'Ref root must be a Django model class, not %r.' % (root,)
            )
        if isinstance(path, str):
            raise TrustsConfigurationError(
                'Ref path must be a sequence of field names, not a string.'
            )
        if not isinstance(path, (tuple, list)):
            raise TrustsConfigurationError(
                'Ref path must be a sequence of field names, not %r.' % (path,)
            )
        object.__setattr__(self, '_root', root)
        object.__setattr__(self, '_path', tuple(path))

    def __getattr__(self, name):
        return Ref(self._root, self._path + (name,))

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Ref is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Ref is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Ref)
            and self._root is other._root
            and self._path == other._path
        )

    def __hash__(self):
        return hash((self._root, self._path))

    def __repr__(self):
        if not self._path:
            return 'Ref(%s)' % self._root.__name__
        return 'Ref(%s).%s' % (self._root.__name__, '.'.join(self._path))


@dataclass(frozen=True, slots=True)
class RegisteredRelation:
    """Immutable normalized record for one permission-bearing relation.

    ``*_field`` is the complete root-relative Django lookup
    (``'__'.join(path)``). ``*_target`` is the last hop's single
    comparison field (``attname``), taken from resolved path metadata.
    """

    root: type
    content_path: tuple
    content_model: type
    content_field: str
    content_target: str
    user_path: tuple
    user_model: type
    user_field: str
    user_target: str
    permission_path: tuple
    permission_model: type
    permission_field: str
    permission_target: str
    condition: None = None


_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}

_TARGET_ATTRS = {
    'user_field': 'user_target',
    'content_field': 'content_target',
    'permission_field': 'permission_target',
}


def _concrete_model(value):
    opts = getattr(value, '_meta', None)
    if opts is None:
        raise TrustsConfigurationError(
            'Expected a model class or instance, not %r.' % (value,)
        )
    return opts.concrete_model


def _require_instance(value, role):
    if not isinstance(value, Model):
        raise TrustsConfigurationError(
            '%s must be a model instance, not %r.' % (role, value)
        )
    return value


def _content_model(content):
    if isinstance(content, QuerySet):
        return content.model._meta.concrete_model
    if _is_model_class(content):
        return content._meta.concrete_model
    if isinstance(content, Model):
        return content._meta.concrete_model
    raise TrustsConfigurationError(
        'content must be a model class, instance, or QuerySet, not %r.'
        % (content,)
    )


@dataclass(frozen=True, slots=True)
class RelationPlan:
    """One correlated plan compiled from applicable ``RegisteredRelation`` rows.

    Root selection, field correlation, and ``EXISTS`` assembly live here.
    Projection methods only choose the outer terminal or wrap ``exists()``.
    Bindings and correlation use the complete stored lookup, not only the
    last path segment. ``OuterRef`` uses the last hop's resolved target
    field, which need not live on the root and is not assumed to be ``pk``.
    """

    records: tuple
    permission_model: type | None = None

    def _bound_root_qs(self, record, **bindings):
        filters = {}
        for role, value in bindings.items():
            filters[getattr(record, _BINDING_FIELDS[role])] = _bind_terminal(
                value, role,
            )
        return record.root._default_manager.filter(**filters)

    def _correlated_exists(self, terminal_field_attr, **bindings):
        parts = []
        for record in self.records:
            terminal = getattr(record, terminal_field_attr)
            target = getattr(record, _TARGET_ATTRS[terminal_field_attr])
            inner = self._bound_root_qs(record, **bindings).filter(
                **{terminal: OuterRef(target)}
            )
            parts.append(Exists(inner))
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return reduce(or_, parts)

    def content_exists(self, user, permission):
        """Candidate-row ``EXISTS`` correlating content through this plan.

        Later readers may OR this predicate with another predicate on the
        same incoming queryset. ``filter_content`` consumes this same
        object; there is no second content-correlation builder.

        ``permission`` may be a permission instance or an unevaluated
        lookup (``Subquery`` / nested ``OuterRef``) so callers can bind
        permission identity in the same SQL statement.
        """
        user = _require_instance(user, 'user')
        permission = _bind_terminal(permission, 'permission')
        if not self.records:
            return None
        return self._correlated_exists(
            'content_field', user=user, permission=permission,
        )

    def common_permissions(self, user, content):
        """Trustee permissions held on every candidate through this plan.

        ``content`` is an instance or QuerySet. Empty candidates yield
        an empty permission queryset. Group extras belong to the handle
        compiler, not this plan-only projection.
        """
        user = _require_instance(user, 'user')
        if not self.records or self.permission_model is None:
            if self.permission_model is None:
                return ()
            return self.permission_model._default_manager.none()
        qs = candidate_queryset(content)
        exists = self.content_exists(user, OuterRef(OuterRef('pk')))
        if exists is None:
            return self.permission_model._default_manager.none()
        return self.permission_model._default_manager.filter(
            Exists(qs),
        ).exclude(
            Exists(qs.filter(~Q(exists))),
        ).distinct()

    def permissions(self, user, content):
        """Distinct permission rows for ``(user, content)``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        if not self.records or self.permission_model is None:
            return ()
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        return self.permission_model._default_manager.filter(exists).distinct()

    def has_permission(self, user, content, permission):
        """SQL ``EXISTS`` membership of ``permission`` in ``permissions()``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        if not self.records or self.permission_model is None:
            return False
        if permission._meta.concrete_model is not self.permission_model:
            return False
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        return self.permission_model._default_manager.filter(
            pk=permission.pk,
        ).filter(exists).exists()

    def filter_content(self, queryset, user, permission):
        """Lazy queryset of candidate rows correlated to the same plan."""
        exists = self.content_exists(user, permission)
        if exists is None:
            return queryset.none()
        return queryset.filter(exists).distinct()


class TrustsRegistry(object):
    """Instantiable registry of permission-bearing relation declarations.

    Create a new instance per isolated context. There is no process-global
    singleton in this slice. ``register`` performs zero SQL. Projection
    methods compile one shared plan from stored records. One root may
    store several records when they terminate on different content models.

    Frozen state is instance-owned. ``freeze()`` is idempotent.
    ``register`` on that exact frozen instance raises
    ``TrustsConfigurationError`` before validation or mutation. Existing
    records, plans, compilers, and authorization reads stay usable.
    A standalone ``TrustsRegistry()`` never inspects Django readiness
    and never auto-freezes.
    """

    def __init__(self):
        self._by_root = {}
        self._order = []
        self._frozen = False

    @property
    def frozen(self):
        return self._frozen

    def freeze(self):
        """Seal this instance against further ``register`` writes."""
        self._frozen = True

    @property
    def records(self):
        return tuple(self._order)

    def records_for_root(self, root):
        """Insertion-ordered records registered for ``root``.

        Raises ``TrustsConfigurationError`` when the root is absent.
        """
        try:
            return tuple(self._by_root[root])
        except KeyError:
            raise TrustsConfigurationError(
                'No registration for %r.' % (getattr(root, '__name__', root),)
            )

    def register(self, *, content, user, permission, condition=None):
        """Register one permission-bearing relation from root-relative refs.

        Exact duplicate normalized registration raises
        ``TrustsConfigurationError``. The same root plus the same content
        terminal with a different registration is a conflict and also
        raises. The same root may register different content terminals.
        Both error outcomes leave stored records unchanged.

        A frozen instance raises ``TrustsConfigurationError`` before
        validation or mutation. This method does not inspect Django's
        global ``apps.ready``.
        """
        if self._frozen:
            raise TrustsConfigurationError(
                'Cannot register on a frozen TrustsRegistry.'
            )
        if condition is not None:
            raise TrustsConfigurationError(
                'condition is not supported; omit it or pass None.'
            )

        content_ref = _require_ref(content, 'content')
        user_ref = _require_ref(user, 'user')
        permission_ref = _require_ref(permission, 'permission')

        roots = (content_ref._root, user_ref._root, permission_ref._root)
        if len(set(roots)) != 1:
            raise TrustsConfigurationError(
                'All refs in one registration must share the same root model; '
                'got %s.' % ', '.join(root._meta.label for root in roots)
            )
        root = roots[0]

        content_path, content_model, content_field, content_target = _resolve_path(
            root, content_ref._path, 'content', trailing_reverse=True,
        )
        user_path, user_model, user_field, user_target = _resolve_path(
            root, user_ref._path, 'user'
        )
        permission_path, permission_model, permission_field, permission_target = (
            _resolve_path(root, permission_ref._path, 'permission')
        )

        record = RegisteredRelation(
            root=root,
            content_path=content_path,
            content_model=content_model,
            content_field=content_field,
            content_target=content_target,
            user_path=user_path,
            user_model=user_model,
            user_field=user_field,
            user_target=user_target,
            permission_path=permission_path,
            permission_model=permission_model,
            permission_field=permission_field,
            permission_target=permission_target,
            condition=None,
        )

        existing_rows = self._by_root.get(root)
        if existing_rows:
            for existing in existing_rows:
                if existing == record:
                    raise TrustsConfigurationError(
                        'Duplicate registration for %s.' % root._meta.label
                    )
                if existing.content_model is record.content_model:
                    raise TrustsConfigurationError(
                        'Conflicting registration for %s content terminal '
                        '%s: existing %r, new %r.'
                        % (
                            root._meta.label,
                            record.content_model._meta.label,
                            existing,
                            record,
                        )
                    )
            existing_rows.append(record)
        else:
            self._by_root[root] = [record]
        self._order.append(record)
        return record

    def _records_for(self, content_model, user_model=None, permission_model=None):
        chosen = []
        for record in self._order:
            if record.content_model is not content_model:
                continue
            if user_model is not None and record.user_model is not user_model:
                continue
            if (
                permission_model is not None
                and record.permission_model is not permission_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def plan_for(self, content, *, user=None, permission=None):
        """Build the common relation plan for these terminals.

        ``content`` may be a model class, instance, or ``QuerySet``.
        Optional ``user`` / ``permission`` instances keep only registrations
        whose inferred terminals match those models. Construction is lazy.
        """
        content_model = _content_model(content)
        user_model = None
        if user is not None:
            user_model = _concrete_model(_require_instance(user, 'user'))
        permission_model = None
        if permission is not None:
            permission_model = _concrete_model(
                _require_instance(permission, 'permission')
            )

        records = self._records_for(content_model, user_model, permission_model)
        if records:
            models = {record.permission_model for record in records}
            if len(models) != 1:
                raise TrustsConfigurationError(
                    'Applicable registrations must share one permission '
                    'model; got %s.'
                    % ', '.join(sorted(model._meta.label for model in models))
                )
            permission_model = models.pop()
        return RelationPlan(records=records, permission_model=permission_model)

    def permissions_for(self, user, content):
        """Distinct permission rows granted to ``user`` on ``content``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        return self.plan_for(content, user=user).permissions(user, content)

    def has_permission(self, user, content, permission):
        """Whether ``permission`` exists in the common plan for this pair."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        return self.plan_for(
            content, user=user, permission=permission,
        ).has_permission(user, content, permission)

    def filter_authorized(self, queryset, user, permission):
        """Lazy queryset of rows ``user`` holds ``permission`` on.

        Consumes ``RelationPlan.content_exists`` through ``filter_content``.
        """
        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_authorized requires a QuerySet, not %r.' % (queryset,)
            )
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        return self.plan_for(
            queryset, user=user, permission=permission,
        ).filter_content(queryset, user, permission)


@dataclass(frozen=True, slots=True)
class BackendHandle:
    """Exact configured path, exact registry identity, and class compiler."""

    path: str
    registry: object
    compiler: object

    @property
    def historical_fallback(self):
        """True when this route uses ``HistoricalGroupQueryCompiler``.

        Noun-blind core does not decide this. The flag identifies the
        concrete compiler for mixin isolation. It does not reopen a
        static content map; undeclared terminals fail closed.
        """
        return bool(getattr(self.compiler, 'historical_fallback', False))
