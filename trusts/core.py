"""Isolated registration and common authorization-plan compiler.

``TrustsRegistry`` validates root-relative ``Ref`` paths through Django
model ``_meta`` and stores immutable records. More than one normalized
registration may share one permission-bearing root when they terminate
on different content models. The same registered records compile into
one correlated relation plan. Three projections change only the
terminal: permission enumeration, object authorization (SQL ``EXISTS``
membership over that enumeration), and authorized-content filtering.

Optional ``Along`` replaces equality at one walk-site with bounded
grant-anchored reachability. V1 compiles that walk only for Django's
SQLite backend.

Closed predicate nodes ``All``, ``Equal``, and ``permission_in`` are an
AND overlay on one permission-bearing root. A requester path may end in
exactly one terminal M2M membership hop after zero or more forward
single-valued hops. Validation is registration-time ``_meta`` only
(zero SQL).

Import from ``trusts.core``. This slice does not re-export a process-global
registry from ``trusts``. Generic compiler protocol, the default plan
compiler, ``any_plan_records()``, ``granted()``, ``all_match()``,
``common_permissions()``, ``filter_authorized_scopes()``,
``ConditionLookup``, and configuration/compiler exceptions live here.
"""

from dataclasses import dataclass
from functools import reduce
from operator import or_

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models import BooleanField, Count, Exists, F, Model, OuterRef, Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Expression
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


class ConditionLookup(object):
    """Duck-typed ``:condition`` overlay protocol. Not a registry or store.

    Bind with ``TrustsRegistry.set_condition_lookup``. Core never imports
    a Zero ``Content`` registry to evaluate conditions. Unbound lookup on
    an instance-only caller is a no-op.

    ``record_for`` returns the registered record or ``None`` (unregistered
    codes fail closed as ``AttributeError`` at the caller). ``compile_q``
    compiles an ``Expr`` to ``Q``. A callable policy must raise
    ``PermissionConditionNotQueryable`` and must never be invoked.
    """

    def record_for(self, model, cond_code):
        raise NotImplementedError

    def compile_q(self, model, perm_string, user):
        raise NotImplementedError


def _scope_prefix_lookups(record, scope_model):
    """Root-relative lookups to proper prefix nodes matching ``scope_model``.

    A proper prefix is a hop on ``content_path`` whose related model is
    ``scope_model`` and that is not the content terminal. Each item is
    ``(root-relative lookup, target attname)``. The attname is the
    hop's resolved identity (``to_field`` when set), not assumed to
    be ``pk``. Uses stored path names and ``_meta`` only (zero SQL).
    """
    path = record.content_path
    if not path:
        return ()
    current = record.root
    lookups = []
    last = len(path) - 1
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            return ()
        related, target_attname = _resolved_hop(field, 'content', path)
        if related._meta.concrete_model is scope_model and index != last:
            lookups.append((_lookup_text(path[:index + 1]), target_attname))
        current = related
    return tuple(lookups)


def filter_authorized_scopes(queryset, user, permission, *, content, handles=None):
    """Filter scope-model rows that appear as a proper prefix of ``content``.

    Fail closed unless ``queryset.model`` is a proper prefix node of some
    applicable record's ``content_path`` whose content terminal is
    ``content``. Compile ``EXISTS`` of root rows correlated to
    ``OuterRef`` of that hop's resolved target field (the related
    ``attname`` from ``get_path_info()``, which need not be ``pk``) at
    that node, bind user + permission from the same record, and OR
    applicable records.

    ``queryset.model`` equal to the content terminal returns ``none()``
    (that path is ``AuthorizedQuerySet.authorized``). Unknown terminal,
    empty handles, or a scope model not on the path return ``none()``.
    ``permission`` must be a model instance. Construction of a fail-closed
    result issues zero SQL; SQL runs only when a compiled predicate is
    evaluated.

    Noun-blind: this builder does not import or name Zero schema models
    and does not use ``trust_grant_q`` or a compiler's historical group
    OR. Group-as-trustee remains a later registered root.
    """
    if not isinstance(queryset, QuerySet):
        raise TrustsConfigurationError(
            'filter_authorized_scopes requires a QuerySet, not %r.'
            % (queryset,)
        )
    user = _require_instance(user, 'user')
    permission = _require_instance(permission, 'permission')
    if handles is None:
        from trusts.apps import kernel_config
        handles = kernel_config().configured_handles()
    if not handles:
        return queryset.none()

    content_model = _content_model(content)
    scope_model = queryset.model._meta.concrete_model
    if scope_model is content_model:
        return queryset.none()

    parts = []
    for handle in handles:
        plan = _plan_for_permission(handle, content, user, permission)
        for record in plan.records:
            for lookup, target_attname in _scope_prefix_lookups(
                record, scope_model,
            ):
                inner = _bind_record_qs(
                    record, user=user, permission=permission,
                ).filter(**{lookup: OuterRef(target_attname)})
                parts.append(Exists(inner))
    if not parts:
        return queryset.none()
    granted_q = parts[0] if len(parts) == 1 else reduce(or_, parts)
    return queryset.filter(granted_q).distinct()


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


def _resolve_m2m_terminal(field, role, path):
    """Resolve a terminal many-to-many hop without ``get_path_info()``.

    M2M path information is two joins (through table + target). Membership
    correlation uses the related model and its primary key only.
    """
    _materialize_related_model(field)
    related = getattr(field, 'related_model', None)
    if not _is_model_class(related):
        remote = getattr(field, 'remote_field', None)
        model = getattr(remote, 'model', None) if remote is not None else None
        if _is_model_class(model):
            related = model
    if not _is_model_class(related):
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, _path_text(path))
        )
    related = related._meta.concrete_model
    pk = related._meta.pk
    attname = getattr(pk, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
        )
    return related, attname


def _resolve_path(root, path, role, *, trailing_reverse=False,
                  terminal_membership=False):
    """Validate a root-relative path and return lookup metadata.

    Permission paths remain one direct single-valued hop. A user path
    may be that same direct hop, or zero or more forward single-valued
    hops followed by exactly one terminal M2M membership hop. Reverse
    one-to-many requester paths stay rejected. A content path may be a
    direct hop, or one or more forward single-valued hops, then a
    reverse one-to-many gateway, then zero to two suffix hops. A suffix
    hop is a forward single-valued, reverse one-to-one, or reverse
    one-to-many relation.
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
    last_kind = None
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
        last_kind = kind
        if terminal_membership and is_last and kind == 'm2m':
            related, target_attname = _resolve_m2m_terminal(field, role, path)
            break
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
        if terminal_membership and last_kind == 'm2m':
            pass
        elif trailing_reverse:
            raise TrustsConfigurationError(
                '%s path %r is not a direct single-valued relation or a '
                'forward path ending in one reverse one-to-many.'
                % (role, _path_text(path))
            )
        else:
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


def _require_same_root(ref, root, role):
    ref = _require_ref(ref, role)
    if ref._root is not root:
        raise TrustsConfigurationError(
            '%s must share the registration root %s; got %s.'
            % (role, root._meta.label, ref._root._meta.label)
        )
    return ref


def _resolve_forward_singles(root, path, role):
    """One or more forward single-valued hops. No multi-valued walks."""
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )
    current = root
    related = None
    target_attname = None
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
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        related, target_attname = _resolved_hop(field, role, path)
        if not is_last:
            current = related
    return tuple(path), related, _lookup_text(path), target_attname


def _resolve_permission_in_path(root, path, role, permission_model):
    """Bounded ceiling path: forward singles, optional reverse O2M, terminal membership."""
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )
    current = root
    related = None
    target_attname = None
    intermediate_multi = False
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
                '%s path %r traverses scalar field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'single':
            if intermediate_multi:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'walks; single-valued hops cannot follow a collection.'
                    % (role, _path_text(path))
                )
            if is_last:
                raise TrustsConfigurationError(
                    '%s path %r must terminate on a multi-valued '
                    'membership hop.'
                    % (role, _path_text(path))
                )
            related, target_attname = _resolved_hop(field, role, path)
            current = related
            continue
        if kind == 'reverse_o2m' and not is_last:
            if intermediate_multi:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            intermediate_multi = True
            related, target_attname = _resolved_hop(field, role, path)
            current = related
            continue
        if kind in ('m2m', 'reverse_o2m') and is_last:
            if kind == 'm2m':
                related, target_attname = _resolve_m2m_terminal(
                    field, role, path,
                )
            else:
                related, target_attname = _resolved_hop(field, role, path)
            if related is not permission_model:
                raise TrustsConfigurationError(
                    '%s path %r terminates on %s, not the registered '
                    'permission model %s.'
                    % (
                        role, _path_text(path), related._meta.label,
                        permission_model._meta.label,
                    )
                )
            return tuple(path), related, _lookup_text(path), target_attname
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        raise TrustsConfigurationError(
            '%s path %r uses unsupported field %r on %s.'
            % (role, _path_text(path), name, current._meta.label)
        )
    raise TrustsConfigurationError(
        '%s path %r must terminate on a multi-valued membership hop.'
        % (role, _path_text(path))
    )


def _validate_equal(predicate, root):
    left = _require_same_root(predicate.left, root, 'Equal left')
    right = _require_same_root(predicate.right, root, 'Equal right')
    _left_path, left_model, _left_field, _left_target = _resolve_forward_singles(
        root, left._path, 'Equal left',
    )
    _right_path, right_model, _right_field, _right_target = (
        _resolve_forward_singles(root, right._path, 'Equal right')
    )
    if left_model is not right_model:
        raise TrustsConfigurationError(
            'Equal paths must terminate on the same model; got %s and %s.'
            % (left_model._meta.label, right_model._meta.label)
        )
    # Compiler compares stored FK columns via F(). Distinct unique
    # fields (``to_field``) on the same model can collide across
    # objects and fail open if only the terminal model is checked.
    if left_target != right_target:
        raise TrustsConfigurationError(
            'Equal paths must share one resolved comparison field; '
            'got %s.%s and %s.%s.'
            % (
                left_model._meta.label, left_target,
                right_model._meta.label, right_target,
            )
        )


def _validate_permission_in(predicate, root, permission_model):
    if not predicate.refs:
        raise TrustsConfigurationError(
            'permission_in requires one or more refs.'
        )
    for ref in predicate.refs:
        bound = _require_same_root(ref, root, 'permission_in')
        _resolve_permission_in_path(
            root, bound._path, 'permission_in', permission_model,
        )


def _validate_condition(condition, root, permission_model):
    """Registration-time ``_meta`` validation. Zero SQL. None is a no-op."""
    if condition is None:
        return None
    if isinstance(condition, All):
        if not condition.predicates:
            raise TrustsConfigurationError(
                'All requires one or more predicates.'
            )
        for predicate in condition.predicates:
            _validate_condition(predicate, root, permission_model)
        return condition
    if isinstance(condition, Equal):
        _validate_equal(condition, root)
        return condition
    if isinstance(condition, PermissionIn):
        _validate_permission_in(condition, root, permission_model)
        return condition
    raise TrustsConfigurationError(
        'condition is not supported; omit it or pass None.'
    )


def _compile_predicate(node, record):
    if node is None:
        return None
    if isinstance(node, All):
        parts = [
            _compile_predicate(predicate, record)
            for predicate in node.predicates
        ]
        parts = [part for part in parts if part is not None]
        if not parts:
            return None
        compiled = parts[0]
        for part in parts[1:]:
            compiled &= part
        return compiled
    if isinstance(node, Equal):
        return Q(**{
            _lookup_text(node.left._path): F(_lookup_text(node.right._path)),
        })
    if isinstance(node, PermissionIn):
        compiled = Q()
        for ref in node.refs:
            compiled &= Q(**{
                _lookup_text(ref._path): F(record.permission_field),
            })
        return compiled
    raise TrustsConfigurationError(
        'condition is not supported; omit it or pass None.'
    )


def _apply_condition(record, queryset):
    compiled = _compile_predicate(record.condition, record)
    if compiled is None:
        return queryset
    return queryset.filter(compiled)


def _bind_record_qs(record, **bindings):
    """Root rows bound to terminals, with the registered condition AND overlay."""
    filters = {}
    for role, value in bindings.items():
        filters[getattr(record, _BINDING_FIELDS[role])] = _bind_terminal(
            value, role,
        )
    return _apply_condition(
        record, record.root._default_manager.filter(**filters),
    )


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


class Along(object):
    """Bounded directed walk that replaces equality at one walk-site.

    ``ref`` names the directed edge from the walk-site. ``bound`` is the
    maximum hop distance (1..64). Depth 0 is always included.
    """

    __slots__ = ('ref', 'bound')

    def __init__(self, ref, bound):
        object.__setattr__(self, 'ref', ref)
        object.__setattr__(self, 'bound', bound)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Along is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Along is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Along)
            and self.ref == other.ref
            and self.bound == other.bound
        )

    def __hash__(self):
        return hash((self.ref, self.bound))

    def __repr__(self):
        return 'Along(%r, bound=%r)' % (self.ref, self.bound)


class Equal(object):
    """Closed equality of two root-relative single-valued refs."""

    __slots__ = ('left', 'right')

    def __init__(self, left, right):
        if not isinstance(left, Ref) or not isinstance(right, Ref):
            raise TrustsConfigurationError(
                'Equal left and right must be root-relative Refs, not %r '
                'and %r.' % (left, right)
            )
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Equal is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Equal is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Equal)
            and self.left == other.left
            and self.right == other.right
        )

    def __hash__(self):
        return hash((Equal, self.left, self.right))

    def __repr__(self):
        return 'Equal(%r, %r)' % (self.left, self.right)


class PermissionIn(object):
    """Closed membership of the registered permission in one or more refs."""

    __slots__ = ('refs',)

    def __init__(self, *refs):
        if not refs:
            raise TrustsConfigurationError(
                'permission_in requires one or more refs.'
            )
        for ref in refs:
            if not isinstance(ref, Ref):
                raise TrustsConfigurationError(
                    'permission_in refs must be root-relative Refs, not %r.'
                    % (ref,)
                )
        object.__setattr__(self, 'refs', refs)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('permission_in is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('permission_in is immutable.')

    def __eq__(self, other):
        return isinstance(other, PermissionIn) and self.refs == other.refs

    def __hash__(self):
        return hash((PermissionIn, self.refs))

    def __repr__(self):
        return 'permission_in(%s)' % ', '.join(repr(ref) for ref in self.refs)


permission_in = PermissionIn


class All(object):
    """Closed AND of one or more typed predicate nodes."""

    __slots__ = ('predicates',)

    def __init__(self, *predicates):
        if not predicates:
            raise TrustsConfigurationError(
                'All requires one or more predicates.'
            )
        for predicate in predicates:
            if not isinstance(predicate, (All, Equal, PermissionIn)):
                raise TrustsConfigurationError(
                    'All predicates must be All, Equal, or permission_in '
                    'nodes, not %r.' % (predicate,)
                )
        object.__setattr__(self, 'predicates', predicates)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('All is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('All is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, All)
            and self.predicates == other.predicates
        )

    def __hash__(self):
        return hash((All, self.predicates))

    def __repr__(self):
        return 'All(%s)' % ', '.join(repr(pred) for pred in self.predicates)


@dataclass(frozen=True, slots=True)
class AlongWalk:
    """Immutable walk metadata resolved from ``Along`` at ``register()``."""

    bound: int
    shape: str
    walk_path: tuple
    walk_model: type
    walk_ident: str
    walk_field: str
    suffix_path: tuple
    suffix_field: str
    ident_family: str
    parent_attname: str | None
    edge_model: type | None
    edge_parent_attname: str | None
    edge_child_attname: str | None
    rewrite_attname: str | None


_ALONG_BOUND_MIN = 1
_ALONG_BOUND_MAX = 64
_DJANGO_SQLITE3 = 'django.db.backends.sqlite3'

_INTEGER_IDENTITY_TYPES = frozenset((
    'AutoField',
    'BigAutoField',
    'SmallAutoField',
    'IntegerField',
    'BigIntegerField',
    'SmallIntegerField',
    'PositiveIntegerField',
    'PositiveSmallIntegerField',
    'PositiveBigIntegerField',
))
_TEXT_IDENTITY_TYPES = frozenset((
    'CharField',
    'TextField',
    'SlugField',
))
_UUID_IDENTITY_TYPES = frozenset(('UUIDField',))


def _common_prefix(left, right):
    n = 0
    for a, b in zip(left, right):
        if a != b:
            break
        n += 1
    return left[:n]


def _target_field(field, role, path):
    """Return ``(related_model, target_field)`` for one hop."""
    related, attname = _resolved_hop(field, role, path)
    target = related._meta.get_field(attname)
    if getattr(target, 'attname', None) != attname:
        for candidate in related._meta.concrete_fields:
            if candidate.attname == attname:
                target = candidate
                break
    return related, target


def _ident_family(field):
    kind = field.get_internal_type()
    if kind in _INTEGER_IDENTITY_TYPES:
        return 'integer'
    if kind in _TEXT_IDENTITY_TYPES:
        return 'text'
    if kind in _UUID_IDENTITY_TYPES:
        return 'uuid'
    raise TrustsConfigurationError(
        'Along identity field %s (%s) is not a V1 integer, text, or UUID '
        'JSON identity.' % (field.attname, kind)
    )


def _concrete_fk(field):
    fk = getattr(field, 'field', None)
    if (
        fk is not None
        and getattr(fk, 'is_relation', False)
        and getattr(fk, 'concrete', False)
    ):
        return fk
    return field


def _resolve_along_edge(walk_model, edge_path):
    """Return S/C/E metadata for hops from ``walk_model`` along ``edge_path``."""
    n = len(edge_path)
    if n == 1:
        try:
            field = walk_model._meta.get_field(edge_path[0])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (_path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        kind = _classify_field(field)
        related, target = _target_field(field, 'along', edge_path)
        if related is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    _path_text(edge_path),
                    walk_model._meta.label,
                    related._meta.label,
                )
            )
        if kind == 'single':
            return 'S', field.attname, None, None, None, target
        if kind == 'reverse_o2m':
            # Reverse PathInfo.target_fields is the related model's PK, not
            # the concrete self-FK's remote to_field. Identity comes from
            # the forward FK metadata; the reverse hop still proves the
            # edge is a self-relation on the walk-site.
            fk = _concrete_fk(field)
            dest, edge_target = _target_field(fk, 'along', edge_path)
            if dest is not walk_model:
                raise TrustsConfigurationError(
                    'along edge %r must terminate on walk-site model %s, not %s.'
                    % (
                        _path_text(edge_path),
                        walk_model._meta.label,
                        dest._meta.label,
                    )
                )
            return 'C', fk.attname, None, None, None, edge_target
        raise TrustsConfigurationError(
            'along edge %r is not a supported S/C/E hop.'
            % (_path_text(edge_path),)
        )
    if n == 2:
        try:
            reverse = walk_model._meta.get_field(edge_path[0])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (_path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        if _classify_field(reverse) != 'reverse_o2m':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (_path_text(edge_path),)
            )
        edge_model, _edge_pk = _target_field(
            reverse, 'along', edge_path[:1],
        )
        try:
            forward = edge_model._meta.get_field(edge_path[1])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (
                    _path_text(edge_path), edge_path[1],
                    edge_model._meta.label,
                )
            )
        if _classify_field(forward) != 'single':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (_path_text(edge_path),)
            )
        dest, parent_target = _target_field(forward, 'along', edge_path)
        if dest is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    _path_text(edge_path),
                    walk_model._meta.label,
                    dest._meta.label,
                )
            )
        child_fk = _concrete_fk(reverse)
        _child_related, child_target = _target_field(
            child_fk, 'along', edge_path[:1],
        )
        if child_target.attname != parent_target.attname:
            raise TrustsConfigurationError(
                'along edge %r mixes identity fields %r and %r.'
                % (
                    _path_text(edge_path),
                    child_target.attname,
                    parent_target.attname,
                )
            )
        return (
            'E',
            None,
            edge_model,
            forward.attname,
            child_fk.attname,
            parent_target,
        )
    raise TrustsConfigurationError(
        'along edge %r is not a supported S/C/E hop.'
        % (_path_text(edge_path),)
    )


def _re_resolve_suffix(walk_model, suffix_path, content_model):
    """Confirm stored suffix names compile from the walk-site model."""
    if not suffix_path:
        if walk_model is not content_model:
            raise TrustsConfigurationError(
                'along suffix path is empty but the content terminal %s '
                'is not the walk-site %s.'
                % (content_model._meta.label, walk_model._meta.label)
            )
        return
    current = walk_model
    for index, name in enumerate(suffix_path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along suffix path %r cannot be resolved from %s; '
                'missing field %r.'
                % (_path_text(suffix_path), walk_model._meta.label, name)
            )
        kind = _classify_field(field)
        if kind not in _SUFFIX_KINDS:
            raise TrustsConfigurationError(
                'along suffix path %r uses unsupported field %r on %s.'
                % (_path_text(suffix_path), name, current._meta.label)
            )
        related, _attname = _resolved_hop(field, 'along suffix', suffix_path)
        current = related
    if current is not content_model:
        raise TrustsConfigurationError(
            'along suffix path %r from %s terminates on %s, not %s.'
            % (
                _path_text(suffix_path),
                walk_model._meta.label,
                current._meta.label,
                content_model._meta.label,
            )
        )


def _suffix_rewrite_attname(walk_model, suffix_path, content_model, walk_ident):
    if len(suffix_path) != 1:
        return None
    try:
        field = walk_model._meta.get_field(suffix_path[0])
    except FieldDoesNotExist:
        return None
    if _classify_field(field) not in ('reverse_o2m', 'reverse_o2o'):
        return None
    fk = _concrete_fk(field)
    if fk.model._meta.concrete_model is not content_model:
        return None
    _related, target = _target_field(fk, 'along suffix', suffix_path)
    if target.attname != walk_ident:
        return None
    return fk.name


def _build_along_walk(root, content_path, content_model, along):
    along_ref = _require_ref(along.ref, 'along')
    if along_ref._root is not root:
        raise TrustsConfigurationError(
            'along ref must share the registration root %s; got %s.'
            % (root._meta.label, along_ref._root._meta.label)
        )
    bound = along.bound
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise TrustsConfigurationError(
            'Along bound must be an integer in %s..%s.'
            % (_ALONG_BOUND_MIN, _ALONG_BOUND_MAX)
        )
    if bound < _ALONG_BOUND_MIN or bound > _ALONG_BOUND_MAX:
        raise TrustsConfigurationError(
            'Along bound must be an integer in %s..%s.'
            % (_ALONG_BOUND_MIN, _ALONG_BOUND_MAX)
        )
    walk_path = _common_prefix(tuple(along_ref._path), tuple(content_path))
    edge_path = tuple(along_ref._path[len(walk_path):])
    suffix_path = tuple(content_path[len(walk_path):])
    if not walk_path:
        raise TrustsConfigurationError(
            'along ref %r and content path %r do not share a walk-site prefix.'
            % (_path_text(along_ref._path), _path_text(content_path))
        )
    if not edge_path:
        raise TrustsConfigurationError(
            'along ref %r has no edge hop beyond the walk-site.'
            % (_path_text(along_ref._path),)
        )
    _walk_path, walk_model, walk_field, walk_ident = _resolve_path(
        root, walk_path, 'along', trailing_reverse=True,
    )
    last_walk_name = walk_path[-1]
    current = root
    for name in walk_path[:-1]:
        field = current._meta.get_field(name)
        current, _att = _resolved_hop(field, 'along', walk_path)
    grant_hop = current._meta.get_field(last_walk_name)
    _grant_related, grant_target = _target_field(grant_hop, 'along', walk_path)
    (
        shape, parent_attname, edge_model, edge_parent_attname,
        edge_child_attname, edge_target,
    ) = _resolve_along_edge(walk_model, edge_path)
    ident_fields = (grant_target, edge_target)
    attnames = {field.attname for field in ident_fields}
    if attnames != {walk_ident}:
        raise TrustsConfigurationError(
            'along identity fields must match across the grant walk hop '
            'and both edge ends; got %s.'
            % ', '.join(sorted(field.attname for field in ident_fields))
        )
    families = {_ident_family(field) for field in ident_fields}
    if len(families) != 1:
        raise TrustsConfigurationError(
            'along identity fields mix JSON families %s.'
            % ', '.join(sorted(families))
        )
    ident_family = families.pop()
    _re_resolve_suffix(walk_model, suffix_path, content_model)
    rewrite_attname = _suffix_rewrite_attname(
        walk_model, suffix_path, content_model, walk_ident,
    )
    return AlongWalk(
        bound=bound,
        shape=shape,
        walk_path=tuple(walk_path),
        walk_model=walk_model,
        walk_ident=walk_ident,
        walk_field=walk_field,
        suffix_path=suffix_path,
        suffix_field=_lookup_text(suffix_path) if suffix_path else '',
        ident_family=ident_family,
        parent_attname=parent_attname,
        edge_model=edge_model,
        edge_parent_attname=edge_parent_attname,
        edge_child_attname=edge_child_attname,
        rewrite_attname=rewrite_attname,
    )


def along_connection_supported(connection):
    """True when ``connection`` is Django's sqlite3 backend (no SQL)."""
    engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
    return engine == _DJANGO_SQLITE3


def probe_along_capabilities(connection):
    """Execute JSON1 + recursive-CTE capability SQL. Raises on failure."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT json_array(1, 'x'), json_group_array(x), "
            "json_array_length(json_array(1)) FROM (SELECT 1 AS x)"
        )
        cursor.fetchone()
        cursor.execute("SELECT value FROM json_each('[1]')")
        cursor.fetchone()
        cursor.execute(
            'WITH RECURSIVE t(n) AS ('
            'SELECT 0 UNION ALL SELECT n + 1 FROM t WHERE n < 0'
            ') SELECT n FROM t'
        )
        cursor.fetchone()


def _require_sqlite_along_renderer(connection):
    if along_connection_supported(connection):
        return
    engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
    raise TrustsConfigurationError(
        'Along reachability requires Django sqlite3 with JSON functions '
        'and recursive CTEs; got ENGINE=%r vendor=%r alias=%r.'
        % (
            engine,
            getattr(connection, 'vendor', None),
            getattr(connection, 'alias', None),
        )
    )


def _neighbor_sql(walk, qn, g, frontier, ident_sql):
    f = 'f'
    if walk.shape == 'S':
        child = qn('child')
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = (
            'FROM json_each(%(g)s.%(frontier)s) AS %(f)s '
            'JOIN %(walk_table)s AS %(child)s '
            'ON %(child)s.%(parent_col)s = %(f)s.value'
            % {
                'g': g, 'frontier': frontier, 'f': f,
                'walk_table': walk_table, 'child': child,
                'parent_col': parent_col,
            }
        )
        project = '%s.%s' % (child, ident_sql)
        return frm, project
    if walk.shape == 'C':
        cur = qn('cur')
        parent = qn('parent')
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = (
            'FROM json_each(%(g)s.%(frontier)s) AS %(f)s '
            'JOIN %(walk_table)s AS %(cur)s '
            'ON %(cur)s.%(ident)s = %(f)s.value '
            'JOIN %(walk_table)s AS %(parent)s '
            'ON %(parent)s.%(ident)s = %(cur)s.%(parent_col)s'
            % {
                'g': g, 'frontier': frontier, 'f': f,
                'walk_table': walk_table, 'cur': cur, 'ident': ident_sql,
                'parent': parent, 'parent_col': parent_col,
            }
        )
        project = '%s.%s' % (parent, ident_sql)
        return frm, project
    if walk.shape == 'E':
        link = qn('link')
        edge_table = qn(walk.edge_model._meta.db_table)
        parent_col = qn(walk.edge_parent_attname)
        child_col = qn(walk.edge_child_attname)
        frm = (
            'FROM json_each(%(g)s.%(frontier)s) AS %(f)s '
            'JOIN %(edge_table)s AS %(link)s '
            'ON %(link)s.%(parent_col)s = %(f)s.value'
            % {
                'g': g, 'frontier': frontier, 'f': f,
                'edge_table': edge_table, 'link': link,
                'parent_col': parent_col,
            }
        )
        project = '%s.%s' % (link, child_col)
        return frm, project
    raise TrustsConfigurationError(
        'Unsupported Along shape %r.' % (walk.shape,)
    )


def _render_reach_sql(walk, seed_sql, seed_params, connection):
    """Return ``(sql, params)`` for the uncorrelated W membership list."""
    qn = connection.ops.quote_name
    gen = qn('gen')
    g = qn('g')
    depth = qn('depth')
    frontier = qn('frontier')
    seen = qn('seen')
    ident = qn(walk.walk_ident)
    ident_alias = qn('ident')
    walk_table = qn(walk.walk_model._meta.db_table)
    site = qn('s')
    j = 'j'
    seed = qn('seed')
    arr = qn('arr')
    frm, project = _neighbor_sql(walk, qn, g, frontier, ident)
    recursive_frontier = (
        '(SELECT COALESCE((SELECT json_group_array(DISTINCT %(project)s) '
        '%(frm)s WHERE %(project)s IS NOT NULL AND %(project)s NOT IN '
        '(SELECT value FROM json_each(%(g)s.%(seen)s))), \'[]\'))'
        % {'project': project, 'frm': frm, 'g': g, 'seen': seen}
    )
    recursive_seen = (
        '(SELECT COALESCE((SELECT json_group_array(x) FROM ('
        'SELECT value AS x FROM json_each(%(g)s.%(seen)s) '
        'UNION SELECT %(project)s %(frm)s WHERE %(project)s IS NOT NULL'
        ')), \'[]\'))'
        % {'g': g, 'seen': seen, 'project': project, 'frm': frm}
    )
    sql = (
        'WITH RECURSIVE %(gen)s(%(depth)s, %(frontier)s, %(seen)s) AS ('
        'SELECT 0, %(seed)s.%(arr)s, %(seed)s.%(arr)s FROM ('
        'SELECT COALESCE((SELECT json_group_array(%(ident_alias)s) FROM (%(seed_sql)s) '
        'AS seed_rows), \'[]\') AS %(arr)s'
        ') AS %(seed)s '
        'UNION ALL '
        'SELECT %(g)s.%(depth)s + 1, %(next_frontier)s, %(next_seen)s '
        'FROM %(gen)s AS %(g)s '
        'WHERE %(g)s.%(depth)s < %%s '
        'AND json_array_length(%(g)s.%(frontier)s) > 0'
        ') '
        'SELECT DISTINCT %(site)s.%(ident)s '
        'FROM %(gen)s, json_each(%(gen)s.%(seen)s) AS %(j)s '
        'JOIN %(walk_table)s AS %(site)s '
        'ON %(site)s.%(ident)s = %(j)s.value'
        % {
            'gen': gen, 'depth': depth, 'frontier': frontier, 'seen': seen,
            'seed': seed, 'arr': arr, 'ident_alias': ident_alias,
            'seed_sql': seed_sql, 'g': g,
            'next_frontier': recursive_frontier, 'next_seen': recursive_seen,
            'site': site, 'ident': ident, 'j': j,
            'walk_table': walk_table,
        }
    )
    return sql, tuple(seed_params) + (walk.bound,)


class _IdentInReach(Expression):
    """Boolean predicate ``alias.ident IN (W)`` compiled on the inner query."""

    def __init__(self, attname, w_sql, w_params):
        super().__init__(output_field=BooleanField())
        self.attname = attname
        self.w_sql = w_sql
        self.w_params = w_params

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        alias = compiler.query.get_initial_alias()
        sql = '%s.%s IN (%s)' % (qn(alias), qn(self.attname), self.w_sql)
        return sql, tuple(self.w_params)


class GrantReach(Expression):
    """Grant-anchored bounded reachability predicate for one recursive record.

    The walk is uncorrelated with candidate rows. One ``IN (WITH RECURSIVE …)``
    per recursive record. Unsupported vendors raise before walk SQL.
    """

    filterable = True
    subquery = True

    def __init__(self, record, user, permission, content=None):
        super().__init__(output_field=BooleanField())
        self.record = record
        self.content = content
        walk = record.along
        seed = _bind_record_qs(
            record, user=user, permission=permission,
        ).filter(
            **{'%s__isnull' % walk.walk_field: False}
        ).values(ident=F(walk.walk_field)).distinct()
        self.seed_query = seed.query.clone()
        self.seed_query.subquery = True
        self.lhs = None
        self.suffix_query = None
        if content is None:
            if walk.rewrite_attname:
                self.lhs = F(walk.rewrite_attname)
            elif not walk.suffix_path:
                self.lhs = F(walk.walk_ident)
            else:
                self.suffix_query = walk.walk_model._default_manager.filter(
                    **{walk.suffix_field: OuterRef(record.content_target)}
                ).query.clone()
                self.suffix_query.subquery = True

    def copy(self):
        clone = super().copy()
        clone.seed_query = clone.seed_query.clone()
        if clone.suffix_query is not None:
            clone.suffix_query = clone.suffix_query.clone()
        return clone

    def get_source_expressions(self):
        exprs = [self.seed_query]
        if self.lhs is not None:
            exprs.append(self.lhs)
        if self.suffix_query is not None:
            exprs.append(self.suffix_query)
        return exprs

    def set_source_expressions(self, exprs):
        exprs = list(exprs)
        self.seed_query = exprs.pop(0)
        if self.lhs is not None:
            self.lhs = exprs.pop(0)
        if self.suffix_query is not None:
            self.suffix_query = exprs.pop(0)

    def as_sql(self, compiler, connection):
        _require_sqlite_along_renderer(connection)
        seed_sql, seed_params = self.seed_query.as_sql(compiler, connection)
        if seed_sql.startswith('(') and seed_sql.endswith(')'):
            seed_sql = seed_sql[1:-1]
        w_sql, w_params = _render_reach_sql(
            self.record.along, seed_sql, seed_params, connection,
        )
        if self.content is not None:
            return self._bound_content_sql(
                compiler, connection, w_sql, w_params,
            )
        if self.lhs is not None:
            lhs_sql, lhs_params = compiler.compile(self.lhs)
            return '%s IN (%s)' % (lhs_sql, w_sql), tuple(lhs_params) + tuple(w_params)
        inner = self.suffix_query.clone()
        inner.add_q(Q(_IdentInReach(
            self.record.along.walk_ident, w_sql, w_params,
        )))
        return Exists(inner).as_sql(compiler, connection)

    def _bound_content_sql(self, compiler, connection, w_sql, w_params):
        walk = self.record.along
        content = self.content
        if not walk.suffix_path:
            inner = walk.walk_model._default_manager.filter(
                pk=content.pk,
            ).query.clone()
        else:
            inner = walk.walk_model._default_manager.filter(
                **{walk.suffix_field: content},
            ).query.clone()
        inner.subquery = True
        inner.add_q(Q(_IdentInReach(walk.walk_ident, w_sql, w_params)))
        return Exists(inner).as_sql(compiler, connection)


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
    condition: object | None = None
    along: AlongWalk | None = None


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
        return _bind_record_qs(record, **bindings)

    def _correlated_exists(self, terminal_field_attr, **bindings):
        parts = []
        for record in self.records:
            if record.along is not None:
                user = bindings['user']
                if terminal_field_attr == 'content_field':
                    parts.append(GrantReach(
                        record, user, bindings['permission'],
                    ))
                else:
                    target = getattr(record, _TARGET_ATTRS[terminal_field_attr])
                    parts.append(GrantReach(
                        record, user, OuterRef(target),
                        content=bindings['content'],
                    ))
                continue
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
        self._condition_lookup = None

    @property
    def frozen(self):
        return self._frozen

    @property
    def condition_lookup(self):
        """Bound ``ConditionLookup``, or ``None`` when unbound."""
        return self._condition_lookup

    def set_condition_lookup(self, lookup):
        """Bind a ``ConditionLookup`` on this instance (zero SQL).

        Both ``record_for`` and ``compile_q`` must be callable. A missing
        method raises ``TrustsConfigurationError`` and does not bind
        (no partial bind). ``lookup is None`` clears the binding.
        Methods are not invoked at bind time.
        """
        if lookup is None:
            self._condition_lookup = None
            return
        record_for = getattr(lookup, 'record_for', None)
        compile_q = getattr(lookup, 'compile_q', None)
        if not callable(record_for) or not callable(compile_q):
            raise TrustsConfigurationError(
                'ConditionLookup must provide record_for and compile_q; '
                'no partial bind.'
            )
        self._condition_lookup = lookup

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

    def register(self, *, content, user, permission, condition=None, along=None):
        """Register one permission-bearing relation from root-relative refs.

        Exact duplicate normalized registration raises
        ``TrustsConfigurationError``. The same root plus the same content
        terminal with a different registration is a conflict and also
        raises. The same root may register different content terminals.
        Both error outcomes leave stored records unchanged.

        Optional ``along`` is an ``Along`` that replaces equality at the
        walk-site with bounded reachability. Along validation uses
        ``_meta`` only (zero SQL) and runs after the frozen check.

        Optional ``condition`` is a closed predicate tree (``All``,
        ``Equal``, ``permission_in``) compiled as an AND overlay on the
        same root row. Validation uses ``_meta`` only (zero SQL).

        A frozen instance raises ``TrustsConfigurationError`` before
        validation or mutation. This method does not inspect Django's
        global ``apps.ready``.
        """
        if self._frozen:
            raise TrustsConfigurationError(
                'Cannot register on a frozen TrustsRegistry.'
            )
        if along is not None and not isinstance(along, Along):
            raise TrustsConfigurationError(
                'along must be an Along instance or None, not %r.' % (along,)
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
            root, user_ref._path, 'user', terminal_membership=True,
        )
        permission_path, permission_model, permission_field, permission_target = (
            _resolve_path(root, permission_ref._path, 'permission')
        )
        along_walk = None
        if along is not None:
            along_walk = _build_along_walk(
                root, content_path, content_model, along,
            )
        condition = _validate_condition(condition, root, permission_model)

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
            condition=condition,
            along=along_walk,
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
