"""Relation plans and the compiler protocol they implement.

``QueryCompiler``, ``PlanQueryCompiler``, ``ConditionLookup``, and
``RelationPlan`` live here with the user-binding and candidate helpers
they close over. Not a public import surface. ``trusts.core`` re-exports
``PlanQueryCompiler``, ``RelationPlan``, and ``ConditionLookup``.
"""

__all__ = []

from dataclasses import dataclass
from functools import reduce
from operator import or_

from django.db.models import Exists, Model, OuterRef, Q, QuerySet
from django.db.models.base import ModelBase

from trusts.plan.rewrites import bind_once
from trusts.commons import (
    _bind_record_qs,
    _bind_terminal,
    _content_type_identity,
    _permission_terminal_is_auth_permission,
    _require_instance,
)
from trusts.plan.recursions import GrantReach
from trusts.errors import TrustsConfigurationError
from trusts.plan.standards import (
    BUILTIN_USER_CONDITIONS,
    bind_skip_flags,
    condition_names,
)


class QueryCompiler(object):
    """Duck-typed compiler protocol. Not a registry or store."""

    historical_fallback = False

    def applies(self, plan):
        """True when this compiler has a grant plan for ``plan``.

        Relationship default recognizes ordinary records and delegation
        records. Construction issues no SQL. Inapplicable backends must not
        compile a grant.
        """
        return bool(
            getattr(plan, 'records', None)
            or getattr(plan, 'delegations', None)
        )

    def complete_exists(self, plan, candidates, user, permission):
        raise NotImplementedError

    def group_exists(self, plan, candidates, user, permission):
        raise NotImplementedError


class PlanQueryCompiler(object):
    """Immutable mixin default: registered plan; group slice is explicit.

    ``complete_exists`` compiles every relationship record, including
    explicit ``group=`` registrations. ``group_exists`` compiles only
    those ``group=`` records. A many-to-many or membership-shaped user
    path is not a Django group. ``permission=`` records stay out of
    ``get_group_permissions``.
    """

    historical_fallback = False

    def applies(self, plan):
        """Relationship applicability: ordinary or delegated records."""
        return bool(
            getattr(plan, 'records', None)
            or getattr(plan, 'delegations', None)
        )

    def complete_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return plan.content_exists(user, permission)

    def group_exists(self, plan, candidates, user, permission):
        grouped = tuple(
            record for record in plan.records
            if getattr(record, 'via_group', False)
        )
        if not grouped:
            return None
        return RelationPlan(
            records=grouped,
            permission_model=plan.permission_model,
            content_identity=getattr(plan, 'content_identity', None),
        ).content_exists(user, permission)


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


class ConditionLookup(object):
    """Duck-typed ``:condition`` overlay protocol. Not a registry or store.

    ``TrustsCompiler`` self-binds a private store adapter at construct.
    ``set_condition_lookup`` remains for tests and explicit unbind.
    Core never imports a Zero ``Content`` registry to evaluate
    conditions. Unbound lookup on an instance-only caller is a no-op.

    ``record_for`` returns the registered record or ``None`` (unregistered
    codes fail closed as ``AttributeError`` at the caller). ``compile_q``
    compiles stored condition IR to ``Q``.
    """

    def record_for(self, model, cond_code):
        raise NotImplementedError

    def compile_q(self, model, perm_string, user):
        raise NotImplementedError


class SkipParams(object):
    """Skip values for one inquiry, and the bound predicate when built."""

    __slots__ = ('denied', 'values', 'predicate')

    def __init__(self, denied, values, predicate=None):
        self.denied = denied
        self.values = values
        self.predicate = predicate


def user_skip_params(user, skip_flags, *, handles=None, registry=None,
                     require_user=True):
    """Validate ``skip_*`` keywords and return their bound values.

    Anonymous, unauthenticated, and ``None`` are denied before SQL.
    An unknown ``skip_*`` is not consulted for that denial.
    ``require_user=False`` is the reverse inquiry.
    """
    selected = {}
    for key, value in skip_flags.items():
        if not key.startswith('skip_') or not key[5:].isidentifier():
            raise TypeError('Unexpected keyword argument %r.' % (key,))
        _require_mode_flag(value, key)
        selected[key[5:]] = value
    denied = require_user and (
        user is None or _user_identity_denied(user)
    )
    if denied:
        return SkipParams(True, {})
    if callable(registry):
        registry = registry()
    if registry is not None:
        known = registry._known_skip_names()
    else:
        known = _known_skip_names(handles or ())
    unknown = next((name for name in selected if name not in known), None)
    if unknown is not None:
        raise TypeError('Unknown skip keyword %r.' % ('skip_%s' % unknown,))
    return SkipParams(False, {
        name: selected.get(name, False) for name in known
    })


def _known_skip_names(handles):
    """Condition and override names on the registries these handles own.

    No registry yet means the built-in ``is_active`` condition only.
    """
    names = set()
    saw = False
    for handle in handles:
        registry = getattr(handle, 'registry', None)
        if registry is None:
            continue
        saw = True
        names.update(condition_names(
            registry._stored_user_conditions(),
            getattr(registry, '_user_override', None),
        ))
    if not saw:
        names.update(rule.name for rule in BUILTIN_USER_CONDITIONS)
    return frozenset(names)


def _outer_permission_identity(permission_model, content_model):
    """Content-type predicate on an outer ``auth.Permission`` row."""
    if (
        permission_model is None
        or content_model is None
        or not _permission_terminal_is_auth_permission(permission_model)
    ):
        return Q()
    app_label, model_name = _content_type_identity(content_model)
    return Q(**{
        'content_type__app_label': app_label,
        'content_type__model': model_name,
    })


def _bound_permission_identity(permission, content_model, permission_model):
    """The bound permission row is this content's ``auth.Permission``.

    Other permission terminals add nothing, matching the ordinary grant.
    """
    if (
        permission is None
        or permission_model is None
        or content_model is None
        or not _permission_terminal_is_auth_permission(permission_model)
    ):
        return Q()
    app_label, model_name = _content_type_identity(content_model)
    from django.contrib.auth.models import Permission

    identity = permission.pk if isinstance(permission, Model) else permission
    return Exists(Permission.objects.filter(
        pk=identity,
        content_type__app_label=app_label,
        content_type__model=model_name,
    ))


def _or_q(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return left | right


def _require_mode_flag(value, name):
    """A skip keyword must be a real boolean."""
    if not isinstance(value, bool):
        raise TypeError('%s must be a bool, not %r.' % (name, value))
    return value


def _user_identity_denied(user):
    """Anonymous and unauthenticated users are denied even when
    ``skip_is_active`` is true.

    Missing attributes keep the identity defaults: not anonymous, and
    authenticated. ``None`` is not this denial; callers that require an
    instance still raise.
    """
    if getattr(user, 'is_anonymous', False):
        return True
    if not getattr(user, 'is_authenticated', True):
        return True
    return False


def bind_checked_user(subject, grant=None, *, rules=None, override=None,
                      identity=None, values=None, plan=None, closed=False,
                      with_override=True, skip_flags=None, require_user=True,
                      registry=None, handles=None):
    """Validate ``skip_*``, deny before SQL, and bind one registration fragment.

    ``skip_flags`` is a public inquiry. ``values`` means that inquiry
    already ran. ``plan`` selects compiled fragments (``closed`` for the
    reverse row). ``with_override`` is false for a group check.
    """
    if skip_flags is not None:
        inquiry = user_skip_params(
            subject, skip_flags, handles=handles, registry=registry,
            require_user=require_user,
        )
        if inquiry.denied:
            return SkipParams(True, {}, None)
        values = inquiry.values
    else:
        values = values or {}
    if plan is not None:
        rules = plan.user_rules_closed if closed else plan.user_rules
        override = plan.user_override_q if with_override else None
    if rules is None:
        return SkipParams(False, values, None)
    rules_q = bind_skip_flags(rules, values)
    override_q = None if override is None else bind_skip_flags(override, values)
    if isinstance(subject, Model):
        base = subject._meta.concrete_model._default_manager.filter(
            pk=subject.pk,
        )
        if rules_q:
            rules_q = Exists(base.filter(rules_q))
        if override_q is not None:
            override_q = Exists(base.filter(override_q))
    if override_q is not None and identity is not None:
        override_q = override_q & identity
    combined = _or_q(grant, override_q)
    if combined is None:
        return SkipParams(False, values, None)
    if not rules_q:
        return SkipParams(False, values, combined)
    return SkipParams(False, values, rules_q & combined)


_TARGET_ATTRS = {
    'user_field': 'user_target',
    'content_field': 'content_target',
    'permission_field': 'permission_target',
}


def _candidate_model(content):
    """Class of the protected object, including a proxy.

    Record selection uses :func:`_content_model` (the concrete model).
    Permission content-type identity uses this class so a proxy is not
    collapsed onto its concrete parent.
    """
    if isinstance(content, QuerySet):
        return content.model
    if isinstance(content, ModelBase):
        return content
    if isinstance(content, Model):
        return content.__class__
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

    ``content_identity`` is the protected object's class, proxy included.
    When the permission terminal is ``auth.Permission``, the grant
    requires that identity. It is not inferred from a codename. Another
    terminal stays a primary-key comparison.
    """

    records: tuple
    delegations: tuple = ()
    permission_model: type | None = None
    content_identity: type | None = None
    user_rules: object | None = None
    user_rules_closed: object | None = None
    user_override_q: object | None = None

    def _bound_root_qs(self, record, **bindings):
        return _bind_record_qs(
            record,
            content_identity=self.content_identity,
            **bindings,
        )

    def _correlated_exists(self, terminal_field_attr, **bindings):
        parts = []
        for record in self.records:
            if record.along is not None:
                if terminal_field_attr == 'content_field':
                    parts.append(GrantReach(
                        record, bindings['user'], bindings['permission'],
                        content_identity=self.content_identity,
                    ))
                elif terminal_field_attr == 'user_field':
                    parts.append(GrantReach(
                        record, OuterRef(record.user_target),
                        bindings['permission'], content=bindings['content'],
                        content_identity=self.content_identity,
                    ))
                else:
                    target = getattr(record, _TARGET_ATTRS[terminal_field_attr])
                    parts.append(GrantReach(
                        record, bindings['user'], OuterRef(target),
                        content=bindings['content'],
                        content_identity=self.content_identity,
                    ))
                continue
            terminal = getattr(record, terminal_field_attr)
            target = getattr(record, _TARGET_ATTRS[terminal_field_attr])
            inner = self._bound_root_qs(
                record,
                correlation=Q(**{terminal: OuterRef(target)}),
                **bindings,
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

    def user_exists(self, content, permission):
        """Candidate-user ``EXISTS`` correlating the user through this plan.

        Inverse of ``content_exists``: content and permission are bound,
        and the user terminal is ``OuterRef`` of the resolved user target.
        Complete records OR together. For ``Along``, walk-site identities
        are derived from the bound content. The inverse walk runs once
        without the outer user. Eligible grants and candidate users join
        outside the recursive CTE.
        """
        content = _require_instance(content, 'content')
        if content.pk is None:
            raise TrustsConfigurationError(
                'content must be a saved %s instance.'
                % content._meta.label
            )
        permission = _bind_terminal(permission, 'permission')
        if not self.records:
            return None
        return self._correlated_exists(
            'user_field', content=content, permission=permission,
        )

    def _bound_queryset(self, subject, grant, values, identity, queryset,
                        empty, *, distinct=True):
        checked = bind_checked_user(
            subject, grant, plan=self, identity=identity, values=values,
        )
        if checked.predicate is None:
            return empty
        filtered = queryset.filter(checked.predicate)
        return bind_once(filtered.distinct() if distinct else filtered)

    def common_permissions(self, user, content, *,
                           skipped=()):
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
        ordinary = None
        if exists is not None:
            ordinary = Exists(qs) & ~Exists(qs.filter(~Q(exists)))
        identity = Exists(qs) & _outer_permission_identity(
            self.permission_model, _candidate_model(content),
        )
        return self._bound_queryset(
            user, ordinary, skipped, identity,
            self.permission_model._default_manager.all(),
            self.permission_model._default_manager.none(),
        )

    def permissions(self, user, content, *, skipped=()):
        """Distinct permission rows for ``(user, content)``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        if not self.records or self.permission_model is None:
            return ()
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        return self._bound_queryset(
            user, exists, skipped,
            _outer_permission_identity(
                self.permission_model, content.__class__,
            ),
            self.permission_model._default_manager.all(),
            self.permission_model._default_manager.none(),
        )

    def has_permission(self, user, content, permission, *,
                       skipped=()):
        """SQL ``EXISTS`` membership of ``permission`` in ``permissions()``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        if permission._meta.concrete_model is not self.permission_model:
            return False
        if not self.records or self.permission_model is None:
            return False
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        found = self._bound_queryset(
            user, exists, skipped,
            _outer_permission_identity(
                self.permission_model, content.__class__,
            ),
            self.permission_model._default_manager.filter(pk=permission.pk),
            None,
            distinct=False,
        )
        if found is None:
            return False
        return found.exists()

    def filter_content(self, queryset, user, permission, *,
                       skipped=()):
        """Lazy queryset of candidate rows correlated to the same plan."""
        return self._bound_queryset(
            user,
            self.content_exists(user, permission),
            skipped,
            _bound_permission_identity(
                permission, queryset.model, self.permission_model,
            ),
            queryset,
            queryset.none(),
        )
