"""Generic Trusts backend mixin.

``TrustModelBackendMixin`` lives only here. Core does not ship
``TrustModelBackend`` or ``HistoricalGroupQueryCompiler``; those names
are ``trusts.zero.backends``. ``trusts.core_backends`` is gone.
"""

from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet, Subquery

from trusts.errors import PermissionConditionError
from trusts.plan.conditions import (
    evaluate_registered_expression,
    permission_has_condition,
)
from trusts.plan.relations import PlanQueryCompiler
from trusts.plan.aggregates import _compiler_applies
from trusts import utils


def _permission_binding(perm, model):
    """Unevaluated Permission pk for ``perm`` (instance or dotted code).

    Unknown codes become an empty subquery and match nothing. This is
    permission identity in SQL, not a second authorization source.
    """
    if isinstance(perm, Permission):
        return perm
    applabel, modelname, action, _cond = utils.parse_perm_code(perm)
    return Subquery(
        Permission.objects.filter(
            codename='%s_%s' % (action, modelname),
            content_type__app_label=applabel.lower(),
            content_type__model=modelname,
        ).values('pk')[:1]
    )


def _perm_codes(permission_qs):
    return set(
        '%s.%s' % (app, code)
        for app, code in permission_qs.values_list(
            'content_type__app_label', 'codename',
        )
    )


def _as_held(value):
    """Normalize an obtained object to the held lowered object.

    The production obtaining path (``configured_backend()``) already
    returns a ``HeldBackend`` and it is returned unchanged -- the
    identical held object, no rebuilding per question. A legacy
    ``BackendHandle`` (compat/test injection only) is lowered once
    for this call; a plain built ``Registry`` is wrapped carrying a
    default compiler. ``None`` (the old factory signal) stays None.
    """
    if value is None:
        return None
    from trusts.plan.registry import HeldBackend, Registry

    if isinstance(value, HeldBackend):
        return value
    if isinstance(value, Registry):
        return HeldBackend(
            path=getattr(value, 'path', '') or '',
            compiler=getattr(value, 'compiler', None) or PlanQueryCompiler(),
            registry=getattr(value, '_raw_registry', value),
            source_version=getattr(
                getattr(value, '_raw_registry', value), '_raw_version', None,
            ),
            records=value.records, delegations=value.delegations,
            conditions=value.conditions,
            user_conditions=value.user_conditions,
            user_override=value.user_override,
            condition_lookup=value.condition_lookup,
        )
    registry = getattr(value, 'registry', None)
    if registry is None:
        return None
    build = getattr(registry, 'build_registry', None)
    built = build() if callable(build) else registry
    if built is None:
        return None
    from trusts.plan.registry import HeldBackend

    kwargs = {}
    if hasattr(built, 'condition_lookup'):
        kwargs['condition_lookup'] = built.condition_lookup
    return HeldBackend(
        path=getattr(value, 'path', '') or '',
        compiler=getattr(value, 'compiler', None) or PlanQueryCompiler(),
        registry=registry,
        source_version=getattr(registry, '_raw_version', None),
        records=getattr(built, 'records', ()),
        delegations=getattr(built, 'delegations', ()),
        conditions=getattr(built, 'conditions', None),
        user_conditions=getattr(built, 'user_conditions', None),
        user_override=getattr(built, 'user_override', None),
        **kwargs,
    )


class TrustModelBackendMixin(object):
    query_compiler = PlanQueryCompiler()

    @staticmethod
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def _trusts_config(self):
        from trusts.apps import implementation_for_class

        return implementation_for_class(type(self), required=True)

    def _held_backend(self):
        """THE obtaining step: the config-held lowered object.

        One line through ``trusts.apps.configured_backend`` (which
        delegates to the owning config's ``configured_backend()``).
        The backend instance holds nothing; every question re-derives
        the same held object from the owning config until a new
        registration invalidates it.
        """
        from trusts.apps import configured_backend

        return configured_backend(self._trusts_config().path_for_backend(self))

    def _obtain_held(self):
        """Held object for one question, normalized for compat seams.

        Production returns the identical ``HeldBackend`` from
        ``configured_backend()``; a test/compat seam that still
        supplies a ``BackendHandle`` is lowered by ``_as_held``.
        """
        return _as_held(self._held_backend())

    def _own_handle(self):
        """Compat shim (internal, not API): return the held object.

        Kept for Zero/gh-permissions/tests that still call this
        name. It mints nothing: it delegates to ``_held_backend()``,
        so the return value is the held lowered object (which also
        carries ``path`` / ``compiler`` / ``registry``). Backend
        inquiry methods below do NOT use this shim; they use
        ``_obtain_held()``.
        """
        return self._held_backend()

    def _built_registry(self, handle=None):
        """Held/built registry for ``handle``, or ``None``.

        Compat name: with no argument it is the held object itself
        (a ``Registry``), not a per-question build. ``None`` is
        translated by every caller to ``False`` / ``set()`` /
        ``None``-predicate and never returned as a Django result.
        """
        if handle is None:
            return self._obtain_held()
        return _as_held(handle)

    def _sponsor_registries(self, own_held):
        """Held objects of other configured paths (sponsors)."""
        from trusts.apps import _relationship_implementation_handles

        own_path = getattr(own_held, 'path', None)
        sponsors = []
        for item in _relationship_implementation_handles():
            if own_path is not None and getattr(item, 'path', None) == own_path:
                continue
            held = _as_held(item)
            if held is not None:
                sponsors.append(held)
        return tuple(sponsors)

    def _own_plan_applies(self, obj, user_obj, *, handle=None, registry=None):
        """True when this path's compiler applies to ``obj``.

        Routes through ``QueryCompiler.applies``. Inapplicable is
        ``False`` at zero SQL, before ``:name`` overlay.
        ``handle``/``registry`` are compat aliases for the held object.
        """
        held = registry if registry is not None else (
            _as_held(handle) if handle is not None else self._obtain_held()
        )
        if held is None:
            return False
        plan = held.plan_for(obj, user=user_obj)
        return _compiler_applies(getattr(held, 'compiler', None) or PlanQueryCompiler(), plan)

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')

    def _path_permissions(self, user_obj, obj, *, kind,
                          skipped=(), handle=None, registry=None):
        held = registry if registry is not None else (
            _as_held(handle) if handle is not None else self._obtain_held()
        )
        if held is None:
            return set()
        qs = held.permissions_for(
            user_obj, obj, kind=kind,
            sponsors=self._sponsor_registries(held),
            compiler=getattr(held, 'compiler', None) or PlanQueryCompiler(),
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if qs is None or qs == ():
            return set()
        return _perm_codes(qs)

    def _skip_inquiry(self, user_obj, skip_flags, *, registry=None):
        from trusts.plan.relations import bind_checked_user

        if registry is not None:
            return bind_checked_user(
                user_obj, skip_flags=skip_flags, registry=registry,
            )
        return bind_checked_user(
            user_obj, skip_flags=skip_flags,
            registry=lambda: self._obtain_held(),
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind,
                            cache=False):
        # Inquiry first (lazy held lookup inside it) so a denied or
        # object-less inquiry returns set() without requiring a
        # configured backend, exactly as before.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        held = self._obtain_held()
        if cache:
            self._ensure_perm_cache(user_obj)
        if isinstance(obj, QuerySet) or isinstance(obj, Model):
            return self._path_permissions(
                user_obj, obj, kind=kind, skipped=inquiry.values,
                registry=held,
            )
        return set()

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """
        return self._listed_permissions(
            user_obj, obj, skip_flags, kind='group',
        )

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        return self._listed_permissions(
            user_obj, obj, skip_flags, kind='complete', cache=True,
        )

    def permission_condition_met(self, record, user_obj, perm, obj):
        if record.expr is None:
            model = obj.model if isinstance(obj, QuerySet) else getattr(obj, '__class__', obj)
            raise PermissionConditionError(
                'Permission condition on %s is unbound.'
                % getattr(getattr(model, '_meta', None), 'label', model)
            )
        if isinstance(obj, QuerySet):
            objs = obj.all()
            model = obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs = obj
            model = None
        else:
            objs = [obj]
            model = obj.__class__

        return all([
            evaluate_registered_expression(
                record.expr, user_obj, perm, o, model=model or o.__class__
            )
            for o in objs
        ])

    def _bound_condition_lookup(self, obj, *, registry=None):
        """Bound ``ConditionLookup`` on this backend path's registry.

        Unbound (after explicit ``set_condition_lookup(None)``) is
        ``None``. A name absent from this path is a local fail-closed
        non-match. Malformed or unbound policy this path owns still
        raises.
        """
        if registry is None:
            registry = self._obtain_held()
        if registry is None:
            return None
        return getattr(registry, 'condition_lookup', None)

    def _condition_overlay(self, permext, obj, user_obj, *, registry=None):
        """Return (record, extra_q) for a ``:condition`` suffix.

        Stored IR on a QuerySet compiles to SQL (AND overlay) from this
        path only. A name absent from this path is ``(None, None)`` so
        the caller can fail closed without raising. An explicit unbound
        lookup on an instance is still a loud configuration failure.

        A bound ``ConditionLookup`` is the only condition path. Core
        does not import Zero modules or discover helpers from a model
        ``__module__``.
        """
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, action, cond = utils.parse_perm_code(permext)
        model = self._get_class(obj)
        lookup = self._bound_condition_lookup(obj, registry=registry)
        if lookup is None:
            if isinstance(obj, QuerySet):
                return None, None
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        record = lookup.record_for(model, cond)
        if record is None:
            return None, None
        extra_q = None
        if isinstance(obj, QuerySet):
            extra_q = lookup.compile_q(obj.model, permext, user_obj)
        return record, extra_q

    def _collection_has_perm(self, user_obj, perm, obj, extra_q=None, *,
                             skipped=(), handle=None, registry=None):
        held = registry if registry is not None else (
            _as_held(handle) if handle is not None else self._obtain_held()
        )
        if held is None:
            return False
        binding = _permission_binding(perm, obj.model)
        return held.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(held),
            compiler=getattr(held, 'compiler', None) or PlanQueryCompiler(), permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )

    def _instance_has_perm(self, user_obj, perm, obj, extra_q=None, *,
                           skipped=(), handle=None, registry=None):
        held = registry if registry is not None else (
            _as_held(handle) if handle is not None else self._obtain_held()
        )
        if held is None:
            return False
        binding = _permission_binding(perm, obj.__class__)
        return held.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(held),
            compiler=getattr(held, 'compiler', None) or PlanQueryCompiler(), permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check for one permission string.

        The string uses the historical codename split to choose the row.
        When that row is an ``auth.Permission``, a content-type mismatch
        with ``obj`` is ``False``. Another permission terminal stays
        primary-key identity inside the plan. ``skip_<name>`` is a bound
        parameter on that registered user condition.
        Django's ``user.has_perm`` does not forward these keywords.
        """
        # Inquiry first (lazy held lookup inside it) so a denied or
        # object-less inquiry returns False without requiring a
        # configured backend, exactly as before.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return False
        skipped = inquiry.values

        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        held = self._obtain_held()
        registry = held

        if not self._own_plan_applies(
            obj, user_obj, registry=registry,
        ):
            return False

        record, extra_q = self._condition_overlay(
            permext, obj, user_obj, registry=registry,
        )
        applabel, modelname, action, _cond = utils.parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)

        if permission_has_condition(permext) and record is None:
            return False

        if isinstance(obj, QuerySet):
            positive = self._collection_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
                skipped=skipped, registry=registry,
            )
        else:
            positive = self._instance_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
                skipped=skipped, registry=registry,
            )
        if not positive:
            return False
        if record is None or extra_q is not None:
            return True
        return self.permission_condition_met(record, user_obj, perm, obj)

    def singular_permission_accepted(self, perm):
        """True when object ``has_perm`` treats ``perm`` as one permission row.

        The mixin default accepts ``auth.Permission`` only. Agreement
        with ``user.has_perm`` uses ``permission.user_perm_str``. Another
        permission-terminal model is accepted only when a backend
        overrides this and ``permitted_users_predicate``.
        """
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply.

        ``None`` contributes no grant. It is not an empty-queryset
        fallback for a path that cannot be reversed. An ``Along``
        registration derives walk-site identities from the bound content,
        walks the inverse graph once without the outer user, and joins
        eligible grants outside that walk. ``skipped`` is the bound
        ``skip_<name>`` parameter map.
        """
        held = self._obtain_held()
        if held is None:
            return None
        return held.permitted_users_predicate(
            content, perm,
            sponsors=self._sponsor_registries(held),
            skipped=skipped, backend=self,
        )
