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

    def _own_handle(self):
        config = self._trusts_config()
        return config.configured_backend(config.path_for_backend(self))

    def _built_registry(self, handle=None):
        """Built registry for ``handle``, or ``None`` (factory signal).

        ``None`` is translated by every caller to ``False`` / ``set()``
        / ``None``-predicate and never returned as a Django result.
        """
        handle = self._own_handle() if handle is None else handle
        build = getattr(handle, 'build_registry', None)
        if callable(build):
            return build()
        registry = getattr(handle, 'registry', None)
        build = getattr(registry, 'build_registry', None)
        return build() if callable(build) else registry

    def _sponsor_registries(self, own_handle):
        """Built registries of other configured paths (sponsors)."""
        from trusts.apps import _relationship_implementation_handles

        own_path = getattr(own_handle, 'path', None)
        sponsors = []
        for handle in _relationship_implementation_handles():
            if own_path is not None and getattr(handle, 'path', None) == own_path:
                continue
            built = self._built_registry(handle)
            if built is not None:
                sponsors.append(built)
        return tuple(sponsors)

    def _own_plan_applies(self, obj, user_obj, *, handle=None, registry=None):
        """True when this path's compiler applies to ``obj``.

        Routes through ``QueryCompiler.applies``. Inapplicable is
        ``False`` at zero SQL, before ``:name`` overlay.
        """
        handle = self._own_handle() if handle is None else handle
        registry = self._built_registry(handle) if registry is None else registry
        if registry is None:
            return False
        plan = registry.plan_for(obj, user=user_obj)
        return _compiler_applies(handle.compiler, plan)

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')

    def _path_permissions(self, user_obj, obj, *, kind,
                          skipped=(), handle=None, registry=None):
        handle = self._own_handle() if handle is None else handle
        registry = self._built_registry(handle) if registry is None else registry
        if registry is None:
            return set()
        qs = registry.permissions_for(
            user_obj, obj, kind=kind,
            sponsors=self._sponsor_registries(handle),
            compiler=handle.compiler,
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
            registry=lambda: self._own_handle().registry,
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind,
                            cache=False):
        # Inquiry first (lazy _own_handle inside it) so a denied or
        # object-less inquiry returns set() without requiring a
        # configured handle, exactly as before Pass 4.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        handle = self._own_handle()
        registry = self._built_registry(handle)
        if cache:
            self._ensure_perm_cache(user_obj)
        if isinstance(obj, QuerySet) or isinstance(obj, Model):
            return self._path_permissions(
                user_obj, obj, kind=kind, skipped=inquiry.values,
                handle=handle, registry=registry,
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
            registry = self._built_registry()
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
        handle = self._own_handle() if handle is None else handle
        registry = self._built_registry(handle) if registry is None else registry
        if registry is None:
            return False
        binding = _permission_binding(perm, obj.model)
        return registry.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(handle),
            compiler=handle.compiler, permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )

    def _instance_has_perm(self, user_obj, perm, obj, extra_q=None, *,
                           skipped=(), handle=None, registry=None):
        handle = self._own_handle() if handle is None else handle
        registry = self._built_registry(handle) if registry is None else registry
        if registry is None:
            return False
        binding = _permission_binding(perm, obj.__class__)
        return registry.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(handle),
            compiler=handle.compiler, permission_model=Permission,
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
        # Inquiry first (lazy _own_handle inside it) so a denied or
        # object-less inquiry returns False without requiring a
        # configured handle, exactly as before Pass 4.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return False
        skipped = inquiry.values

        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        handle = self._own_handle()
        registry = self._built_registry(handle)

        if not self._own_plan_applies(
            obj, user_obj, handle=handle, registry=registry,
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
                skipped=skipped, handle=handle, registry=registry,
            )
        else:
            positive = self._instance_has_perm(
                user_obj, perm, obj, extra_q=extra_q,
                skipped=skipped, handle=handle, registry=registry,
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
        handle = self._own_handle()
        registry = self._built_registry(handle)
        if registry is None:
            return None
        return registry.permitted_users_predicate(
            content, perm,
            sponsors=self._sponsor_registries(handle),
            skipped=skipped, backend=self,
        )
