"""Generic Trusts backend mixin.

``TrustModelBackendMixin`` lives only here. Core does not ship
``TrustModelBackend`` or ``HistoricalGroupQueryCompiler``; those names
are ``trusts.zero.backends``. ``trusts.core_backends`` is gone.
"""

from collections.abc import Callable
from typing import TypeVar

from django.conf import settings
from django.contrib.auth.models import Permission
from django.utils.module_loading import import_string
from django.db.models import Model, QuerySet, Subquery

from trusts.compile.factory import PublicRegistration, TrustsCompiler
from trusts.compile.resolution import _resolve_path
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.conditions import (
    evaluate_registered_expression,
    permission_has_condition,
)
from trusts.plan.relations import PlanQueryCompiler
from trusts.plan.aggregates import _compiler_applies, compiler_for_class
from trusts import utils


registries = {}

T = TypeVar('T', bound=Model)


def _listed_paths(cls):
    paths = []
    for path in (getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()):
        if not isinstance(path, str):
            continue
        try:
            resolved = import_string(path)
        except Exception:
            continue
        if resolved is cls:
            paths.append(path)
    return tuple(paths)

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

    def __init__(self):
        cls = type(self)
        if cls not in registries:
            registries[cls] = SimpleRegistry(cls)

    def get_registry(self):
        cls = type(self)
        registry = registries.get(cls)
        if registry is None:
            registry = registries[cls] = SimpleRegistry(cls)
        return registry

    def ready(self, visitor=None):
        registry = self.get_registry()
        registry.freeze()
        if visitor is not None:
            return registry.walk(visitor)
        return registry.build_compiled()

    def _own_compiled(self):
        compiled = self.get_registry().build_compiled()
        compiled.compiler = compiler_for_class(type(self))
        paths = _listed_paths(type(self))
        if paths:
            compiled.path = paths[0]
        return compiled

    def _built_compiled(self, handle=None):
        """Compiled plan for ``handle``, or ``None`` (factory signal).

        ``None`` is translated by every caller to ``False`` / ``set()``
        / ``None``-predicate and never returned as a Django result.
        """
        handle = self._own_compiled() if handle is None else handle
        build = getattr(handle, 'build_compiled', None)
        if callable(build):
            return build()
        registry = getattr(handle, 'registry', None)
        build = getattr(registry, 'build_compiled', None)
        return build() if callable(build) else registry

    def _sponsor_registries(self, own_handle):
        """Built registries of other configured paths (sponsors)."""
        from trusts.apps import _relationship_compiled_plans

        own_path = getattr(own_handle, 'path', None)
        sponsors = []
        for handle in _relationship_compiled_plans():
            if own_path is not None and getattr(handle, 'path', None) == own_path:
                continue
            built = self._built_compiled(handle)
            if built is not None:
                sponsors.append(built)
        return tuple(sponsors)

    def _own_plan_applies(self, obj, user_obj, *, handle=None, registry=None):
        """True when this path's compiler applies to ``obj``.

        Routes through ``QueryCompiler.applies``. Inapplicable is
        ``False`` at zero SQL, before ``:name`` overlay.
        """
        handle = self._own_compiled() if handle is None else handle
        registry = self._built_compiled(handle) if registry is None else registry
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
        handle = self._own_compiled() if handle is None else handle
        registry = self._built_compiled(handle) if registry is None else registry
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
            registry=lambda: self._built_compiled(),
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind,
                            cache=False):
        # Inquiry first (lazy _own_compiled inside it) so a denied or
        # object-less inquiry returns set() without requiring a
        # configured handle, exactly as before Pass 4.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        handle = self._own_compiled()
        registry = self._built_compiled(handle)
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
            registry = self._built_compiled()
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
        handle = self._own_compiled() if handle is None else handle
        registry = self._built_compiled(handle) if registry is None else registry
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
        handle = self._own_compiled() if handle is None else handle
        registry = self._built_compiled(handle) if registry is None else registry
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
        # Inquiry first (lazy _own_compiled inside it) so a denied or
        # object-less inquiry returns False without requiring a
        # configured handle, exactly as before Pass 4.
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return False
        skipped = inquiry.values

        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        handle = self._own_compiled()
        registry = self._built_compiled(handle)

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
        handle = self._own_compiled()
        registry = self._built_compiled(handle)
        if registry is None:
            return None
        return registry.permitted_users_predicate(
            content, perm,
            sponsors=self._sponsor_registries(handle),
            skipped=skipped, backend=self,
        )

class SimpleRegistry(object):
    """The one registry for one backend class.

    ``DocumentBackend().get_registry()`` returns the identical object
    for every instance of that backend class (module-level
    ``registries`` keyed by backend class). This class itself holds
    the raw registrations: ``register()`` validates symbolically via
    ``TrustsCompiler.build_public_registration`` and stores the raw
    kwargs dict per content model in ``principles`` / ``delegates``;
    lowering into records happens on freeze / first inquiry, when the
    stored shapes are replayed into the compiler. The lowered
    answering object is ``CompiledPlan``, never a registry.
    """

    def __init__(self, backend_class=None):
        self._backend_class = backend_class
        self.principles = {}
        self.delegates = {}
        self.named_filters = {}
        self.user_conditions = {}
        self.user_overrides = {}
        self.frozen = False
        self._compiler = TrustsCompiler()
        self._shapes = []
        self._lowered = 0

    # -- registration (public before private) -------------------------
    def register(
        self, *, trust: type[T], user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object] | Callable[[T, object], object] | None
        ) = None,
        along=None,
    ) -> PublicRegistration:
        if self.frozen:
            raise TrustsConfigurationError('registry is frozen already')
        shape = self._compiler.build_public_registration(
            trust=trust, user=user, permission=permission, content=content,
            group=group, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        content_model = _resolve_path(
            trust, shape.content._path, 'content', trailing_reverse=True,
        )[1]
        raw_all = {
            'trust': trust, 'user': user, 'permission': permission,
            'content': content, 'group': group, 'delegate': delegate,
            'sponsor': sponsor, 'condition': condition, 'along': along,
        }
        if shape.delegate is not None:
            raw = {
                k: raw_all[k]
                for k in ("trust", "sponsor", "delegate", "content", "condition")
                if raw_all[k] is not None
            }
            if along is not None:
                raw['along'] = along
            self.delegates.setdefault(content_model, []).append(raw)
        else:
            raw = {
                k: raw_all[k]
                for k in ("trust", "user", "permission", "content", "condition")
                if raw_all[k] is not None
            }
            if group is not None:
                raw['group'] = group
            if along is not None:
                raw['along'] = along
            self.principles.setdefault(content_model, []).append(raw)
        self._shapes.append(shape)
        return shape

    def add_named_filter(self, model, code, predicate):
        if self.frozen:
            raise TrustsConfigurationError('registry is frozen already')
        result = self._compiler.register_permission_condition(
            model, code, predicate,
        )
        self.named_filters.setdefault(model, {})[code] = predicate
        return result

    def set_user_condition(self, name, expr, on='*'):
        if self.frozen:
            raise TrustsConfigurationError('registry is frozen already')
        if self._shapes:
            raise TrustsConfigurationError(
                'Set user conditions and the user override before register().'
            )
        result = self._compiler.set_user_condition(name, expr, on=on)
        if expr is None:
            self.user_conditions.pop(name, None)
        else:
            self.user_conditions[name] = result
        return result

    def set_user_override(self, name, expr, on='user'):
        if self.frozen:
            raise TrustsConfigurationError('registry is frozen already')
        if self._shapes:
            raise TrustsConfigurationError(
                'Set user conditions and the user override before register().'
            )
        result = self._compiler.set_user_override(name, expr, on=on)
        if expr is None:
            self.user_overrides.pop(name, None)
        else:
            self.user_overrides[name] = result
        return result

    def freeze(self):
        self.frozen = True
        return self.build_compiled()

    def walk(self, visitor, sponsors=()):
        return self.build_compiled().walk_questions(visitor, sponsors=sponsors)

    # -- lowering / answering -------------------------------------------
    def build_compiled(self):
        for shape in self._shapes[self._lowered:]:
            if shape.delegate is not None:
                self._compiler.register_delegation(
                    content=shape.content, delegate=shape.delegate,
                    sponsor=shape.sponsor, condition=shape.condition,
                    along=shape.along,
                )
            elif shape.group is not None:
                self._compiler.register(
                    content=shape.content, user=shape.user,
                    group=shape.group, condition=shape.condition,
                    along=shape.along,
                )
            else:
                self._compiler.register(
                    content=shape.content, user=shape.user,
                    permission=shape.permission, condition=shape.condition,
                    along=shape.along,
                )
            self._lowered += 1
        compiled = self._compiler.build_compiled()
        if self._backend_class is not None:
            if _has_query_compiler(self._backend_class):
                compiled.compiler = compiler_for_class(self._backend_class)
            paths = _listed_paths(self._backend_class)
            if paths:
                compiled.path = paths[0]
        return compiled

    @property
    def records(self):
        return self.build_compiled().records

    @property
    def delegations(self):
        return self.build_compiled().delegations

    @property
    def conditions(self):
        return self._compiler.conditions

    @property
    def condition_lookup(self):
        return self._compiler.condition_lookup

    def set_condition_lookup(self, lookup):
        return self._compiler.set_condition_lookup(lookup)

    def plan_for(self, content, *, user=None, permission=None):
        return self.build_compiled().plan_for(
            content, user=user, permission=permission,
        )

    def has_permission(self, user, content, permission, **skip_flags):
        return self.build_compiled().has_permission(
            user, content, permission, **skip_flags,
        )

    def permissions_for(self, user, content, **skip_flags):
        return self.build_compiled().permissions_for(
            user, content, **skip_flags,
        )

    def filter_authorized(self, queryset, user, permission, **skip_flags):
        return self.build_compiled().filter_authorized(
            queryset, user, permission, **skip_flags,
        )

    def compile_registered_condition_q(self, model, perm, user):
        return self._compiler.compile_registered_condition_q(model, perm, user)

    def get_permission_condition_record(self, model, cond_code):
        return self._compiler.get_permission_condition_record(model, cond_code)

    def iter_permission_conditions(self):
        return self._compiler.iter_permission_conditions()

    def _stored_user_conditions(self):
        return self._compiler._stored_user_conditions()

    def _known_skip_names(self):
        return self._compiler._known_skip_names()

    @property
    def _user_override(self):
        return self._compiler._user_override


def _has_query_compiler(cls):
    return getattr(cls, 'query_compiler', None) is not None
