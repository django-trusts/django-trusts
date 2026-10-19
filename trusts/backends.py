"""Generic Trusts backend mixin.

``TrustModelBackendMixin`` lives only here. Core does not ship
``TrustModelBackend`` or ``HistoricalGroupQueryCompiler``. Registration
is a per-class ``Recorder``. ``ready()`` freezes it, replays it through
``RegistryFactory``, and stores the built object on ``registries[cls]``.
``get_registry()`` returns the recorder.
"""

from django.contrib.auth import get_backends
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet, Subquery

import trusts.apps as trusts_apps
from trusts.apps import (
    implementation_configs,
    implementation_for_class,
    listed_backend_class,
    recorders,
    registries,
)
from trusts.errors import (
    PermissionConditionError,
    TrustsConfigurationError,
)
import trusts.inspect.checks  # noqa: F401
from trusts.plan.handles import registry_of
from trusts.plan.relations import PlanQueryCompiler, bind_checked_user
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


def _canonical_path(cls):
    return '%s.%s' % (cls.__module__, cls.__qualname__)


class TrustModelBackendMixin(object):
    """Object-permission backend. One recorder and one built registry per class."""

    family = 'relationship'

    @staticmethod
    def _get_class(obj):
        if isinstance(obj, QuerySet):
            klass = obj.model
        else:
            klass = obj.__class__
        return klass

    def __init__(self):
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()
        self.recorder = recorders[cls]

    def _trusts_config(self):
        """Implementation owner for this class, if one is installed."""
        return implementation_for_class(type(self), required=True)

    def get_registry(self):
        """The application registry: this class's recorder, still open until ``ready``."""
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()
            self.recorder = recorders[cls]
        return recorders[cls]


    def ready(self) -> None:
        self._get_or_create_catalog()

    def _get_or_create_catalog() -> Catalog:
        """Freeze the class recorder and publish ``catalogs[cls]``.

        Idempotent once this class is sealed. A later replacement of
        ``catalogs[cls]`` (test isolation) is left in place.
        """
        cls = type(self)
        recorder = recorders.get(cls)
        if recorder is None:
            recorder = Recorder()
            recorders[cls] = recorder
            self.recorder = recorder
        if recorder.frozen and cls in catalogs:
            return catalogs[cls]
        recorder.freeze()

        catalog = Catalog(path=_canonical_path(cls), family=getattr(cls, 'family', 'relationship'))
        recorder.play(catalog.get_record_adapter())
        catalog.build()
        catalogs[cls] = catalog

        return catalog

    @property
    def registry(self):
        """Built registry for this class. Seals on first read."""
        return self._answered_registry()

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

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check for one permission string.

        The string uses the historical codename split to choose the row.
        When that row is an ``auth.Permission``, a content-type mismatch
        with ``obj`` is ``False``. Another permission terminal stays
        primary-key identity inside the plan. ``skip_<name>`` is a bound
        parameter on that registered user condition.
        Django's ``user.has_perm`` does not forward these keywords.
        """

        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return False
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False

        catalog = self._get_or_create_catalog()

        entry = catalog.prepare_has_perm_entry(user_obj, permext, obj, **skip_flags)
        return entry.execute()

    # @TODO: move other permission inquires entry to this backend
    # follow the same pattern as has_perm. check things, then obtain an entry from catalog
    # the permission inquiry decide to return the qs or execute it.
    # backend is becoming a thin object that keep the register() via Recorder, and forward the
    # eval to Catalog. everything /compile or /plan created by this backend directly or directly
    # always belong to a single backend cls, so no handle is needed. the backend should not have
    # any information that /compile or /plan needs after they are built. all the information
    #  /compile or /plan needed are passed to them at __init__, built, or catalog.prepare_xyz call

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
        registry = self._answered_registry()
        if registry is None:
            return None
        return registry.permitted_users_predicate(
            content, perm,
            sponsors=self._sponsor_registries(),
            skipped=skipped, backend=self,
        )

    def _sponsor_registries(self):
        """Built registries of other relationship-family paths."""
        own_path = _canonical_path(type(self))
        stored = registries.get(type(self))
        sponsors = []
        # Attribute lookup: tests patch this name on trusts.apps.
        for handle in trusts_apps._relationship_implementation_handles():
            if getattr(handle, 'path', None) == own_path:
                continue
            registry = registry_of(handle)
            if registry is None or registry is stored:
                continue
            build = getattr(registry, 'build_registry', None)
            built = build() if callable(build) else registry
            if built is not None:
                sponsors.append(built)
        return tuple(sponsors)

    def _skip_inquiry(self, user_obj, skip_flags):
        return bind_checked_user(
            user_obj, skip_flags=skip_flags,
            registry=self._answered_registry,
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind, cache=False):
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        registry = self._answered_registry()
        if cache:
            self._ensure_perm_cache(user_obj)
        if isinstance(obj, QuerySet) or isinstance(obj, Model):
            return self._path_permissions(
                user_obj, obj, kind=kind, skipped=inquiry.values,
                registry=registry,
            )
        return set()

    def _path_permissions(self, user_obj, obj, *, kind, skipped=(), registry=None):
        registry = self._answered_registry() if registry is None else registry
        if registry is None:
            return set()
        qs = registry.permissions_for(
            user_obj, obj, kind=kind,
            sponsors=self._sponsor_registries(),
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if qs is None or qs == ():
            return set()
        return _perm_codes(qs)

    def _bound_condition_lookup(self, obj, *, registry=None):
        """Bound lookup, or ``None`` when the built registry unbinds it."""
        if registry is None:
            registry = self._answered_registry()
        if registry is None:
            return None
        return getattr(registry, 'condition_lookup', None)

    def _condition_overlay(self, permext, obj, user_obj, *, registry=None):
        """``(record, extra_q)`` for a ``:condition`` suffix.

        A missing name is ``(None, None)``. An unbound lookup on an
        instance raises. QuerySet IR compiles to an AND overlay.
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
                             skipped=(), registry=None):
        registry = self._answered_registry() if registry is None else registry
        if registry is None:
            return False
        binding = _permission_binding(perm, obj.model)
        return registry.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(),
            permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )

    def _instance_has_perm(self, user_obj, perm, obj, extra_q=None, *,
                           skipped=(), registry=None):
        registry = self._answered_registry() if registry is None else registry
        if registry is None:
            return False
        binding = _permission_binding(perm, obj.__class__)
        return registry.has_permission(
            user_obj, obj, binding, extra_q=extra_q,
            sponsors=self._sponsor_registries(),
            permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')


class _Once(object):
    """Invoke ``fn`` once. ``play`` and the scratch check both call it."""

    def __init__(self, fn):
        self.fn = fn
        self.called = False
        self.cached = None

    def __call__(self, *args, **kwargs):
        if not self.called:
            self.cached = self.fn(*args, **kwargs)
            self.called = True
        return self.cached


class Recorder(object):
    """Registrations for one backend class. Does not answer questions."""

    def __init__(self):
        self.principals = {}
        self.delegates = {}
        self.named_filters = []
        self.user_conditions = []
        self.user_overrides = []
        self._rows = []
        self.frozen = False

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen.'
            )

    def register(self, *, trust, content, user=None, permission=None,
                 group=None, delegate=None, sponsor=None, condition=None,
                 along=None):
        self._open()
        shape = RegistryFactory().build_public_registration(
            trust=trust, user=user, permission=permission, content=content,
            group=group, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        if shape.delegate is not None:
            payload = {
                'content': shape.content, 'delegate': shape.delegate,
                'sponsor': shape.sponsor, 'condition': shape.condition,
                'along': shape.along,
            }
            record = self._scratch().register_delegation(**payload)
            self.delegates.setdefault(record.content_model, []).append(payload)
            self._rows.append(('delegate', record.content_model, payload))
            return record
        payload = {
            'content': shape.content, 'user': shape.user,
            'condition': shape.condition, 'along': shape.along,
        }
        if shape.group is not None:
            payload['group'] = shape.group
        else:
            payload['permission'] = shape.permission
        record = self._scratch().register(**payload)
        self.principals.setdefault(record.content_model, []).append(payload)
        self._rows.append(('principal', record.content_model, payload))
        return record

    def add_named_filter(self, model, code, predicate):
        self._open()
        once = _Once(predicate)
        record = RegistryFactory().register_permission_condition(model, code, once)
        self.named_filters.append((model, code, once))
        return record

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        result = self._scratch().set_user_condition(name, expr, on=on)
        self.user_conditions.append((name, expr, on))
        return result

    def set_user_override(self, name, expr, on='user'):
        self._open()
        result = self._scratch().set_user_override(name, expr, on=on)
        self.user_overrides.append((name, expr, on))
        return result

    def freeze(self):
        self.frozen = True

    def play(self, visitor):
        for name, expr, on in self.user_conditions:
            visitor.set_user_condition(name, expr, on=on)
        for name, expr, on in self.user_overrides:
            visitor.set_user_override(name, expr, on=on)
        for model, code, predicate in self.named_filters:
            visitor.add_named_filter(model, code, predicate)
        for kind, _model, payload in self._rows:
            if kind == 'principal':
                visitor.register_principal(**payload)
            else:
                visitor.register_delegate(**payload)

    def _scratch(self):
        """Discarded factory holding the rows already stored."""
        factory = RegistryFactory()
        self.play(factory.get_record_adapter())
        return factory


def seal_configured_backends(apps_registry=None):
    """Compile every owned backend class. Safe to call more than once."""
    classes = set()
    loaded = list(get_backends())
    for config in implementation_configs(apps_registry):
        for path in config.owned_backend_paths():
            cls = listed_backend_class(path)
            if isinstance(cls, type):
                classes.add(cls)
    for backend in loaded:
        if type(backend) in classes and isinstance(backend, TrustModelBackendMixin):
            backend.ready()

