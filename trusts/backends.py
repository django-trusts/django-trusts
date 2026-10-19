"""Generic Trusts backend mixin.

Registration is a per-class ``Recorder``. ``ready()`` compiles every
configured class, then stores ``catalogs[cls]`` with that class's
family registries fixed. Peers are fixed at that first sweep. A class
compiled after the sweep is not a supported production path, and
earlier peer tuples are not rewritten. Registration closes when the
catalog is built.
"""

from django.contrib.auth import get_backends
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet

from trusts.apps import (
    catalogs,
    implementation_configs,
    implementation_for_class,
    listed_backend_class,
    recorders,
)
from trusts.compile.catalogs import Catalog
from trusts.compile.factory import RegistryFactory
from trusts.errors import TrustsConfigurationError
from trusts.inspect.commands import install_policy_commands
import trusts.inspect.checks  # noqa: F401
from trusts.plan.relations import PlanQueryCompiler, bind_checked_user

install_policy_commands()


class TrustModelBackendMixin(object):
    """Object-permission backend. One recorder and one built registry per class."""

    query_compiler = PlanQueryCompiler()
    family = 'relationship'

    def __init__(self):
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()
        self.recorder = recorders[cls]

    def get_registry(self):
        """The application registry: this class's recorder, still open until ``ready``."""
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()
            self.recorder = recorders[cls]
        return recorders[cls]

    def ready(self):
        """Build this class's catalog when it is not stored yet."""
        _materialize_configured_catalogs(self)
        return catalogs[type(self)]

    def _answered_catalog(self):
        """Catalog stored for this class. ``ready()`` only if it is missing."""
        cls = type(self)
        if cls not in catalogs:
            return self.ready()
        return catalogs[cls]

    def _answered_registry(self):
        return self._answered_catalog().registry

    @property
    def registry(self):
        """Built registry stored on this class's catalog."""
        return self._answered_registry()

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        return self._listed_permissions(
            user_obj, obj, skip_flags, kind='group',
        )

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        return self._listed_permissions(
            user_obj, obj, skip_flags, kind='complete', cache=True,
        )

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. The catalog prepares the answer; this executes it."""
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return False
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        catalog = self._answered_catalog()
        entry = catalog.prepare_has_perm(
            user_obj, permext, obj, skipped=inquiry.values,
        )
        return entry.execute()

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        catalog = self._answered_catalog()
        return catalog.registry.permitted_users_predicate(
            content, perm,
            family_registries=catalog.family_registries,
            skipped=skipped,
            condition_lookup=catalog.registry.condition_lookup,
            accepts_permission=self.singular_permission_accepted,
        )

    def _trusts_config(self):
        """Implementation owner for this class, if one is installed."""
        return implementation_for_class(type(self), required=True)

    def _skip_inquiry(self, user_obj, skip_flags):
        return bind_checked_user(
            user_obj, skip_flags=skip_flags,
            registry=self._answered_registry(),
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind, cache=False):
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        if cache:
            self._ensure_perm_cache(user_obj)
        if isinstance(obj, QuerySet) or isinstance(obj, Model):
            return self._path_permissions(
                user_obj, obj, kind=kind, skipped=inquiry.values,
            )
        return set()

    def _path_permissions(self, user_obj, obj, *, kind, skipped):
        catalog = self._answered_catalog()
        qs = catalog.registry.permissions_for(
            user_obj, obj, kind=kind,
            family_registries=catalog.family_registries,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if qs is None or qs == ():
            return set()
        return _perm_codes(qs)

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')


class Recorder(object):
    """Registrations for one backend class. Does not answer questions."""

    def __init__(self):
        self.principals = {}
        self.delegates = {}
        self.named_filters = []
        self.user_conditions = []
        self.user_overrides = []
        self._rows = []
        self._factory = RegistryFactory()
        self.frozen = False

    def register(self, *, trust, content, user=None, permission=None,
                 group=None, delegate=None, sponsor=None, condition=None,
                 along=None):
        self._open()
        shape = self._factory.build_public_registration(
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
            record = self._factory.register_delegation(**payload)
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
        record = self._factory.register(**payload)
        self.principals.setdefault(record.content_model, []).append(payload)
        self._rows.append(('principal', record.content_model, payload))
        return record

    def add_named_filter(self, model, code, predicate):
        self._open()
        once = _Once(predicate)
        record = self._factory.register_permission_condition(model, code, once)
        self.named_filters.append((model, code, once))
        return record

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        result = self._factory.set_user_condition(name, expr, on=on)
        self.user_conditions.append((name, expr, on))
        return result

    def set_user_override(self, name, expr, on='user'):
        self._open()
        result = self._factory.set_user_override(name, expr, on=on)
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

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen.'
            )


class _Once(object):
    """Invoke ``fn`` once. ``add_named_filter`` and ``play`` both call it."""

    def __init__(self, fn):
        self.fn = fn
        self.called = False
        self.cached = None

    def __call__(self, *args, **kwargs):
        if not self.called:
            self.cached = self.fn(*args, **kwargs)
            self.called = True
        return self.cached


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


def _perm_codes(permission_qs):
    return set(
        '%s.%s' % (app, code)
        for app, code in permission_qs.values_list(
            'content_type__app_label', 'codename',
        )
    )


def _canonical_path(cls):
    return '%s.%s' % (cls.__module__, cls.__qualname__)


def _sponsorship_family(cls):
    """Family of the implementation owner, or the class attribute when none."""
    config = implementation_for_class(cls, required=False)
    if config is None:
        return cls.family
    return config._authorization_family


def _materialize_configured_catalogs(extra):
    """Compile every missing class, then fix each catalog's family registries."""
    backends = list(get_backends())
    if extra is not None:
        backends.append(extra)
    chosen = []
    seen = set()
    for backend in backends:
        if not isinstance(backend, TrustModelBackendMixin):
            continue
        cls = type(backend)
        if cls in seen:
            continue
        seen.add(cls)
        chosen.append(backend)
    pending = []
    for backend in chosen:
        cls = type(backend)
        if cls in catalogs:
            continue
        recorder = recorders.get(cls)
        if recorder is None:
            recorder = Recorder()
            recorders[cls] = recorder
        backend.recorder = recorder
        path = _canonical_path(cls)
        family = _sponsorship_family(cls)
        factory, registry = Catalog.compile(
            path=path, family=family,
            compiler=backend.query_compiler, recorder=recorder,
        )
        pending.append((cls, path, family, factory, registry))
    pool = [(catalog.family, catalog.registry) for catalog in catalogs.values()]
    pool.extend(
        (family, registry)
        for _cls, _path, family, _factory, registry in pending
    )
    for cls, path, family, factory, registry in pending:
        peers = tuple(
            other for other_family, other in pool
            if other_family == family and other is not registry
        )
        catalogs[cls] = Catalog(
            cls=cls, path=path, family=family,
            factory=factory, registry=registry, family_registries=peers,
        )
