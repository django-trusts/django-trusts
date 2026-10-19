"""Generic Trusts backend mixin.

Registration is a per-class ``Recorder``. ``ready()`` builds a
``Catalog`` for each configured class and stores ``catalogs[cls]``.
Sponsors are the other classes' built registries, passed into that
constructor. ``registries[cls]`` receives the built registry when the
key is empty so existing readers keep a registry object.
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
    registries,
)
from trusts.compile.catalogs import Catalog
from trusts.compile.factory import RegistryFactory
from trusts.errors import TrustsConfigurationError
import trusts.inspect.checks  # noqa: F401
from trusts.plan.relations import PlanQueryCompiler, bind_checked_user


class TrustModelBackendMixin(object):
    """Object-permission backend. One recorder and one built registry per class."""

    query_compiler = PlanQueryCompiler()
    family = 'relationship'

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

    def ready(self):
        return self._get_or_create_catalog()

    def _get_or_create_catalog(self):
        """Return this class's catalog. A catalog already stored is kept."""
        _materialize_configured_catalogs(self)
        return catalogs[type(self)]

    def _built_registry(self):
        return self._get_or_create_catalog().registry

    @property
    def registry(self):
        """Built registry for this class. Seals on first read."""
        return self._built_registry()

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
        catalog = self._get_or_create_catalog()
        entry = catalog.prepare_has_perm(
            user_obj, permext, obj, skipped=inquiry.values,
        )
        return entry.execute()

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        catalog = self._get_or_create_catalog()
        return catalog.registry.permitted_users_predicate(
            content, perm,
            sponsors=catalog.sponsors,
            skipped=skipped, backend=self,
        )

    def _skip_inquiry(self, user_obj, skip_flags):
        return bind_checked_user(
            user_obj, skip_flags=skip_flags,
            registry=self._built_registry,
        )

    def _listed_permissions(self, user_obj, obj, skip_flags, *, kind, cache=False):
        inquiry = self._skip_inquiry(user_obj, skip_flags)
        if obj is None or inquiry.denied:
            return set()
        registry = self._built_registry()
        if cache:
            self._ensure_perm_cache(user_obj)
        if isinstance(obj, QuerySet) or isinstance(obj, Model):
            return self._path_permissions(
                user_obj, obj, kind=kind, skipped=inquiry.values,
                registry=registry,
            )
        return set()

    def _path_permissions(self, user_obj, obj, *, kind, skipped=(), registry=None):
        registry = self._built_registry() if registry is None else registry
        if registry is None:
            return set()
        qs = registry.permissions_for(
            user_obj, obj, kind=kind,
            sponsors=self._get_or_create_catalog().sponsors,
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


def _materialize_configured_catalogs(extra):
    """Compile each missing class, then construct catalogs with sponsors."""
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
    missing = [backend for backend in chosen if type(backend) not in catalogs]
    if missing:
        compiled = []
        for backend in missing:
            cls = type(backend)
            recorder = recorders.get(cls)
            if recorder is None:
                recorder = Recorder()
                recorders[cls] = recorder
            backend.recorder = recorder
            path = _canonical_path(cls)
            family = cls.family
            factory, registry = Catalog.compile(
                path=path, family=family,
                compiler=backend.query_compiler, recorder=recorder,
            )
            compiled.append((cls, path, family, factory, registry))
        by_cls = {cls: catalog.registry for cls, catalog in catalogs.items()}
        for cls, path, family, factory, registry in compiled:
            by_cls[cls] = registry
        for cls, path, family, factory, registry in compiled:
            sponsors = tuple(
                by_cls[other]
                for other in by_cls
                if other is not cls and other.family == family
            )
            catalogs[cls] = Catalog(
                cls=cls, path=path, family=family,
                factory=factory, registry=registry, sponsors=sponsors,
            )
    for backend in chosen:
        cls = type(backend)
        registries.setdefault(cls, catalogs[cls].registry)

