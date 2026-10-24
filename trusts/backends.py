"""Generic Trusts backend mixin.

The app config holds one state object per key. ``get_registry()`` is
how an application registers. Each listed backend answers from that
state's catalog only. A miss returns nothing. Callers OR the grant
``Q`` objects.
"""

from collections.abc import Callable
from typing import Protocol, TypeVar, runtime_checkable

from django.apps import apps
from django.contrib.auth import get_backends, get_user_model, load_backend
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet, Subquery

from trusts.apps import AppLifecycle
from trusts.compile.appbuild import build_app_catalog
from trusts.compile.catalogs import compile_catalog_users, filter_catalogs
from trusts.compile.listener import RegistrationListener
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import (
    _build_document,
    _installed_document,
    resolve_policy_database,
)

T = TypeVar('T', bound=Model)
RELATIONSHIP_BACKEND_KEY = 'relationship_backend'


@runtime_checkable
class Registry(Protocol):
    """Registration calls returned by ``get_registry()``."""

    def register(
        self, *,
        trust: type[T],
        user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object] | Callable[[T, object], object] | None
        ) = None,
        along=None,
    ):
        self._accept('register', (), {
            'trust': trust,
            'user': user,
            'permission': permission,
            'content': content,
            'group': group,
            'delegate': delegate,
            'sponsor': sponsor,
            'condition': condition,
            'along': along,
        })

    def add_named_filter(self, model, code, predicate):
        """Record a named-filter builder. The compiler parses it at build."""
        self._accept('add_named_filter', (model, code, predicate), {})

    def set_user_condition(self, name, expr, on='*'):
        self._accept('set_user_condition', (name, expr), {'on': on})

    def set_user_override(self, name, expr, on='user'):
        self._accept('set_user_override', (name, expr), {'on': on})

    def _accept(self, name, args, kwargs):
        """Store one registration call. ``Recorder`` implements this."""


class Recorder(Registry):
    """Ordered log of registration calls for one app.

    ``play`` replays each call, in order, as the same method on
    ``target``. The log must already be frozen. A later ``play``
    replays those same calls onto the new target.
    """

    def __init__(self, listener):
        self._rows = []
        self.frozen = False
        self._listener = listener

    def _accept(self, name, args, kwargs):
        self._open(name)
        getattr(self._listener, name)(*args, **kwargs)
        self._rows.append((name, args, kwargs))

    def freeze(self):
        self.frozen = True

    def play(self, target):
        """Replay this log on ``target``.

        The caller freezes the log first. A second play replays the
        same calls onto that target.
        """
        for name, args, kwargs in self._rows:
            getattr(target, name)(*args, **kwargs)

    def _open(self, method):
        if self.frozen:
            raise TrustsConfigurationError(
                '%s refused: this registry is frozen. '
                'The catalog is already built.' % method
            )


class RelationshipBackend(AppLifecycle):
    """Registration log and catalog for one app config.

    ``family`` and ``query_compiler`` come from the backend class that
    first created this state. The catalog path is the app config class.
    """

    def __init__(self, family='relationship', query_compiler=None):
        self.family = family
        self.query_compiler = query_compiler
        self.recorder = Recorder(RegistrationListener())
        self.catalog = None

    def app_ready(self, app_config):
        build_app_catalog(self, app_config)


class TrustModelBackendMixin(object):
    """Object-permission backend. The app config holds this backend's state."""

    family = 'relationship'
    query_compiler = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_registry(self) -> Registry:
        """Open registration log for this backend's app.

        Not the built catalog. Registration does not resolve the user
        model and does not build the catalog.
        """
        config = apps.get_containing_app_config(type(self).__module__)
        backend_type = type(self)
        state = config.get_or_create_config(
            RELATIONSHIP_BACKEND_KEY,
            lambda: RelationshipBackend(
                family=backend_type.family,
                query_compiler=backend_type.query_compiler,
            ),
        )
        return state.recorder

    def _state(self):
        config = apps.get_containing_app_config(type(self).__module__)
        states = getattr(config, '_states', None) if config is not None else None
        if not isinstance(states, dict):
            return None
        return states.get(RELATIONSHIP_BACKEND_KEY)

    def _catalog(self):
        """Catalog this backend answers from, or ``None`` when unset."""
        state = self._state()
        if state is None:
            return None
        return state.catalog

    def walk_questions(self, visitor):
        """Walk this catalog's questions in document order."""
        catalog = self._catalog()
        if catalog is None:
            return None
        return catalog.walk_questions(visitor)

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No object denies. No catalog denies."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return False
        catalog = self._catalog()
        if catalog is None:
            return False
        return catalog.has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        """Permissions this catalog grants on the object."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        catalog = self._catalog()
        if catalog is None:
            return set()
        return catalog.get_all_permissions(user_obj, obj, **skip_flags)

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        """Group permissions this catalog grants on the object."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        catalog = self._catalog()
        if catalog is None:
            return set()
        return catalog.get_group_permissions(user_obj, obj, **skip_flags)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        catalog = self._catalog()
        if catalog is None:
            return None
        return catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def authorized_grant_q(self, subject, user, permission, *, skipped=()):
        """Grant for an authorized-row filter."""
        catalog = self._catalog()
        if catalog is None:
            return None
        return catalog.complete_grant_q(
            subject, user, permission, skipped=skipped)

    def permitted_grant_q(self, subject, user, permission, *, skipped=(),
                          conditions=(), binding=None, api=None):
        """Grant for a permitted-row filter."""
        catalog = self._catalog()
        if catalog is None:
            return None
        model = subject.model if isinstance(subject, QuerySet) else subject
        predicate, _owned = catalog.authorization_grant(
            subject, user, model, permission, conditions, binding,
            api=api, skipped=skipped)
        return predicate

    def filter_permitted(self, queryset, user, permission, *, conditions=(),
                         **skip_flags):
        """Rows this backend permits. Other backends are not consulted.

        No applicable plan, a selected name this catalog does not own,
        or a permission string this catalog cannot read, returns an
        empty queryset and does not raise.
        """
        if (
            not isinstance(permission, str) or permission.count('.') != 1
            or ':' in permission
        ):
            return queryset.none()
        catalog = self._catalog()
        if catalog is None:
            return queryset.none()
        has_plan, owns = catalog.authorization_preflight(
            queryset.model, conditions)
        if not has_plan or not owns:
            return queryset.none()
        return filter_catalogs(
            ((self, catalog),), queryset, user,
            ask=lambda item, skipped: item.permitted_grant_q(
                queryset, user, permission, skipped=skipped,
                conditions=conditions,
                binding=codename_binding(
                    queryset.model, *permission.split('.', 1)),
                api='authorization_required'),
            skip_flags=skip_flags, user_model=get_user_model())

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, **skip_flags):
        """Scope rows this backend permits as a prefix of ``content``.

        No applicable plan, or a user or permission that is not a saved
        model instance, returns an empty queryset and does not raise.
        """
        catalog = self._catalog()
        if catalog is None:
            return queryset.none()
        return catalog.filter_by_permitted_content(
            queryset, user, permission, content=content, **skip_flags,
        )

    def policy_document(self, *, alias=None):
        """This backend's part of the policy document.

        Same shape as the project document: ``schema_version``,
        ``database``, and ``backends`` holding this catalog only.
        ``alias`` overrides ``TRUSTS_POLICY_DATABASE`` for this call.
        """
        resolved = resolve_policy_database(alias)
        catalog = self._catalog()
        catalogs = () if catalog is None else (catalog,)
        return _build_document(catalogs, resolved)


def policy_document(backend=None, *, alias=None):
    """Policy document for one backend, or the whole project.

    ``backend=None`` is every configured Trusts backend, the document
    ``trusts_policy_sql`` renders. A dotted path is loaded the way
    ``User.objects.with_perm(..., backend=)`` loads one backend, and
    the result is that backend's ``policy_document()``.
    """
    if backend is None:
        return _installed_document(alias=alias)
    if not isinstance(backend, str):
        raise TypeError(
            'backend must be a dotted import path string (got %r).' % backend)
    loaded = load_backend(backend)
    if not isinstance(loaded, TrustModelBackendMixin):
        raise TrustsConfigurationError(
            'backend %r is not a Trusts backend.' % backend)
    return loaded.policy_document(alias=alias)


def codename_binding(model, app_label, codename):
    """Unevaluated pk of the exact codename on ``model``'s content type."""
    return Subquery(
        Permission.objects.filter(
            content_type__app_label=app_label.lower(),
            content_type__model=model._meta.model_name,
            codename=codename,
        ).values('pk')[:1]
    )


def permission_backends(backend=None):
    """Listed backends, or the one ``backend`` dotted path."""
    if backend is None:
        return get_backends()
    if not isinstance(backend, str):
        raise TypeError(
            'backend must be a dotted import path string (got %r).' % backend)
    return (load_backend(backend),)


def trusts_backends(backend=None):
    """Listed Trusts backends. Each answers from its own catalog."""
    return tuple(
        item for item in permission_backends(backend)
        if isinstance(item, TrustModelBackendMixin))


def filter_listed(queryset, user, *, ask, backend=None,
                  skip_flags, require_user=True, extra_q=None):
    """OR each listed backend's own grant and bind ``AUTH_USER_MODEL``.

    A ``skip_<name>`` keyword is checked against the catalog being
    asked. A catalog that does not own the selected names contributes
    nothing. No contributor yields an empty queryset.
    """
    return filter_catalogs(
        _catalogs(backend), queryset, user,
        ask=ask, skip_flags=skip_flags, require_user=require_user,
        extra_q=extra_q, user_model=get_user_model(),
    )


def compile_permitted_users(content, perm, *, user_queryset=None,
                            backend=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    Listed backends are asked once, in order. Each catalog that
    registered the content contributes its own user predicate, including
    that catalog's override. ``skip_<name>`` is checked against that
    catalog. Predicates are OR'd and bound with ``AUTH_USER_MODEL``.
    Unsaved content, a permission this inquiry cannot read, a
    ``user_queryset`` that is not a ``QuerySet`` or whose model is not
    ``AUTH_USER_MODEL``, and a catalog whose registered user model is
    not that candidate all yield an empty queryset and do not raise.
    ``backend`` is one dotted path.
    """
    return compile_catalog_users(
        _catalogs(backend), content, perm,
        user_queryset=user_queryset, user_model=get_user_model(),
        **skip_flags,
    )


def _catalogs(backend):
    """Listed backends, one entry per catalog object, in list order.

    A backend with no catalog contributes nothing.
    """
    chosen, seen = [], set()
    for item in trusts_backends(backend):
        catalog = item._catalog()
        if catalog is None:
            continue
        marker = id(catalog)
        if marker in seen:
            continue
        seen.add(marker)
        chosen.append((item, catalog))
    return chosen
