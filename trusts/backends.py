"""Generic Trusts backend mixin.

Registration is a per-class ``Recorder``. Inquiry reads the catalog
``TrustsImplementationConfig.ready`` stored for this class. A class with no catalog
denies: ``has_perm`` is false and permission or user queries are empty.
"""

from collections.abc import Callable
from typing import TypeVar

from django.conf import settings
from django.contrib.auth import get_backends
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet

from trusts.errors import TrustsConfigurationError
import trusts.plan.standards as standards
from trusts.plan.relations import PlanQueryCompiler

catalogs = {}
recorders: dict[type, "Recorder"] = {}

T = TypeVar('T', bound=Model)


class TrustModelBackendMixin(object):
    """Object-permission backend. One recorder per class; one catalog after ready."""

    query_compiler = PlanQueryCompiler()
    family = 'relationship'

    def __init__(self):
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()

    def get_registry(self) -> "Recorder":
        """Open recorder for registration. Not the built catalog."""
        return recorders[type(self)]

    def get_catalog(self):
        """Catalog stored at ready, or ``None`` when this class was not built."""
        return catalogs.get(type(self))

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No catalog, or no object, denies."""
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return False
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        return catalog.has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='complete',
        )

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='group',
        )

    def get_permitted_users(self, content, perm, **skip_flags):
        """Users permitted on ``content``. No catalog yields no users."""
        catalog = self.get_catalog()
        if catalog is None:
            return _no_users()
        return catalog.permitted_users(content, perm, **skip_flags)

    def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):
        """Users holding ``perm`` on ``obj``. No catalog or no object yields no users."""
        del is_active, include_superusers
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return _no_users()
        return catalog.permitted_users(obj, perm)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        catalog = self.get_catalog()
        if catalog is None:
            return None
        return catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def _permission_codes(self, user_obj, obj, skip_flags, *, kind):
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return set()
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return set()
        if kind == 'group':
            return catalog.get_group_permissions(user_obj, obj, **skip_flags)
        return catalog.get_all_permissions(user_obj, obj, **skip_flags)


class Recorder(object):
    """Ordered log of registration calls for one backend class.

    The log stores the call arguments. The ready-time sweep is the only
    validation and the only build.
    """

    def __init__(self):
        self._rows = []
        self.frozen = False

    @property
    def rows(self):
        """Recorded calls, in registration order."""
        return self._rows

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
        self._open()
        self._rows.append(('register', {
            'trust': trust,
            'user': user,
            'permission': permission,
            'content': content,
            'group': group,
            'delegate': delegate,
            'sponsor': sponsor,
            'condition': condition,
            'along': along,
        }))

    def add_named_filter(self, model, code, predicate):
        """Record a named-filter builder for the ready-time sweep."""
        self._open()
        self._rows.append(('filter', model, code, predicate))

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        self._rows.append(('condition', name, expr, on))

    def set_user_override(self, name, expr, on='user'):
        self._open()
        self._rows.append(('override', name, expr, on))

    def freeze(self):
        self.frozen = True

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen.'
            )


def configured_catalogs():
    """Catalogs of listed mixin backends, in ``get_backends()`` order.

    An empty ``AUTHENTICATION_BACKENDS`` is no catalogs. Django's
    ``get_backends()`` raises in that case; this inquiry does not.
    A class that was not built contributes nothing. Callers treat a
    missing catalog as no grants.
    """
    if not tuple(settings.AUTHENTICATION_BACKENDS):
        return ()
    found = []
    seen = set()
    for backend in get_backends():
        if not isinstance(backend, TrustModelBackendMixin):
            continue
        cls = type(backend)
        if cls in seen:
            continue
        seen.add(cls)
        catalog = backend.get_catalog()
        if catalog is None:
            continue
        found.append(catalog)
    return tuple(found)


def _no_users():
    """Empty user queryset after ready, or an empty tuple before it."""
    model = standards.user_model
    if model is None:
        return ()
    return model._default_manager.none()
