"""Generic Trusts backend mixin.

The backend reads the catalog of the app config that contains its
class. That config is a ``TrustsConfigMixin``. ``get_registry()`` is
how an application registers. Each listed backend answers from that
catalog only. A miss returns nothing. Callers OR the grant ``Q``
objects.
"""

from django.apps import apps
from django.contrib.auth import get_backends, get_user_model, load_backend
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet, Subquery

from trusts.apps import Registry, TrustsConfigMixin
from trusts.compile.catalogs import compile_catalog_users, filter_catalogs
from trusts.errors import TrustsConfigurationError, TrustsMixinRequired
from trusts.inspect.snapshot import (
    _build_document,
    _installed_document,
    resolve_policy_database,
)


class TrustModelBackendMixin(object):
    """Object-permission backend. The catalog belongs to the app config."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = apps.get_containing_app_config(type(self).__module__)
        if not isinstance(config, TrustsConfigMixin):
            raise TrustsMixinRequired(_mixin_required_message(
                config,
                '%s.%s' % (type(self).__module__, type(self).__qualname__),
            ))
        self._config = config

    def get_registry(self) -> Registry:
        """Open registration log for this backend's app.

        Not the built catalog. Registration does not resolve the user
        model and does not build the catalog.
        """
        return self._config.recorder

    def _catalog(self):
        """Catalog this instance answers from. The app config owns it."""
        return self._config.catalog

    def walk_questions(self, visitor):
        """Walk this catalog's questions in document order."""
        return self._catalog().walk_questions(visitor)

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No object denies."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return False
        return self._catalog().has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        """Permissions this catalog grants on the object."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        return self._catalog().get_all_permissions(user_obj, obj, **skip_flags)

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        """Group permissions this catalog grants on the object."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        return self._catalog().get_group_permissions(user_obj, obj, **skip_flags)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        return self._catalog().permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def authorized_grant_q(self, subject, user, permission, *, skipped=()):
        """Grant for an authorized-row filter."""
        return self._catalog().complete_grant_q(
            subject, user, permission, skipped=skipped)

    def permitted_grant_q(self, subject, user, permission, *, skipped=(),
                          conditions=(), binding=None, api=None):
        """Grant for a permitted-row filter."""
        model = subject.model if isinstance(subject, QuerySet) else subject
        predicate, _owned = self._catalog().authorization_grant(
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
        return self._catalog().filter_by_permitted_content(
            queryset, user, permission, content=content, **skip_flags,
        )

    def policy_document(self, *, alias=None):
        """This backend's part of the policy document.

        Same shape as the project document: ``schema_version``,
        ``database``, and ``backends`` holding this catalog only.
        ``alias`` overrides ``TRUSTS_POLICY_DATABASE`` for this call.
        """
        resolved = resolve_policy_database(alias)
        return _build_document((self._catalog(),), resolved)


def policy_document(backend=None, *, alias=None):
    """Policy document for one backend, or the whole project.

    ``backend=None`` is every installed Trusts config, the document
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


def _mixin_required_message(config, backend_path):
    return (
        'Backend %s is not inside an app whose config extends '
        'TrustsConfigMixin.' % backend_path
        if config is None else
        'App %s must extend TrustsConfigMixin.' % config.label)


def _catalogs(backend):
    """Listed backends, one entry per catalog object, in list order."""
    chosen, seen = [], set()
    for item in trusts_backends(backend):
        catalog = item._catalog()
        marker = id(catalog)
        if marker in seen:
            continue
        seen.add(marker)
        chosen.append((item, catalog))
    return chosen
