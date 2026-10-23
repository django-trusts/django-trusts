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

from trusts.apps import Recorder, TrustsConfigMixin
from trusts.compile.catalogs import (
    assert_same_database,
    catalog_models,
    database_alias,
)
from trusts.errors import TrustsConfigurationError, TrustsMixinRequired
from trusts.plan.contents import permitted_content_q
from trusts.plan.relations import bind_checked_user
from trusts.plan.rewrites import bind_once
from trusts.plan.users import assert_persisted_principal


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

    def get_registry(self) -> Recorder:
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
        has_plan, owns = self._catalog().authorization_preflight(
            queryset.model, conditions)
        if not has_plan or not owns:
            return queryset.none()
        return filter_listed(
            queryset, user,
            ask=lambda item, skipped: item.permitted_grant_q(
                queryset, user, permission, skipped=skipped,
                conditions=conditions,
                binding=codename_binding(
                    queryset.model, *permission.split('.', 1)),
                api='authorization_required'),
            backend='%s.%s' % (type(self).__module__, type(self).__qualname__),
            skip_flags=skip_flags)

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, **skip_flags):
        """Scope rows this backend permits as a prefix of ``content``.

        No applicable plan, or a user or permission that is not a saved
        model instance, returns an empty queryset and does not raise.
        """
        if (
            not isinstance(user, Model)
            or not isinstance(permission, Model)
            or permission.pk is None
        ):
            return queryset.none()
        return filter_listed(
            queryset, user,
            ask=lambda item, skipped: permitted_content_q(
                queryset.model, user, permission, content=content,
                catalog=item._catalog(), skipped=skipped),
            backend='%s.%s' % (type(self).__module__, type(self).__qualname__),
            skip_flags=skip_flags)

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
        resolved = resolve_policy_database(alias)
        return _build_document(tuple(
            config.catalog for config in apps.get_app_configs()
            if isinstance(config, TrustsConfigMixin)), resolved)
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
    combined = None
    for item, catalog in _catalogs(backend):
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags, require_user=require_user,
            catalog=catalog)
        if inquiry.denied:
            return queryset.none()
        part = ask(item, inquiry.values)
        if part is None:
            continue
        clause = part if extra_q is None else part & extra_q
        combined = clause if combined is None else combined | clause
    if combined is None:
        return queryset.none()
    return bind_once(
        queryset.filter(combined).distinct(), user_model=get_user_model())


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
    if user_queryset is not None and not isinstance(user_queryset, QuerySet):
        return get_user_model()._default_manager.none()
    if user_queryset is not None and (
        user_queryset.model is None
        or user_queryset.model._meta.concrete_model
        is not get_user_model()._meta.concrete_model
    ):
        return (
            get_user_model()._default_manager.none()
            if user_queryset.model is None else user_queryset.none()
        )
    if (
        not isinstance(content, Model) or content.pk is None
        or isinstance(perm, QuerySet)
        or not isinstance(perm, (str, Model))
        or (isinstance(perm, Model) and perm.pk is None)
    ):
        return _empty_users(user_queryset)
    if user_queryset is None:
        user_queryset = get_user_model()._default_manager.get_queryset()
    principal = user_queryset.model
    assert_persisted_principal(principal)
    combined = None
    involved = [principal, type(content)]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    for item, catalog in _catalogs(backend):
        inquiry = bind_checked_user(
            None, skip_flags=skip_flags, require_user=False, catalog=catalog)
        if inquiry.denied:
            return _empty_users(user_queryset)
        predicate = item.permitted_users_predicate(
            content, perm, skipped=inquiry.values)
        if predicate is None:
            continue
        models = catalog_models(catalog, content, principal)
        if models is None:
            continue
        combined = predicate if combined is None else combined | predicate
        involved.extend(models)
    if combined is None:
        return _empty_users(user_queryset)
    alias = database_alias(content, user_queryset)
    assert_same_database(alias, involved)
    if user_queryset.db != alias:
        user_queryset = user_queryset.using(alias)
    return bind_once(
        user_queryset.filter(combined).distinct(), user_model=principal)


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


def _empty_users(user_queryset):
    """Empty user queryset. No caller queryset uses ``AUTH_USER_MODEL``."""
    if user_queryset is not None:
        return user_queryset.none()
    return get_user_model()._default_manager.none()


# snapshot imports policy_document. These names are bound first.
from trusts.inspect.snapshot import _build_document, resolve_policy_database
