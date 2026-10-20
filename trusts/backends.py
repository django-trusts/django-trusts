"""Generic Trusts backend mixin.

The backend borrows the recorder and catalog of the app config that
contains its class. That config is a ``TrustsConfigMixin``. Inquiry
reads ``self.catalog``.
"""

from django.apps import apps
from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet

from trusts.apps import TrustsConfigMixin
from trusts.errors import TrustsConfigurationError


class TrustModelBackendMixin(object):
    """Object-permission backend. The catalog belongs to the app config."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = apps.get_containing_app_config(type(self).__module__)
        if not isinstance(config, TrustsConfigMixin):
            dotted = '%s.%s' % (type(self).__module__, type(self).__qualname__)
            raise TrustsConfigurationError(
                '%s must live inside an app whose config subclasses '
                'TrustsConfigMixin.' % dotted
            )
        self.catalog = config.get_catalog()
        self.recorder = config.recorder

    def get_catalog(self):
        """Catalog taken from the containing app config at construction."""
        return self.catalog

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No object denies."""
        if obj is None:
            return False
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        return self.catalog.has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='complete',
        )

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='group',
        )

    def get_permitted_users(self, content, perm, **skip_flags):
        """Users permitted on ``content``."""
        return self.catalog.permitted_users(content, perm, **skip_flags)

    def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):
        """Users holding ``perm`` on ``obj``. No object yields no users."""
        del is_active, include_superusers
        if obj is None:
            return self._no_users()
        return self.catalog.permitted_users(obj, perm)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        return self.catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def _permission_codes(self, user_obj, obj, skip_flags, *, kind):
        if obj is None:
            return set()
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return set()
        if kind == 'group':
            return self.catalog.get_group_permissions(user_obj, obj, **skip_flags)
        return self.catalog.get_all_permissions(user_obj, obj, **skip_flags)

    def _no_users(self):
        """Empty user queryset from the catalog's user model."""
        return self.catalog.user_model._default_manager.none()
