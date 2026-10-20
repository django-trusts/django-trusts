from django.db.models import Manager

from trusts.models.query import AuthorizedQuerySet, PermittedQuerySet


class AuthorizedManagerMixin:
    """Add ``authorized()`` without replacing an application's manager."""

    def authorized(self, user, permission, extra_q=None, **skip_flags):
        return AuthorizedQuerySet.authorized(
            self.get_queryset(), user, permission, extra_q=extra_q,
            **skip_flags,
        )


class PermittedUsersManagerMixin:
    """Optional adapter on an application's existing user manager.

    ``User.objects.permitted(content, perm)`` returns a lazy user
    queryset. The name is ``permitted`` because the manager already
    identifies the user model, and Django's ``get`` convention implies
    one row. Does not replace that manager or its queryset class. Stock
    ``auth.User`` does not acquire this method. The content adapter
    ``get_permitted_users`` remains the path that does not require a
    user-manager change.
    """

    def permitted(self, content, perm, **skip_flags):
        from trusts.compile.catalogs import compile_permitted_users

        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(), **skip_flags,
        )


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)
PermittedManager = Manager.from_queryset(PermittedQuerySet)
