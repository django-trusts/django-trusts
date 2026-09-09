"""Authorized queryset / manager surface (issue #47 S1).

The class name is ``AuthorizedQuerySet`` (not ``AuthorizationQuerySet``).
That matches accepted framework-execution-r1/r2: ``authorized`` is the
neutral verb, and Zero keeps ``permitted`` with its Django-permission
argument order. The manager is ``AuthorizedManager``.
"""

from django.db import models

from trusts.runtime import filter_authorized


class AuthorizedQuerySet(models.QuerySet):
    """QuerySet that filters rows through the composed grant predicate."""

    def authorized(self, principal, operation, **kwargs):
        """SQL-filter this queryset with ``filter_authorized``.

        ``kwargs`` are the isolated-registry / adapter-name options of
        ``filter_authorized`` (``context``, ``trustee``, ``names``).
        """
        return filter_authorized(self, principal, operation, **kwargs)


class AuthorizedManager(models.Manager.from_queryset(AuthorizedQuerySet)):
    """Default manager that exposes ``QuerySet.authorized``."""


__all__ = [
    'AuthorizedManager',
    'AuthorizedQuerySet',
]
