from django.db import models

from trusts.models import AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin


class RowQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
    pass


class Binder(models.Model):
    title = models.CharField(max_length=40)
    parent = models.ForeignKey(
        'self', null=True, related_name='children', on_delete=models.CASCADE,
    )


class Page(PermittedUsersMixin, models.Model):
    title = models.CharField(max_length=40)
    binder = models.ForeignKey(
        Binder, related_name='pages', on_delete=models.CASCADE,
    )
    objects = models.Manager.from_queryset(RowQuerySet)()


class PageGrant(models.Model):
    """Grant table registered with ``along=`` on beta's catalog."""

    binder = models.ForeignKey(Binder, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey('auth.Permission', on_delete=models.CASCADE)


class PageDirect(models.Model):
    """Same pages, registered on alpha's catalog without ``along=``."""

    binder = models.ForeignKey(Binder, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey('auth.Permission', on_delete=models.CASCADE)
