from django.db import models

from trusts.models import AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin


class RowQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
    pass


class Shelf(models.Model):
    title = models.CharField(max_length=40)


class Note(PermittedUsersMixin, models.Model):
    title = models.CharField(max_length=40)
    shelf = models.ForeignKey(Shelf, related_name='notes', on_delete=models.CASCADE)
    objects = models.Manager.from_queryset(RowQuerySet)()


class NoteGrant(models.Model):
    shelf = models.ForeignKey(Shelf, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey('auth.Permission', on_delete=models.CASCADE)


class NoteAlso(models.Model):
    """Second grant table. Another catalog may register the same Note."""

    shelf = models.ForeignKey(Shelf, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey('auth.Permission', on_delete=models.CASCADE)
