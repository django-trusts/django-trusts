from django.db import models

from trusts.query import AuthorizedManager


class Repository(models.Model):
    """Instance-only GH-shaped model. Not a Trusts Content subclass."""

    name = models.CharField(max_length=40)

    objects = AuthorizedManager()

    class Meta:
        app_label = 'gh_permissions'
