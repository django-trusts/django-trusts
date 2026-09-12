from django.contrib.auth.models import Permission
from django.db import models

from trusts.query import AuthorizedManager


class Document(models.Model):
    title = models.CharField(max_length=200)
    confidential = models.BooleanField(default=False)
    objects = AuthorizedManager()

    class Meta:
        app_label = 'myapp'


class DocumentGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'myapp'
