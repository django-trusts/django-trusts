from django.contrib.auth.models import Permission
from django.db import models

from trusts.models import AuthorizedManager, PermittedUsersMixin


class Document(PermittedUsersMixin, models.Model):
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


class DocumentAltGrant(models.Model):
    """Second Document grant table for share-nothing split-path proofs."""

    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'myapp'


class DocumentDelegation(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    delegate = models.ForeignKey(
        'auth.User', related_name='received_document_delegations',
        on_delete=models.CASCADE,
    )
    sponsor = models.ForeignKey(
        'auth.User', related_name='sponsored_document_delegations',
        on_delete=models.CASCADE,
    )
    allowed_permissions = models.ManyToManyField(Permission)
    approved = models.BooleanField(default=True)

    class Meta:
        app_label = 'myapp'


from django.apps import apps as django_apps

from tests.myapp.backends import DocumentBackend


def register_document_grants(registry):
    """Document grants. Called from models import and from ``ready()``.

    ``set_installed_apps()`` builds a new app config and does not
    re-execute this module, so ``ready()`` registers there. The first
    import registers here and marks that config.
    """
    registry.register(
        trust=DocumentGrant,
        user='user',
        permission='permission',
        content='document',
    )
    registry.register(
        trust=DocumentDelegation,
        delegate='delegate',
        sponsor='sponsor',
        content='document',
        condition=lambda relationship, permission: (
            relationship.allowed_permissions.contains(permission)
        ),
    )


_backend = DocumentBackend()
register_document_grants(_backend.get_registry())
django_apps.get_app_config('myapp')._grants = True
del _backend
