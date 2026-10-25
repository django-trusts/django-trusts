from django.apps import apps
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


from tests.myapp.backends import DocumentBackend


def register_document_grants(registry):
    """Document grant rows. The named filter is registered beside them."""
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


def register_document_app(registry):
    """Everything this app registers. Called from the end of this module."""
    register_document_grants(registry)
    registry.add_named_filter(
        Document,
        'non_confidential',
        lambda u, p, o: o.confidential != True,
    )


_config = apps.get_containing_app_config(DocumentBackend.__module__)
if _config is not None and _config.label == 'myapp':
    _registry = DocumentBackend().get_registry()
    if not _registry.frozen:
        register_document_app(_registry)
        _config._registered_from_models = True
