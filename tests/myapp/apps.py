from trusts.apps import TrustsImplementationConfig

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'


class DocumentConfig(TrustsImplementationConfig):
    name = 'tests.myapp'
    label = 'myapp'
    default = False
    default_auto_field = 'django.db.models.AutoField'
    trusts_backend_paths = (DOCUMENT_BACKEND,)

    def ready(self):
        super().ready()
        from tests.myapp.models import (
            Document,
            DocumentDelegation,
            DocumentGrant,
        )

        from tests.myapp.backends import DocumentBackend

        registry = DocumentBackend().get_registry()
        if getattr(self, '_document_grant_registry_id', None) is registry:
            return
        if getattr(registry, '_document_contributed', False):
            self._document_grant_registry_id = registry
            return
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
        registry.add_named_filter(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self.freeze_owned_backends()
        registry._document_contributed = True
        self._document_grant_registry_id = registry
