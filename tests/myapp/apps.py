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
        from tests.myapp.models import Document, DocumentGrant

        handle = self.configured_backend()
        registry = handle.registry
        if getattr(self, '_document_grant_registry_id', None) is registry:
            return
        handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        handle.register_permission_condition(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self._document_grant_registry_id = registry
