from trusts.apps import TrustsImplementationConfig
from trusts.conditions import RegistryConditionLookup
from trusts.core import Ref

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
        j = Ref(DocumentGrant)
        registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        handle.register_permission_condition(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        handle.registry.set_condition_lookup(
            RegistryConditionLookup(handle.registry),
        )
        self._document_grant_registry_id = registry
