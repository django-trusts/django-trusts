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
        from tests.myapp.backends import DocumentBackend
        from tests.myapp.models import (
            Document,
            DocumentDelegation,
            DocumentGrant,
        )

        # A swapped path store (test isolation) is written here.
        # Production leaves that dict empty and writes the class
        # recorder. ``configured_backend()`` would seal before these
        # rows exist, so it is not the writer.
        if DOCUMENT_BACKEND in self.registries:
            target = self.registries[DOCUMENT_BACKEND]
            register = target.register_public
            add_filter = target.register_permission_condition
            registry = target
        else:
            target = DocumentBackend().get_registry()
            register = target.register
            add_filter = target.add_named_filter
            registry = target
        if getattr(self, '_document_grant_registry_id', None) is registry:
            return
        if getattr(registry, 'frozen', False):
            # set_installed_apps() builds a new config against a recorder
            # that an inquiry or the tests app already sealed.
            self._document_grant_registry_id = registry
            return
        register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )
        add_filter(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self._document_grant_registry_id = registry
