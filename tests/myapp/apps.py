from django.apps import AppConfig

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'


class DocumentConfig(AppConfig):
    name = 'tests.myapp'
    label = 'myapp'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        from tests.myapp.backends import DocumentBackend
        from tests.myapp.models import (
            Document,
            DocumentDelegation,
            DocumentGrant,
        )

        target = DocumentBackend().get_registry()
        register = target.register
        add_filter = target.add_named_filter
        if target.frozen:
            # set_installed_apps() builds a new config against a recorder
            # the sweep already froze.
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
