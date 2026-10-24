import trusts.apps as trusts_apps

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'


class DocumentConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests.myapp'
    label = 'myapp'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Models import after the app registry has started populate.
        # Phase 1 loads this module before models, so the import stays
        # in ready(). Re-entry finds the recorder frozen and stops
        # before register.
        if self.recorder.frozen:
            return
        from tests.myapp.models import (
            Document,
            DocumentDelegation,
            DocumentGrant,
        )

        self.recorder.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.recorder.register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )
        self.recorder.add_named_filter(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        super().ready()
