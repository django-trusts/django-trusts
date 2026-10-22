from django.apps import apps as django_apps

import trusts.apps as trusts_apps

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'


class DocumentConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests.myapp'
    label = 'myapp'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Grants are registered at the end of models.py. A rebuilt app
        # config (override_settings INSTALLED_APPS) does not re-import
        # models, so this ready() registers them when that import did
        # not. The named filter stays here so a ready() path stays
        # tested. isolate_apps() uses another registry; only the process
        # registry contributes.
        if self.apps is not django_apps:
            return
        if getattr(self, '_grants', False) and getattr(self, '_named_filter', False):
            super().ready()
            return
        from tests.myapp.backends import DocumentBackend
        from tests.myapp.models import Document, register_document_grants

        registry = DocumentBackend().get_registry()
        if not getattr(self, '_grants', False):
            register_document_grants(registry)
            self._grants = True
        if not getattr(self, '_named_filter', False):
            registry.add_named_filter(
                Document,
                'non_confidential',
                lambda u, p, o: o.confidential != True,
            )
            self._named_filter = True
        super().ready()
