from django.apps import apps as django_apps

import trusts.apps as trusts_apps

DOCUMENT_BACKEND = 'tests.myapp.backends.DocumentBackend'


class DocumentConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests.myapp'
    label = 'myapp'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Registration lives at the end of models.py. isolate_apps()
        # uses another registry; only the process registry imports checks.
        # override_settings builds a new config and does not re-import
        # models.py, so an empty log is filled here before the freeze.
        if self.apps is not django_apps:
            return
        # models.py already logged this process. override_settings builds
        # a new config and does not re-import models.py, so only an empty
        # config is filled here, before the freeze.
        from tests.support import read_catalog

        if read_catalog(self) is None and not getattr(
            self, '_registered_from_models', False,
        ):
            from tests.myapp.backends import DocumentBackend
            from tests.myapp.models import register_document_app
            register_document_app(DocumentBackend().get_registry())
            self._registered_from_models = True
        super().ready()
