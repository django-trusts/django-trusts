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
        if self.apps is not django_apps:
            return
        super().ready()
