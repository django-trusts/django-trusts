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
        from django.apps import apps as django_apps

        from tests.myapp.backends import DocumentBackend
        from tests.myapp.models import (
            Document,
            DocumentDelegation,
            DocumentGrant,
        )
        from trusts.backends import seal_configured_backends

        # A swapped path store (test isolation) is the object this
        # ready() writes. Production leaves that dict empty and writes
        # the class recorder, which is what ``get_registry()`` returns.
        # ``configured_backend()`` is not used in that case: it would
        # seal the recorder before these rows exist.
        if DOCUMENT_BACKEND in self.registries:
            writer = self.configured_backend(DOCUMENT_BACKEND)
            registry = writer.registry
        else:
            writer = DocumentBackend().get_registry()
            registry = writer
        if getattr(self, '_document_grant_registry_id', None) is registry:
            self._seal_if_no_tests_app(django_apps, seal_configured_backends)
            return
        if getattr(registry, 'frozen', False):
            # set_installed_apps() builds a new config against a recorder
            # TestsConfig already sealed. Registering again is refused.
            self._document_grant_registry_id = registry
            self._seal_if_no_tests_app(django_apps, seal_configured_backends)
            return
        writer.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        writer.register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )
        writer.add_named_filter(
            Document,
            'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self._document_grant_registry_id = registry
        self._seal_if_no_tests_app(django_apps, seal_configured_backends)

    def _seal_if_no_tests_app(self, django_apps, seal_configured_backends):
        try:
            django_apps.get_app_config('trusts_tests')
        except LookupError:
            seal_configured_backends(getattr(self, 'apps', None))
