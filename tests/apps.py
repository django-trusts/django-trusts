from django.apps import AppConfig

from trusts.errors import TrustsConfigurationError


def junction_content_field(junction_model):
    """Return the Junction→content field from the concrete Junction contract.

    Uses ``get_content_model()`` plus Django ``_meta``. Does not consult
    a static content map, hard-code ``content``, or guess reverse names.
    """
    content_model = junction_model.get_content_model()._meta.concrete_model
    matches = [
        field for field in junction_model._meta.fields
        if field.remote_field is not None
        and field.remote_field.model._meta.concrete_model is content_model
    ]
    if len(matches) != 1:
        raise TrustsConfigurationError(
            '%s does not expose exactly one content field for %s.'
            % (junction_model._meta.label, content_model._meta.label)
        )
    return matches[0]


class TestsConfig(AppConfig):
    name = 'tests'
    label = 'trusts_tests'
    default_auto_field = 'django.db.models.AutoField'

    def import_models(self):
        # Django imports this app's models before any ready(). Ticket's
        # Meta declares permission_conditions, so the option has to exist
        # first. The library still registers it from ready(); this only
        # covers the installed tests app.
        from trusts.apps import _ensure_permission_conditions_option

        _ensure_permission_conditions_option()
        super().import_models()

    def ready(self):
        # Contribute TUP→Trust←Category, TUP→Trust←Ticket, and the
        # Junction-backed Group terminal to the implementation-owned
        # recorder when this Apps instance has exactly one owner.
        # isolate_apps() constructs a second TestsConfig whose apps
        # registry has no implementation owner; that instance must not
        # donate or seal the live recorders.
        if getattr(self, 'apps', None) is None:
            return

        from django.apps import apps as django_apps
        from django.contrib.auth import get_backends

        from trusts.backends import TrustModelBackendMixin

        if self.apps is not django_apps:
            return
        classes = []
        for backend in get_backends():
            if isinstance(backend, TrustModelBackendMixin):
                cls = type(backend)
                if cls not in classes:
                    classes.append(cls)
        if len(classes) != 1:
            return
        try:
            TrustUserPermission = self.apps.get_model(
                'trusts', 'TrustUserPermission',
            )
            from tests.models import Category, TestGroupJunction, Ticket
        except (LookupError, ImportError):
            return
        self._donate_tup(
            classes[0], TrustUserPermission, Category, Ticket,
            TestGroupJunction,
        )

    def _donate_tup(self, backend_cls, TrustUserPermission, Category, Ticket,
                    TestGroupJunction):
        recorder = backend_cls().get_registry()
        if not getattr(self, '_trusts_tup_category_done', False):
            rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev: (
                    getattr(relationship.trust, _rev)
                ),
            )
            self._trusts_tup_category_done = True
        if not getattr(self, '_trusts_tup_ticket_done', False):
            rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev: (
                    getattr(relationship.trust, _rev)
                ),
            )
            self._trusts_tup_ticket_done = True
        if not getattr(self, '_trusts_tup_group_done', False):
            content_name = junction_content_field(TestGroupJunction).name
            rev = TestGroupJunction._meta.get_field(
                'trust',
            ).remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev, _name=content_name: (
                    getattr(getattr(relationship.trust, _rev), _name)
                ),
            )
            self._trusts_tup_group_done = True
