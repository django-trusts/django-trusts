from django.apps import apps as django_apps

import trusts.apps as trusts_apps
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


class TestsConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests'
    label = 'trusts_tests'
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Zero's TrustUserPermission is absent from kernel settings.
        # Register those rows on this config when the model is installed.
        # Re-entry finds the rows already registered and stops.
        # isolate_apps() builds another Apps registry. Importing the check
        # stack from that registry's ready() breaks reverse relations on
        # models created in the test, so only the process registry builds.
        if self.apps is not django_apps:
            return
        if getattr(self, '_donated', False):
            super().ready()
            return
        try:
            TrustUserPermission = self.apps.get_model(
                'trusts', 'TrustUserPermission',
            )
            Category = self.get_model('Category')
            Ticket = self.get_model('Ticket')
            TestGroupJunction = self.get_model('TestGroupJunction')
        except LookupError:
            super().ready()
            return
        self._donate_tup(
            TrustUserPermission, Category, Ticket, TestGroupJunction,
        )
        self._donated = True
        super().ready()

    def _donate_tup(self, TrustUserPermission, Category, Ticket,
                    TestGroupJunction):
        from tests.backends import TestsTrustBackend

        registry = TestsTrustBackend().get_registry()
        rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
        registry.register(
            trust=TrustUserPermission,
            user='entity',
            permission='permission',
            content=lambda relationship, _rev=rev: (
                getattr(relationship.trust, _rev)
            ),
        )
        rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
        registry.register(
            trust=TrustUserPermission,
            user='entity',
            permission='permission',
            content=lambda relationship, _rev=rev: (
                getattr(relationship.trust, _rev)
            ),
        )
        content_name = junction_content_field(TestGroupJunction).name
        rev = TestGroupJunction._meta.get_field(
            'trust',
        ).remote_field.get_accessor_name()
        registry.register(
            trust=TrustUserPermission,
            user='entity',
            permission='permission',
            content=lambda relationship, _rev=rev, _name=content_name: (
                getattr(getattr(relationship.trust, _rev), _name)
            ),
        )
