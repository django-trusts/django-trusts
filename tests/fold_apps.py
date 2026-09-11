from django.apps import AppConfig


class FoldTestsConfig(AppConfig):
    """Models-free trusts_tests label for OrderedFold PostgreSQL runs.

    isolate_apps('tests', ...) still resolves. create_test_db does not
    sync historical Organization/Category tables that FK auth_user
    before auth migrations finish on PostgreSQL.
    """

    name = 'tests'
    label = 'trusts_tests'
    default_auto_field = 'django.db.models.AutoField'

    def import_models(self):
        # Skip tests.models. Organization.manager → auth.User would
        # otherwise enter sync_apps before auth_user exists on PostgreSQL.
        self.models = self.apps.all_models[self.label]
        self.models_module = None
