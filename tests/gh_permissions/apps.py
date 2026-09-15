from django.apps import AppConfig


class GhPermissionsConfig(AppConfig):
    """Stub GH app until G1. Label ``gh_permissions``; no Trusts schema."""

    name = 'tests.gh_permissions'
    label = 'gh_permissions'
    default_auto_field = 'django.db.models.AutoField'
