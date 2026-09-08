from django.apps import AppConfig


class CustomAuthConfig(AppConfig):
    name = 'tests.custom_auth'
    label = 'custom_auth'
    default_auto_field = 'django.db.models.AutoField'
