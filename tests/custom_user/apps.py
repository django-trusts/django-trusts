from django.apps import AppConfig


class CustomUserConfig(AppConfig):
    name = 'tests.custom_user'
    label = 'custom_user'
    default_auto_field = 'django.db.models.AutoField'
