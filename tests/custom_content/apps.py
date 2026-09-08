from django.apps import AppConfig


class CustomContentConfig(AppConfig):
    name = 'tests.custom_content'
    label = 'custom_content'
    default_auto_field = 'django.db.models.AutoField'
