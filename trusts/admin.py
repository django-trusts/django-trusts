"""Auto ModelAdmin registration for Content/Junction subclasses.

Concrete Trust/Role admins are owned by django-trusts-zero. This module
does not import ``trusts.models``.
"""
from django.contrib import admin
from django.apps import apps as django_apps


def _is_content_or_junction(model):
    for base in model.__mro__:
        meta = getattr(base, '_meta', None)
        if (
            meta is not None
            and meta.abstract
            and meta.app_label == 'trusts'
            and base.__name__ in ('Content', 'Junction')
        ):
            return True
    return False


def register_auto_modeladmins(admin_site=None):
    """Register concrete Content/Junction subclasses with ``auto_modeladmin=True``.

    Opt-in only. Already registered models are skipped. Safe to call more
    than once. No-op when Zero is not installed (no Content/Junction).
    """
    site = admin_site if admin_site is not None else admin.site
    for model in django_apps.get_models():
        if model._meta.abstract:
            continue
        if not getattr(model._meta, 'auto_modeladmin', False):
            continue
        if not _is_content_or_junction(model):
            continue
        if site.is_registered(model):
            continue
        site.register(model)
