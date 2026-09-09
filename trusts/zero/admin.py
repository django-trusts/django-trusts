from django.contrib import admin
from django.apps import apps as django_apps

from trusts.zero.models import (
    Content, Junction, Trust, Role, RolePermission, TrustUserPermission,
    TrustGroup, TrustGroupPermission,
)


class TrustGroupPermissionInline(admin.TabularInline):
    model = TrustGroupPermission
    extra = 0


class TrustGroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'trust', 'group')
    inlines = (TrustGroupPermissionInline,)


admin.site.register(Trust, admin.ModelAdmin)
admin.site.register(Role, admin.ModelAdmin)
admin.site.register(RolePermission, admin.ModelAdmin)
admin.site.register(TrustUserPermission, admin.ModelAdmin)
admin.site.register(TrustGroup, TrustGroupAdmin)
admin.site.register(TrustGroupPermission, admin.ModelAdmin)


def register_auto_modeladmins(admin_site=None):
    """Register concrete Content/Junction subclasses with ``auto_modeladmin=True``.

    Opt-in only. Core models stay explicitly registered above. Already
    registered models are skipped. Safe to call more than once.
    """
    site = admin_site if admin_site is not None else admin.site
    for model in django_apps.get_models():
        if model._meta.abstract:
            continue
        if not getattr(model._meta, 'auto_modeladmin', False):
            continue
        if not issubclass(model, (Content, Junction)):
            continue
        if site.is_registered(model):
            continue
        site.register(model)
