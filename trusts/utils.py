from django.db.models import Model


def get_short_model_name_lower(klass):
    if isinstance(klass, str):
        return klass.lower()
    if issubclass(klass, Model):
        return '%s.%s' % (klass._meta.app_label.lower(), klass._meta.model_name)
    return ''


def get_short_model_name(klass):
    if isinstance(klass, str):
        return klass
    if issubclass(klass, Model):
        return '%s.%s' % (klass._meta.app_label, klass._meta.object_name)
    return ''


def parse_perm_code(perm):
    """Split ``app.action_model`` plus an optional ``:condition`` suffix.

The condition is partitioned first so condition codes may contain
underscores (``app.change_ticket:own_item``). This is a parse-order
fix, not a new permission form.
    """
    applabel, rest = perm.split('.', 1)
    rest, _sep, cond = rest.partition(':')
    action, modelname = rest.rsplit('_', 1)
    return applabel, modelname, action, cond


def has_related_query_name(model, query_name):
    """True when ``model.objects.filter(**{query_name: ...})`` is a valid lookup."""
    from django.core.exceptions import FieldDoesNotExist

    try:
        model._meta.get_field(query_name)
        return True
    except FieldDoesNotExist:
        pass
    for rel in model._meta.related_objects:
        if rel.related_query_name() == query_name:
            return True
    return False


def sync_configured_permissions():
    """Copy ``auth.Permission`` rows into ``TRUSTS_PERMISSION_MODEL``.

    Django only auto-creates ``auth.Permission``. A separate configured
    permission table is not populated by ``create_permissions``. Call this
    from a project ``post_migrate`` receiver or data migration when the
    two models differ. No-op when they are the same model. Expects the
    Django permission shape: ``name``, ``content_type``, ``codename``.
    """
    from django.contrib.auth.models import Permission as AuthPermission
    from trusts import get_permission_model

    Permission = get_permission_model()
    if Permission is AuthPermission:
        return 0
    created = 0
    for perm in AuthPermission.objects.all():
        _obj, was_created = Permission.objects.get_or_create(
            content_type=perm.content_type,
            codename=perm.codename,
            defaults={'name': perm.name},
        )
        created += int(was_created)
    return created

