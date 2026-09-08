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


def lookup_relation(model, query_name):
    """Return the relation used by ``model.objects.filter(**{query_name: v})``.

    ``None`` when the lookup is missing or is not a relation. A scalar
    field with that name is ``None``: Django may coerce a model instance
    to a pk or string through that field, which must not count as
    membership.
    """
    from django.core.exceptions import FieldDoesNotExist

    try:
        field = model._meta.get_field(query_name)
    except FieldDoesNotExist:
        field = None
    else:
        if getattr(field, 'is_relation', False):
            return field
        return None
    for rel in model._meta.related_objects:
        if rel.related_query_name() == query_name:
            return rel
    return None


def related_model_of(field_or_rel):
    if field_or_rel is None:
        return None
    remote = getattr(field_or_rel, 'remote_field', None)
    if remote is not None and getattr(remote, 'model', None) is not None:
        return remote.model
    return getattr(field_or_rel, 'related_model', None)


def same_concrete_model(left, right):
    if left is None or right is None:
        return False
    left_meta = getattr(left, '_meta', None)
    right_meta = getattr(right, '_meta', None)
    if left_meta is None or right_meta is None:
        return left is right
    return left_meta.concrete_model is right_meta.concrete_model


def group_user_set_related_model(group_model):
    """Related model of ``group.user_set``, or ``None`` if that accessor is absent.

    Reverse M2M descriptors expose the forward field on the entity; using
    ``field.related_model`` would return the group model itself.
    """
    try:
        descriptor = getattr(group_model, 'user_set')
    except AttributeError:
        return None
    reverse = getattr(descriptor, 'reverse', False)
    field = getattr(descriptor, 'field', None)
    if field is not None:
        if reverse:
            return getattr(field, 'model', None)
        return related_model_of(field)
    rel = getattr(descriptor, 'rel', None)
    if rel is not None:
        return getattr(rel, 'related_model', None) or getattr(rel, 'model', None)
    return None


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
