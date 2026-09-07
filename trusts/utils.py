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
