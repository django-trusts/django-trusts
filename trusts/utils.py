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
    applabel, action_modelname_permcode = perm.split('.', 1)
    action, modelname_permcode = action_modelname_permcode.rsplit('_', 1)
    modelname, sep, cond = modelname_permcode.partition(':')

    return applabel, modelname, action, cond
