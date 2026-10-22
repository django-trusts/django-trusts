"""Path and model identity from Django ``_meta``. No registry and no ``Q``."""

from django.core.exceptions import AppRegistryNotReady
from django.db.models import Model
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet

from trusts.errors import TrustsConfigurationError

__all__ = [
    'lookup_text',
    'path_text',
    'concrete_model',
    'content_model',
    'require_instance',
    'resolved_hop',
]


def lookup_text(path):
    return '__'.join(path)


def path_text(path):
    return '.'.join(path)


def concrete_model(value):
    opts = getattr(value, '_meta', None)
    if opts is None:
        raise TrustsConfigurationError(
            'Expected a model class or instance, not %r.' % (value,)
        )
    return opts.concrete_model


def content_model(content):
    if isinstance(content, QuerySet):
        return content.model._meta.concrete_model
    if isinstance(content, ModelBase):
        return content._meta.concrete_model
    if isinstance(content, Model):
        return content._meta.concrete_model
    raise TrustsConfigurationError(
        'content must be a model class, instance, or QuerySet, not %r.'
        % (content,)
    )


def require_instance(value, role):
    if not isinstance(value, Model):
        raise TrustsConfigurationError(
            '%s must be a model instance, not %r.' % (role, value)
        )
    return value


def relation_target(field):
    """Model a relation points at, before ``apps.models_ready``.

    ``Field.related_model`` calls ``apps.check_models_ready()``.
    Registration from ``models.py`` runs while that flag is still false.
    ``remote_field.model`` is the resolved class once the target is
    registered.
    """
    remote = getattr(field, 'remote_field', None)
    if remote is not None:
        model = getattr(remote, 'model', None)
        if model is not None:
            return model
    try:
        return getattr(field, 'related_model', None)
    except AppRegistryNotReady:
        return None


def resolved_hop(field, role, path):
    """Resolve one hop from Django path information.

    Requires exactly one ``PathInfo`` and exactly one target field.
    Terminal model and outer comparison field come from that metadata.
    """
    getter = getattr(field, 'get_path_info', None)
    if not callable(getter):
        raise TrustsConfigurationError(
            '%s path %r has no resolvable path information.'
            % (role, path_text(path))
        )
    infos = getter()
    if infos is None:
        infos = ()
    infos = tuple(infos)
    if len(infos) != 1:
        raise TrustsConfigurationError(
            '%s path %r does not resolve to exactly one relation hop; '
            'composite and multi-join relations are not supported.'
            % (role, path_text(path))
        )
    info = infos[0]
    target_fields = getattr(info, 'target_fields', None) or ()
    if len(target_fields) != 1:
        raise TrustsConfigurationError(
            '%s path %r exposes %s target fields; composite and '
            'multi-column correlation are not supported.'
            % (role, path_text(path), len(target_fields))
        )
    to_opts = getattr(info, 'to_opts', None)
    related = None
    if to_opts is not None:
        related = getattr(to_opts, 'concrete_model', None) or getattr(
            to_opts, 'model', None
        )
    if not isinstance(related, ModelBase):
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, path_text(path))
        )
    target = target_fields[0]
    attname = getattr(target, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, path_text(path))
        )
    return related._meta.concrete_model, attname
