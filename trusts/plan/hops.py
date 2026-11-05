"""Path and model identity from Django ``_meta``. No registry and no ``Q``."""

from django.db.models import Model
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet

from trusts.errors import TrustsConfigurationError

__all__ = [
    'lookup_text',
    'path_text',
    'concrete_model',
    'content_model',
    'content_scope_lookup',
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


def content_scope_lookup(root, path, prefix, target_attname):
    """Lookup on the content model equal to this prefix row.

    ``prefix`` is the content-path hop names up to the scope row.
    The lookup walks back from the protected object. A forward hop
    uses the reverse accessor. A reverse hop uses the foreign key
    that points at the scope row.
    """
    path = tuple(path)
    prefix = tuple(prefix)
    suffix = path[len(prefix):]
    current = root
    for name in prefix:
        field = current._meta.get_field(name)
        current, _attname = resolved_hop(field, 'content', path)
    steps = []
    for name in suffix:
        field = current._meta.get_field(name)
        if getattr(field, 'many_to_many', False):
            raise TrustsConfigurationError(
                'filter_by_permitted_content cannot apply a content '
                'filter through many-to-many hop %r.' % name
            )
        steps.append(field)
        current, _attname = resolved_hop(field, 'content', path)
    parts = []
    for index, field in enumerate(reversed(steps)):
        last = index == len(steps) - 1
        reverse = (
            getattr(field, 'auto_created', False)
            and not getattr(field, 'concrete', False)
        )
        if reverse:
            stored = field.field
            parts.append(stored.attname if last else stored.name)
            continue
        if not getattr(field, 'concrete', False) or not field.is_relation:
            raise TrustsConfigurationError(
                'filter_by_permitted_content cannot apply a content '
                'filter through %r.' % lookup_text(prefix)
            )
        accessor = field.remote_field.get_accessor_name()
        if last:
            parts.append('%s__%s' % (accessor, target_attname))
        else:
            parts.append(accessor)
    return '__'.join(parts)
