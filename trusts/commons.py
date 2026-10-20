"""Record binding, the predicate visitor, and shared path helpers.

The path helpers below are pure Django ``_meta`` math (models, strings,
and values only; no registry or plan/compile types), shared by compile
and plan. Walk execution lives in ``trusts.plan.walk``. This module does
not import ``plan`` or ``compile``.
"""

__all__ = []

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models import F, Model, Q
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet

from trusts.errors import TrustsConfigurationError


def _is_lookup_expression(value):
    """True for OuterRef / Subquery / other SQL expressions."""
    return hasattr(value, 'resolve_expression') and not isinstance(value, Model)


def _bind_terminal(value, role):
    """Accept a model instance or an unevaluated lookup expression."""
    if _is_lookup_expression(value):
        return value
    return _require_instance(value, role)


def _lookup_text(path):
    return '__'.join(path)


def _auth_group_and_permission():
    """Django ``auth.Group`` and ``auth.Permission``. Metadata only."""
    from django.contrib.auth.models import Group, Permission
    return Group, Permission


class _PredicateCompiler(object):
    """Compile one stored predicate node. The node dispatches; Q stays here."""

    def __init__(self, record, permission):
        self.record = record
        self.permission = permission

    def compile(self, node):
        if node is None:
            return None
        accept = getattr(type(node), 'accept', None)
        if accept is None:
            raise TrustsConfigurationError(
                'condition is not supported; omit it or pass None.'
            )
        return accept(node, self)

    def visit_all(self, node):
        parts = [
            self.compile(predicate) for predicate in node.predicates
        ]
        parts = [part for part in parts if part is not None]
        if not parts:
            return None
        compiled = parts[0]
        for part in parts[1:]:
            compiled &= part
        return compiled

    def visit_equal(self, node):
        return Q(**{
            _lookup_text(node.left._path): F(_lookup_text(node.right._path)),
        })

    def visit_permission_in(self, node):
        compiled = Q()
        for ref in node.refs:
            compiled &= Q(**{
                _lookup_text(ref._path): F(self.record.permission_field),
            })
        return compiled

    def visit_inquiry_permission_match(self, node):
        if self.permission is None:
            raise TrustsConfigurationError(
                'Delegated inquiry-permission condition needs the requested '
                'permission binding.'
            )
        require = getattr(type(node.ref), 'require_same_root', None)
        if require is None:
            raise TrustsConfigurationError(
                '%s must be a root-relative Ref, not %r.'
                % ('delegated inquiry permission', node.ref)
            )
        ref = require(
            node.ref, self.record.root, 'delegated inquiry permission',
        )
        return Q(**{
            _lookup_text(ref._path): _bind_terminal(
                self.permission, 'permission',
            ),
        })


def _compile_predicate(node, record, *, permission=None):
    return _PredicateCompiler(record, permission).compile(node)


def _permission_terminal_is_auth_permission(permission_model):
    """True when the terminal's concrete model is ``auth.Permission``.

    Typed content identity applies only to that model, on a direct
    foreign key or a terminal many-to-many. Any other terminal,
    including one that happens to have a ``content_type`` foreign key,
    stays primary-key identity. Metadata only (zero SQL). This is an
    exact model-identity check, not a field-name scan and not a
    codename parse.
    """
    _group, permission = _auth_group_and_permission()
    return (
        permission_model._meta.concrete_model
        is permission._meta.concrete_model
    )


def _content_type_identity(model):
    """``(app_label, model_name)`` for ``for_concrete_model=False``.

    ``ContentType.get_for_model(model, for_concrete_model=False)`` uses
    the model's own ``app_label`` and ``model_name``. A real proxy keeps
    its own pair. No content-type row is loaded.
    """
    return model._meta.app_label.lower(), model._meta.model_name


def _permission_content_type_filters(record, content_identity):
    """Lookup kwargs that pin the permission row to one content type.

    The lookups extend ``permission_field`` so they share that join.
    A second many-to-many alias would let one group row satisfy the
    permission id and a different row satisfy the content type.
    """
    if not _permission_terminal_is_auth_permission(record.permission_model):
        return {}
    model = content_identity if content_identity is not None else record.content_model
    app_label, model_name = _content_type_identity(model)
    field = record.permission_field
    return {
        '%s__content_type__app_label' % field: app_label,
        '%s__content_type__model' % field: model_name,
    }


def _record_predicate(record, correlation=None, *, content_identity=None,
                      **bindings):
    """Bindings, condition, and correlation as one ``Q``.

    Separate ``filter()`` calls give a repeated many-to-many hop its own
    alias. ``Group.permissions`` has to stay one join so the local
    ceiling and the requested permission are the same row. Content-type
    identity is part of that same ``Q`` for the same reason.
    """
    filters = {}
    for role, value in bindings.items():
        filters[getattr(record, _BINDING_FIELDS[role])] = _bind_terminal(
            value, role,
        )
    filters.update(_permission_content_type_filters(record, content_identity))
    combined = Q(**filters)
    compiled = _compile_predicate(record.condition, record)
    if compiled is not None:
        combined &= compiled
    if correlation is not None:
        combined &= correlation
    return combined


def _bind_record_qs(record, correlation=None, *, content_identity=None, **bindings):
    """Root rows for one record. One ``filter()`` for every predicate."""
    return record.root._default_manager.filter(
        _record_predicate(
            record,
            correlation=correlation,
            content_identity=content_identity,
            **bindings,
        ),
    )


_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}


def _concrete_model(value):
    opts = getattr(value, '_meta', None)
    if opts is None:
        raise TrustsConfigurationError(
            'Expected a model class or instance, not %r.' % (value,)
        )
    return opts.concrete_model


def _content_model(content):
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


def _require_instance(value, role):
    if not isinstance(value, Model):
        raise TrustsConfigurationError(
            '%s must be a model instance, not %r.' % (role, value)
        )
    return value


def _path_text(path):
    return '.'.join(path)


def _materialize_related_model(field):
    """Resolve a still-string ``remote_field.model`` through the app registry.

    Isolated ``ForeignKey(settings.AUTH_USER_MODEL)`` fields keep a string
    until Django's lazy related-class hook runs. Path information needs the
    model class. ``apps.get_model`` is metadata only (zero SQL).
    """
    remote = getattr(field, 'remote_field', None)
    if remote is None:
        return
    model = getattr(remote, 'model', None)
    if isinstance(model, ModelBase):
        return
    related = getattr(field, 'related_model', None)
    if isinstance(related, str) or related is None:
        label = related if isinstance(related, str) else model
        if isinstance(label, str):
            try:
                related = django_apps.get_model(label)
            except (LookupError, ValueError):
                return
    if isinstance(related, ModelBase):
        try:
            remote.model = related
        except (AttributeError, TypeError):
            return


def _resolved_hop(field, role, path):
    """Resolve one hop from Django path information.

    Requires exactly one ``PathInfo`` and exactly one target field.
    Terminal model and outer comparison field come from that metadata.
    """
    _materialize_related_model(field)
    getter = getattr(field, 'get_path_info', None)
    if not callable(getter):
        raise TrustsConfigurationError(
            '%s path %r has no resolvable path information.'
            % (role, _path_text(path))
        )
    infos = getter()
    if infos is None:
        infos = ()
    infos = tuple(infos)
    if len(infos) != 1:
        raise TrustsConfigurationError(
            '%s path %r does not resolve to exactly one relation hop; '
            'composite and multi-join relations are not supported.'
            % (role, _path_text(path))
        )
    info = infos[0]
    target_fields = getattr(info, 'target_fields', None) or ()
    if len(target_fields) != 1:
        raise TrustsConfigurationError(
            '%s path %r exposes %s target fields; composite and '
            'multi-column correlation are not supported.'
            % (role, _path_text(path), len(target_fields))
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
            % (role, _path_text(path))
        )
    target = target_fields[0]
    attname = getattr(target, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
        )
    return related._meta.concrete_model, attname


def _root_relative_column(model, path):
    """Concrete column lookup for a forward single-valued path.

    ``sponsor`` becomes ``sponsor_id``. ``sponsor_link__user`` becomes
    ``sponsor_link__user_id``. Every prefix stays on the path, so ``F()``
    cannot bind a bare ``user_id`` on the delegation root. The last
    component is that field's attname: the column that stores the
    comparison identity, including a non-PK ``to_field``. The path was
    already resolved at registration.
    """
    parts = str(path).split('__')
    current = model
    prefix = []
    field = None
    for index, name in enumerate(parts):
        field = current._meta.get_field(name)
        if index == len(parts) - 1:
            break
        prefix.append(name)
        current = field.related_model
    return '__'.join(prefix + [field.attname])


def _scope_prefix_lookups(record, scope_model):
    """Root-relative lookups to proper prefix nodes matching ``scope_model``.

    A proper prefix is a hop on ``content_path`` whose related model is
    ``scope_model`` and that is not the content terminal. Each item is
    ``(root-relative lookup, target attname)``. The attname is the
    hop's resolved identity (``to_field`` when set), not assumed to
    be ``pk``. Uses stored path names and ``_meta`` only (zero SQL).
    """
    path = record.content_path
    if not path:
        return ()
    current = record.root
    lookups = []
    last = len(path) - 1
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            return ()
        related, target_attname = _resolved_hop(field, 'content', path)
        if related._meta.concrete_model is scope_model and index != last:
            lookups.append((_lookup_text(path[:index + 1]), target_attname))
        current = related
    return tuple(lookups)


def _object_memory_value(instance, path):
    """Field value already present on ``instance``. Does not query."""
    if not path:
        return instance
    current = instance
    model = instance.__class__
    for index, name in enumerate(path):
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise TrustsConfigurationError(
                'Permission condition field %r is not on %s.'
                % (name, model._meta.label)
            ) from exc
        last = index == len(path) - 1
        if field.many_to_many or field.one_to_many:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot compile multi-valued '
                'condition field %s.%s.' % (model._meta.label, name)
            )
        if not last and getattr(field, 'is_relation', False):
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot traverse %s.%s without '
                'a construction query.' % (model._meta.label, name)
            )
        attname = field.attname
        if attname not in current.__dict__:
            raise TrustsConfigurationError(
                'Reverse permission inquiry needs %s.%s loaded on the '
                'content instance to compile a named filter without SQL.'
                % (model._meta.label, attname)
            )
        current = current.__dict__[attname]
        if not last:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot traverse %s.%s.'
                % (model._meta.label, name)
            )
    return current


def _user_lookup(user_model, path):
    if not path:
        return 'pk'
    current = user_model
    for name in path:
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise TrustsConfigurationError(
                'Permission condition field %r is not on %s.'
                % (name, current._meta.label)
            ) from exc
        if field.many_to_many or field.one_to_many:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot compile multi-valued '
                'principal field %s.%s.' % (current._meta.label, name)
            )
        if getattr(field, 'is_relation', False) and field.related_model is not None:
            current = field.related_model
    return '__'.join(path)
