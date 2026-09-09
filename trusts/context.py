"""Registry-driven Context resolution contract.

The reusable question:

    Starting from this resource model, what validated relational path
    resolves its authorization scope?

Two registration forms:

* **Direct** — the resource owns a single-valued relationship to its
  policy scope (``register_direct(model, scope_field=...)``).
* **Related** — the resource reaches an already registered resource
  through a validated, single-valued relational path and therefore
  resolves the same scope (``register_related(model, through=...)``).

Registration is static during application loading and frozen before
authorization queries. Validation uses Django ``_meta`` only: no
getters, descriptors, properties, or callbacks are executed.

This module is the reusable layer. It must not name a concrete
authorization product's resource, scope, or compatibility-wrapper
classes.
"""

from django.apps import apps
from django.core.exceptions import AppRegistryNotReady, FieldDoesNotExist
from django.db.models import Q, UniqueConstraint
from django.db.models.constants import LOOKUP_SEP


KIND_DIRECT = 'direct'
KIND_RELATED = 'related'


class ContextRegistrationError(ValueError):
    """A Context path is missing, cyclic, ambiguous, scalar, many-valued,
    or terminates at a model that is not already registered.
    """


class ContextRegistryFrozen(ValueError):
    """Registration after freeze is rejected so query resolution stays static."""


class ContextNotRegistered(ValueError):
    """Lookup of a model that has no Context adapter."""


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _model_key(model):
    return model._meta.concrete_model


def _related_ref(field):
    """Related model or string label without forcing ``apps.models_ready``.

    ``field.related_model`` calls ``check_models_ready()`` and cannot be
    used during ``class_prepared`` / class-body registration.
    """
    remote = getattr(field, 'remote_field', None)
    if remote is None:
        return None
    return getattr(remote, 'model', None)


def _resolve_related_model(field):
    related = _related_ref(field)
    if related is None:
        raise ContextRegistrationError(
            'Relation %r has no related model (ambiguous or generic).' % (field,)
        )
    if isinstance(related, str):
        try:
            related = apps.get_model(related, require_ready=False)
        except (LookupError, AppRegistryNotReady) as exc:
            raise ContextRegistrationError(
                'Related model %r is not available: %s' % (related, exc)
            )
    return related


def _get_field(model, name, path):
    try:
        return model._meta.get_field(name)
    except FieldDoesNotExist:
        raise ContextRegistrationError(
            'Path %r: %r is not a field or relation on %s.' % (
                path, name, _model_label(model),
            )
        )


def _forward_field(field):
    if getattr(field, 'concrete', False):
        return field
    fwd = getattr(field, 'field', None)
    if fwd is not None:
        return fwd
    return getattr(field, 'remote_field', None)


def _usable_reverse_lookup(name):
    """True when ``name`` can appear in a composable ORM lookup.

    ``related_name='+'`` (and ``+suffix``) disables the reverse accessor.
    Names containing ``LOOKUP_SEP`` (``fields.E309``) or ending with ``_``
    (``fields.E308``) are ambiguous even if those checks are silenced.
    Those names are not invertible and must not become ``resource_path``.
    """
    if not isinstance(name, str) or not name:
        return False
    if name == '+' or name.startswith('+'):
        return False
    if name.endswith('_') or LOOKUP_SEP in name:
        return False
    if name[0].isdigit():
        return False
    return all(ch.isalnum() or ch == '_' for ch in name)


def _assert_forward_invertible(field, path, model):
    if not getattr(field, 'concrete', False):
        return
    reverse = field.related_query_name()
    if not _usable_reverse_lookup(reverse):
        raise ContextRegistrationError(
            'Path %r: %r on %s has no invertible reverse lookup (%r).' % (
                path, field.name, _model_label(model), reverse,
            )
        )


def _unconditional_single_field_unique(constraint, field_name):
    """True when ``constraint`` unconditionally unique-indexes ``field_name``.

    A ``condition=`` (partial unique) is not single-valued: excluded
    rows may still share the same parent. Other options such as
    ``deferrable`` / ``include`` / ``opclasses`` do not add extra rows.
    """
    if not isinstance(constraint, UniqueConstraint):
        return False
    fields = getattr(constraint, 'fields', None)
    if fields is None or tuple(fields) != (field_name,):
        return False
    if getattr(constraint, 'condition', None) is not None:
        return False
    return True


def _reverse_is_unique(field):
    """True when a reverse relation is constrained to one row.

    ``ForeignKey(unique=True)`` and a single-field ``unique_together`` /
    unconditional ``UniqueConstraint`` are single-valued even when
    Django still exposes the reverse as ``one_to_many``.
    """
    fwd = _forward_field(field)
    if fwd is None:
        return False
    if getattr(fwd, 'unique', False):
        return True
    concrete = getattr(fwd, 'model', None)
    name = getattr(fwd, 'name', None)
    if concrete is None or not name:
        return False
    for unique in concrete._meta.unique_together:
        if tuple(unique) == (name,):
            return True
    for constraint in getattr(concrete._meta, 'constraints', ()):
        if _unconditional_single_field_unique(constraint, name):
            return True
    return False


def _is_single_valued_relation(field):
    if getattr(field, 'is_relation', False) is not True:
        return False
    if _related_ref(field) is None:
        return False
    if getattr(field, 'many_to_many', False):
        return False
    if getattr(field, 'one_to_one', False) or getattr(field, 'many_to_one', False):
        return True
    if getattr(field, 'one_to_many', False):
        return _reverse_is_unique(field)
    return False


def _assert_single_valued_relation(field, path, model, hop):
    if getattr(field, 'is_relation', False) is not True:
        raise ContextRegistrationError(
            'Path %r: %r on %s is a scalar field, not a relation.' % (
                path, hop, _model_label(model),
            )
        )
    if _related_ref(field) is None:
        raise ContextRegistrationError(
            'Path %r: %r on %s is ambiguous (no related model).' % (
                path, hop, _model_label(model),
            )
        )
    if _is_single_valued_relation(field):
        return
    if getattr(field, 'many_to_many', False) or getattr(field, 'one_to_many', False):
        raise ContextRegistrationError(
            'Path %r: %r on %s is many-valued. Many-valued hops require '
            'an explicit all/any policy and are not part of this contract.' % (
                path, hop, _model_label(model),
            )
        )
    raise ContextRegistrationError(
        'Path %r: %r on %s is not a single-valued relation.' % (
            path, hop, _model_label(model),
        )
    )


def _split_path(path, api_name):
    if not isinstance(path, str) or not path:
        raise ContextRegistrationError(
            '%s must be a non-empty string, not %r.' % (api_name, path)
        )
    parts = path.split('__')
    if any(part == '' or part == 'None' for part in parts):
        raise ContextRegistrationError(
            '%s %r is not a composable relational path.' % (api_name, path)
        )
    return parts


def _invert_hop(model, name, path):
    """Return ``(related_model, reverse_lookup_name)`` for one hop on ``model``."""
    field = _get_field(model, name, path)
    _assert_single_valued_relation(field, path, model, name)
    _assert_forward_invertible(field, path, model)
    target = _resolve_related_model(field)
    if field.concrete:
        reverse = field.related_query_name()
        if not _usable_reverse_lookup(reverse):
            raise ContextRegistrationError(
                'Path %r: %r on %s has no invertible reverse lookup (%r).' % (
                    path, name, _model_label(model), reverse,
                )
            )
        return target, reverse
    remote = field.remote_field
    reverse = getattr(remote, 'name', None)
    if not reverse and hasattr(field, 'field') and field.field is not None:
        reverse = field.field.name
    if not reverse:
        raise ContextRegistrationError(
            'Path %r: cannot invert reverse relation %r on %s.' % (
                path, name, _model_label(model),
            )
        )
    return target, reverse


def _walk(model, path, seen=None):
    """Walk a resource-origin path. Return ``(terminal, hops)``.

    ``hops`` is a list of ``(from_model, name, to_model)``.
    """
    parts = _split_path(path, 'path')
    seen = list(seen or ())
    seen.append(_model_key(model))
    hops = []
    current = model
    for name in parts:
        field = _get_field(current, name, path)
        _assert_single_valued_relation(field, path, current, name)
        _assert_forward_invertible(field, path, current)
        target = _resolve_related_model(field)
        key = _model_key(target)
        if key in seen:
            raise ContextRegistrationError(
                'Path %r is cyclic: %s is visited twice.' % (
                    path, _model_label(target),
                )
            )
        hops.append((current, name, target))
        seen.append(key)
        current = target
    return current, hops


class ContextAdapter(object):
    """Immutable record of one registered resource → scope resolution."""

    __slots__ = ('kind', 'model', 'decl', 'registry')

    def __init__(self, kind, model, decl, registry):
        self.kind = kind
        self.model = model
        self.decl = decl
        self.registry = registry

    def __repr__(self):
        return 'ContextAdapter(%s, %s, %r)' % (
            self.kind, _model_label(self.model), self.decl,
        )

    @property
    def label(self):
        return self.model._meta.label

    def scope_model(self):
        """Terminal policy-scope model this adapter resolves to."""
        if self.kind == KIND_DIRECT:
            field = _get_field(self.model, self.decl, self.decl)
            return _resolve_related_model(field)
        terminal = self.terminal_model()
        return self.registry.get(terminal).scope_model()

    def terminal_model(self):
        """Direct: the resource itself. Related: the registered parent."""
        if self.kind == KIND_DIRECT:
            return self.model
        terminal, _hops = _walk(self.model, self.decl)
        return terminal

    def scope_path(self):
        """Resource → scope ORM lookup shared by exists and list filters."""
        if self.kind == KIND_DIRECT:
            return self.decl
        parent = self.registry.get(self.terminal_model())
        return '%s__%s' % (self.decl, parent.scope_path())

    def resource_path(self):
        """Scope → resource ORM lookup (the inverse of ``scope_path``)."""
        if self.kind == KIND_DIRECT:
            _target, reverse = _invert_hop(self.model, self.decl, self.decl)
            return reverse
        parent = self.registry.get(self.terminal_model())
        inverted = []
        current = self.model
        for name in self.decl.split('__'):
            current, reverse = _invert_hop(current, name, self.decl)
            inverted.append(reverse)
        inverted.reverse()
        return '%s__%s' % (parent.resource_path(), '__'.join(inverted))

    def equivalent(self, other):
        return (
            self.kind == other.kind
            and _model_key(self.model) is _model_key(other.model)
            and self.decl == other.decl
        )


class ContextRegistry(object):
    """Mutable adapter map that freezes before authorization queries."""

    def __init__(self):
        self._adapters = {}
        self._frozen = False
        self._finalizers = []
        self._finalized = False
        self._finalizing = False

    def is_frozen(self):
        return self._frozen

    def add_finalizer(self, func):
        """Register work that must finish before this registry freezes.

        Query paths call ``ensure_frozen()``, which runs every finalizer
        once and then freezes. Integration layers register pending
        synchronization here so this module stays product-agnostic.
        After a successful finalization, finalizers do not run again.
        After freeze, new finalizers are rejected.
        """
        if self._frozen or self._finalized:
            raise ContextRegistryFrozen(
                'Context registry is frozen; cannot add a finalizer.'
            )
        if func not in self._finalizers:
            self._finalizers.append(func)

    def freeze(self):
        """Run registered finalizers once, then make the adapter map static.

        A finalizer failure restores the adapter snapshot and leaves the
        registry unfrozen so a partial map is never accepted.
        """
        if self._frozen:
            return
        if self._finalizing:
            return
        self._finalizing = True
        try:
            if not self._finalized:
                snapshot = dict(self._adapters)
                try:
                    for func in list(self._finalizers):
                        func()
                except Exception:
                    self._adapters.clear()
                    self._adapters.update(snapshot)
                    raise
                self._finalizers = []
                self._finalized = True
            self._frozen = True
        finally:
            self._finalizing = False

    def ensure_frozen(self):
        self.freeze()

    def adapters(self):
        """Complete installed set, ordered by model label."""
        return tuple(
            self._adapters[key]
            for key in sorted(self._adapters, key=lambda k: k._meta.label)
        )

    def is_registered(self, model):
        if not isinstance(model, type):
            model = model.__class__
        try:
            return _model_key(model) in self._adapters
        except AttributeError:
            return False

    def get(self, model):
        if not isinstance(model, type):
            model = model.__class__
        key = _model_key(model)
        try:
            return self._adapters[key]
        except KeyError:
            raise ContextNotRegistered(
                '%s is not a registered Context resource.' % _model_label(model)
            )

    def get_or_none(self, model):
        if not self.is_registered(model):
            return None
        return self.get(model)

    def scope_path(self, model):
        return self.get(model).scope_path()

    def resource_path(self, model):
        return self.get(model).resource_path()

    def scope_q(self, model, scope):
        """``Q`` matching rows whose registered path resolves to ``scope``.

        Instance and queryset/list ``scope`` values use the same lookup.
        """
        path = self.scope_path(model)
        if hasattr(scope, 'pk') and not hasattr(scope, 'model'):
            return Q(**{path: scope})
        return Q(**{'%s__in' % path: scope})

    def filter_by_scope(self, queryset, scope):
        """SQL-filter ``queryset`` with the registered resolution (one query)."""
        self.ensure_frozen()
        return queryset.filter(self.scope_q(queryset.model, scope))

    def resolves_to_scope(self, obj, scope):
        """One-query exists check using the same lookup as ``filter_by_scope``."""
        self.ensure_frozen()
        model = obj.__class__
        return model.objects.filter(pk=obj.pk).filter(self.scope_q(model, scope)).exists()

    def register_direct(self, model, scope_field):
        """Register a resource that owns a single-valued scope relation."""
        parts = _split_path(scope_field, 'scope_field')
        if len(parts) != 1:
            raise ContextRegistrationError(
                'scope_field must be a single hop, not %r.' % (scope_field,)
            )
        field = _get_field(model, scope_field, scope_field)
        _assert_single_valued_relation(field, scope_field, model, scope_field)
        _assert_forward_invertible(field, scope_field, model)
        _resolve_related_model(field)
        adapter = ContextAdapter(KIND_DIRECT, model, scope_field, self)
        return self._commit(adapter)

    def register_related(self, model, through):
        """Register a resource that reaches an already registered resource."""
        terminal, _hops = _walk(model, through)
        if not self.is_registered(terminal):
            raise ContextRegistrationError(
                'Related path %r on %s terminates at %s, which is not '
                'an already registered Context resource.' % (
                    through, _model_label(model), _model_label(terminal),
                )
            )
        adapter = ContextAdapter(KIND_RELATED, model, through, self)
        return self._commit(adapter)

    def _commit(self, adapter):
        key = _model_key(adapter.model)
        existing = self._adapters.get(key)
        if existing is not None:
            if existing.equivalent(adapter):
                return existing
            raise ContextRegistrationError(
                '%s is already registered as %s %r; cannot register as %s %r.' % (
                    _model_label(adapter.model),
                    existing.kind, existing.decl,
                    adapter.kind, adapter.decl,
                )
            )
        if self._frozen:
            raise ContextRegistryFrozen(
                'Context registry is frozen; cannot register %s.' % (
                    _model_label(adapter.model),
                )
            )
        self._adapters[key] = adapter
        return adapter

    def revalidate(self, adapter):
        """Re-walk a stored adapter. Raise ``ContextRegistrationError`` if stale."""
        if adapter.kind == KIND_DIRECT:
            parts = _split_path(adapter.decl, 'scope_field')
            if len(parts) != 1:
                raise ContextRegistrationError(
                    'scope_field must be a single hop, not %r.' % (adapter.decl,)
                )
            field = _get_field(adapter.model, adapter.decl, adapter.decl)
            _assert_single_valued_relation(
                field, adapter.decl, adapter.model, adapter.decl,
            )
            _assert_forward_invertible(field, adapter.decl, adapter.model)
            _resolve_related_model(field)
            adapter.scope_path()
            adapter.resource_path()
            return
        terminal, _hops = _walk(adapter.model, adapter.decl)
        if not self.is_registered(terminal):
            raise ContextRegistrationError(
                'Related path %r on %s terminates at %s, which is not '
                'an already registered Context resource.' % (
                    adapter.decl, _model_label(adapter.model),
                    _model_label(terminal),
                )
            )
        adapter.scope_path()
        adapter.resource_path()


def check_registration(model, kind, path, registry=None):
    """Validate a proposed registration without committing it.

    Returns ``None`` when valid. Returns a ``ContextRegistrationError``
    instance when invalid. Does not execute getters or properties.
    """
    registry = registry if registry is not None else ContextRegistry()
    try:
        if kind == KIND_DIRECT:
            parts = _split_path(path, 'scope_field')
            if len(parts) != 1:
                raise ContextRegistrationError(
                    'scope_field must be a single hop, not %r.' % (path,)
                )
            field = _get_field(model, path, path)
            _assert_single_valued_relation(field, path, model, path)
            _assert_forward_invertible(field, path, model)
            _resolve_related_model(field)
        elif kind == KIND_RELATED:
            terminal, _hops = _walk(model, path)
            source = registry if registry.is_registered(terminal) else Context.registry
            if not source.is_registered(terminal):
                raise ContextRegistrationError(
                    'Related path %r on %s terminates at %s, which is not '
                    'an already registered Context resource.' % (
                        path, _model_label(model), _model_label(terminal),
                    )
                )
        else:
            raise ContextRegistrationError('Unknown Context kind %r.' % (kind,))
    except ContextRegistrationError as exc:
        return exc
    return None


class Context(object):
    """Process-wide Context registry. Public API is classmethods.

    Tests that need an isolated map construct ``ContextRegistry()``
    directly. Authorization queries use this default instance.
    """

    registry = ContextRegistry()

    KIND_DIRECT = KIND_DIRECT
    KIND_RELATED = KIND_RELATED

    @classmethod
    def register_direct(cls, model, scope_field):
        return cls.registry.register_direct(model, scope_field)

    @classmethod
    def register_related(cls, model, through):
        return cls.registry.register_related(model, through)

    @classmethod
    def add_finalizer(cls, func):
        return cls.registry.add_finalizer(func)

    @classmethod
    def freeze(cls):
        cls.registry.freeze()

    @classmethod
    def ensure_frozen(cls):
        cls.registry.ensure_frozen()

    @classmethod
    def is_frozen(cls):
        return cls.registry.is_frozen()

    @classmethod
    def adapters(cls):
        return cls.registry.adapters()

    @classmethod
    def is_registered(cls, model):
        return cls.registry.is_registered(model)

    @classmethod
    def get(cls, model):
        return cls.registry.get(model)

    @classmethod
    def get_or_none(cls, model):
        return cls.registry.get_or_none(model)

    @classmethod
    def scope_path(cls, model):
        return cls.registry.scope_path(model)

    @classmethod
    def resource_path(cls, model):
        return cls.registry.resource_path(model)

    @classmethod
    def scope_q(cls, model, scope):
        return cls.registry.scope_q(model, scope)

    @classmethod
    def filter_by_scope(cls, queryset, scope):
        return cls.registry.filter_by_scope(queryset, scope)

    @classmethod
    def resolves_to_scope(cls, obj, scope):
        return cls.registry.resolves_to_scope(obj, scope)


__all__ = [
    'KIND_DIRECT',
    'KIND_RELATED',
    'Context',
    'ContextAdapter',
    'ContextNotRegistered',
    'ContextRegistrationError',
    'ContextRegistry',
    'ContextRegistryFrozen',
    'check_registration',
]
