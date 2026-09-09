"""Registry-driven Trustee resolution contract.

The reusable question:

    By what validated relational path does a requester reach a trustee,
    and by what concrete relation does that trustee participate in a
    scoped authorization decision?

Adapters are declared explicitly. Mixin inheritance is declaration
convenience only; automatic subclass discovery is not a query-building
source.

Registration is static during application loading and frozen before
authorization queries. Validation uses Django ``_meta`` only: no
getters, descriptors, properties, or callbacks are executed.

This module is the reusable layer. It must not name a concrete
authorization product's principal, collective, bundle, scope, or grant
tables.
"""

from django.apps import apps
from django.core.exceptions import AppRegistryNotReady, FieldDoesNotExist
from django.db import models
from django.db.models import Exists, OuterRef, Q, UniqueConstraint
from django.db.models.constants import LOOKUP_SEP


KIND_GRANT = 'grant'


class TrusteeRegistrationError(ValueError):
    """A Trustee path is missing, incomplete, scalar, callable, ambiguous,
    many-valued where uniqueness is required, or terminates at the wrong
    requester or operation model.
    """


class TrusteeRegistryFrozen(ValueError):
    """Registration after freeze is rejected so query resolution stays static."""


class TrusteeNotRegistered(ValueError):
    """Lookup of an adapter name that is not installed."""


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
        raise TrusteeRegistrationError(
            'Relation %r has no related model (ambiguous or generic).' % (field,)
        )
    if isinstance(related, str):
        try:
            related = apps.get_model(related, require_ready=False)
        except (LookupError, AppRegistryNotReady) as exc:
            raise TrusteeRegistrationError(
                'Related model %r is not available: %s' % (related, exc)
            )
    return related


def _resolve_model(value, what):
    if value is None:
        raise TrusteeRegistrationError('%s is required.' % what)
    if isinstance(value, str):
        if not value or '.' not in value:
            raise TrusteeRegistrationError(
                '%s must be a model class or app_label.Model label, not %r.' % (
                    what, value,
                )
            )
        try:
            return apps.get_model(value, require_ready=False)
        except (LookupError, AppRegistryNotReady, ValueError) as exc:
            raise TrusteeRegistrationError(
                '%s %r is not available: %s' % (what, value, exc)
            )
    if isinstance(value, type) and hasattr(value, '_meta'):
        return value
    raise TrusteeRegistrationError(
        '%s must be a model class or app_label.Model label, not %r.' % (
            what, value,
        )
    )


def _get_field(model, name, path):
    try:
        return model._meta.get_field(name)
    except FieldDoesNotExist:
        raise TrusteeRegistrationError(
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


def _unconditional_single_field_unique(constraint, field_name):
    if not isinstance(constraint, UniqueConstraint):
        return False
    fields = getattr(constraint, 'fields', None)
    if fields is None or tuple(fields) != (field_name,):
        return False
    if getattr(constraint, 'condition', None) is not None:
        return False
    return True


def _reverse_is_unique(field):
    """True when a reverse relation is constrained to one row."""
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


def _assert_relation(field, path, model, hop):
    if getattr(field, 'is_relation', False) is not True:
        raise TrusteeRegistrationError(
            'Path %r: %r on %s is a scalar field, not a relation.' % (
                path, hop, _model_label(model),
            )
        )
    if _related_ref(field) is None:
        raise TrusteeRegistrationError(
            'Path %r: %r on %s is ambiguous (no related model).' % (
                path, hop, _model_label(model),
            )
        )


def _assert_single_valued_relation(field, path, model, hop):
    _assert_relation(field, path, model, hop)
    if _is_single_valued_relation(field):
        return
    if getattr(field, 'many_to_many', False) or getattr(field, 'one_to_many', False):
        raise TrusteeRegistrationError(
            'Path %r: %r on %s is many-valued. Many-valued hops are '
            'ambiguous for grant identity and are not part of this '
            'contract.' % (
                path, hop, _model_label(model),
            )
        )
    raise TrusteeRegistrationError(
        'Path %r: %r on %s is not a single-valued relation.' % (
            path, hop, _model_label(model),
        )
    )


def _split_path(path, api_name, allow_empty=False):
    if callable(path):
        raise TrusteeRegistrationError(
            '%s must be a relational path string, not a callable.' % api_name
        )
    if path is None:
        if allow_empty:
            return []
        raise TrusteeRegistrationError(
            '%s must be a non-empty string, not %r.' % (api_name, path)
        )
    if not isinstance(path, str):
        raise TrusteeRegistrationError(
            '%s must be a non-empty string, not %r.' % (api_name, path)
        )
    if path == '':
        if allow_empty:
            return []
        raise TrusteeRegistrationError(
            '%s must be a non-empty string, not %r.' % (api_name, path)
        )
    parts = path.split(LOOKUP_SEP)
    if any(part == '' or part == 'None' for part in parts):
        raise TrusteeRegistrationError(
            '%s %r is not a composable relational path.' % (api_name, path)
        )
    return parts


def _walk(model, path, api_name, single_valued, seen=None):
    """Walk ``path`` from ``model``. Return ``(terminal, hops)``.

    ``hops`` is a list of ``(from_model, name, to_model)``.
    """
    parts = _split_path(path, api_name)
    seen = list(seen or ())
    seen.append(_model_key(model))
    hops = []
    current = model
    for name in parts:
        field = _get_field(current, name, path)
        if single_valued:
            _assert_single_valued_relation(field, path, current, name)
        else:
            _assert_relation(field, path, current, name)
        target = _resolve_related_model(field)
        key = _model_key(target)
        if key in seen:
            raise TrusteeRegistrationError(
                'Path %r is cyclic: %s is visited twice.' % (
                    path, _model_label(target),
                )
            )
        hops.append((current, name, target))
        seen.append(key)
        current = target
    return current, hops


def _join_paths(*parts):
    chunks = [part for part in parts if part]
    return LOOKUP_SEP.join(chunks)


def _scope_id_ref(scope_from_row):
    """OuterRef target for the filtered row's scope primary key."""
    if not scope_from_row:
        return 'pk'
    parts = scope_from_row.split(LOOKUP_SEP)
    if len(parts) == 1:
        return '%s_id' % scope_from_row
    return '%s_id' % scope_from_row


def _scope_filter(scope_path, scopes):
    if scopes is None:
        return {}
    if hasattr(scopes, 'pk') and not hasattr(scopes, 'model'):
        return {scope_path: scopes}
    return {'%s__in' % scope_path: scopes}


class TrusteeMixin(models.Model):
    """Abstract declaration convenience. Adds no concrete fields.

    Inheriting this mixin does not register an adapter. The frozen
    registry—not automatic subclass discovery—is the complete
    query-building source.
    """

    class Meta:
        abstract = True


class TrusteeAdapter(object):
    """Immutable record of one registered requester → trustee → grant path."""

    __slots__ = (
        'kind', 'name', 'trustee_model', 'membership_path', 'grant_model',
        'trustee_path', 'scope_path', 'operation_path', 'constraint_paths',
        'registry',
    )

    def __init__(
        self, kind, name, trustee_model, membership_path, grant_model,
        trustee_path, scope_path, operation_path, constraint_paths, registry,
    ):
        self.kind = kind
        self.name = name
        self.trustee_model = trustee_model
        self.membership_path = membership_path
        self.grant_model = grant_model
        self.trustee_path = trustee_path
        self.scope_path = scope_path
        self.operation_path = operation_path
        self.constraint_paths = tuple(constraint_paths)
        self.registry = registry

    def __repr__(self):
        return 'TrusteeAdapter(%s, %r, %s)' % (
            self.kind, self.name, _model_label(self.trustee_model),
        )

    @property
    def label(self):
        return self.name

    def requester_from_grant_path(self):
        """Grant → requester ORM lookup (trustee hop plus membership)."""
        return _join_paths(self.trustee_path, self.membership_path)

    def scope_model(self):
        terminal, _hops = _walk(
            self.grant_model, self.scope_path, 'scope_path', True,
        )
        return terminal

    def operation_model(self):
        terminal, _hops = _walk(
            self.grant_model, self.operation_path, 'operation_path', True,
        )
        return terminal

    def requester_model(self):
        if not self.membership_path:
            return self.trustee_model
        terminal, _hops = _walk(
            self.trustee_model, self.membership_path, 'membership_path', False,
        )
        return terminal

    def equivalent(self, other):
        return (
            self.kind == other.kind
            and self.name == other.name
            and _model_key(self.trustee_model) is _model_key(other.trustee_model)
            and _model_key(self.grant_model) is _model_key(other.grant_model)
            and self.membership_path == other.membership_path
            and self.trustee_path == other.trustee_path
            and self.scope_path == other.scope_path
            and self.operation_path == other.operation_path
            and self.constraint_paths == other.constraint_paths
        )

    def _base_grant_qs(self, requester, operation, extra=None):
        filters = {
            self.requester_from_grant_path(): requester,
            self.operation_path: operation,
        }
        if extra:
            filters.update(extra)
        qs = self.grant_model._default_manager.filter(**filters)
        if self.constraint_paths:
            constraint = Q()
            for path in self.constraint_paths:
                constraint |= Q(**{path: operation})
            qs = qs.filter(constraint)
        return qs

    def exists_q(self, requester, operation, scope_from_row=''):
        """``Exists`` matching this adapter on the filtered row's scope."""
        extra = {
            '%s__pk' % self.scope_path: OuterRef(_scope_id_ref(scope_from_row)),
        }
        return Exists(self._base_grant_qs(requester, operation, extra=extra))

    def operation_exists_q(self, requester, scopes):
        """``Exists`` matching this adapter against an outer operation row."""
        extra = {self.operation_path: OuterRef('pk')}
        extra.update(_scope_filter(self.scope_path, scopes))
        qs = self.grant_model._default_manager.filter(
            **{self.requester_from_grant_path(): requester}
        ).filter(**extra)
        if self.constraint_paths:
            constraint = Q()
            for path in self.constraint_paths:
                constraint |= Q(**{path: OuterRef('pk')})
            qs = qs.filter(constraint)
        return Exists(qs)


class TrusteeRegistry(object):
    """Mutable adapter map that freezes before authorization queries."""

    def __init__(self, requester_model=None):
        self._adapters = {}
        self._requester_model = requester_model
        self._frozen = False
        self._finalizers = []
        self._finalized = False
        self._finalizing = False

    def is_frozen(self):
        return self._frozen

    def requester_model(self):
        if self._requester_model is None:
            raise TrusteeRegistrationError(
                'Requester model is not configured.'
            )
        return _resolve_model(self._requester_model, 'requester_model')

    def configure(self, requester_model):
        """Set the requester model membership paths must terminate at."""
        resolved = _resolve_model(requester_model, 'requester_model')
        if self._requester_model is not None:
            existing = _resolve_model(self._requester_model, 'requester_model')
            if _model_key(existing) is _model_key(resolved):
                return existing
            if self._frozen or self._finalized:
                raise TrusteeRegistryFrozen(
                    'Trustee registry is frozen; cannot reconfigure the requester.'
                )
            raise TrusteeRegistrationError(
                'Requester is already configured as %s; cannot configure %s.' % (
                    _model_label(existing), _model_label(resolved),
                )
            )
        if self._frozen or self._finalized:
            raise TrusteeRegistryFrozen(
                'Trustee registry is frozen; cannot configure the requester.'
            )
        self._requester_model = resolved
        return resolved

    def add_finalizer(self, func):
        """Register work that must finish before this registry freezes.

        Query paths call ``ensure_frozen()``, which runs every finalizer
        once and then freezes. Integration layers register pending
        synchronization here so this module stays product-agnostic.
        After a successful finalization, finalizers do not run again.
        After freeze, new finalizers are rejected.
        """
        if self._frozen or self._finalized:
            raise TrusteeRegistryFrozen(
                'Trustee registry is frozen; cannot add a finalizer.'
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
                requester_snapshot = self._requester_model
                try:
                    for func in list(self._finalizers):
                        func()
                except Exception:
                    self._adapters.clear()
                    self._adapters.update(snapshot)
                    self._requester_model = requester_snapshot
                    raise
                self._finalizers = []
                self._finalized = True
            self._frozen = True
        finally:
            self._finalizing = False

    def ensure_frozen(self):
        self.freeze()

    def adapters(self):
        """Complete installed set, ordered by adapter name."""
        return tuple(
            self._adapters[name]
            for name in sorted(self._adapters)
        )

    def is_registered(self, name):
        return name in self._adapters

    def get(self, name):
        try:
            return self._adapters[name]
        except KeyError:
            raise TrusteeNotRegistered(
                'Trustee adapter %r is not registered.' % (name,)
            )

    def get_or_none(self, name):
        return self._adapters.get(name)

    def register(
        self, name, trustee_model, grant_model, trustee_path, scope_path,
        operation_path, membership_path='', constraint_paths=(),
    ):
        """Register one grant adapter.

        ``membership_path`` is the trustee → requester relation. An empty
        path is identity: the trustee model is the configured requester.
        ``constraint_paths`` are grant-origin relations to the same
        operation model; they constrain a completed path and never create
        authorization. They are OR-composed with each other and AND-ed
        with the grant match.
        """
        adapter = self._build_adapter(
            KIND_GRANT, name, trustee_model, membership_path, grant_model,
            trustee_path, scope_path, operation_path, constraint_paths,
        )
        return self._commit(adapter)

    def _build_adapter(
        self, kind, name, trustee_model, membership_path, grant_model,
        trustee_path, scope_path, operation_path, constraint_paths,
    ):
        if callable(name):
            raise TrusteeRegistrationError(
                'name must be a non-empty string, not a callable.'
            )
        if not isinstance(name, str) or not name:
            raise TrusteeRegistrationError(
                'name must be a non-empty string, not %r.' % (name,)
            )
        trustee_model = _resolve_model(trustee_model, 'trustee_model')
        grant_model = _resolve_model(grant_model, 'grant_model')
        membership_path = '' if membership_path is None else membership_path
        _split_path(membership_path, 'membership_path', allow_empty=True)
        _split_path(trustee_path, 'trustee_path')
        _split_path(scope_path, 'scope_path')
        _split_path(operation_path, 'operation_path')
        if constraint_paths is None:
            constraint_paths = ()
        if callable(constraint_paths):
            raise TrusteeRegistrationError(
                'constraint_paths must be a sequence of relational paths, '
                'not a callable.'
            )
        constraint_paths = tuple(constraint_paths)
        for path in constraint_paths:
            _split_path(path, 'constraint_path')

        requester = self.requester_model()
        if membership_path:
            terminal, _hops = _walk(
                trustee_model, membership_path, 'membership_path', False,
            )
            if _model_key(terminal) is not _model_key(requester):
                raise TrusteeRegistrationError(
                    'Membership path %r on %s terminates at %s, which is '
                    'not the configured requester %s.' % (
                        membership_path, _model_label(trustee_model),
                        _model_label(terminal), _model_label(requester),
                    )
                )
        elif _model_key(trustee_model) is not _model_key(requester):
            raise TrusteeRegistrationError(
                'Identity membership requires trustee_model %s to be the '
                'configured requester %s.' % (
                    _model_label(trustee_model), _model_label(requester),
                )
            )

        _walk(grant_model, trustee_path, 'trustee_path', True)
        trustee_terminal, _hops = _walk(
            grant_model, trustee_path, 'trustee_path', True,
        )
        if _model_key(trustee_terminal) is not _model_key(trustee_model):
            raise TrusteeRegistrationError(
                'trustee_path %r on %s terminates at %s, which is not '
                'trustee_model %s.' % (
                    trustee_path, _model_label(grant_model),
                    _model_label(trustee_terminal), _model_label(trustee_model),
                )
            )
        _walk(grant_model, scope_path, 'scope_path', True)
        operation_terminal, _hops = _walk(
            grant_model, operation_path, 'operation_path', True,
        )
        for path in constraint_paths:
            constraint_terminal, _hops = _walk(
                grant_model, path, 'constraint_path', False,
            )
            if _model_key(constraint_terminal) is not _model_key(operation_terminal):
                raise TrusteeRegistrationError(
                    'constraint_path %r on %s terminates at %s, which is '
                    'not the operation model %s.' % (
                        path, _model_label(grant_model),
                        _model_label(constraint_terminal),
                        _model_label(operation_terminal),
                    )
                )

        return TrusteeAdapter(
            kind, name, trustee_model, membership_path, grant_model,
            trustee_path, scope_path, operation_path, constraint_paths, self,
        )

    def _commit(self, adapter):
        existing = self._adapters.get(adapter.name)
        if existing is not None:
            if existing.equivalent(adapter):
                return existing
            raise TrusteeRegistrationError(
                'Trustee adapter %r is already registered; cannot replace it.' % (
                    adapter.name,
                )
            )
        for other in self._adapters.values():
            if (
                _model_key(other.trustee_model) is _model_key(adapter.trustee_model)
                and _model_key(other.grant_model) is _model_key(adapter.grant_model)
                and other.membership_path == adapter.membership_path
                and other.trustee_path == adapter.trustee_path
                and other.scope_path == adapter.scope_path
                and other.operation_path == adapter.operation_path
                and other.constraint_paths == adapter.constraint_paths
            ):
                raise TrusteeRegistrationError(
                    'Trustee adapter %r duplicates %r for the same '
                    'validated paths.' % (adapter.name, other.name)
                )
        if self._frozen:
            raise TrusteeRegistryFrozen(
                'Trustee registry is frozen; cannot register %r.' % (
                    adapter.name,
                )
            )
        self._adapters[adapter.name] = adapter
        return adapter

    def revalidate(self, adapter):
        """Re-walk a stored adapter. Raise ``TrusteeRegistrationError`` if stale."""
        rebuilt = self._build_adapter(
            adapter.kind, adapter.name, adapter.trustee_model,
            adapter.membership_path, adapter.grant_model, adapter.trustee_path,
            adapter.scope_path, adapter.operation_path, adapter.constraint_paths,
        )
        if not rebuilt.equivalent(adapter):
            raise TrusteeRegistrationError(
                'Trustee adapter %r no longer matches its stored declaration.' % (
                    adapter.name,
                )
            )
        rebuilt.requester_from_grant_path()
        rebuilt.scope_model()
        rebuilt.operation_model()

    def _enabled(self, names):
        if names is None:
            return self.adapters()
        return tuple(self.get(name) for name in names)

    def grant_q(self, requester, operation, scope_from_row='', names=None):
        """OR-compose ``Exists`` predicates for the enabled grant adapters.

        ``scope_from_row`` is the lookup from the filtered model to the
        policy scope (empty when the row is the scope). Direct exists
        checks and list filters share this predicate.
        """
        self.ensure_frozen()
        adapters = self._enabled(names)
        if not adapters:
            return Q(pk__in=[])
        grant_q = adapters[0].exists_q(requester, operation, scope_from_row)
        for adapter in adapters[1:]:
            grant_q |= adapter.exists_q(requester, operation, scope_from_row)
        return grant_q

    def operation_grant_q(self, requester, scopes, names=None):
        """OR-compose ``Exists`` predicates against an outer operation queryset."""
        self.ensure_frozen()
        adapters = self._enabled(names)
        if not adapters:
            return Q(pk__in=[])
        grant_q = adapters[0].operation_exists_q(requester, scopes)
        for adapter in adapters[1:]:
            grant_q |= adapter.operation_exists_q(requester, scopes)
        return grant_q

    def filter_granted(self, queryset, requester, operation, scope_from_row='', names=None):
        """SQL-filter ``queryset`` with the compiled grant predicate (one query)."""
        self.ensure_frozen()
        return queryset.filter(
            self.grant_q(
                requester, operation, scope_from_row=scope_from_row, names=names,
            )
        )

    def row_is_granted(self, obj, requester, operation, scope_from_row='', names=None):
        """One-query exists check using the same predicate as ``filter_granted``."""
        self.ensure_frozen()
        model = obj.__class__
        return model._default_manager.filter(pk=obj.pk).filter(
            self.grant_q(
                requester, operation, scope_from_row=scope_from_row, names=names,
            )
        ).exists()


def check_registration(
    name, trustee_model, grant_model, trustee_path, scope_path,
    operation_path, membership_path='', constraint_paths=(),
    requester_model=None, registry=None,
):
    """Validate a proposed registration without committing it.

    Returns ``None`` when valid. Returns a ``TrusteeRegistrationError``
    instance when invalid. Does not execute getters or properties.
    """
    if registry is None:
        registry = TrusteeRegistry(requester_model=requester_model)
    elif requester_model is not None and registry._requester_model is None:
        registry.configure(requester_model)
    try:
        registry._build_adapter(
            KIND_GRANT, name, trustee_model, membership_path, grant_model,
            trustee_path, scope_path, operation_path, constraint_paths,
        )
    except TrusteeRegistrationError as exc:
        return exc
    return None


class Trustee(object):
    """Process-wide Trustee registry. Public API is classmethods.

    Tests that need an isolated map construct ``TrusteeRegistry()``
    directly. Authorization queries use this default instance.
    """

    registry = TrusteeRegistry()

    KIND_GRANT = KIND_GRANT

    @classmethod
    def configure(cls, requester_model):
        return cls.registry.configure(requester_model)

    @classmethod
    def register(
        cls, name, trustee_model, grant_model, trustee_path, scope_path,
        operation_path, membership_path='', constraint_paths=(),
    ):
        return cls.registry.register(
            name, trustee_model, grant_model, trustee_path, scope_path,
            operation_path, membership_path=membership_path,
            constraint_paths=constraint_paths,
        )

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
    def is_registered(cls, name):
        return cls.registry.is_registered(name)

    @classmethod
    def get(cls, name):
        return cls.registry.get(name)

    @classmethod
    def get_or_none(cls, name):
        return cls.registry.get_or_none(name)

    @classmethod
    def grant_q(cls, requester, operation, scope_from_row='', names=None):
        return cls.registry.grant_q(
            requester, operation, scope_from_row=scope_from_row, names=names,
        )

    @classmethod
    def operation_grant_q(cls, requester, scopes, names=None):
        return cls.registry.operation_grant_q(
            requester, scopes, names=names,
        )

    @classmethod
    def filter_granted(cls, queryset, requester, operation, scope_from_row='', names=None):
        return cls.registry.filter_granted(
            queryset, requester, operation, scope_from_row=scope_from_row,
            names=names,
        )

    @classmethod
    def row_is_granted(cls, obj, requester, operation, scope_from_row='', names=None):
        return cls.registry.row_is_granted(
            obj, requester, operation, scope_from_row=scope_from_row,
            names=names,
        )


__all__ = [
    'KIND_GRANT',
    'Trustee',
    'TrusteeAdapter',
    'TrusteeMixin',
    'TrusteeNotRegistered',
    'TrusteeRegistrationError',
    'TrusteeRegistry',
    'TrusteeRegistryFrozen',
    'check_registration',
]
