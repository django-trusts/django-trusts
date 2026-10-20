"""Generic Trusts backend mixin.

Registration is a per-class ``Recorder``. Inquiry reads the catalog
``TrustsImplementationConfig.ready`` stored for this class. A class with no catalog
denies: ``has_perm`` is false and permission or user queries are empty.
This module does not build a registry or a catalog.
"""

from collections.abc import Callable
from typing import TypeVar

from django.conf import settings
from django.contrib.auth import get_backends, get_user_model
from django.db.models import Model, QuerySet

from trusts.apps import catalogs, recorders, user_model
from trusts.compile.rows import (
    build_delegation,
    build_public_registration,
    build_relation,
    validate_delegation,
    validate_named_filter,
    validate_principal,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import PlanQueryCompiler
from trusts.plan.standards import (
    UserCondition,
    builtin_user_conditions,
    concrete_rule,
    normalize_on,
    normalize_override_on,
    validate_user_rule_name,
)

T = TypeVar('T', bound=Model)


class TrustModelBackendMixin(object):
    """Object-permission backend. One recorder per class; one catalog after ready."""

    query_compiler = PlanQueryCompiler()
    family = 'relationship'

    def __init__(self):
        cls = type(self)
        if cls not in recorders:
            recorders[cls] = Recorder()

    def get_registry(self):
        """Open recorder for registration. Not the built catalog."""
        return recorders[type(self)]

    def get_catalog(self):
        """Catalog stored at ready, or ``None`` when this class was not built."""
        return catalogs.get(type(self))

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No catalog, or no object, denies."""
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return False
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return False
        return catalog.has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='complete',
        )

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='group',
        )

    def get_permitted_users(self, content, perm, **skip_flags):
        """Users permitted on ``content``. No catalog yields no users."""
        catalog = self.get_catalog()
        if catalog is None:
            return _no_users()
        return catalog.permitted_users(content, perm, **skip_flags)

    def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):
        """Users holding ``perm`` on ``obj``. No catalog or no object yields no users."""
        del is_active, include_superusers
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return _no_users()
        return catalog.permitted_users(obj, perm)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        from django.contrib.auth.models import Permission

        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        catalog = self.get_catalog()
        if catalog is None:
            return None
        return catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
            owner_name=type(self).__name__,
        )

    def _permission_codes(self, user_obj, obj, skip_flags, *, kind):
        catalog = self.get_catalog()
        if catalog is None or obj is None:
            return set()
        if not isinstance(obj, QuerySet) and not isinstance(obj, Model):
            return set()
        if kind == 'group':
            return catalog.get_group_permissions(user_obj, obj, **skip_flags)
        return catalog.get_all_permissions(user_obj, obj, **skip_flags)

    def _ensure_perm_cache(self, user_obj):
        """Documented ``_trust_perm_cache`` attribute; not an auth source."""
        if not hasattr(user_obj, '_trust_perm_cache'):
            setattr(user_obj, '_trust_perm_cache', dict())
        return getattr(user_obj, '_trust_perm_cache')


class Recorder(object):
    """One ordered log of rows for a backend class, plus the frozen flag.

    ``register`` validates the new row against the rows already recorded
    and appends it. It does not build a registry. The ready-time sweep
    is the only build.
    """

    def __init__(self):
        self._rows = []
        self.frozen = False

    @property
    def rows(self):
        """Recorded rows, in registration order."""
        return self._rows

    def register(
        self, *,
        trust: type[T],
        user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object] | Callable[[T, object], object] | None
        ) = None,
        along=None,
    ):
        self._open()
        shape = build_public_registration(
            trust=trust, user=user, permission=permission, content=content,
            group=group, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        conditions, override = self._recorded_rules()
        if shape.delegate is not None:
            payload = {
                'content': shape.content, 'delegate': shape.delegate,
                'sponsor': shape.sponsor, 'condition': shape.condition,
                'along': shape.along,
            }
            record = build_delegation(**payload)
            record = validate_delegation(
                record, self._kind('delegate'),
                conditions=conditions, override=override,
            )
            self._rows.append(('delegate', record, payload))
            return record
        payload = {
            'content': shape.content, 'user': shape.user,
            'condition': shape.condition, 'along': shape.along,
        }
        if shape.group is not None:
            payload['group'] = shape.group
        else:
            payload['permission'] = shape.permission
        record = build_relation(**payload)
        record = validate_principal(
            record, self._kind('principal'),
            conditions=conditions, override=override,
        )
        self._rows.append(('principal', record, payload))
        return record

    def add_named_filter(self, model, code, predicate):
        """Validate the builder once and record it for the compile replay."""
        self._open()
        once = _Once(predicate)
        record = validate_named_filter(model, code, once)
        self._rows.append(('filter', model, code, once))
        return record

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        self._rules_before_rows()
        model = get_user_model()
        validate_user_rule_name(name, kind='condition')
        target = normalize_on(on)
        conditions, override = self._folded(model)
        if (
            expr is not None and override is not None
            and override.name == name
        ):
            raise TrustsConfigurationError(
                'User condition name %r collides with the user override.'
                % (name,)
            )
        if conditions is None:
            conditions = {
                rule.name: rule
                for rule in builtin_user_conditions(model)
            }
        if expr is None:
            if name not in conditions:
                raise TrustsConfigurationError(
                    'User condition %r is not registered.' % (name,)
                )
            self._rows.append(('condition', name, None, on))
            return None
        rule = UserCondition(
            name, concrete_rule(expr, name, model), target,
        )
        self._rows.append(('condition', name, expr, on))
        return rule

    def set_user_override(self, name, expr, on='user'):
        self._open()
        self._rules_before_rows()
        model = get_user_model()
        validate_user_rule_name(name, kind='override')
        normalize_override_on(on)
        conditions, override = self._folded(model)
        if conditions is None:
            names = tuple(
                rule.name for rule in builtin_user_conditions(model)
            )
        else:
            names = tuple(conditions)
        if expr is not None and name in names:
            raise TrustsConfigurationError(
                'User override name %r collides with a user condition.'
                % (name,)
            )
        if expr is None:
            if override is None or override.name != name:
                raise TrustsConfigurationError(
                    'User override %r is not the current override.' % (name,)
                )
            self._rows.append(('override', name, None, on))
            return None
        rule = UserCondition(
            name, concrete_rule(expr, name, model), 'user',
        )
        self._rows.append(('override', name, expr, on))
        return rule

    def freeze(self):
        self.frozen = True

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen.'
            )

    def _rules_before_rows(self):
        if self._kind('principal') or self._kind('delegate'):
            raise TrustsConfigurationError(
                'Set user conditions and the user override before '
                'register() or register_delegation().'
            )

    def _kind(self, kind):
        return tuple(entry[1] for entry in self._rows if entry[0] == kind)

    def _recorded_rules(self, model=None):
        """Rule tuple passed to validation. ``None`` means the built-in rule."""
        conditions, override = self._folded(model)
        if conditions is None:
            return None, override
        return tuple(conditions.values()), override

    def _folded(self, model=None):
        """Current condition map and override, folded from the log."""
        conditions = None
        override = None
        for entry in self._rows:
            if entry[0] == 'condition':
                name, expr, on = entry[1], entry[2], entry[3]
                if conditions is None:
                    if model is None:
                        model = get_user_model()
                    conditions = {
                        rule.name: rule
                        for rule in builtin_user_conditions(model)
                    }
                if expr is None:
                    conditions.pop(name, None)
                else:
                    if model is None:
                        model = get_user_model()
                    conditions[name] = UserCondition(
                        name, concrete_rule(expr, name, model),
                        normalize_on(on),
                    )
            elif entry[0] == 'override':
                name, expr = entry[1], entry[2]
                if expr is None:
                    override = None
                else:
                    if model is None:
                        model = get_user_model()
                    override = UserCondition(
                        name, concrete_rule(expr, name, model), 'user',
                    )
        return conditions, override


class _Once(object):
    """Invoke ``fn`` once. Registration and the sweep both call it."""

    def __init__(self, fn):
        self.fn = fn
        self.called = False
        self.cached = None

    def __call__(self, *args, **kwargs):
        if not self.called:
            self.cached = self.fn(*args, **kwargs)
            self.called = True
        return self.cached


def configured_catalogs():
    """Catalogs of listed mixin backends, in ``get_backends()`` order.

    An empty ``AUTHENTICATION_BACKENDS`` is no catalogs. Django's
    ``get_backends()`` raises in that case; this inquiry does not.
    A class that was not built contributes nothing. Callers treat a
    missing catalog as no grants.
    """
    if not tuple(settings.AUTHENTICATION_BACKENDS):
        return ()
    found = []
    seen = set()
    for backend in get_backends():
        if not isinstance(backend, TrustModelBackendMixin):
            continue
        cls = type(backend)
        if cls in seen:
            continue
        seen.add(cls)
        catalog = backend.get_catalog()
        if catalog is None:
            continue
        found.append(catalog)
    return tuple(found)


def _no_users():
    """Empty user queryset after ready, or an empty tuple before it."""
    model = user_model()
    if model is None:
        return ()
    return model._default_manager.none()
