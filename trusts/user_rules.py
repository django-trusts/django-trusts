"""Named user conditions compiled to concrete boolean SQL.

A condition is a lambda walked once at registration. The walk accepts
concrete boolean field lookups, ``&``, and ``~``. The lockfile records
the SQL that comparison becomes. There is no separate rule key.
"""

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q

from trusts.core import TrustsConfigurationError


class FieldRef(object):
    __slots__ = ('name',)

    def __init__(self, name):
        self.name = name


class NotExpr(object):
    __slots__ = ('inner',)

    def __init__(self, inner):
        self.inner = inner


class AndExpr(object):
    __slots__ = ('left', 'right')

    def __init__(self, left, right):
        self.left = left
        self.right = right


class UserCondition(object):
    __slots__ = ('name', 'expr', 'on')

    def __init__(self, name, expr, on):
        self.name = name
        self.expr = expr
        self.on = on


BUILTIN_USER_CONDITIONS = (
    UserCondition('is_active', FieldRef('is_active'), '*'),
)


def condition_targets(on):
    """Roles a stored ``on`` value covers."""
    if on == '*':
        return frozenset(('user', 'sponsor'))
    return frozenset((on,))


def normalize_override_on(on):
    """Overrides accept only the checked user.

    Omit ``on`` or pass ``"user"``. ``"sponsor"`` and ``"*"`` raise.
    Sponsor authority stays an ordinary grant.
    """
    if on == 'user':
        return 'user'
    raise TrustsConfigurationError(
        'User override on= applies only to the checked user. '
        'Omit on= or pass on="user", not %r.' % (on,)
    )


def normalize_on(on):
    """``*``, ``user``, ``sponsor``, or a non-empty tuple of those names.

    ``("user", "sponsor")`` is stored as ``*``. Any other value fails.
    """
    if on == '*':
        return '*'
    if on in ('user', 'sponsor'):
        return on
    if isinstance(on, tuple):
        if not on or any(item not in ('user', 'sponsor') for item in on):
            raise TrustsConfigurationError(
                'User condition on= must be "*", "user", "sponsor", or a '
                'non-empty tuple of "user" and "sponsor", not %r.' % (on,)
            )
        names = set(on)
        if names == {'user', 'sponsor'}:
            return '*'
        if names == {'user'}:
            return 'user'
        return 'sponsor'
    raise TrustsConfigurationError(
        'User condition on= must be "*", "user", "sponsor", or a '
        'non-empty tuple of "user" and "sponsor", not %r.' % (on,)
    )


# Inquiry parameters. A condition name, and the ``skip_<name>`` keyword
# derived from it, must not reuse one of these. ``skip_is_active`` is
# absent on purpose: it is the keyword for the ``is_active`` condition.
_INQUIRY_KEYWORDS = frozenset({
    'user', 'user_obj', 'permission', 'perm', 'permext', 'content', 'obj',
    'extra_q', 'conditions', 'queryset', 'handles', 'kind', 'candidates',
    'plan', 'sponsor_handles', 'permission_model', 'skipped', 'skip_flags',
})


def validate_user_rule_name(name, *, kind):
    """Fail when ``name`` cannot become the keyword ``skip_<name>``."""
    label = 'User condition' if kind == 'condition' else 'User override'
    if not isinstance(name, str) or not name.isidentifier():
        raise TrustsConfigurationError(
            '%s name must be an identifier, not %r.' % (label, name)
        )
    flag = 'skip_%s' % name
    if name in _INQUIRY_KEYWORDS or flag in _INQUIRY_KEYWORDS:
        raise TrustsConfigurationError(
            '%s name %r collides with an inquiry keyword.' % (label, name)
        )


def condition_names(conditions, override=None):
    """Registered condition names, plus the override name when one is set."""
    rules = BUILTIN_USER_CONDITIONS if conditions is None else conditions
    names = {rule.name for rule in rules}
    if override is not None:
        names.add(override.name)
    return frozenset(names)


def collect_skipped(*, known=None, **flags):
    """Names whose ``skip_<name>=True`` drops that condition.

    Each keyword is ``skip_`` plus a registered condition name. The
    built-in ``is_active`` condition is what makes ``skip_is_active``
    accepted. There is no separate ``skip_is_active`` parameter.
    ``known`` is that name set; a ``skip_*`` keyword outside it raises
    ``TypeError``. A non-boolean or an unrelated keyword fails before
    SQL. ``False`` is not a request.
    """
    from trusts.query import require_mode_flag

    requested = []
    for key, value in flags.items():
        if (
            not key.startswith('skip_')
            or not key[len('skip_'):].isidentifier()
        ):
            raise TypeError('Unexpected keyword argument %r.' % (key,))
        require_mode_flag(value, key)
        suffix = key[len('skip_'):]
        if known is not None and suffix not in known:
            raise TypeError('Unknown skip keyword %r.' % (key,))
        if value:
            requested.append(suffix)
    return frozenset(requested)


def enforces_is_active(conditions, skipped, *, role='user'):
    """Whether the built-in activity condition still applies to ``role``."""
    rules = BUILTIN_USER_CONDITIONS if conditions is None else conditions
    skipped = frozenset(skipped or ())
    for rule in rules:
        if rule.name != 'is_active' or rule.name in skipped:
            continue
        if role in condition_targets(rule.on):
            return True
    return False


class _Expr(object):
    def __and__(self, other):
        if not isinstance(other, _Expr):
            raise TrustsConfigurationError(
                'User conditions only combine concrete boolean fields with &.'
            )
        return _And(self, other)

    def __rand__(self, other):
        return self.__and__(other)

    def __invert__(self):
        return _Not(self)

    def __bool__(self):
        raise TrustsConfigurationError(
            'User conditions only support concrete boolean fields, &, and ~.'
        )

    def __eq__(self, other):
        raise TrustsConfigurationError(
            'User conditions only support concrete boolean fields, &, and ~.'
        )

    def __or__(self, other):
        raise TrustsConfigurationError(
            'User conditions only support concrete boolean fields, &, and ~.'
        )

    def __call__(self, *args, **kwargs):
        raise TrustsConfigurationError(
            'User conditions only support concrete boolean fields, &, and ~.'
        )


class _Attr(_Expr):
    def __init__(self, name):
        self.name = name


class _Not(_Expr):
    def __init__(self, inner):
        self.inner = inner


class _And(_Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right


class _UserProxy(object):
    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return _Attr(name)


def _lower(node):
    if isinstance(node, _Attr):
        return FieldRef(node.name)
    if isinstance(node, _Not):
        return NotExpr(_lower(node.inner))
    if isinstance(node, _And):
        return AndExpr(_lower(node.left), _lower(node.right))
    raise TrustsConfigurationError(
        'User conditions only support concrete boolean fields, &, and ~.'
    )


def walk_user_lambda(expr):
    """Walk ``lambda u: ...`` once. Does not call it with a user instance."""
    if not callable(expr):
        raise TrustsConfigurationError(
            'User condition expression must be a callable or None, not %r.'
            % (expr,)
        )
    try:
        result = expr(_UserProxy())
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            'User conditions only support concrete boolean fields, &, and ~.'
        ) from exc
    return _lower(result)


def iter_field_names(expr):
    if isinstance(expr, FieldRef):
        yield expr.name
        return
    if isinstance(expr, NotExpr):
        yield from iter_field_names(expr.inner)
        return
    if isinstance(expr, AndExpr):
        yield from iter_field_names(expr.left)
        yield from iter_field_names(expr.right)
        return
    raise TrustsConfigurationError(
        'User conditions only support concrete boolean fields, &, and ~.'
    )


def assert_concrete_booleans(model, expr, name):
    """Fail registration when a field is missing, a property, or not boolean."""
    for field_name in iter_field_names(expr):
        try:
            field = model._meta.get_field(field_name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'User condition %r needs a concrete BooleanField %s.%s.'
                % (name, model._meta.label, field_name)
            ) from None
        if (
            not getattr(field, 'concrete', False)
            or field.get_internal_type() != 'BooleanField'
        ):
            raise TrustsConfigurationError(
                'User condition %r needs a concrete BooleanField %s.%s.'
                % (name, model._meta.label, field_name)
            )


def _expr_availability(model, expr):
    """``ok`` when every field is a concrete boolean, ``missing`` otherwise.

    A field that exists and is not a concrete boolean is a configuration
    error. A missing column is left to the caller: checked-user SQL omits
    that rule, and sponsor eligibility fails closed.
    """
    for field_name in iter_field_names(expr):
        try:
            field = model._meta.get_field(field_name)
        except FieldDoesNotExist:
            return 'missing'
        if (
            not getattr(field, 'concrete', False)
            or field.get_internal_type() != 'BooleanField'
        ):
            raise TrustsConfigurationError(
                '%s.%s must be a concrete BooleanField.'
                % (model._meta.label, field_name)
            )
    return 'ok'


def _lookup(path, name):
    if path:
        return '%s__%s' % (path, name)
    return name


def _compile_expr(path, expr):
    if isinstance(expr, FieldRef):
        return Q(**{_lookup(path, expr.name): True})
    if isinstance(expr, NotExpr):
        return ~_compile_expr(path, expr.inner)
    if isinstance(expr, AndExpr):
        return _compile_expr(path, expr.left) & _compile_expr(path, expr.right)
    raise TrustsConfigurationError(
        'User conditions only support concrete boolean fields, &, and ~.'
    )


def compile_user_rules(model, path, conditions, *, role, skipped, missing='omit'):
    """SQL for the conditions that apply to ``role``.

    ``conditions is None`` is the built-in ``is_active`` rule. ``missing``
    is ``omit`` for the checked user (no invented term) and ``closed`` for
    a sponsor eligibility check that cannot see the column. Returns ``None``
    when ``missing`` is ``closed`` and a required field is absent.
    """
    rules = BUILTIN_USER_CONDITIONS if conditions is None else tuple(conditions)
    skipped = frozenset(skipped or ())
    parts = []
    for rule in rules:
        if role not in condition_targets(rule.on):
            continue
        if rule.name in skipped:
            continue
        if _expr_availability(model, rule.expr) == 'missing':
            if missing == 'closed':
                return None
            continue
        parts.append(_compile_expr(path, rule.expr))
    if not parts:
        return Q()
    combined = parts[0]
    for part in parts[1:]:
        combined &= part
    return combined
