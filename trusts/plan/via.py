"""User-side reachability. The recursive SQL is the along walk.

``via=`` replaces equality at the user, delegate, or sponsor walk-site.
The ``WITH RECURSIVE`` statement, the depth cap, the cycle clause, and
the reset predicate are the ones ``along=`` renders. This module chooses
the seed, the user match, and the comparisons on a walked user.
"""

__all__ = []

import copy
from contextlib import contextmanager
from contextvars import ContextVar

from django.db.models import BooleanField, Model, OuterRef, Q, Subquery
from django.db.models.expressions import Expression

from trusts.errors import TrustsConfigurationError
from trusts.plan.conditions import condition_model_key
from trusts.plan.grammar import Tree
from trusts.plan.predicates import bind_record_qs, bind_terminal
from trusts.plan.rewrites import CallInput
from trusts.plan.standards import (
    builtin_user_conditions,
    compile_user_rules,
    rule_applies,
)
from trusts.plan.walk import (
    _grant_walk_attname,
    _m2m_columns,
    _render_reach_sql,
    _require_along_renderer,
    _suffix_link,
    _walk_ident_field,
    _walk_identity_column,
)


_inquiry = ContextVar('trusts_via_inquiry', default=None)
_reuse = ContextVar('trusts_via_reuse', default=None)
_hop_record = ContextVar('trusts_via_hop_record', default=None)
_UNSET = object()


@contextmanager
def via_scope(catalog=None, skipped=None, filters=_UNSET, content=_UNSET):
    """Inquiry values read while a ``via=`` predicate is built.

    ``filters`` and ``content`` are kept when a nested scope does not
    pass them. ``content`` is a saved object for a reverse inquiry; a
    forward inquiry leaves it unset so object values stay outer columns.
    """
    current = dict(_inquiry.get() or {})
    if catalog is not None:
        current['conditions'] = getattr(catalog, 'user_conditions', None)
    if skipped is not None:
        current['skipped'] = dict(skipped or {})
    if filters is not _UNSET:
        current['filters'] = tuple(filters or ())
    if content is not _UNSET:
        current['content'] = content
    token = _inquiry.set(current)
    try:
        yield
    finally:
        _inquiry.reset(token)


class _HopWalk(object):
    """Along walk plus the user-condition text for one inquiry."""

    def __init__(self, walk, hop_sql, hop_format=None):
        self._walk = walk
        self.hop_sql = hop_sql
        self.hop_format = hop_format or {}

    def __getattr__(self, name):
        return getattr(self._walk, name)


class _HopValue(Expression):
    """One constant carried into the seed. The recursive member copies it."""

    def __init__(self, value, hint):
        super().__init__()
        self.value = value
        self.hint = hint

    def as_sql(self, compiler, connection):
        return '%s', (self.value,)

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('_HopValue has no source expressions.')


def via_side(record):
    """``user``, ``delegate``, or ``sponsor`` for this record's walk."""
    walk = getattr(record, 'via', None)
    if walk is None:
        return None
    if getattr(record, 'user_path', None) is not None:
        return 'user'
    path = tuple(walk.walk_path)
    delegate = tuple(record.delegate_path[:len(path)]) == path
    sponsor = tuple(record.sponsor_path[:len(path)]) == path
    if delegate and sponsor:
        raise TrustsConfigurationError(
            'via path %r shares a prefix with delegate and sponsor.'
            % ('__'.join(walk.path),)
        )
    if delegate:
        return 'delegate'
    if sponsor:
        return 'sponsor'
    raise TrustsConfigurationError(
        'via path %r does not share a walk-site prefix.'
        % ('__'.join(walk.path),)
    )


def cuts_users(walk, model):
    """True when the walked row is the principal, so a failure stops the path."""
    if walk is None or model is None or walk.suffix_path:
        return False
    return (
        walk.walk_model._meta.concrete_model
        is model._meta.concrete_model
    )


def principal_model(record):
    model = getattr(record, 'user_model', None)
    if model is not None:
        return model
    return record.delegate_model


def condition_role(record):
    """User-rule role applied to people this walk reaches."""
    if via_side(record) == 'sponsor':
        return 'sponsor'
    return 'user'


def replaces_user(record):
    """True when ``via=`` replaces equality on an ordinary ``user=`` path."""
    return via_side(record) == 'user'


def selects_reached_users(record):
    """True when sponsor conditions select users and the walk continues."""
    walk = getattr(record, 'via', None)
    if via_side(record) != 'sponsor':
        return False
    return not cuts_users(walk, principal_model(record))


def via_grant_q(record, user):
    """This row's walk reaches ``user``. ``user`` is the actor."""
    return Q(ViaReach(record, user, mode='from_row'))


def walk_seed_expression(record):
    """Walk identity of ``record``'s row, as seen from a nested grant query."""
    walk = record.via
    if len(walk.walk_path) == 1:
        return OuterRef(_grant_walk_attname(record, walk))
    return Subquery(
        record.root._default_manager.filter(
            pk=OuterRef('pk'),
        ).values(walk.walk_field)[:1]
    )


def sponsor_via_q(delegation, ordinary):
    """Ordinary row whose user the delegation's sponsor walk reaches."""
    return Q(ViaReach(
        delegation,
        walk_seed_expression(delegation),
        mode='from_value',
        match_record=ordinary,
    ))


def sponsor_constraint(delegation, ordinary):
    """User predicate for one ordinary grant, or ``None`` for equality.

    A sponsor walk, an ordinary ``via=``, or both. Sponsor conditions
    select each reached user when the walked row is a group or a link.
    """
    side = via_side(delegation)
    ordinary_via = replaces_user(ordinary)
    if side != 'sponsor' and not ordinary_via:
        return None
    if side == 'sponsor' and ordinary_via:
        part = Q(ViaMeet(delegation, ordinary))
    elif side == 'sponsor':
        part = sponsor_via_q(delegation, ordinary)
    else:
        part = via_grant_q(ordinary, OuterRef(delegation.sponsor_field))
    extra = _reached_sponsor_q(delegation, ordinary)
    if extra is not None:
        part = part & extra
    return part


def delegate_q(record, user):
    """Delegate equality, or the delegate walk when ``via=`` selects it."""
    if via_side(record) == 'delegate':
        return via_grant_q(record, user)
    return Q(**{record.delegate_field: bind_terminal(user, 'delegate')})


def delegate_user_q(record, user):
    """``user_q`` for the delegation content seed, or ``None``."""
    if via_side(record) == 'delegate':
        return via_grant_q(record, user)
    return None


def bind_grant_qs(record, *, user, permission=None, correlation=None,
                  content_identity=None):
    """Root rows for one grant. ``via=`` replaces user equality."""
    kwargs = {}
    if permission is not None:
        kwargs['permission'] = permission
    reach = None
    if replaces_user(record):
        reach = via_grant_q(record, user)
    else:
        kwargs['user'] = user
    qs = bind_record_qs(
        record,
        correlation=correlation,
        content_identity=content_identity,
        **kwargs,
    )
    if reach is not None:
        qs = qs.filter(reach)
    return qs


def _reached_sponsor_q(delegation, ordinary):
    """Sponsor rules on the ordinary user column.

    Used when the walked row is not itself a user and the ordinary grant
    stores that user. The walk of groups or links is unchanged.
    """
    if not selects_reached_users(delegation) or replaces_user(ordinary):
        return None
    inquiry = _inquiry.get() or {}
    if 'conditions' in inquiry:
        conditions = inquiry['conditions']
    else:
        conditions = None
    skipped = inquiry.get('skipped') or {}
    model = ordinary.user_model._meta.concrete_model
    rules = compile_user_rules(
        model, ordinary.user_field, conditions, role='sponsor',
        values=skipped, scope=ordinary.root,
    )
    identity = _identity_lookups(model, ordinary.user_field)
    if identity:
        rules = rules & Q(**identity)
    return rules


def _identity_lookups(model, path):
    lookups = {}
    for name, expected in (('is_anonymous', False), ('is_authenticated', True)):
        try:
            field = model._meta.get_field(name)
        except Exception:
            continue
        if (
            not getattr(field, 'concrete', False)
            or field.get_internal_type() != 'BooleanField'
        ):
            continue
        lookups['%s__%s' % (path, name)] = expected
    return lookups


def _capture(record):
    inquiry = _inquiry.get() or {}
    model = principal_model(record)
    if 'conditions' in inquiry:
        stored = inquiry['conditions']
    else:
        stored = None
    rules = stored if stored is not None else builtin_user_conditions(model)
    skipped = inquiry.get('skipped') or {}
    role = condition_role(record)
    selected = []
    for rule in rules:
        if rule_applies(rule.on, role):
            selected.append((rule.name, rule.expr, bool(skipped.get(rule.name, False))))
    filters = ()
    if cuts_users(record.via, model):
        filters = tuple(inquiry.get('filters') or ())
    content = inquiry.get('content', None)
    return selected, filters, content


def assert_hop_rules(record, conditions):
    """Reject a user walk whose rules cannot be a row comparison."""
    model = principal_model(record)
    if not cuts_users(getattr(record, 'via', None), model):
        return
    rules = conditions if conditions is not None else builtin_user_conditions(model)
    role = condition_role(record)
    selected = []
    for rule in rules:
        if rule_applies(rule.on, role):
            selected.append((rule.name, rule.expr, False))
    _render_hop(record, selected, (), None, lambda name: name)


def assert_via_filters(record, named_filters):
    """Reject a user walk whose named filters cannot be a row comparison."""
    model = principal_model(record)
    if not cuts_users(getattr(record, 'via', None), model):
        return
    label = condition_model_key(record.content_model)
    trees = []
    for (key, _code), (_filter_model, tree) in named_filters.items():
        if key == label:
            trees.append(tree)
    if trees:
        _render_hop(record, (), trees, None, lambda name: name)


def _cannot(name):
    if name:
        return TrustsConfigurationError(
            'via user condition %r cannot be written in the recursive member.'
            % (name,)
        )
    return TrustsConfigurationError(
        'via named filter cannot be written in the recursive member.'
    )


def _render_hop(record, rules, filters, content, qn):
    """Return ``(template, carriers)``. An empty template is no hop."""
    token = _hop_record.set(record)
    try:
        if not cuts_users(getattr(record, 'via', None), principal_model(record)):
            return '', []
        user_model = principal_model(record)._meta.concrete_model
        content_model = record.content_model
        carriers = []
        parts = []
        for name, expr, skipped in rules:
            if skipped:
                continue
            rendered = _walk_node(
                expr, user_model, content_model, content, carriers, name,
                qn, force=True,
            )
            if rendered:
                parts.append(rendered)
        for expr in filters:
            rendered = _walk_node(
                expr, user_model, content_model, content, carriers, None,
                qn, force=False,
            )
            if rendered:
                parts.append(rendered)
        return ' AND '.join(parts), carriers
    finally:
        _hop_record.reset(token)


def _mentions(node, root):
    if not isinstance(node, Tree):
        return False
    if node.kind == 'field':
        return node.root == root
    if node.kind in ('and', 'or', 'eq', 'ne', 'contains'):
        return _mentions(node.left, root) or _mentions(node.right, root)
    if node.kind in ('not', 'bare'):
        return _mentions(node.item, root)
    return False


def _walk_node(node, user_model, content_model, content, carriers, name, qn,
               force):
    if not isinstance(node, Tree):
        raise _cannot(name)
    if node.kind == 'and':
        left = _walk_node(
            node.left, user_model, content_model, content, carriers, name,
            qn, force,
        )
        right = _walk_node(
            node.right, user_model, content_model, content, carriers, name,
            qn, force,
        )
        if left is None:
            return right
        if right is None:
            return left
        return '(%s AND %s)' % (left, right)
    if node.kind == 'or':
        if (
            not force
            and not _mentions(node, 'user')
        ):
            return None
        left = _walk_node(
            node.left, user_model, content_model, content, carriers, name,
            qn, True,
        )
        right = _walk_node(
            node.right, user_model, content_model, content, carriers, name,
            qn, True,
        )
        if left is None or right is None:
            raise _cannot(name)
        return '(%s OR %s)' % (left, right)
    if node.kind == 'not':
        inner = _walk_node(
            node.item, user_model, content_model, content, carriers, name,
            qn, force,
        )
        if inner is None:
            return None
        return '(NOT %s)' % inner
    if node.kind == 'bare':
        return _walk_node(
            node.item, user_model, content_model, content, carriers, name,
            qn, force,
        )
    if node.kind == 'field':
        return _field_sql(
            node, user_model, content_model, content, carriers, name, qn, force,
        )
    if node.kind in ('eq', 'ne'):
        return _compare_sql(
            node, user_model, content_model, content, carriers, name, qn, force,
        )
    if node.kind == 'contains':
        return _contains_sql(
            node, user_model, content_model, content, carriers, name, qn, force,
        )
    raise _cannot(name)


def _local_field(model, path, name):
    if not path:
        return model._meta.pk
    if len(path) != 1:
        raise _cannot(name)
    try:
        field = model._meta.get_field(path[0])
    except Exception as exc:
        raise _cannot(name) from exc
    if (
        not getattr(field, 'concrete', False)
        or getattr(field, 'many_to_many', False)
        or field.model._meta.db_table != model._meta.db_table
    ):
        raise _cannot(name)
    return field


def _field_sql(node, user_model, content_model, content, carriers, name, qn,
               force):
    if node.root == 'user':
        field = _local_field(user_model, node.path, name)
        if field.get_internal_type() != 'BooleanField':
            raise _cannot(name)
        return '{alias}.%s IS TRUE' % qn(field.column)
    if node.root == 'object':
        if not force and not _mentions(node, 'user'):
            return None
        index = _add_carrier(carriers, _object_value(
            content_model, content, node.path, name,
        ))
        return '{c%s} IS TRUE' % index
    if node.root == 'permission':
        return _permission_predicate(
            node.path, 'IS TRUE', None, carriers, name, qn,
        )
    raise _cannot(name)


def _const_value(node):
    value = node.value
    if isinstance(value, Model):
        return value.pk
    return value


def _compare_sql(node, user_model, content_model, content, carriers, name, qn,
                 force):
    left, right = node.left, node.right
    if getattr(left, 'kind', None) == 'const':
        left, right = right, left
    if not _mentions(node, 'user') and not force:
        return None
    if (
        getattr(left, 'kind', None) == 'field'
        and left.root == 'user'
        and getattr(right, 'kind', None) == 'const'
        and isinstance(right.value, bool)
    ):
        field = _local_field(user_model, left.path, name)
        if field.get_internal_type() != 'BooleanField':
            raise _cannot(name)
        positive = right.value if node.kind == 'eq' else (not right.value)
        word = 'IS TRUE' if positive else 'IS FALSE'
        return '{alias}.%s %s' % (qn(field.column), word)
    permission_node = None
    user_node = None
    if _is_permission_field(right):
        permission_node, user_node = right, left
    elif _is_permission_field(left):
        permission_node, user_node = left, right
    if permission_node is not None:
        op = '=' if node.kind == 'eq' else '<>'
        user_sql = _user_operand(
            user_node, user_model, content_model, content, carriers, name, qn,
        )
        return _permission_predicate(
            permission_node.path, op, user_sql, carriers, name, qn,
        )
    if getattr(left, 'kind', None) != 'field' or left.root != 'user':
        raise _cannot(name)
    user_field = _local_field(user_model, left.path, name)
    user_sql = '{alias}.%s' % qn(user_field.column)
    if getattr(right, 'kind', None) == 'const' and _const_value(right) is None:
        word = 'IS NULL' if node.kind == 'eq' else 'IS NOT NULL'
        return '%s %s' % (user_sql, word)
    other_sql = _other_operand(
        right, user_model, content_model, content, carriers, name, qn,
        field=user_field,
    )
    if node.kind == 'eq':
        return '%s = %s' % (user_sql, other_sql)
    if node.kind != 'ne':
        raise _cannot(name)
    if getattr(right, 'kind', None) == 'const':
        return '(%s IS NULL OR %s <> %s)' % (user_sql, user_sql, other_sql)
    return '%s <> %s' % (user_sql, other_sql)


def _user_operand(node, user_model, content_model, content, carriers, name, qn):
    if getattr(node, 'kind', None) != 'field' or node.root != 'user':
        raise _cannot(name)
    field = _local_field(user_model, node.path, name)
    return '{alias}.%s' % qn(field.column)


def _other_operand(node, user_model, content_model, content, carriers, name, qn,
                   field=None):
    if getattr(node, 'kind', None) == 'const':
        value = node.value
        target = getattr(field, 'target_field', None) if field is not None else None
        if isinstance(value, Model) and target is not None:
            value = getattr(value, target.attname)
        elif isinstance(value, Model):
            value = value.pk
        index = _add_carrier(carriers, _HopValue(value, 'via.const'))
        return '{c%s}' % index
    if getattr(node, 'kind', None) == 'field' and node.root == 'object':
        index = _add_carrier(carriers, _object_value(
            content_model, content, node.path, name,
        ))
        return '{c%s}' % index
    if getattr(node, 'kind', None) == 'field' and node.root == 'user':
        field = _local_field(user_model, node.path, name)
        return '{alias}.%s' % qn(field.column)
    if getattr(node, 'kind', None) == 'field' and node.root == 'permission':
        index = _add_carrier(carriers, _permission_value(node.path, name))
        return '{c%s}' % index
    raise _cannot(name)


def _contains_sql(node, user_model, content_model, content, carriers, name, qn,
                  force):
    left = node.left
    if not _mentions(node, 'user') and not force:
        return None
    if getattr(left, 'kind', None) != 'field' or left.root != 'user':
        raise _cannot(name)
    if len(left.path) != 1:
        raise _cannot(name)
    try:
        field = user_model._meta.get_field(left.path[0])
    except Exception as exc:
        raise _cannot(name) from exc
    if getattr(field, 'many_to_many', False):
        forward, user_col, target_col = _m2m_columns(field)
        through_model = forward.remote_field.through
        user_fk = _fk_by_column(through_model, user_col, name)
        far_fk = _fk_by_column(through_model, target_col, name)
        member = _other_operand(
            node.right, user_model, content_model, content, carriers, name, qn,
            field=far_fk,
        )
        probe = qn('hopm')
        return (
            'EXISTS (SELECT 1 FROM %s AS %s '
            'WHERE %s.%s = {alias}.%s AND %s.%s = %s)'
            % (
                qn(through_model._meta.db_table), probe,
                probe, qn(user_fk.column),
                qn(user_fk.target_field.column),
                probe, qn(far_fk.column), member,
            )
        )
    if getattr(field, 'concrete', False) and getattr(field, 'many_to_one', False):
        member = _other_operand(
            node.right, user_model, content_model, content, carriers, name, qn,
            field=field,
        )
        return '{alias}.%s = %s' % (qn(field.column), member)
    raise _cannot(name)


def _add_carrier(carriers, expr):
    reuse = _reuse.get()
    if reuse is not None:
        carriers.append(reuse[len(carriers)])
    else:
        carriers.append(expr)
    return len(carriers) - 1


def _object_value(model, content, path, name):
    if not path:
        raise _cannot(name)
    if content is not None:
        value = _read_instance(content, path, name)
        hint = 'content.%s' % path[-1]
        return _HopValue(value, hint)
    if len(path) == 1:
        try:
            field = model._meta.get_field(path[0])
        except Exception as exc:
            raise _cannot(name) from exc
        if getattr(field, 'concrete', False):
            return OuterRef(field.attname)
    lookup = '__'.join(path)
    return Subquery(
        model._default_manager.filter(pk=OuterRef('pk')).values(lookup)[:1]
    )


def _is_permission_field(node):
    return (
        getattr(node, 'kind', None) == 'field'
        and node.root == 'permission'
        and len(node.path) == 1
    )


def _permission_value(path, name):
    if len(path) != 1:
        raise _cannot(name)
    record = _hop_record.get()
    if record is None or _permission_is_collection(record, name):
        raise _cannot(name)
    _permission_column(record, path[0], name)
    return _PermissionColumn(record, path[0])


def _permission_predicate(path, op, user_sql, carriers, name, qn):
    """One permission column compared at every hop.

    A single-valued terminal is one carried value. A many-to-many
    terminal is ``EXISTS``: the grant can point at more than one row,
    and a scalar subquery would not be one value. Inequality against
    that set is not one SQL predicate, so it is rejected.
    """
    if len(path) != 1:
        raise _cannot(name)
    record = _hop_record.get()
    if record is None:
        raise _cannot(name)
    column = _permission_column(record, path[0], name)
    if not _permission_is_collection(record, name):
        index = _add_carrier(carriers, _PermissionColumn(record, path[0]))
        value = '{c%s}' % index
        if op == 'IS TRUE':
            return '%s IS TRUE' % value
        if user_sql is None:
            raise _cannot(name)
        return '%s %s %s' % (user_sql, op, value)
    if op == '<>':
        raise _cannot(name)
    index = _add_carrier(carriers, _GrantKey())
    steps = _permission_steps(record, name)
    root_alias = qn('hopg')
    joins, perm_alias = _permission_join_sql(
        record.root, steps, root_alias, qn, name,
    )
    if op == 'IS TRUE':
        match = '%s.%s IS TRUE' % (perm_alias, qn(column.column))
    else:
        match = '%s.%s %s %s' % (perm_alias, qn(column.column), op, user_sql)
    return (
        'EXISTS (SELECT 1 FROM %s AS %s%s WHERE %s.%s = {c%s} AND %s)'
        % (
            qn(record.root._meta.db_table), root_alias, joins,
            root_alias, qn(record.root._meta.pk.column), index, match,
        )
    )


def _permission_column(record, name, label):
    model = getattr(record, 'permission_model', None)
    if model is None:
        raise _cannot(label)
    try:
        field = model._meta.get_field(name)
    except Exception as exc:
        raise _cannot(label) from exc
    if (
        not getattr(field, 'concrete', False)
        or getattr(field, 'many_to_many', False)
        or field.model._meta.db_table != model._meta.db_table
    ):
        raise _cannot(label)
    return field


def _permission_is_collection(record, name):
    steps = _permission_steps(record, name)
    return bool(steps) and getattr(steps[-1], 'many_to_many', False)


def _permission_steps(record, name):
    path = tuple(getattr(record, 'permission_path', ()) or ())
    if not path:
        raise _cannot(name)
    current = record.root
    steps = []
    for index, part in enumerate(path):
        try:
            field = current._meta.get_field(part)
        except Exception as exc:
            raise _cannot(name) from exc
        steps.append(field)
        if getattr(field, 'many_to_many', False):
            if index != len(path) - 1:
                raise _cannot(name)
            return steps
        if not (
            getattr(field, 'concrete', False)
            and getattr(field, 'many_to_one', False)
        ):
            raise _cannot(name)
        current = field.remote_field.model
    return steps


def _fk_by_column(model, column, name):
    for candidate in model._meta.local_fields:
        if (
            getattr(candidate, 'column', None) == column
            and getattr(candidate, 'is_relation', False)
        ):
            return candidate
    raise _cannot(name)


def _permission_join_sql(root, steps, source_alias, qn, name):
    """Joins from ``source_alias`` (the grant row) to the permission row."""
    sql = ''
    perm_alias = source_alias
    for index, field in enumerate(steps, start=1):
        dest = qn('hopp%s' % index)
        if getattr(field, 'many_to_many', False):
            forward, here_col, there_col = _m2m_columns(field)
            through = forward.remote_field.through
            here_fk = _fk_by_column(through, here_col, name)
            there_fk = _fk_by_column(through, there_col, name)
            through_alias = qn('hopt%s' % index)
            sql += (
                ' JOIN %s AS %s ON %s.%s = %s.%s'
                ' JOIN %s AS %s ON %s.%s = %s.%s'
                % (
                    qn(through._meta.db_table), through_alias,
                    through_alias, qn(here_fk.column),
                    source_alias, qn(here_fk.target_field.column),
                    qn(there_fk.remote_field.model._meta.db_table), dest,
                    dest, qn(there_fk.target_field.column),
                    through_alias, qn(there_fk.column),
                )
            )
            perm_alias = dest
            source_alias = dest
            continue
        sql += (
            ' JOIN %s AS %s ON %s.%s = %s.%s'
            % (
                qn(field.remote_field.model._meta.db_table), dest,
                dest, qn(field.target_field.column),
                source_alias, qn(field.column),
            )
        )
        perm_alias = dest
        source_alias = dest
    if perm_alias == source_alias and not steps:
        raise _cannot(name)
    return sql, perm_alias


def _read_instance(obj, path, name):
    current = obj
    for part in path:
        if current is None:
            raise _cannot(name)
        try:
            field = current._meta.get_field(part)
        except Exception as exc:
            raise _cannot(name) from exc
        if getattr(field, 'concrete', False) and getattr(field, 'many_to_one', False):
            current = getattr(current, field.attname)
        else:
            current = getattr(current, part)
    if isinstance(current, Model):
        return current.pk
    return current


class _GrantKey(Expression):
    """Primary key of the grant row, carried into the recursive member."""

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        alias = qn(compiler.query.get_initial_alias())
        column = qn(compiler.query.model._meta.pk.column)
        return '%s.%s' % (alias, column), ()

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('_GrantKey has no source expressions.')


class _PermissionColumn(Expression):
    """One column of the grant's permission terminal, read in the seed."""

    def __init__(self, record, name):
        super().__init__()
        self.record = record
        self.column_name = name

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        grant_alias = qn(compiler.query.get_initial_alias())
        token = _hop_record.set(self.record)
        try:
            column = _permission_column(self.record, self.column_name, None)
            steps = _permission_steps(self.record, None)
        finally:
            _hop_record.reset(token)
        if steps and getattr(steps[-1], 'many_to_many', False):
            raise _cannot(None)
        root_alias = qn('hopg')
        joins, perm_alias = _permission_join_sql(
            self.record.root, steps, root_alias, qn, None,
        )
        sql = (
            '(SELECT %s.%s FROM %s AS %s%s WHERE %s.%s = %s.%s)'
            % (
                perm_alias, qn(column.column),
                qn(self.record.root._meta.db_table), root_alias, joins,
                root_alias, qn(self.record.root._meta.pk.column),
                grant_alias, qn(compiler.query.model._meta.pk.column),
            )
        )
        return sql, ()

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)


def _user_match_attname(record):
    """User column this walk compares. Not the primary key when ``to_field`` differs."""
    model = principal_model(record)
    fallback = model._meta.pk.attname
    walk = getattr(record, 'via', None)
    if walk is None:
        return fallback
    if not walk.suffix_path:
        if cuts_users(walk, model):
            return walk.walk_ident
        return fallback
    if len(walk.suffix_path) != 1:
        return fallback
    field = walk.walk_model._meta.get_field(walk.suffix_path[0])
    if getattr(field, 'many_to_many', False):
        forward, _node_col, user_col = _m2m_columns(field)
        through = forward.remote_field.through
        for candidate in through._meta.local_fields:
            if (
                getattr(candidate, 'column', None) == user_col
                and getattr(candidate, 'is_relation', False)
                and getattr(candidate, 'target_field', None) is not None
            ):
                return candidate.target_field.attname
        return fallback
    if getattr(field, 'concrete', False) and getattr(field, 'many_to_one', False):
        target = getattr(field, 'target_field', None)
        if target is not None:
            return target.attname
    return fallback


def _user_source(user, record=None):
    if isinstance(user, Model):
        attname = user._meta.pk.attname
        if record is not None:
            attname = _user_match_attname(record)
        return CallInput(getattr(user, attname), 'user.%s' % attname)
    return user


class _ViaSources(Expression):
    """User, captured rules, and carrier expressions for one walk."""

    def __init__(self, record, user, *, mode, output_field=None):
        if output_field is None:
            super().__init__()
        else:
            super().__init__(output_field=output_field)
        self.record = record
        self.mode = mode
        self.via_bound = record.via.bound
        self.user = _user_source(user, record)
        self.rules, self.filters, self.content = _capture(record)
        _ignored, self.carriers = _render_hop(
            record, self.rules, self.filters, self.content, lambda name: name,
        )

    def get_source_expressions(self):
        exprs = []
        if self.user is not None:
            exprs.append(self.user)
        exprs.extend(self.carriers)
        return exprs

    def set_source_expressions(self, exprs):
        exprs = list(exprs)
        if self.user is not None and exprs:
            self.user = exprs.pop(0)
        self.carriers = exprs


class ViaReach(_ViaSources):
    """Bounded user reach for one grant or delegation row.

    ``from_row`` seeds the walk from this row and matches ``user``.
    ``from_value`` seeds the walk from ``user`` and matches the user
    column of ``match_record``. The recursive member does not read the
    outer query.
    """

    filterable = True
    subquery = True

    def __init__(self, record, user, *, mode, match_record=None):
        super().__init__(record, user, mode=mode, output_field=BooleanField())
        self.match_record = record if match_record is None else match_record

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        w_sql, w_params = _reach_sql(
            self, compiler, connection,
        )
        match_sql, match_params = self._match_sql(
            compiler, connection, w_sql,
        )
        return match_sql, tuple(match_params) + tuple(w_params)

    def _match_sql(self, compiler, connection, w_sql):
        qn = connection.ops.quote_name
        if self.mode == 'from_value':
            user_sql, user_params = _stored_user_sql(
                compiler, connection, qn, self.match_record,
            )
        else:
            user_sql, user_params = compiler.compile(self.user)
        sql = _user_in_reach(
            self.record.via, user_sql, w_sql, qn, principal_model(self.record),
        )
        return sql, user_params


class _ReachedUsers(_ViaSources):
    """User ids reached by one walk. The depth cap is ``via_bound``."""

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        w_sql, w_params = _reach_sql(self, compiler, connection)
        qn = connection.ops.quote_name
        sql = _users_select(
            self.record.via, w_sql, qn, principal_model(self.record),
        )
        return sql, tuple(w_params)


class ViaMeet(Expression):
    """A user reached by the sponsor walk and by the ordinary walk."""

    filterable = True
    subquery = True

    def __init__(self, delegation, ordinary):
        super().__init__(output_field=BooleanField())
        self.sponsor_users = _ReachedUsers(
            delegation, walk_seed_expression(delegation), mode='from_value',
        )
        self.ordinary_users = _ReachedUsers(
            ordinary, None, mode='from_row',
        )

    def get_source_expressions(self):
        return [self.sponsor_users, self.ordinary_users]

    def set_source_expressions(self, exprs):
        self.sponsor_users, self.ordinary_users = exprs

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        left_sql, left_params = compiler.compile(self.sponsor_users)
        right_sql, right_params = compiler.compile(self.ordinary_users)
        alias = qn('su')
        sql = (
            'EXISTS (SELECT 1 FROM (%s) AS %s WHERE %s.%s IN (%s))'
            % (left_sql, alias, alias, qn('user_id'), right_sql)
        )
        return sql, tuple(left_params) + tuple(right_params)


def _reach_sql(node, compiler, connection):
    qn = connection.ops.quote_name
    token = _reuse.set(node.carriers)
    try:
        template, _fresh = _render_hop(
            node.record, node.rules, node.filters, node.content, qn,
        )
    finally:
        _reuse.reset(token)
    names = ['c%s' % index for index in range(len(node.carriers))]
    seed_sql, seed_params = _seed_sql(
        node, compiler, connection, qn, template, names,
    )
    hop_format = {}
    g = qn('g')
    for name in names:
        hop_format[name] = '%s.%s' % (g, qn(name))
    walk = node.record.via
    walked = _HopWalk(walk, template, hop_format) if template else walk
    return _render_reach_sql(
        walked, seed_sql, seed_params, connection, carriers=tuple(names),
    )


def _seed_sql(node, compiler, connection, qn, template, names):
    if node.mode == 'from_value':
        value_sql, value_params = compiler.compile(node.user)
    elif node.user is None and node.mode == 'from_row':
        value_sql, value_params = _row_ident_sql(
            node.record, compiler, connection, qn,
        )
    else:
        value_sql, value_params = _row_ident_sql(
            node.record, compiler, connection, qn,
        )
    ident = qn('ident')
    carrier_sql = []
    carrier_params = []
    carrier_lists = []
    for expr in node.carriers:
        sql, params = compiler.compile(expr)
        carrier_sql.append(sql)
        carrier_params.extend(params)
        carrier_lists.append(tuple(params))
    model = principal_model(node.record)
    cutting = cuts_users(node.record.via, model) and (template or names)
    if not cutting:
        if names:
            raise TrustsConfigurationError(
                'via named filter cannot be written in the recursive member.'
            )
        return 'SELECT %s AS %s' % (value_sql, ident), value_params
    # The starting row is a user. The predicate has to read that row:
    # a projection of ident and carriers has no user columns, so a
    # failing user on the grant would not stop the path.
    alias = qn('hop_user')
    table = qn(model._meta.db_table)
    # The recursive ident is the walk identity, which a self-FK ``to_field``
    # can store in a column other than the primary key.
    identity = qn(_walk_ident_field(node.record.via).column)
    selected = ['%s.%s AS %s' % (alias, identity, ident)]
    for index, sql in enumerate(carrier_sql):
        selected.append('(%s) AS %s' % (sql, qn(names[index])))
    where = '%s.%s = (%s)' % (alias, identity, value_sql)
    params = list(carrier_params)
    params.extend(value_params)
    if template:
        values = {'alias': alias}
        for index, sql in enumerate(carrier_sql):
            values['c%s' % index] = '(%s)' % sql
        where = '%s AND (%s)' % (where, template.format(**values))
        params.extend(_placeholder_params(template, carrier_lists))
    sql = 'SELECT %s FROM %s AS %s WHERE %s' % (
        ', '.join(selected), table, alias, where,
    )
    return sql, tuple(params)


def _placeholder_params(template, carrier_lists):
    """Params for ``{cN}`` placeholders, in the order ``format`` emits them."""
    params = []
    cursor = 0
    while True:
        start = template.find('{c', cursor)
        if start < 0:
            return params
        end = template.find('}', start)
        if end < 0:
            return params
        token = template[start + 2:end]
        if token.isdigit():
            params.extend(carrier_lists[int(token)])
        cursor = end + 1


def _row_ident_sql(record, compiler, connection, qn):
    walk = record.via
    if len(walk.walk_path) == 1:
        alias = qn(compiler.query.get_initial_alias())
        field = record.root._meta.get_field(walk.walk_path[0])
        return '%s.%s' % (alias, qn(field.column)), ()
    col = _walk_identity_column(compiler.query, walk)
    return compiler.compile(col)


def _stored_user_sql(compiler, connection, qn, record):
    path = record.user_path
    if len(path) == 1:
        alias = qn(compiler.query.get_initial_alias())
        field = record.root._meta.get_field(path[0])
        return '%s.%s' % (alias, qn(field.column)), ()
    column = _walk_identity_column(compiler.query, _UserColumn(record))
    return compiler.compile(column)


class _UserColumn(object):
    """Path shape ``_walk_identity_column`` reads for an ordinary user."""

    def __init__(self, record):
        self.walk_path = record.user_path
        self.walk_model = record.user_model
        self.walk_ident = record.user_target


def _user_in_reach(walk, user_sql, w_sql, qn, principal):
    """SQL: ``user_sql`` is a user reached from the walk result ``w_sql``."""
    link = _suffix_link(walk, qn, principal)
    if link is None:
        return '%s IN (%s)' % (user_sql, w_sql)
    table, alias, user_col, node_col = link
    return (
        'EXISTS (SELECT 1 FROM %s AS %s '
        'WHERE %s.%s = %s AND %s.%s IN (%s))'
        % (table, alias, alias, user_col, user_sql, alias, node_col, w_sql)
    )


def _users_select(walk, w_sql, qn, principal):
    """SQL selecting ``user_id`` for every user the walk reaches."""
    user_id = qn('user_id')
    link = _suffix_link(walk, qn, principal)
    if link is None:
        alias = qn('w')
        return 'SELECT DISTINCT %s.%s AS %s FROM (%s) AS %s' % (
            alias, qn('ident'), user_id, w_sql, alias,
        )
    table, alias, user_col, node_col = link
    return (
        'SELECT DISTINCT %s.%s AS %s FROM %s AS %s WHERE %s.%s IN (%s)'
        % (alias, user_col, user_id, table, alias, alias, node_col, w_sql)
    )
