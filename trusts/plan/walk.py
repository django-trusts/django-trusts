"""Along walk execution.

Neighbor SQL, reach rendering, and the grant and content seeds. The
five reach expressions stay in ``trusts.plan.recursions``. ``AlongWalk``
stays in ``trusts.compile.graph``. Record binding lives in
``trusts.plan.predicates``.
"""

__all__ = []

from django.db.models import F, Q
from django.db.models.fields.related import ManyToManyRel

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.predicates import bind_record_qs, bind_terminal
from trusts.plan.trivalent import (
    Expr,
    Scope,
    _export_param,
    _exporting,
    _runtime_param,
    has_contains,
    lower,
)
from trusts.plan.writers import member_pk


_DJANGO_SQLITE3 = 'django.db.backends.sqlite3'


_ALONG_ENGINES = frozenset((
    _DJANGO_SQLITE3,
    'django.db.backends.postgresql',
    'django.db.backends.mysql',
))


def along_connection_supported(connection):
    """True for SQLite, PostgreSQL, or MySQL 8.4+.

    MariaDB uses Django's mysql backend and is not supported yet.
    ``mysql_is_mariadb is True`` rejects it before walk SQL. Other
    engines do not carry that flag.
    """
    engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
    if engine not in _ALONG_ENGINES:
        return False
    return getattr(connection, 'mysql_is_mariadb', False) is not True


def _require_along_renderer(connection):
    if along_connection_supported(connection):
        return
    engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
    raise TrustsConfigurationError(
        'Along reachability requires a recursive CTE on Django sqlite3, '
        'postgresql, or mysql; got ENGINE=%r vendor=%r alias=%r.'
        % (
            engine,
            getattr(connection, 'vendor', None),
            getattr(connection, 'alias', None),
        )
    )


def _and_sql(predicate):
    if not predicate:
        return ''
    return ' AND ' + predicate


def _model_column(model, attname):
    """Database column for ``attname``. ``db_column`` may differ from it."""
    for field in model._meta.concrete_fields:
        if field.attname == attname:
            return field.column
    raise TrustsConfigurationError(
        'Along column %r is not a concrete field on %s.'
        % (attname, model._meta.label)
    )


def _column_or_attname(model, attname):
    """Column for ``attname`` when ``model`` owns it, else ``attname``.

    A bind-once probe compiles an along predicate with the outer query's
    model. That probe must not raise. The statement compiler resolves
    the column on the query that owns the field.
    """
    if model is None:
        return attname
    for field in model._meta.concrete_fields:
        if field.attname == attname:
            return field.column
    return attname


def _m2m_columns(field):
    """Through columns ``(forward field, node column, user column)``."""
    if isinstance(field, ManyToManyRel):
        forward = field.field
        return forward, forward.m2m_reverse_name(), forward.m2m_column_name()
    return field, field.m2m_column_name(), field.m2m_reverse_name()


def _quoted_column(model, attname, qn):
    """Quote the database column for an attname.

    SQL has to name ``db_column`` when it differs from the attname. The
    attname stays the ORM identity used to match the two ends of a walk.
    """
    if model is not None and attname:
        for field in model._meta.concrete_fields:
            if field.attname == attname:
                return qn(field.column)
    return qn(attname)


def _suffix_link(walk, qn, principal):
    """One-hop table that joins a user to a walk ident, or ``None``.

    The same link is the membership test and the user-id projection.
    Columns are already quoted.
    """
    if not walk.suffix_path:
        return None
    if len(walk.suffix_path) != 1:
        raise TrustsConfigurationError(
            'via suffix %r cannot be compiled.'
            % ('__'.join(walk.suffix_path),)
        )
    field = walk.walk_model._meta.get_field(walk.suffix_path[0])
    if getattr(field, 'many_to_many', False):
        forward, node_col, user_col = _m2m_columns(field)
        return (
            qn(forward.remote_field.through._meta.db_table),
            qn('mem'),
            qn(user_col),
            qn(node_col),
        )
    if getattr(field, 'concrete', False) and getattr(field, 'many_to_one', False):
        return (
            qn(walk.walk_model._meta.db_table),
            qn('site'),
            qn(field.column),
            _quoted_column(walk.walk_model, walk.walk_ident, qn),
        )
    if walk.rewrite_attname:
        fk = principal._meta.get_field(walk.rewrite_attname)
        return (
            qn(principal._meta.db_table),
            qn('reached_user'),
            qn(principal._meta.pk.column),
            qn(fk.column),
        )
    raise TrustsConfigurationError(
        'via suffix %r cannot be compiled.' % (walk.suffix_field,)
    )


class _ProofOps(object):
    def quote_name(self, name):
        return '"%s"' % name

    def adapt_booleanfield_value(self, value):
        return value


class _ProofConnection(object):
    """Quoter used to prove a condition renders. It does not open a database."""

    vendor = 'sqlite'
    ops = _ProofOps()
    mysql_is_mariadb = False


class _CompiledWalk(object):
    """Walk plus the SQL for its path condition and any hop already stored."""

    def __init__(self, walk, hop_sql, hop_format=None):
        self._walk = walk
        self.hop_sql = hop_sql
        self.hop_format = hop_format or {}

    def __getattr__(self, name):
        return getattr(self._walk, name)


def _condition_params(params, connection):
    if _exporting():
        return tuple(_export_param(param) for param in params)
    return tuple(_runtime_param(param, connection) for param in params)


def _prepare_walk(walk, connection):
    """Compile a stored path condition into the per-hop predicate."""
    condition = getattr(walk, 'condition', None)
    if condition is None:
        return walk, ()
    expr = compile_walk_condition(condition, walk.walk_model, connection)
    sql = expr.sql
    existing = getattr(walk, 'hop_sql', None) or ''
    if existing:
        sql = '(%s) AND (%s)' % (sql, existing)
    hop_format = getattr(walk, 'hop_format', None) or {}
    return (
        _CompiledWalk(walk, sql, hop_format),
        _condition_params(expr.params, connection),
    )


def prove_walk_condition(node, model):
    """Reject a condition that cannot be rendered. No query is issued."""
    compile_walk_condition(node, model, _ProofConnection())


def compile_walk_condition(node, model, connection):
    """SQL for ``node`` on one walked row. ``{alias}`` names that row."""
    return _lower_walk_node(node, model, connection)


def _lower_walk_node(node, model, connection):
    qn = connection.ops.quote_name
    if node.kind == 'contains':
        return _contains_expr(node, model, qn)
    if node.kind in ('and', 'or') and has_contains(node):
        left = _lower_walk_node(node.left, model, connection)
        right = _lower_walk_node(node.right, model, connection)
        word = 'AND' if node.kind == 'and' else 'OR'
        return Expr(
            '((%s) %s (%s))' % (left.sql, word, right.sql),
            left.params + right.params,
        )
    if node.kind == 'not' and has_contains(node):
        inner = _lower_walk_node(node.item, model, connection)
        return Expr('(NOT (%s))' % inner.sql, inner.params)
    try:
        return lower(node, Scope(
            {'row': ('alias', model, ())}, qn, connection, '{alias}',
        ))
    except PermissionConditionError:
        raise
    except Exception as exc:
        raise PermissionConditionError(
            'This condition cannot be rendered in SQL: %s' % exc
        ) from exc


def _contains_expr(node, model, qn):
    left = node.left
    if getattr(left, 'kind', None) != 'field' or left.root != 'row' or not left.path:
        raise PermissionConditionError(
            'This condition cannot be rendered in SQL.'
        )
    current = model
    hops = []
    field = None
    for index, name in enumerate(left.path):
        try:
            field = current._meta.get_field(name)
        except Exception as exc:
            raise PermissionConditionError(
                'This condition cannot be rendered in SQL.'
            ) from exc
        last = index == len(left.path) - 1
        if not last:
            if not (
                getattr(field, 'concrete', False)
                and (
                    getattr(field, 'many_to_one', False)
                    or getattr(field, 'one_to_one', False)
                )
            ):
                raise PermissionConditionError(
                    'This condition cannot be rendered in SQL.'
                )
            hops.append(field)
            current = field.remote_field.model
    member_sql, member_params = _member_sql(node.right, model, qn)
    if getattr(field, 'many_to_many', False) and not isinstance(field, ManyToManyRel):
        return _m2m_contains(field, hops, member_sql, member_params, qn)
    if getattr(field, 'concrete', False) and not getattr(field, 'many_to_many', False):
        return _column_equals(hops, field, member_sql, member_params, qn)
    raise PermissionConditionError(
        'This condition cannot be rendered in SQL.'
    )


def _member_sql(node, model, qn):
    if getattr(node, 'kind', None) == 'const':
        return '%s', (member_pk(node.value),)
    if (
        getattr(node, 'kind', None) == 'field'
        and node.root == 'row'
        and len(node.path) == 1
    ):
        try:
            field = model._meta.get_field(node.path[0])
        except Exception as exc:
            raise PermissionConditionError(
                'This condition cannot be rendered in SQL.'
            ) from exc
        if getattr(field, 'concrete', False) and not getattr(field, 'many_to_many', False):
            return '{alias}.%s' % qn(field.column), ()
    raise PermissionConditionError(
        'This condition cannot be rendered in SQL.'
    )


def _chain(hops, qn):
    """Related-row FROM clause correlated to ``{alias}``, and that row's alias."""
    if not hops:
        return '{alias}', '', ''
    first = hops[0]
    dest = qn('cnd0')
    frm = '%s AS %s' % (qn(first.remote_field.model._meta.db_table), dest)
    where = '%s.%s = {alias}.%s' % (
        dest, qn(first.target_field.column), qn(first.column),
    )
    prev = dest
    for index, field in enumerate(hops[1:], start=1):
        nxt = qn('cnd%s' % index)
        frm += ' JOIN %s AS %s ON %s.%s = %s.%s' % (
            qn(field.remote_field.model._meta.db_table), nxt,
            nxt, qn(field.target_field.column),
            prev, qn(field.column),
        )
        prev = nxt
    return prev, frm, where


def _column_equals(hops, field, member_sql, member_params, qn):
    if not hops:
        return Expr(
            '{alias}.%s = %s' % (qn(field.column), member_sql), member_params,
        )
    owner, frm, where = _chain(hops, qn)
    sql = '(SELECT %s.%s FROM %s WHERE %s) = %s' % (
        owner, qn(field.column), frm, where, member_sql,
    )
    return Expr(sql, member_params)


def _fk_for_column(model, column):
    for candidate in model._meta.local_fields:
        if (
            getattr(candidate, 'column', None) == column
            and getattr(candidate, 'is_relation', False)
        ):
            return candidate
    raise PermissionConditionError(
        'This condition cannot be rendered in SQL.'
    )


def _m2m_contains(field, hops, member_sql, member_params, qn):
    forward, here_col, there_col = _m2m_columns(field)
    through = forward.remote_field.through
    here_fk = _fk_for_column(through, here_col)
    far_fk = _fk_for_column(through, there_col)
    probe = qn('cndm')
    through_sql = '%s AS %s' % (qn(through._meta.db_table), probe)
    owner, frm, where = _chain(hops, qn)
    link = '%s.%s = %s.%s' % (
        probe, qn(here_fk.column), owner, qn(here_fk.target_field.column),
    )
    far = '%s.%s = %s' % (probe, qn(far_fk.column), member_sql)
    if hops:
        sql = 'EXISTS (SELECT 1 FROM %s JOIN %s ON %s WHERE %s AND %s)' % (
            frm, through_sql, link, where, far,
        )
    else:
        sql = 'EXISTS (SELECT 1 FROM %s WHERE %s AND %s)' % (
            through_sql, link, far,
        )
    return Expr(sql, member_params)


def _hop_predicate(walk, qn, node_alias):
    """Condition text on one walked node. Empty when the hop is unconditional.

    ``{alias}`` in the stored template is this node's quoted alias.
    ``{c0}`` and the following names are values copied onto the
    recursive row. The text does not name the recursive result inside a
    subquery and it does not read the outer query. AND-ing the text into
    the hop keeps the step only when the condition is true. False and
    NULL do not match.
    """
    template = getattr(walk, 'hop_sql', None)
    if not template:
        return ''
    values = {'alias': node_alias}
    extra = getattr(walk, 'hop_format', None)
    if extra:
        values.update(extra)
    return template.format(**values)


def _entered_predicate(walk, qn, node_alias):
    """Condition text for the row a hop is entering."""
    return _hop_predicate(walk, qn, node_alias)


def _node_guard(walk, qn, match_sql):
    """Join the walked row when this step does not already expose it.

    The joined alias supplies the columns the condition reads. The
    predicate is true only for a step that continues.
    """
    alias = qn('rstn')
    predicate = _entered_predicate(walk, qn, alias)
    if not predicate:
        return ''
    return (
        'JOIN %s AS %s ON %s.%s = %s AND %s '
        % (
            qn(walk.walk_model._meta.db_table),
            alias,
            alias,
            qn(_model_column(walk.walk_model, walk.walk_ident)),
            match_sql,
            predicate,
        )
    )


def _neighbor_sql(walk, qn, gen, g, ident_col, ident_sql):
    """Join generation ``g`` to the next identity. The CTE is referenced once."""
    source = 'FROM %(gen)s AS %(g)s ' % {'gen': gen, 'g': g}
    if walk.shape == 'S':
        child = qn('child')
        parent_col = qn(_model_column(walk.walk_model, walk.parent_attname))
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(child)s '
            'ON %(child)s.%(parent_col)s = %(g)s.%(ident_col)s%(extra)s'
            % {
                'g': g, 'walk_table': walk_table, 'child': child,
                'parent_col': parent_col, 'ident_col': ident_col,
                'extra': _and_sql(_entered_predicate(walk, qn, child)),
            }
        )
        project = '%s.%s' % (child, ident_sql)
        return frm, project
    if walk.shape == 'C':
        cur = qn('cur')
        parent = qn('parent')
        parent_col = qn(_model_column(walk.walk_model, walk.parent_attname))
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(cur)s '
            'ON %(cur)s.%(ident)s = %(g)s.%(ident_col)s '
            'JOIN %(walk_table)s AS %(parent)s '
            'ON %(parent)s.%(ident)s = %(cur)s.%(parent_col)s%(extra)s'
            % {
                'g': g, 'walk_table': walk_table, 'cur': cur,
                'ident': ident_sql, 'ident_col': ident_col,
                'parent': parent, 'parent_col': parent_col,
                'extra': _and_sql(_entered_predicate(walk, qn, parent)),
            }
        )
        project = '%s.%s' % (parent, ident_sql)
        return frm, project
    if walk.shape == 'E':
        link = qn('link')
        edge_table = qn(walk.edge_model._meta.db_table)
        parent_col = qn(_model_column(walk.edge_model, walk.edge_parent_attname))
        child_col = qn(_model_column(walk.edge_model, walk.edge_child_attname))
        frm = source + (
            'JOIN %(edge_table)s AS %(link)s '
            'ON %(link)s.%(parent_col)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'edge_table': edge_table, 'link': link,
                'parent_col': parent_col, 'ident_col': ident_col,
            }
        )
        guard = _node_guard(walk, qn, '%s.%s' % (link, child_col))
        if guard:
            frm += ' ' + guard
        project = '%s.%s' % (link, child_col)
        return frm, project
    raise TrustsConfigurationError(
        'Unsupported Along shape %r.' % (walk.shape,)
    )


def _inverse_neighbor_sql(walk, qn, gen, g, ident_col, ident_sql):
    """Walk one hop backward. The CTE is still referenced once.

    Shape S forward visits children, so the inverse projects the parent.
    Shape C forward visits parents, so the inverse visits children.
    Shape E forward follows parent to child, so the inverse follows
    child to parent.
    """
    source = 'FROM %(gen)s AS %(g)s ' % {'gen': gen, 'g': g}
    if walk.shape == 'S':
        cur = qn('cur')
        parent_col = qn(_model_column(walk.walk_model, walk.parent_attname))
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(cur)s '
            'ON %(cur)s.%(ident)s = %(g)s.%(ident_col)s%(extra)s'
            % {
                'g': g, 'walk_table': walk_table, 'cur': cur,
                'ident': ident_sql, 'ident_col': ident_col,
                'extra': _and_sql(_entered_predicate(walk, qn, cur)),
            }
        )
        return frm, '%s.%s' % (cur, parent_col)
    if walk.shape == 'C':
        child = qn('child')
        parent_col = qn(_model_column(walk.walk_model, walk.parent_attname))
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + _node_guard(
            walk, qn, '%s.%s' % (g, ident_col),
        ) + (
            'JOIN %(walk_table)s AS %(child)s '
            'ON %(child)s.%(parent_col)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'walk_table': walk_table, 'child': child,
                'parent_col': parent_col, 'ident_col': ident_col,
            }
        )
        return frm, '%s.%s' % (child, ident_sql)
    if walk.shape == 'E':
        link = qn('link')
        edge_table = qn(walk.edge_model._meta.db_table)
        parent_col = qn(_model_column(walk.edge_model, walk.edge_parent_attname))
        child_col = qn(_model_column(walk.edge_model, walk.edge_child_attname))
        frm = source + _node_guard(
            walk, qn, '%s.%s' % (g, ident_col),
        ) + (
            'JOIN %(edge_table)s AS %(link)s '
            'ON %(link)s.%(child_col)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'edge_table': edge_table, 'link': link,
                'child_col': child_col, 'ident_col': ident_col,
            }
        )
        return frm, '%s.%s' % (link, parent_col)
    raise TrustsConfigurationError(
        'Unsupported Along shape %r.' % (walk.shape,)
    )


def _along_cycle_clause(connection, ident_col, qn):
    """One PostgreSQL cycle suffix. SQLite and MySQL stay plain.

    ``CYCLE ident SET is_cycle USING path`` prunes only a path that
    revisits an ident already on that same path. It does not suppress
    diamonds. The outer query does not select the added columns. The
    depth cap still guarantees termination on every engine.
    """
    if getattr(connection, 'vendor', None) != 'postgresql':
        return ''
    return 'CYCLE %s SET %s USING %s ' % (
        ident_col, qn('is_cycle'), qn('path'),
    )


def _render_reach_sql(walk, seed_sql, seed_params, connection, neighbor=None,
                      carriers=()):
    """Return ``(sql, params)`` for the uncorrelated W membership list.

    SQLite, PostgreSQL, and MySQL 8.4+ share one plain ``WITH RECURSIVE``:
    ``UNION ALL``, a depth column capped at the ``along`` bound, and one
    join to the next hop. The cap guarantees termination. On SQLite and
    MySQL, ``UNION ALL`` can revisit a cycle. PostgreSQL appends
    ``CYCLE ident SET is_cycle USING path``, which prunes only a path
    that revisits an ident already on that same path, and does not
    project those columns. A diamond is not such a path, so fan-out to
    the same node by two routes multiplies on all three engines, bounded
    by the cap. The outer ``DISTINCT`` keeps the reachable set correct.
    That growth is the accepted tradeoff for dropping the JSON seen-set.
    The lockfile records the plain statement. MariaDB is rejected before
    this SQL.
    """
    walk, hop_params = _prepare_walk(walk, connection)
    qn = connection.ops.quote_name
    gen = qn('gen')
    g = qn('g')
    depth = qn('depth')
    ident_col = qn('ident')
    ident = qn(_model_column(walk.walk_model, walk.walk_ident))
    walk_table = qn(walk.walk_model._meta.db_table)
    site = qn('s')
    seed_alias = qn('seed_rows')
    if neighbor is None:
        neighbor = _neighbor_sql
    frm, project = neighbor(walk, qn, gen, g, ident_col, ident)
    carrier_cols = ''
    carrier_seed = ''
    carrier_copy = ''
    for name in carriers:
        quoted = qn(name)
        carrier_cols += ', %s' % quoted
        carrier_seed += ', %s.%s' % (seed_alias, quoted)
        carrier_copy += ', %s.%s' % (g, quoted)
    sql = (
        'WITH RECURSIVE %(gen)s(%(ident_col)s%(carrier_cols)s, %(depth)s) AS ('
        'SELECT %(seed_alias)s.%(ident_col)s%(carrier_seed)s, 0 '
        'FROM (%(seed_sql)s) AS %(seed_alias)s '
        'UNION ALL '
        'SELECT %(project)s%(carrier_copy)s, %(g)s.%(depth)s + 1 '
        '%(frm)s '
        'WHERE %(g)s.%(depth)s < %%s AND %(project)s IS NOT NULL'
        ') '
        '%(cycle)s'
        'SELECT DISTINCT %(site)s.%(ident)s '
        'FROM %(gen)s '
        'JOIN %(walk_table)s AS %(site)s '
        'ON %(site)s.%(ident)s = %(gen)s.%(ident_col)s'
        % {
            'gen': gen, 'ident_col': ident_col, 'depth': depth,
            'seed_alias': seed_alias, 'seed_sql': seed_sql,
            'project': project, 'g': g, 'frm': frm,
            'site': site, 'ident': ident, 'walk_table': walk_table,
            'cycle': _along_cycle_clause(connection, ident_col, qn),
            'carrier_cols': carrier_cols,
            'carrier_seed': carrier_seed,
            'carrier_copy': carrier_copy,
        }
    )
    return sql, tuple(seed_params) + tuple(hop_params) + (walk.bound,)


def _content_walk_seed(walk, content):
    """Walk-site identities derived from the bound content.

    No user and no grant table. An empty suffix selects that content's
    walk-site identity. A suffix selects the related walk-site rows,
    such as the Cabinet identities for a Sheet.
    """
    if not walk.suffix_path:
        qs = walk.walk_model._default_manager.filter(
            **{walk.walk_ident: getattr(content, walk.walk_ident)},
        )
    else:
        qs = walk.walk_model._default_manager.filter(
            **{walk.suffix_field: content},
        )
    # ``values(ident=...)`` collides when the walk identity column is
    # already named ``ident`` (a UUID ``to_field``). Selecting that
    # column keeps the seed alias the walk template reads.
    if walk.walk_ident == 'ident':
        seed = qs.values(walk.walk_ident).distinct()
    else:
        seed = qs.values(ident=F(walk.walk_ident)).distinct()
    query = seed.query.clone()
    query.subquery = True
    # Policy SQL binds content.<target> only for this comparison.
    query.where.children[0].trusts_content_bind = True
    return query


def _grant_walk_attname(record, walk=None):
    """Grant-root column that stores a one-hop walk identity.

    A direct hop keeps that identity on the root row, and that column is
    the comparison outside the recursive CTE. A longer path does not.
    Callers join ``_walk_identity_column`` instead of reading this.
    """
    if walk is None:
        walk = record.along
    if len(walk.walk_path) != 1:
        raise TrustsConfigurationError(
            'Walk path %r is not one hop; the walk identity is not '
            'a column of %s.'
            % ('__'.join(walk.walk_path), record.root._meta.label)
        )
    field = record.root._meta.get_field(walk.walk_path[0])
    return field.attname


def _walk_ident_field(walk):
    """Concrete walk-site field whose attname is the walk identity."""
    for field in walk.walk_model._meta.concrete_fields:
        if field.attname == walk.walk_ident:
            return field
    raise TrustsConfigurationError(
        'Along walk identity %r is not a concrete field on %s.'
        % (walk.walk_ident, walk.walk_model._meta.label)
    )


def _walk_identity_column(query, walk, reuse=None):
    """Join the full walk path and return the walk-site identity column.

    The forward seed already selects ``walk_field``. The upward walk has
    to compare that same column, including when the walk site is a
    reverse one-to-many more than one hop from the grant row.
    """
    field = _walk_ident_field(walk)
    join_info = query.setup_joins(
        [*walk.walk_path, field.name],
        query.get_meta(),
        query.get_initial_alias(),
        can_reuse=reuse,
        allow_many=True,
    )
    targets, alias, _joins = query.trim_joins(
        join_info.targets, join_info.joins, join_info.path,
    )
    if len(targets) != 1:
        raise TrustsConfigurationError(
            'Along walk identity %r does not resolve to one column.'
            % (walk.walk_ident,)
        )
    return targets[0].get_col(alias)


def _render_keyed_reach_sql(walk, seed_sql, seed_params, connection, neighbor=None):
    """Recursive walk that carries one non-identity column.

    ``seed_sql`` selects ``carrier`` and ``ident``. The recursive member
    copies ``carrier`` and replaces ``ident`` with the next hop. The final
    select returns carriers whose ident equals the caller's candidate.
    The recursive member does not reference the outer query. The depth
    cap is the same bound as an ordinary ``along=`` walk. PostgreSQL's
    ``CYCLE`` clause stays the only engine-specific suffix, and it still
    names the ident column.
    """
    walk, hop_params = _prepare_walk(walk, connection)
    qn = connection.ops.quote_name
    gen = qn('gen')
    g = qn('g')
    depth = qn('depth')
    ident_col = qn('ident')
    carrier = qn('carrier')
    ident = qn(_model_column(walk.walk_model, walk.walk_ident))
    walk_table = qn(walk.walk_model._meta.db_table)
    site = qn('s')
    seed_alias = qn('seed_rows')
    if neighbor is None:
        neighbor = _neighbor_sql
    frm, project = neighbor(walk, qn, gen, g, ident_col, ident)
    sql = (
        'WITH RECURSIVE %(gen)s(%(carrier)s, %(ident_col)s, %(depth)s) AS ('
        'SELECT %(seed_alias)s.%(carrier)s, %(seed_alias)s.%(ident_col)s, 0 '
        'FROM (%(seed_sql)s) AS %(seed_alias)s '
        'UNION ALL '
        'SELECT %(g)s.%(carrier)s, %(project)s, %(g)s.%(depth)s + 1 '
        '%(frm)s '
        'WHERE %(g)s.%(depth)s < %%s AND %(project)s IS NOT NULL'
        ') '
        '%(cycle)s'
        'SELECT DISTINCT %(gen)s.%(carrier)s '
        'FROM %(gen)s '
        'JOIN %(walk_table)s AS %(site)s '
        'ON %(site)s.%(ident)s = %(gen)s.%(ident_col)s '
        'WHERE %(site)s.%(ident)s = '
        % {
            'gen': gen, 'carrier': carrier, 'ident_col': ident_col,
            'depth': depth, 'seed_alias': seed_alias, 'seed_sql': seed_sql,
            'project': project, 'g': g, 'frm': frm,
            'site': site, 'ident': ident, 'walk_table': walk_table,
            'cycle': _along_cycle_clause(connection, ident_col, qn),
        }
    )
    return sql, tuple(seed_params) + tuple(hop_params) + (walk.bound,)


def _unwrap_seed_sql(seed_sql):
    if seed_sql.startswith('(') and seed_sql.endswith(')'):
        return seed_sql[1:-1]
    return seed_sql


def _sponsor_walk_seed(ordinary, permission, content_identity, *,
                       constraint=None, carrier=None):
    """Grant identities that carry the sponsoring user through the walk.

    The seed is not filtered to one user. The delegation row matches its
    sponsor column to ``carrier`` outside the recursive member, so the
    CTE does not reference the delegation row. ``constraint`` limits the
    seed to users a sponsor walk reaches, and ``carrier`` replaces the
    user column when that comparison is the grant's own primary key.
    """
    walk = ordinary.along
    qs = bind_record_qs(
        ordinary,
        permission=permission,
        correlation=Q(**{'%s__isnull' % walk.walk_field: False}),
        content_identity=content_identity,
    )
    if constraint is not None:
        qs = qs.filter(constraint)
    if carrier is None:
        carrier = F(ordinary.user_field)
    seed = qs.values(
        carrier=carrier,
        ident=F(walk.walk_field),
    ).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query


def _delegation_walk_seed(record, user, user_q=None):
    """Delegation-row identities for one delegate.

    ``user`` is the bound actor, a constant in the seed. Reach is matched
    back to ``carrier`` (the delegation primary key) outside the CTE.
    ``user_q`` replaces delegate equality when the delegate is a walk.
    """
    walk = record.along
    filt = {'%s__isnull' % walk.walk_field: False}
    if user_q is None:
        filt[record.delegate_field] = bind_terminal(user, 'delegate')
    qs = record.root._default_manager.filter(**filt)
    if user_q is not None:
        qs = qs.filter(user_q)
    seed = qs.values(
        carrier=F(record.root._meta.pk.attname),
        ident=F(walk.walk_field),
    ).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query
