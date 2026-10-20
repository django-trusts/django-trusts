"""Along walk execution.

Neighbor SQL, reach rendering, and the grant and content seeds. The
five reach expressions stay in ``trusts.plan.recursions``. ``AlongWalk``
stays in ``trusts.compile.paths``. Record binding lives in
``trusts.plan.predicates``.
"""

__all__ = []

from django.db.models import F, Q

from trusts.plan.predicates import bind_record_qs, bind_terminal
from trusts.errors import TrustsConfigurationError


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


def _neighbor_sql(walk, qn, gen, g, ident_col, ident_sql):
    """Join generation ``g`` to the next identity. The CTE is referenced once."""
    source = 'FROM %(gen)s AS %(g)s ' % {'gen': gen, 'g': g}
    if walk.shape == 'S':
        child = qn('child')
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(child)s '
            'ON %(child)s.%(parent_col)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'walk_table': walk_table, 'child': child,
                'parent_col': parent_col, 'ident_col': ident_col,
            }
        )
        project = '%s.%s' % (child, ident_sql)
        return frm, project
    if walk.shape == 'C':
        cur = qn('cur')
        parent = qn('parent')
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(cur)s '
            'ON %(cur)s.%(ident)s = %(g)s.%(ident_col)s '
            'JOIN %(walk_table)s AS %(parent)s '
            'ON %(parent)s.%(ident)s = %(cur)s.%(parent_col)s'
            % {
                'g': g, 'walk_table': walk_table, 'cur': cur,
                'ident': ident_sql, 'ident_col': ident_col,
                'parent': parent, 'parent_col': parent_col,
            }
        )
        project = '%s.%s' % (parent, ident_sql)
        return frm, project
    if walk.shape == 'E':
        link = qn('link')
        edge_table = qn(walk.edge_model._meta.db_table)
        parent_col = qn(walk.edge_parent_attname)
        child_col = qn(walk.edge_child_attname)
        frm = source + (
            'JOIN %(edge_table)s AS %(link)s '
            'ON %(link)s.%(parent_col)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'edge_table': edge_table, 'link': link,
                'parent_col': parent_col, 'ident_col': ident_col,
            }
        )
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
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
            'JOIN %(walk_table)s AS %(cur)s '
            'ON %(cur)s.%(ident)s = %(g)s.%(ident_col)s'
            % {
                'g': g, 'walk_table': walk_table, 'cur': cur,
                'ident': ident_sql, 'ident_col': ident_col,
            }
        )
        return frm, '%s.%s' % (cur, parent_col)
    if walk.shape == 'C':
        child = qn('child')
        parent_col = qn(walk.parent_attname)
        walk_table = qn(walk.walk_model._meta.db_table)
        frm = source + (
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
        parent_col = qn(walk.edge_parent_attname)
        child_col = qn(walk.edge_child_attname)
        frm = source + (
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


def _render_reach_sql(walk, seed_sql, seed_params, connection, neighbor=None):
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
    qn = connection.ops.quote_name
    gen = qn('gen')
    g = qn('g')
    depth = qn('depth')
    ident_col = qn('ident')
    ident = qn(walk.walk_ident)
    walk_table = qn(walk.walk_model._meta.db_table)
    site = qn('s')
    seed_alias = qn('seed_rows')
    if neighbor is None:
        neighbor = _neighbor_sql
    frm, project = neighbor(walk, qn, gen, g, ident_col, ident)
    sql = (
        'WITH RECURSIVE %(gen)s(%(ident_col)s, %(depth)s) AS ('
        'SELECT %(seed_alias)s.%(ident_col)s, 0 '
        'FROM (%(seed_sql)s) AS %(seed_alias)s '
        'UNION ALL '
        'SELECT %(project)s, %(g)s.%(depth)s + 1 '
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
        }
    )
    return sql, tuple(seed_params) + (walk.bound,)


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


def _grant_walk_attname(record):
    """Grant-root column that stores the walk identity.

    The walk site is one hop from the grant root in every Along
    registration this compiler renders. That hop's column is the join
    key outside the recursive CTE.
    """
    walk = record.along
    field = record.root._meta.get_field(walk.walk_path[0])
    return field.attname


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
    qn = connection.ops.quote_name
    gen = qn('gen')
    g = qn('g')
    depth = qn('depth')
    ident_col = qn('ident')
    carrier = qn('carrier')
    ident = qn(walk.walk_ident)
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
    return sql, tuple(seed_params) + (walk.bound,)


def _unwrap_seed_sql(seed_sql):
    if seed_sql.startswith('(') and seed_sql.endswith(')'):
        return seed_sql[1:-1]
    return seed_sql


def _sponsor_walk_seed(ordinary, permission, content_identity):
    """Grant identities that carry the sponsoring user through the walk.

    The seed is not filtered to one user. The delegation row matches its
    sponsor column to ``carrier`` outside the recursive member, so the
    CTE does not reference the delegation row.
    """
    walk = ordinary.along
    qs = bind_record_qs(
        ordinary,
        permission=permission,
        correlation=Q(**{'%s__isnull' % walk.walk_field: False}),
        content_identity=content_identity,
    )
    seed = qs.values(
        carrier=F(ordinary.user_field),
        ident=F(walk.walk_field),
    ).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query


def _delegation_walk_seed(record, user):
    """Delegation-row identities for one delegate.

    ``user`` is the bound actor, a constant in the seed. Reach is matched
    back to ``carrier`` (the delegation primary key) outside the CTE.
    """
    walk = record.along
    qs = record.root._default_manager.filter(**{
        record.delegate_field: bind_terminal(user, 'delegate'),
        '%s__isnull' % walk.walk_field: False,
    })
    seed = qs.values(
        carrier=F(record.root._meta.pk.attname),
        ident=F(walk.walk_field),
    ).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query
