"""Helpers shared by relation plans, recursive reach, and content grants.

These names are the overlap of those three compilers. This module is
not a public import surface. ``trusts.core`` re-exports every name
defined here.
"""

__all__ = []

from django.db.models import BooleanField, Exists, F, Model, OuterRef, Q
from django.db.models.expressions import Expression

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


class _IdentInReach(Expression):
    """Boolean predicate ``alias.ident IN (W)`` compiled on the inner query."""

    def __init__(self, attname, w_sql, w_params, bound):
        super().__init__(output_field=BooleanField())
        self.attname = attname
        self.w_sql = w_sql
        self.w_params = w_params
        self.bound = bound

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        alias = compiler.query.get_initial_alias()
        sql = '%s.%s IN (%s)' % (qn(alias), qn(self.attname), self.w_sql)
        return sql, tuple(self.w_params)


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


class GrantReach(Expression):
    """Grant-anchored bounded reachability predicate for one recursive record.

    The forward walk is uncorrelated with candidate rows. One plain
    ``IN (WITH RECURSIVE …)`` per recursive record, with a depth counter
    capped at the bound. The reverse walk is also uncorrelated. It
    derives walk-site identities from the bound content, walks the
    inverse edges once without the outer user, then joins eligible
    grants and candidate users outside the CTE. The grant query is
    correlated to the outer candidate user only after the walk. SQLite
    and MySQL 8.4+ use that statement.
    PostgreSQL appends ``CYCLE ident SET is_cycle USING path`` and does
    not project those columns. MariaDB and other engines raise before
    walk SQL.
    """

    filterable = True
    subquery = True

    def __init__(self, record, user, permission, content=None, *, content_identity=None):
        super().__init__(output_field=BooleanField())
        self.record = record
        self.content = content
        walk = record.along
        self.lhs = None
        self.suffix_query = None
        self.grant_query = None
        if content is not None:
            self.seed_query = _content_walk_seed(walk, content)
            grant = _bind_record_qs(
                record,
                user=user,
                permission=permission,
                content_identity=content_identity,
            )
            self.grant_query = grant.query.clone()
            self.grant_query.subquery = True
            return
        seed = _bind_record_qs(
            record,
            user=user,
            permission=permission,
            correlation=Q(**{'%s__isnull' % walk.walk_field: False}),
            content_identity=content_identity,
        ).values(ident=F(walk.walk_field)).distinct()
        self.seed_query = seed.query.clone()
        self.seed_query.subquery = True
        if walk.rewrite_attname:
            self.lhs = F(walk.rewrite_attname)
        elif not walk.suffix_path:
            self.lhs = F(walk.walk_ident)
        else:
            self.suffix_query = walk.walk_model._default_manager.filter(
                **{walk.suffix_field: OuterRef(record.content_target)}
            ).query.clone()
            self.suffix_query.subquery = True

    def copy(self):
        clone = super().copy()
        clone.seed_query = clone.seed_query.clone()
        if clone.grant_query is not None:
            clone.grant_query = clone.grant_query.clone()
        if clone.suffix_query is not None:
            clone.suffix_query = clone.suffix_query.clone()
        return clone

    def get_source_expressions(self):
        exprs = [self.seed_query]
        if self.grant_query is not None:
            exprs.append(self.grant_query)
        if self.lhs is not None:
            exprs.append(self.lhs)
        if self.suffix_query is not None:
            exprs.append(self.suffix_query)
        return exprs

    def set_source_expressions(self, exprs):
        exprs = list(exprs)
        self.seed_query = exprs.pop(0)
        if self.grant_query is not None:
            self.grant_query = exprs.pop(0)
        if self.lhs is not None:
            self.lhs = exprs.pop(0)
        if self.suffix_query is not None:
            self.suffix_query = exprs.pop(0)

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        if self.content is not None:
            return self._reverse_sql(compiler, connection)
        seed_sql, seed_params = self._seed_sql(compiler, connection)
        w_sql, w_params = _render_reach_sql(
            self.record.along, seed_sql, seed_params, connection,
        )
        if self.lhs is not None:
            lhs_sql, lhs_params = compiler.compile(self.lhs)
            return '%s IN (%s)' % (lhs_sql, w_sql), tuple(lhs_params) + tuple(w_params)
        inner = self.suffix_query.clone()
        inner.add_q(Q(_IdentInReach(
            self.record.along.walk_ident, w_sql, w_params,
            self.record.along.bound,
        )))
        return Exists(inner).as_sql(compiler, connection)

    def _seed_sql(self, compiler, connection):
        seed_sql, seed_params = self.seed_query.as_sql(compiler, connection)
        if seed_sql.startswith('(') and seed_sql.endswith(')'):
            seed_sql = seed_sql[1:-1]
        return seed_sql, seed_params

    def _reverse_sql(self, compiler, connection):
        # Resolve may clone the seed. Keep the content comparison marked.
        self.seed_query.where.children[0].trusts_content_bind = True
        seed_sql, seed_params = self._seed_sql(compiler, connection)
        w_sql, w_params = _render_reach_sql(
            self.record.along, seed_sql, seed_params, connection,
            neighbor=_inverse_neighbor_sql,
        )
        inner = self.grant_query.clone()
        inner.add_q(Q(_IdentInReach(
            _grant_walk_attname(self.record),
            w_sql, w_params, self.record.along.bound,
        )))
        return Exists(inner).as_sql(compiler, connection)


_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}


def _require_instance(value, role):
    if not isinstance(value, Model):
        raise TrustsConfigurationError(
            '%s must be a model instance, not %r.' % (role, value)
        )
    return value
