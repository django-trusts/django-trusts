"""Recursive reach expressions.

``GrantReach``, ``_IdentInReach``, ``_KeyedReach``,
``_AnchorInInverseReach``, and ``_PrefixInForwardWalk``. Not a public
import surface. ``trusts.core`` does not re-export them.
"""

__all__ = []

from django.db.models import BooleanField, Exists, F, OuterRef, Q
from django.db.models.expressions import Expression

from trusts.commons import _bind_record_qs
from trusts.plan.walk import (
    _content_walk_seed,
    _grant_walk_attname,
    _inverse_neighbor_sql,
    _render_keyed_reach_sql,
    _render_reach_sql,
    _require_along_renderer,
    _unwrap_seed_sql,
)


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


class _KeyedReach(Expression):
    """``key IN (carriers whose walk ident is the candidate)``.

    Used on a delegation queryset. ``key`` is a column of that row (the
    sponsor foreign key, or the delegation primary key). ``candidate`` is
    the requested object's walk identity on the outer content query.
    """

    filterable = True
    subquery = True

    def __init__(self, walk, seed_query, key, candidate):
        super().__init__(output_field=BooleanField())
        self.walk = walk
        self.seed_query = seed_query
        self.key = key
        self.candidate = candidate

    def copy(self):
        clone = super().copy()
        clone.seed_query = clone.seed_query.clone()
        return clone

    def get_source_expressions(self):
        return [self.seed_query, self.key, self.candidate]

    def set_source_expressions(self, exprs):
        self.seed_query, self.key, self.candidate = exprs

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        seed_sql, seed_params = self.seed_query.as_sql(compiler, connection)
        seed_sql = _unwrap_seed_sql(seed_sql)
        w_sql, w_params = _render_keyed_reach_sql(
            self.walk, seed_sql, seed_params, connection,
        )
        key_sql, key_params = compiler.compile(self.key)
        cand_sql, cand_params = compiler.compile(self.candidate)
        sql = '(%s) IN (%s(%s))' % (key_sql, w_sql, cand_sql)
        return sql, tuple(key_params) + tuple(w_params) + tuple(cand_params)


class _AnchorInInverseReach(Expression):
    """Delegation walk column ``IN`` the inverse walk from a saved object.

    The seed is the bound content, as in an ordinary reverse ``along=``
    check. The delegation row is correlated only outside the CTE.
    """

    filterable = True
    subquery = True

    def __init__(self, record, content):
        super().__init__(output_field=BooleanField())
        self.record = record
        self.seed_query = _content_walk_seed(record.along, content)

    def copy(self):
        clone = super().copy()
        clone.seed_query = clone.seed_query.clone()
        return clone

    def get_source_expressions(self):
        return [self.seed_query]

    def set_source_expressions(self, exprs):
        self.seed_query = exprs[0]

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        self.seed_query.where.children[0].trusts_content_bind = True
        seed_sql, seed_params = self.seed_query.as_sql(compiler, connection)
        seed_sql = _unwrap_seed_sql(seed_sql)
        w_sql, w_params = _render_reach_sql(
            self.record.along, seed_sql, seed_params, connection,
            neighbor=_inverse_neighbor_sql,
        )
        qn = connection.ops.quote_name
        alias = compiler.query.get_initial_alias()
        attname = _grant_walk_attname(self.record)
        sql = '%s.%s IN (%s)' % (qn(alias), qn(attname), w_sql)
        return sql, tuple(w_params)


class _PrefixInForwardWalk(Expression):
    """Outer prefix column is in the forward grant walk.

    The seed and ``WITH RECURSIVE`` statement are the ones ``GrantReach``
    uses for a forward check. ``suffix_lookup`` is empty when the queryset
    model is the walk site: that identity is compared directly. A later
    prefix passes the path from the walk site to that prefix, and the
    walk-site row must be related to the outer row.
    """

    filterable = True
    subquery = True

    def __init__(self, record, user, permission, attname, *,
                 content_identity=None, suffix_lookup=None):
        super().__init__(output_field=BooleanField())
        walk = record.along
        seed = _bind_record_qs(
            record,
            user=user,
            permission=permission,
            correlation=Q(**{'%s__isnull' % walk.walk_field: False}),
            content_identity=content_identity,
        ).values(ident=F(walk.walk_field)).distinct()
        self.seed_query = seed.query.clone()
        self.seed_query.subquery = True
        self.record = record
        self.lhs = None
        self.suffix_query = None
        if suffix_lookup:
            self.suffix_query = walk.walk_model._default_manager.filter(
                **{suffix_lookup: OuterRef(attname)},
            ).query.clone()
            self.suffix_query.subquery = True
        else:
            self.lhs = F(attname)

    def copy(self):
        clone = super().copy()
        clone.seed_query = clone.seed_query.clone()
        if clone.suffix_query is not None:
            clone.suffix_query = clone.suffix_query.clone()
        return clone

    def get_source_expressions(self):
        exprs = [self.seed_query]
        if self.lhs is not None:
            exprs.append(self.lhs)
        if self.suffix_query is not None:
            exprs.append(self.suffix_query)
        return exprs

    def set_source_expressions(self, exprs):
        exprs = list(exprs)
        self.seed_query = exprs.pop(0)
        if self.lhs is not None:
            self.lhs = exprs.pop(0)
        if self.suffix_query is not None:
            self.suffix_query = exprs.pop(0)

    def as_sql(self, compiler, connection):
        _require_along_renderer(connection)
        seed_sql, seed_params = self.seed_query.as_sql(compiler, connection)
        seed_sql = _unwrap_seed_sql(seed_sql)
        w_sql, w_params = _render_reach_sql(
            self.record.along, seed_sql, seed_params, connection,
        )
        if self.lhs is not None:
            lhs_sql, lhs_params = compiler.compile(self.lhs)
            return (
                '%s IN (%s)' % (lhs_sql, w_sql),
                tuple(lhs_params) + tuple(w_params),
            )
        inner = self.suffix_query.clone()
        inner.add_q(Q(_IdentInReach(
            self.record.along.walk_ident, w_sql, w_params,
            self.record.along.bound,
        )))
        return Exists(inner).as_sql(compiler, connection)
