"""Bounded SQLite Along reachability (issue #92 / #91 r2+r3).

Isolated noun-neutral models only. Structural and behavioral tests —
no source-token or frozen-SQL-string assertions.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, connections, models
from django.db.models.query import QuerySet
from django.db.utils import OperationalError
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.apps import forget_models, isolate_live_registry
from trusts.checks import CHECK_ID_ALONG_RENDERER, check_along_renderer
from trusts.core import (
    Along,
    BackendHandle,
    GrantReach,
    PlanQueryCompiler,
    Ref,
    TrustsCompilerError,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    common_permissions,
    granted,
)


CONCRETE = 'trusts.backends.TrustModelBackend'


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


def _perm(codename):
    ct, _created = ContentType.objects.get_or_create(
        app_label='trusts_tests', model='node',
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _pks(rows):
    return {row.pk for row in rows}


def _direct_handle(registry, path='tests.along.direct'):
    return BackendHandle(
        path=path, registry=registry, compiler=PlanQueryCompiler(),
    )


def _plan_text(qs):
    sql, params = qs.query.sql_with_params()
    with connection.cursor() as cursor:
        cursor.execute('EXPLAIN QUERY PLAN ' + sql, params)
        return '\n'.join(row[-1] for row in cursor.fetchall())


def _assert_no_historical_names(*models_):
    forbidden = {
        'Trust', 'Content', 'Junction', 'Group', 'Role', 'Windows',
        'FileSystem', 'Filesystem',
    }
    for model in models_:
        names = {cls.__name__ for cls in model.__mro__}
        leftover = forbidden.intersection(names)
        if leftover:
            raise AssertionError('historical noun in mock MRO: %s' % leftover)


def _node_graph_models():
    class Node(models.Model):
        title = models.CharField(max_length=40)
        parent = models.ForeignKey(
            'self', null=True, related_name='children',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Payload(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Row(models.Model):
        node = models.ForeignKey(
            Node, related_name='rows', on_delete=models.CASCADE,
        )
        content = models.ForeignKey(
            Payload, related_name='rows', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Item(models.Model):
        node = models.ForeignKey(
            Node, related_name='items', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Image(models.Model):
        item = models.ForeignKey(
            Item, related_name='image', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class ImageMeta(models.Model):
        image = models.ForeignKey(
            Image, related_name='image', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Portrait(models.Model):
        item = models.OneToOneField(
            Item, related_name='portrait', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Link(models.Model):
        child = models.ForeignKey(
            Node, related_name='parent_links', on_delete=models.CASCADE,
        )
        parent = models.ForeignKey(
            Node, related_name='child_links', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    User = get_user_model()

    class NodeGrant(models.Model):
        node = models.ForeignKey(Node, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class NodePermit(models.Model):
        node = models.ForeignKey(Node, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return (
        Node, Payload, Row, Item, Image, ImageMeta, Portrait, Link,
        NodeGrant, NodePermit,
    )


def _register_along(registry, grant, content_attr='node', along_attr=None, bound=16):
    j = Ref(grant)
    content = getattr(j, content_attr) if isinstance(content_attr, str) else content_attr(j)
    along_ref = j.node.parent if along_attr is None else along_attr(j)
    return registry.register(
        content=content,
        user=j.user,
        permission=j.permission,
        along=Along(along_ref, bound=bound),
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongRegistrationTest(SimpleTestCase):
    def test_s_c_e_and_suffix_metadata(self):
        Node, _p, _r, Item, Image, ImageMeta, Portrait, Link, Grant, _np = (
            _node_graph_models()
        )
        _assert_no_historical_names(Node, Item, Image, ImageMeta, Portrait, Link, Grant)
        registry = TrustsRegistry()
        j = Ref(Grant)
        rec_s = registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertEqual(rec_s.along.shape, 'S')
        self.assertEqual(rec_s.along.walk_path, ('node',))
        self.assertIs(rec_s.along.walk_model, Node)
        self.assertEqual(rec_s.along.walk_ident, Node._meta.pk.attname)
        self.assertEqual(rec_s.along.suffix_path, ())
        self.assertEqual(rec_s.along.parent_attname, 'parent_id')
        self.assertEqual(rec_s.along.ident_family, 'integer')
        self.assertIsNone(rec_s.along.rewrite_attname)

        other = TrustsRegistry()
        rec_c = other.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.children, bound=8),
        )
        self.assertEqual(rec_c.along.shape, 'C')
        self.assertEqual(rec_c.along.parent_attname, 'parent_id')

        rec_e = TrustsRegistry().register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent_links.parent, bound=4),
        )
        self.assertEqual(rec_e.along.shape, 'E')
        self.assertIs(rec_e.along.edge_model, Link)
        self.assertEqual(rec_e.along.edge_parent_attname, 'parent_id')
        self.assertEqual(rec_e.along.edge_child_attname, 'child_id')

        rec_d1 = TrustsRegistry().register(
            content=j.node.items.image, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertEqual(rec_d1.along.suffix_path, ('items', 'image'))
        self.assertEqual(rec_d1.along.suffix_field, 'items__image')
        self.assertIs(rec_d1.content_model, Image)
        self.assertIsNone(rec_d1.along.rewrite_attname)

        rec_d2 = TrustsRegistry().register(
            content=j.node.items.image.image, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertEqual(rec_d2.along.suffix_path, ('items', 'image', 'image'))

        rec_o2o = TrustsRegistry().register(
            content=j.node.items.portrait, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertIs(rec_o2o.content_model, Portrait)

        rec_j1 = TrustsRegistry().register(
            content=j.node.rows.content, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertEqual(rec_j1.along.suffix_field, 'rows__content')

        rec_rev = TrustsRegistry().register(
            content=j.node.items, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertEqual(rec_rev.along.rewrite_attname, 'node')
        self.assertIs(rec_rev.content_model, Item)

    def test_frozen_raises_before_along_validation(self):
        _n, _p, _r, _i, _im, _m, _po, _l, Grant, _np = _node_graph_models()
        registry = TrustsRegistry()
        registry.freeze()
        j = Ref(Grant)
        for kwargs in (
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=16)),
            dict(content=j.node, user=j.user, permission=j.permission, along='bad'),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=0)),
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register(**kwargs)
            self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, ())

    def test_zero_mutation_on_every_rejection(self):
        Node, _p, _r, _i, _im, _m, _po, Link, Grant, Permit = _node_graph_models()
        registry = TrustsRegistry()
        j = Ref(Grant)
        k = Ref(Permit)
        first = registry.register(
            content=j.node, user=j.user, permission=j.permission,
        )
        stored = registry.records
        attempts = [
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=16)),
            dict(content=j.node, user=k.user, permission=j.permission,
                 along=Along(j.node.parent, bound=16)),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=0)),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=65)),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.parent, bound=True)),
            dict(content=j.node, user=j.user, permission=j.permission, along=object()),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node, bound=4)),
            dict(content=j.node, user=j.user, permission=j.permission,
                 along=Along(j.node.rows.content, bound=4)),
        ]
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError):
                registry.register(**kwargs)
            self.assertEqual(registry.records, stored)
            self.assertIs(registry.records[0], first)

    def test_registration_is_zero_sql(self):
        # SimpleTestCase forbids database connections. Completing Along
        # register here is the zero-SQL proof; a query would raise
        # DatabaseOperationForbidden.
        _n, _p, _r, _i, _im, _m, _po, _l, Grant, _np = _node_graph_models()
        registry = TrustsRegistry()
        j = Ref(Grant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.node, user=j.user, permission=j.permission,
                along=Along(j.node.parent, bound=0),
            )

    def test_bound_64_is_accepted(self):
        _n, _p, _r, _i, _im, _m, _po, _l, Grant, _np = _node_graph_models()
        registry = TrustsRegistry()
        j = Ref(Grant)
        rec = registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, 64),
        )
        self.assertEqual(rec.along.bound, 64)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongIdentityRejectionTest(SimpleTestCase):
    def _reject(self, ident_field, suffix):
        User = get_user_model()
        Site = type('IdentSite%s' % suffix, (models.Model,), {
            '__module__': __name__,
            'ident': ident_field,
            'parent': models.ForeignKey(
                'self', to_field='ident', null=True, on_delete=models.CASCADE,
            ),
            'Meta': type('Meta', (), {'app_label': 'trusts_tests'}),
        })
        SiteGrant = type('IdentGrant%s' % suffix, (models.Model,), {
            '__module__': __name__,
            'site': models.ForeignKey(
                Site, to_field='ident', on_delete=models.CASCADE,
            ),
            'user': models.ForeignKey(User, on_delete=models.CASCADE),
            'permission': models.ForeignKey(Permission, on_delete=models.CASCADE),
            'Meta': type('Meta', (), {'app_label': 'trusts_tests'}),
        })
        try:
            registry = TrustsRegistry()
            j = Ref(SiteGrant)
            with self.assertRaises(TrustsConfigurationError):
                registry.register(
                    content=j.site, user=j.user, permission=j.permission,
                    along=Along(j.site.parent, bound=4),
                )
            self.assertEqual(registry.records, ())
        finally:
            forget_models(Site, SiteGrant)

    def test_rejected_identity_families(self):
        fields = (
            models.BinaryField(unique=True),
            models.FileField(upload_to='x', unique=True),
            models.ImageField(upload_to='x', unique=True),
            models.DateField(unique=True),
            models.DateTimeField(unique=True),
            models.TimeField(unique=True),
            models.DurationField(unique=True),
            models.DecimalField(max_digits=6, decimal_places=2, unique=True),
            models.FloatField(unique=True),
            models.BooleanField(unique=True),
            models.JSONField(unique=True),
            models.GenericIPAddressField(unique=True),
        )
        for index, field in enumerate(fields):
            with self.subTest(type=field.get_internal_type(), index=index):
                self._reject(field, suffix=str(index))

    def test_uuid_versus_text_is_rejected(self):
        User = get_user_model()

        class Site(models.Model):
            code = models.CharField(max_length=36, unique=True)
            parent = models.ForeignKey(
                'self', to_field='code', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class SiteGrant(models.Model):
            site = models.ForeignKey(Site, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        # Grant hop uses PK (integer); Along parent uses CharField.
        registry = TrustsRegistry()
        j = Ref(SiteGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.site, user=j.user, permission=j.permission,
                along=Along(j.site.parent, bound=4),
            )
        self.assertEqual(registry.records, ())

        class UuidSite(models.Model):
            ident = models.UUIDField(unique=True)
            slug = models.SlugField(unique=True, default='x')
            parent = models.ForeignKey(
                'self', to_field='slug', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class UuidGrant(models.Model):
            site = models.ForeignKey(
                UuidSite, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        j = Ref(UuidGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.site, user=j.user, permission=j.permission,
                along=Along(j.site.parent, bound=4),
            )
        self.assertEqual(registry.records, ())


class _AlongProjectionMixin(object):
    def _users(self, suffix):
        User = get_user_model()
        self.alice = User.objects.create_user(
            username='alice-%s' % suffix, password='x',
        )
        self.bob = User.objects.create_user(
            username='bob-%s' % suffix, password='x',
        )
        self.read = _perm('read_%s' % suffix)
        self.write = _perm('write_%s' % suffix)

    def _assert_projections(self, registry, Model, granted_rows, denied_rows):
        handle = _direct_handle(registry)
        with self.assertNumQueries(1):
            self.assertTrue(
                registry.has_permission(self.alice, granted_rows[0], self.read),
            )
        for obj in granted_rows:
            self.assertTrue(
                registry.has_permission(self.alice, obj, self.read),
            )
            self.assertFalse(
                registry.has_permission(self.alice, obj, self.write),
            )
            self.assertFalse(
                registry.has_permission(self.bob, obj, self.read),
            )
            with self.assertNumQueries(1):
                self.assertEqual(
                    _pks(registry.permissions_for(self.alice, obj)),
                    {self.read.pk},
                )
        for obj in denied_rows:
            self.assertFalse(
                registry.has_permission(self.alice, obj, self.read),
            )
        expected = list(granted_rows)
        qs = registry.filter_authorized(
            Model.objects.order_by('pk'), self.alice, self.read,
        )
        self.assertIsInstance(qs, QuerySet)
        with self.assertNumQueries(0):
            sliced = qs[:max(1, len(expected))]
        with self.assertNumQueries(1):
            self.assertEqual(list(qs), expected)
        with self.assertNumQueries(1):
            list(sliced)
        granted_qs = Model.objects.filter(pk__in=[row.pk for row in granted_rows])
        mixed_qs = Model.objects.order_by('pk')
        with self.assertNumQueries(1):
            self.assertTrue(all_match((handle,), granted_qs, self.alice, self.read))
        with self.assertNumQueries(1):
            self.assertFalse(all_match((handle,), mixed_qs, self.alice, self.read))
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(common_permissions((handle,), granted_qs, self.alice)),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(common_permissions((handle,), mixed_qs, self.alice)),
                [],
            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongShapeAndGraphTest(_AlongProjectionMixin, TransactionTestCase):
    def setUp(self):
        (
            self.Node, self.Payload, self.Row, self.Item, self.Image,
            self.ImageMeta, self.Portrait, self.Link, self.Grant, self.Permit,
        ) = _node_graph_models()
        self._cm = _tables(
            self.Node, self.Payload, self.Row, self.Item, self.Image,
            self.ImageMeta, self.Portrait, self.Link, self.Grant, self.Permit,
        )
        self._cm.__enter__()
        self._users('along')

    def tearDown(self):
        self._cm.__exit__(None, None, None)

    def test_shape_s_terminal_and_query_plan(self):
        root = self.Node.objects.create(title='root')
        child = self.Node.objects.create(title='child', parent=root)
        leaf = self.Node.objects.create(title='leaf', parent=child)
        other = self.Node.objects.create(title='other')
        self.Grant.objects.create(node=root, user=self.alice, permission=self.read)
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self._assert_projections(
            registry, self.Node, [root, child, leaf], [other],
        )
        qs = registry.filter_authorized(
            self.Node.objects.order_by('pk'), self.alice, self.read,
        )
        plan = _plan_text(qs)
        self.assertIn('LIST SUBQUERY', plan)
        self.assertIn('MATERIALIZE', plan)
        self.assertEqual(plan.count('MATERIALIZE'), 1)
        self.assertIn('SCAN trusts_tests_node', plan.split('\n')[0])

    def test_shape_c_grant_on_descendant_authorizes_ancestors(self):
        root = self.Node.objects.create(title='root')
        mid = self.Node.objects.create(title='mid', parent=root)
        leaf = self.Node.objects.create(title='leaf', parent=mid)
        other = self.Node.objects.create(title='other')
        self.Grant.objects.create(node=leaf, user=self.alice, permission=self.read)
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.children, bound=16),
        )
        self.assertTrue(registry.has_permission(self.alice, leaf, self.read))
        self.assertTrue(registry.has_permission(self.alice, mid, self.read))
        self.assertTrue(registry.has_permission(self.alice, root, self.read))
        self.assertFalse(registry.has_permission(self.alice, other, self.read))

    def test_shape_e_membership_edge(self):
        a = self.Node.objects.create(title='a')
        b = self.Node.objects.create(title='b')
        c = self.Node.objects.create(title='c')
        other = self.Node.objects.create(title='other')
        self.Link.objects.create(child=b, parent=a)
        self.Link.objects.create(child=c, parent=b)
        self.Grant.objects.create(node=a, user=self.alice, permission=self.read)
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent_links.parent, bound=16),
        )
        self.assertTrue(registry.has_permission(self.alice, a, self.read))
        self.assertTrue(registry.has_permission(self.alice, b, self.read))
        self.assertTrue(registry.has_permission(self.alice, c, self.read))
        self.assertFalse(registry.has_permission(self.alice, other, self.read))

    def test_self_link_two_node_cycle_diamond_duplicates_null_empty_bound(self):
        self_node = self.Node.objects.create(title='self')
        self_node.parent = self_node
        self_node.save()
        a = self.Node.objects.create(title='cyc-a')
        b = self.Node.objects.create(title='cyc-b', parent=a)
        a.parent = b
        a.save()
        top = self.Node.objects.create(title='top')
        left = self.Node.objects.create(title='left', parent=top)
        right = self.Node.objects.create(title='right', parent=top)
        # Uneven diamond via E: two edge paths from top to diamond.
        diamond = self.Node.objects.create(title='diamond')
        self.Link.objects.create(child=left, parent=top)
        self.Link.objects.create(child=right, parent=top)
        self.Link.objects.create(child=diamond, parent=left)
        self.Link.objects.create(child=diamond, parent=right)
        dangling = self.Node.objects.create(title='dangling', parent=None)
        deep = self.Node.objects.create(title='deep', parent=left)
        deeper = self.Node.objects.create(title='deeper', parent=deep)
        self.Grant.objects.create(node=self_node, user=self.alice, permission=self.read)
        self.Grant.objects.create(node=a, user=self.alice, permission=self.read)
        self.Grant.objects.create(node=top, user=self.alice, permission=self.read)
        self.Grant.objects.create(node=top, user=self.alice, permission=self.read)
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertTrue(registry.has_permission(self.alice, self_node, self.read))
        self.assertTrue(registry.has_permission(self.alice, a, self.read))
        self.assertTrue(registry.has_permission(self.alice, b, self.read))
        self.assertTrue(registry.has_permission(self.alice, left, self.read))
        self.assertTrue(registry.has_permission(self.alice, deeper, self.read))
        self.assertFalse(registry.has_permission(self.alice, dangling, self.read))
        authorized = _pks(registry.filter_authorized(
            self.Node.objects.all(), self.alice, self.read,
        ))
        self.assertEqual(len(authorized), len(authorized))
        self.assertIn(self_node.pk, authorized)

        edge_reg = TrustsRegistry()
        edge_reg.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent_links.parent, bound=16),
        )
        self.assertTrue(edge_reg.has_permission(self.alice, diamond, self.read))
        self.assertEqual(
            list(edge_reg.filter_authorized(
                self.Node.objects.filter(title='diamond'), self.alice, self.read,
            )),
            [diamond],
        )

        cut = TrustsRegistry()
        cut.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=1),
        )
        self.assertTrue(cut.has_permission(self.alice, left, self.read))
        self.assertFalse(cut.has_permission(self.alice, deeper, self.read))

        empty = TrustsRegistry()
        empty.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertFalse(
            empty.has_permission(self.bob, top, self.read),
        )
        self.assertEqual(
            list(empty.filter_authorized(self.Node.objects.all(), self.bob, self.read)),
            [],
        )

    def test_suffix_shapes_and_shared_row(self):
        folder_a = self.Node.objects.create(title='fa')
        folder_b = self.Node.objects.create(title='fb')
        child_a = self.Node.objects.create(title='ca', parent=folder_a)
        item_a = self.Item.objects.create(node=child_a, title='ia')
        item_b = self.Item.objects.create(
            node=self.Node.objects.create(title='cb', parent=folder_b), title='ib',
        )
        img_a = self.Image.objects.create(item=item_a, title='ima')
        img_b = self.Image.objects.create(item=item_b, title='imb')
        meta_a = self.ImageMeta.objects.create(image=img_a, title='ma')
        meta_b = self.ImageMeta.objects.create(image=img_b, title='mb')
        port_a = self.Portrait.objects.create(item=item_a, title='pa')
        port_b = self.Portrait.objects.create(item=item_b, title='pb')
        pay_a = self.Payload.objects.create(title='pa')
        pay_b = self.Payload.objects.create(title='pb')
        pay_shared = self.Payload.objects.create(title='shared')
        self.Row.objects.create(node=child_a, content=pay_a)
        self.Row.objects.create(node=folder_b, content=pay_b)
        self.Row.objects.create(node=child_a, content=pay_shared)
        self.Row.objects.create(node=folder_b, content=pay_shared)
        self.Grant.objects.create(node=folder_a, user=self.alice, permission=self.read)

        j = Ref(self.Grant)
        d1 = TrustsRegistry()
        d1.register(
            content=j.node.items.image, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self._assert_projections(d1, self.Image, [img_a], [img_b])

        d2 = TrustsRegistry()
        d2.register(
            content=j.node.items.image.image, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertTrue(d2.has_permission(self.alice, meta_a, self.read))
        self.assertFalse(d2.has_permission(self.alice, meta_b, self.read))

        o2o = TrustsRegistry()
        o2o.register(
            content=j.node.items.portrait, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertTrue(o2o.has_permission(self.alice, port_a, self.read))
        self.assertFalse(o2o.has_permission(self.alice, port_b, self.read))

        j1 = TrustsRegistry()
        j1.register(
            content=j.node.rows.content, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertTrue(j1.has_permission(self.alice, pay_a, self.read))
        self.assertTrue(j1.has_permission(self.alice, pay_shared, self.read))
        self.assertFalse(j1.has_permission(self.alice, pay_b, self.read))
        self.assertFalse(j1.has_permission(self.alice, pay_a, self.write))

        rev = TrustsRegistry()
        rev.register(
            content=j.node.items, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        self.assertTrue(rev.has_permission(self.alice, item_a, self.read))
        self.assertFalse(rev.has_permission(self.alice, item_b, self.read))

    def test_direct_recursive_or_and_multiple_handles(self):
        granted_node = self.Node.objects.create(title='g')
        child = self.Node.objects.create(title='c', parent=granted_node)
        direct = self.Node.objects.create(title='d')
        other = self.Node.objects.create(title='o')
        self.Grant.objects.create(
            node=granted_node, user=self.alice, permission=self.read,
        )
        self.Permit.objects.create(
            node=direct, user=self.alice, permission=self.read,
        )
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        k = Ref(self.Permit)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        registry.register(
            content=k.node, user=k.user, permission=k.permission,
        )
        self.assertTrue(registry.has_permission(self.alice, child, self.read))
        self.assertTrue(registry.has_permission(self.alice, direct, self.read))
        self.assertFalse(registry.has_permission(self.alice, other, self.read))
        sql = str(registry.filter_authorized(
            self.Node.objects.all(), self.alice, self.read,
        ).query).upper()
        self.assertIn(' OR ', sql)
        self.assertIn('WITH RECURSIVE', sql)
        self.assertIn('EXISTS', sql)

        rec_reg = TrustsRegistry()
        rec_reg.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=16),
        )
        dir_reg = TrustsRegistry()
        dir_reg.register(
            content=k.node, user=k.user, permission=k.permission,
        )
        handles = (
            _direct_handle(rec_reg, 'tests.along.a'),
            _direct_handle(dir_reg, 'tests.along.b'),
        )
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(self.Node.objects.filter(
                    granted(handles, self.Node.objects.all(), self.alice, self.read),
                ).distinct()),
                {granted_node.pk, child.pk, direct.pk},
            )

    def test_non_recursive_sql_and_results_unchanged(self):
        node = self.Node.objects.create(title='n')
        other = self.Node.objects.create(title='o')
        self.Grant.objects.create(node=node, user=self.alice, permission=self.read)
        registry = TrustsRegistry()
        j = Ref(self.Grant)
        registry.register(content=j.node, user=j.user, permission=j.permission)
        sql = str(registry.filter_authorized(
            self.Node.objects.all(), self.alice, self.read,
        ).query).upper()
        self.assertIn('EXISTS', sql)
        self.assertNotIn('WITH RECURSIVE', sql)
        self.assertTrue(registry.has_permission(self.alice, node, self.read))
        self.assertFalse(registry.has_permission(self.alice, other, self.read))
        self.assertEqual(
            list(registry.filter_authorized(
                self.Node.objects.order_by('pk'), self.alice, self.read,
            )),
            [node],
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongToFieldAndUuidTest(_AlongProjectionMixin, TransactionTestCase):
    def test_text_to_field_and_uuid_identities(self):
        User = get_user_model()

        class CodedNode(models.Model):
            code = models.SlugField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='code', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class CodedItem(models.Model):
            node = models.ForeignKey(
                CodedNode, related_name='items', on_delete=models.CASCADE,
            )
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class CodedGrant(models.Model):
            node = models.ForeignKey(
                CodedNode, to_field='code', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class UuidNode(models.Model):
            ident = models.UUIDField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='ident', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class UuidGrant(models.Model):
            node = models.ForeignKey(
                UuidNode, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(CodedNode, CodedItem, CodedGrant, UuidNode, UuidGrant):
            alice = User.objects.create_user(username='alice-id', password='x')
            read = _perm('read_id92')
            a = CodedNode.objects.create(code='alpha')
            b = CodedNode.objects.create(code='beta', parent=a)
            other = CodedNode.objects.create(code='omega')
            item_a = CodedItem.objects.create(node=b, title='ia')
            item_o = CodedItem.objects.create(node=other, title='io')
            CodedGrant.objects.create(node=a, user=alice, permission=read)
            registry = TrustsRegistry()
            j = Ref(CodedGrant)
            rec = registry.register(
                content=j.node, user=j.user, permission=j.permission,
                along=Along(j.node.parent, bound=8),
            )
            self.assertEqual(rec.along.walk_ident, 'code')
            self.assertEqual(rec.along.ident_family, 'text')
            self.assertTrue(registry.has_permission(alice, a, read))
            self.assertTrue(registry.has_permission(alice, b, read))
            self.assertFalse(registry.has_permission(alice, other, read))
            suf = TrustsRegistry()
            suf_rec = suf.register(
                content=j.node.items, user=j.user, permission=j.permission,
                along=Along(j.node.parent, bound=8),
            )
            self.assertEqual(suf_rec.content_target, CodedItem._meta.pk.attname)
            self.assertTrue(suf.has_permission(alice, item_a, read))
            self.assertFalse(suf.has_permission(alice, item_o, read))

            ua = UuidNode.objects.create(ident=uuid4())
            ub = UuidNode.objects.create(ident=uuid4(), parent=ua)
            uo = UuidNode.objects.create(ident=uuid4())
            UuidGrant.objects.create(node=ua, user=alice, permission=read)
            ureg = TrustsRegistry()
            uj = Ref(UuidGrant)
            urec = ureg.register(
                content=uj.node, user=uj.user, permission=uj.permission,
                along=Along(uj.node.parent, bound=8),
            )
            self.assertEqual(urec.along.ident_family, 'uuid')
            self.assertTrue(ureg.has_permission(alice, ua, read))
            self.assertTrue(ureg.has_permission(alice, ub, read))
            self.assertFalse(ureg.has_permission(alice, uo, read))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongRuntimeGateTest(TransactionTestCase):
    def test_as_sql_rejects_non_sqlite_before_walk_sql(self):
        User = get_user_model()

        class Node(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class NodeGrant(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Node, NodeGrant):
            alice = User.objects.create_user(username='alice-gate', password='x')
            read = _perm('read_gate')
            node = Node.objects.create()
            NodeGrant.objects.create(node=node, user=alice, permission=read)
            registry = TrustsRegistry()
            j = Ref(NodeGrant)
            record = registry.register(
                content=j.node, user=j.user, permission=j.permission,
                along=Along(j.node.parent, bound=4),
            )
            expr = GrantReach(record, alice, read)
            compiler = Node.objects.filter(pk=node.pk).query.get_compiler('default')

            class Stub(object):
                vendor = 'mysql'
                alias = 'replica'
                settings_dict = {'ENGINE': 'django.db.backends.mysql'}

            executed = []
            stub = Stub()
            stub.cursor = lambda: (_ for _ in ()).throw(AssertionError('probe'))
            with self.assertRaises(TrustsConfigurationError) as ctx:
                expr.as_sql(compiler, stub)
            self.assertNotIsInstance(ctx.exception, TrustsCompilerError)
            self.assertIn('mysql', str(ctx.exception).lower())
            self.assertIn('replica', str(ctx.exception))
            self.assertEqual(executed, [])
            sql = str(registry.filter_authorized(
                Node.objects.all(), alice, read,
            ).query).upper()
            self.assertIn('WITH RECURSIVE', sql)


class _LiveRegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = apps.get_app_config('trusts')
        self.saved = dict(self.live.registries)

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved)
        super().tearDown()


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongE005Test(_LiveRegistryRestoreMixin, TransactionTestCase):
    def _along_registry(self):
        User = get_user_model()

        class Node(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class NodeGrant(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        j = Ref(NodeGrant)
        registry.register(
            content=j.node, user=j.user, permission=j.permission,
            along=Along(j.node.parent, bound=4),
        )
        return registry, Node, NodeGrant

    def test_no_aliases_is_not_all_clear(self):
        registry, Node, NodeGrant = self._along_registry()
        isolate_live_registry(self.live, registry)
        self.assertEqual(check_along_renderer(None), [])
        self.assertEqual(check_along_renderer(None, databases=None), [])
        self.assertEqual(check_along_renderer(None, databases=()), [])
        self.assertEqual(check_along_renderer(None, databases=[]), [])

    def test_supported_alias(self):
        registry, Node, NodeGrant = self._along_registry()
        isolate_live_registry(self.live, registry)
        messages = check_along_renderer(None, databases=['default'])
        self.assertEqual(messages, [])

    def test_unsupported_and_several_aliases(self):
        registry, Node, NodeGrant = self._along_registry()
        isolate_live_registry(self.live, registry)
        fake = MagicMock()
        fake.settings_dict = {'ENGINE': 'django.db.backends.postgresql'}
        fake.vendor = 'postgresql'
        fake.alias = 'other'
        mapping = {
            'default': connections['default'],
            'other': fake,
            'also': fake,
        }

        class _Conns(object):
            def __getitem__(self, alias):
                return mapping[alias]

        with patch('django.db.connections', _Conns()):
            messages = check_along_renderer(
                None, databases=['default', 'other', 'also'],
            )
        errors = [m for m in messages if m.id == CHECK_ID_ALONG_RENDERER]
        self.assertEqual(len(errors), 2)
        aliases = ' '.join(m.msg for m in errors)
        self.assertIn("'other'", aliases)
        self.assertIn("'also'", aliases)
        self.assertTrue(all('default' not in m.msg.split('ENGINE')[0] for m in errors))

    def test_failed_probe(self):
        registry, Node, NodeGrant = self._along_registry()
        isolate_live_registry(self.live, registry)

        class BoomCursor(object):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                raise OperationalError('no such function: json_group_array')

            def fetchone(self):
                return None

        with patch.object(connections['default'], 'cursor', lambda: BoomCursor()):
            messages = check_along_renderer(None, databases=['default'])
        errors = [m for m in messages if m.id == CHECK_ID_ALONG_RENDERER]
        self.assertEqual(len(errors), 1)
        self.assertIn('default', errors[0].msg)
        self.assertIn('json_group_array', errors[0].msg)

    def test_isolated_registry_is_not_scanned(self):
        self._along_registry()
        messages = check_along_renderer(None, databases=['default'])
        self.assertEqual(
            [m for m in messages if m.id == CHECK_ID_ALONG_RENDERER],
            [],
        )
