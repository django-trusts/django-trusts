"""Noun-neutral long-path genericity for issue #18.

Isolated models whose names are unrelated to Trust/Group/Role/Permission.
A long root-relative ceiling walks several ordinary forward FK hops, then
the bounded M2M→M2M membership shape. Two alternative records share
content/user/permission bindings and differ only in the closed
``permission_in`` ceiling.

Core must resolve every hop from Django ``_meta`` / stored path metadata.
This module does not import ``trusts.zero`` and does not special-case
Zero class names, app labels, field names, or path length.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import options as model_options
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    permission_in,
)
from trusts.query import AuthorizedManager


def _long_path_models():
    """Isolated nouns. Four forward FK hops before the collective ceiling."""

    class Actor(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Token(models.Model):
        code = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Hall(models.Model):
        title = models.CharField(max_length=40)
        badges = models.ManyToManyField(
            Token, related_name='badged_halls', blank=True,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Cluster(models.Model):
        title = models.CharField(max_length=40)
        tokens = models.ManyToManyField(
            Token, related_name='clustered', blank=True,
        )
        halls = models.ManyToManyField(
            Hall, related_name='clusters', blank=True,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Building(models.Model):
        hall = models.ForeignKey(
            Hall, related_name='buildings', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Floor(models.Model):
        building = models.ForeignKey(
            Building, related_name='floors', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Wing(models.Model):
        floor = models.ForeignKey(
            Floor, related_name='wings', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Artifact(models.Model):
        title = models.CharField(max_length=40)

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class Placement(models.Model):
        artifact = models.ForeignKey(
            Artifact, related_name='placements', on_delete=models.CASCADE,
        )
        actor = models.ForeignKey(
            Actor, related_name='placements', on_delete=models.CASCADE,
        )
        token = models.ForeignKey(
            Token, related_name='placements', on_delete=models.CASCADE,
        )
        wing = models.ForeignKey(
            Wing, related_name='placements', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    return (
        Actor, Token, Hall, Cluster, Building, Floor, Wing,
        Artifact, Placement,
    )


def _colliding_to_field_models():
    """M2M through-FK uses a non-PK ``to_field`` on the token model."""

    class Actor(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Token(models.Model):
        code = models.CharField(max_length=8, unique=True)

        class Meta:
            app_label = 'trusts_tests'

    class Hall(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Cluster(models.Model):
        title = models.CharField(max_length=40)
        halls = models.ManyToManyField(
            Hall, related_name='clusters', blank=True,
        )

        class Meta:
            app_label = 'trusts_tests'

    class ClusterToken(models.Model):
        cluster = models.ForeignKey(
            Cluster, related_name='+', on_delete=models.CASCADE,
        )
        token = models.ForeignKey(
            Token, related_name='+', on_delete=models.CASCADE, to_field='code',
        )

        class Meta:
            app_label = 'trusts_tests'

    Cluster.add_to_class(
        'tokens',
        models.ManyToManyField(
            Token, through=ClusterToken, related_name='+',
        ),
    )

    class Building(models.Model):
        hall = models.ForeignKey(
            Hall, related_name='buildings', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Floor(models.Model):
        building = models.ForeignKey(
            Building, related_name='floors', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Wing(models.Model):
        floor = models.ForeignKey(
            Floor, related_name='wings', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Artifact(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Placement(models.Model):
        artifact = models.ForeignKey(
            Artifact, related_name='+', on_delete=models.CASCADE,
        )
        actor = models.ForeignKey(
            Actor, related_name='+', on_delete=models.CASCADE,
        )
        token = models.ForeignKey(
            Token, related_name='+', on_delete=models.CASCADE,
        )
        wing = models.ForeignKey(
            Wing, related_name='+', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    return (
        Actor, Token, Hall, Cluster, ClusterToken, Building, Floor, Wing,
        Artifact, Placement,
    )


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


def _direct_ceiling(registry, placement):
    p = Ref(placement)
    return registry.register(
        content=p.artifact,
        user=p.actor,
        permission=p.token,
        condition=permission_in(p.wing.floor.building.hall.badges),
    )


def _cluster_ceiling(registry, placement):
    p = Ref(placement)
    return registry.register(
        content=p.artifact,
        user=p.actor,
        permission=p.token,
        condition=permission_in(p.wing.floor.building.hall.clusters.tokens),
    )


def _pks(rows):
    return {row.pk for row in rows}


class CoreImportBoundaryTest(SimpleTestCase):
    def test_core_package_does_not_import_trusts_zero(self):
        import ast
        import inspect
        from pathlib import Path

        import trusts

        root = Path(inspect.getfile(trusts)).resolve().parent
        forbidden = []
        for path in sorted(root.rglob('*.py')):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or '']
                else:
                    continue
                if any(
                    name == 'trusts.zero' or name.startswith('trusts.zero.')
                    for name in names
                ):
                    forbidden.append(str(path))
        self.assertEqual(forbidden, [])
        self.assertFalse(hasattr(trusts, 'get_entity_model'))
        self.assertFalse(hasattr(trusts, 'get_group_model'))
        self.assertFalse(hasattr(trusts, 'get_permission_model'))
        self.assertFalse(hasattr(trusts, 'ENTITY_MODEL_NAME'))
        self.assertFalse(hasattr(trusts, 'ROOT_PK'))


class PermissionConditionsMetaOptionTest(SimpleTestCase):
    def test_generic_option_is_registered_idempotently(self):
        from trusts.conditions import _ensure_permission_conditions_option

        self.assertIn('permission_conditions', model_options.DEFAULT_NAMES)
        before = model_options.DEFAULT_NAMES
        count = before.count('permission_conditions')
        _ensure_permission_conditions_option()
        _ensure_permission_conditions_option()
        self.assertIs(model_options.DEFAULT_NAMES, before)
        self.assertEqual(
            model_options.DEFAULT_NAMES.count('permission_conditions'),
            count,
        )
        self.assertEqual(count, 1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class LongPathRegistrationTest(TestCase):
    def test_alternative_ceilings_register_with_zero_sql(self):
        models_ = _long_path_models()
        Placement = models_[-1]
        Artifact = models_[-2]
        registry = TrustsRegistry()
        with self.assertNumQueries(0):
            direct = _direct_ceiling(registry, Placement)
            clustered = _cluster_ceiling(registry, Placement)
        self.assertEqual(len(registry.records), 2)
        self.assertIs(direct.content_model, Artifact)
        self.assertIs(clustered.content_model, Artifact)
        self.assertEqual(direct.user_path, ('actor',))
        self.assertEqual(clustered.user_path, ('actor',))
        self.assertEqual(direct.permission_path, ('token',))
        self.assertEqual(clustered.permission_path, ('token',))
        self.assertEqual(
            direct.condition.refs[0]._path,
            ('wing', 'floor', 'building', 'hall', 'badges'),
        )
        self.assertEqual(
            clustered.condition.refs[0]._path,
            ('wing', 'floor', 'building', 'hall', 'clusters', 'tokens'),
        )
        self.assertGreaterEqual(len(clustered.condition.refs[0]._path), 6)

    def test_exact_duplicate_rejects_and_leaves_store_unchanged(self):
        models_ = _long_path_models()
        Placement = models_[-1]
        registry = TrustsRegistry()
        first = _cluster_ceiling(registry, Placement)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
                _cluster_ceiling(registry, Placement)
        self.assertEqual(registry.records, (first,))

    def test_different_bindings_still_conflict(self):
        models_ = _long_path_models()
        Placement = models_[-1]
        registry = TrustsRegistry()
        first = _cluster_ceiling(registry, Placement)
        p = Ref(Placement)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
                registry.register(
                    content=p.wing,
                    user=p.actor,
                    permission=p.token,
                    condition=permission_in(
                        p.wing.floor.building.hall.clusters.tokens,
                    ),
                )
        self.assertEqual(registry.records, (first,))

    def test_wrong_terminal_malformed_and_gfk_fail_closed(self):
        models_ = _long_path_models()
        Placement = models_[-1]
        registry = TrustsRegistry()
        p = Ref(Placement)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'permission model',
            ):
                registry.register(
                    content=p.artifact,
                    user=p.actor,
                    permission=p.token,
                    condition=permission_in(p.wing.floor.building.hall.clusters),
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'extra or intermediate multi-valued',
            ):
                registry.register(
                    content=p.artifact,
                    user=p.actor,
                    permission=p.token,
                    condition=permission_in(
                        p.wing.floor.building.hall.clusters.tokens.clustered,
                    ),
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'scalar field|single-valued hops',
            ):
                registry.register(
                    content=p.artifact,
                    user=p.actor,
                    permission=p.token,
                    condition=permission_in(
                        p.wing.floor.building.hall.clusters.title,
                    ),
                )
        self.assertEqual(registry.records, ())

        class Tagged(models.Model):
            label = models.CharField(max_length=20)
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            target = GenericForeignKey('content_type', 'object_id')

            class Meta:
                app_label = 'trusts_tests'

        class TaggedGrant(models.Model):
            tagged = models.ForeignKey(Tagged, on_delete=models.CASCADE)
            actor = models.ForeignKey(models_[0], on_delete=models.CASCADE)
            token = models.ForeignKey(models_[1], on_delete=models.CASCADE)
            artifact = models.ForeignKey(models_[-2], on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        g = Ref(TaggedGrant)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'generic foreign key',
            ):
                registry.register(
                    content=g.artifact,
                    user=g.actor,
                    permission=g.token,
                    condition=permission_in(g.tagged.target),
                )
        self.assertEqual(registry.records, ())

    def test_colliding_to_field_membership_fails_closed(self):
        (
            _Actor, _Token, _Hall, Cluster, _Through, _Building, _Floor,
            _Wing, Artifact, Placement,
        ) = _colliding_to_field_models()
        registry = TrustsRegistry()
        p = Ref(Placement)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'resolved comparison field',
            ):
                registry.register(
                    content=p.artifact,
                    user=p.actor,
                    permission=p.token,
                    condition=permission_in(
                        p.wing.floor.building.hall.clusters.tokens,
                    ),
                )
        self.assertEqual(registry.records, ())
        self.assertIs(Cluster._meta.concrete_model, Cluster)
        self.assertIs(Artifact._meta.concrete_model, Artifact)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class LongPathAuthorizationTest(TransactionTestCase):
    def setUp(self):
        (
            self.Actor,
            self.Token,
            self.Hall,
            self.Cluster,
            self.Building,
            self.Floor,
            self.Wing,
            self.Artifact,
            self.Placement,
        ) = _long_path_models()
        self._table_cm = _tables(
            self.Actor,
            self.Token,
            self.Hall,
            self.Cluster,
            self.Building,
            self.Floor,
            self.Wing,
            self.Artifact,
            self.Placement,
        )
        self._table_cm.__enter__()
        self.actor = self.Actor.objects.create(name='member')
        self.stranger = self.Actor.objects.create(name='stranger')
        self.read = self.Token.objects.create(code='read')
        self.write = self.Token.objects.create(code='write')
        self.hall = self.Hall.objects.create(title='east')
        self.cluster = self.Cluster.objects.create(title='night')
        self.cluster.halls.add(self.hall)
        self.building = self.Building.objects.create(
            hall=self.hall, title='north',
        )
        self.floor = self.Floor.objects.create(
            building=self.building, title='3',
        )
        self.wing = self.Wing.objects.create(floor=self.floor, title='lab')
        self.artifact = self.Artifact.objects.create(title='scope')
        self.other = self.Artifact.objects.create(title='other')
        self.Placement.objects.create(
            artifact=self.artifact, actor=self.actor, token=self.read,
            wing=self.wing,
        )
        self.registry = TrustsRegistry()
        _direct_ceiling(self.registry, self.Placement)
        _cluster_ceiling(self.registry, self.Placement)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _handles(self):
        return (BackendHandle(
            path='issue18',
            registry=self.registry,
            compiler=PlanQueryCompiler(),
        ),)

    def _agree(self, principal, token, obj, expected):
        with self.assertNumQueries(1):
            via_obj = self.registry.has_permission(principal, obj, token)
        with self.assertNumQueries(1):
            via_list = obj in list(
                self.registry.filter_authorized(
                    self.Artifact.objects.filter(pk=obj.pk),
                    principal, token,
                )
            )
        with patch(
            'trusts.apps.configured_implementation_handles',
            return_value=self._handles(),
        ):
            with self.assertNumQueries(1):
                via_manager = obj in list(
                    self.Artifact.objects.filter(pk=obj.pk).authorized(
                        principal, token,
                    )
                )
        enumerated = {
            row.pk for row in self.registry.permissions_for(principal, obj)
        }
        self.assertEqual(via_obj, expected)
        self.assertEqual(via_list, expected)
        self.assertEqual(via_manager, expected)
        if expected:
            self.assertIn(token.pk, enumerated)
        else:
            self.assertNotIn(token.pk, enumerated)

    def test_direct_ceiling_alone_grants(self):
        self.hall.badges.add(self.read)
        self._agree(self.actor, self.read, self.artifact, True)
        self._agree(self.actor, self.write, self.artifact, False)
        self._agree(self.stranger, self.read, self.artifact, False)
        self._agree(self.actor, self.read, self.other, False)

    def test_cluster_ceiling_alone_grants(self):
        self.cluster.tokens.add(self.read)
        self._agree(self.actor, self.read, self.artifact, True)
        self._agree(self.actor, self.write, self.artifact, False)

    def test_either_alternative_grants_and_removing_both_denies(self):
        self.hall.badges.add(self.read)
        self._agree(self.actor, self.read, self.artifact, True)
        self.hall.badges.remove(self.read)
        self._agree(self.actor, self.read, self.artifact, False)
        self.cluster.tokens.add(self.read)
        self._agree(self.actor, self.read, self.artifact, True)
        self.cluster.tokens.remove(self.read)
        self._agree(self.actor, self.read, self.artifact, False)

    def test_fixed_query_object_list_and_enumeration_agree(self):
        self.hall.badges.add(self.read)
        with self.assertNumQueries(0):
            qs = self.registry.filter_authorized(
                self.Artifact.objects.all(), self.actor, self.read,
            )
            enumerated = self.registry.permissions_for(
                self.actor, self.artifact,
            )
        self.assertIsInstance(qs, QuerySet)
        self.assertIsInstance(enumerated, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.artifact.pk})
        with self.assertNumQueries(1):
            self.assertEqual(_pks(enumerated), {self.read.pk})
        sql = str(
            self.registry.filter_authorized(
                self.Artifact.objects.all(), self.actor, self.read,
            ).query
        ).lower().replace('_', '').replace('"', '')
        self.assertIn('exists', sql)
        self.assertIn('placement', sql)
        self.assertIn('cluster', sql)
