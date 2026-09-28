"""Lockfile C1 snapshot seam (#147).

Immutable finalized projection, registration fingerprints, readable
labels, unsupported-family failure, and the default-alias renderer
profile. No generate/check command, no runtime gate, no SQL.
"""

import hashlib
import json
from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connections, models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.conditions._ir import (
    ConditionRecord,
    Const,
    Eq,
    ModelIdentity,
    Ref as FilterRef,
)
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import (
    ALONG_SUPPORTED,
    ALONG_UNSUPPORTED,
    COMPILER_VERSION,
    GENERIC_UNSUPPORTED_ALONG_PROFILE,
    PolicyManifest,
    SCHEMA_VERSION,
    SQLITE_JSON1_RCTE_PROFILE,
    build_policy_manifest,
    fingerprint_registration,
    manifest_to_json_data,
)


_FINGERPRINT = __import__('re').compile(r'^sha256:[0-9a-f]{64}$')

_REGISTRATION_KEYS = (
    'fingerprint', 'label', 'kind', 'root',
    'user', 'user_model', 'user_target',
    'permission', 'permission_model', 'permission_target',
    'content', 'content_model', 'content_target',
    'condition', 'along',
)


def _policy_models():
    User = get_user_model()

    class Org(models.Model):
        name = models.CharField(max_length=40)
        code = models.CharField(max_length=40, unique=True)

        class Meta:
            app_label = 'trusts_tests'

    class Doc(models.Model):
        title = models.CharField(max_length=40)
        confidential = models.BooleanField(default=False)
        rank = models.IntegerField(default=0)
        organization = models.ForeignKey(
            Org, related_name='docs', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Grant(models.Model):
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        document = models.ForeignKey(Doc, on_delete=models.CASCADE)
        team_org = models.ForeignKey(
            Org, related_name='team_grants', on_delete=models.CASCADE,
        )
        repo_org = models.ForeignKey(
            Org, related_name='repo_grants', on_delete=models.CASCADE,
        )
        alt_org = models.ForeignKey(
            Org, related_name='alt_grants', on_delete=models.CASCADE,
        )
        coded_org = models.ForeignKey(
            Org, to_field='code', related_name='coded_grants',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Node(models.Model):
        parent = models.ForeignKey(
            'self', null=True, related_name='children',
            on_delete=models.CASCADE,
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

    class NodeGrant(models.Model):
        node = models.ForeignKey(Node, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Org, Doc, Grant, Node, Item, NodeGrant


def _direct(registry, grant, content='document'):
    root = Ref(grant)
    return registry.register(
        content=getattr(root, content),
        user=root.user,
        permission=root.permission,
    )


def _handle(registry, path, compiler=None):
    registry.freeze()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler() if compiler is None else compiler,
    )


def _data(handles, **kwargs):
    return manifest_to_json_data(build_policy_manifest(handles, **kwargs))


def _semantic_digest(data):
    text = json.dumps(
        data, ensure_ascii=False, indent=2, separators=(',', ': '),
        sort_keys=False,
    )
    if not text.endswith('\n'):
        text += '\n'
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _payload(registration):
    return {
        key: registration[key]
        for key in _REGISTRATION_KEYS
        if key not in ('fingerprint', 'label')
    }


@contextmanager
def _forbid_sql():
    """Fail if snapshot construction opens a cursor or probes Along."""
    connection = connections['default']
    with patch.object(
        connection, 'cursor', side_effect=AssertionError('cursor'),
    ), patch.object(
        connection, 'ensure_connection', side_effect=AssertionError('connect'),
    ), patch(
        'trusts.core.probe_along_capabilities',
        side_effect=AssertionError('probed'),
    ):
        yield


@contextmanager
def _engine(engine, **extra):
    connection = connections['default']
    saved = connection.settings_dict
    try:
        replaced = dict(saved)
        replaced['ENGINE'] = engine
        replaced.update(extra)
        connection.settings_dict = replaced
        yield connection
    finally:
        connection.settings_dict = saved


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PolicyLockSnapshotTest(SimpleTestCase):
    def test_detached_conversion_does_not_alias_live_state(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        record = registry.get_permission_condition_record(
            Doc, 'non_confidential',
        )
        handle = _handle(registry, 'tests.policy.direct')
        manifest = build_policy_manifest([handle])
        self.assertIsInstance(manifest, PolicyManifest)
        with self.assertRaises(TrustsConfigurationError):
            manifest.schema_version = 2
        first = manifest_to_json_data(manifest)
        second = manifest_to_json_data(manifest)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first['handles'], second['handles'])
        first['handles'][0]['registrations'][0]['content'].append('leaked')
        first['handles'][0]['named_filters'][0]['expr']['right']['const']['value'] = False
        self.assertEqual(
            manifest_to_json_data(manifest)['handles'][0]['registrations'][0]['content'],
            ['document'],
        )
        self.assertIs(
            manifest_to_json_data(manifest)['handles'][0]['named_filters'][0]['expr']['right']['const']['value'],
            True,
        )
        record.expr.right.value = False
        registry._order.append(registry._order[0])
        self.assertIs(
            manifest_to_json_data(manifest)['handles'][0]['named_filters'][0]['expr']['right']['const']['value'],
            True,
        )
        self.assertEqual(
            len(manifest_to_json_data(manifest)['handles'][0]['registrations']),
            1,
        )
        blob = json.dumps(manifest_to_json_data(manifest))
        self.assertNotIn('RegisteredRelation', blob)
        self.assertNotIn('AlongWalk', blob)
        self.assertNotIn('Expr', blob)
        self.assertNotIn(str(id(registry)), blob)
        self.assertNotIn(str(id(handle)), blob)
        self.assertNotIn(str(id(handle.compiler)), blob)

    def test_manifest_to_json_data_rejects_live_objects(self):
        with self.assertRaises(TypeError):
            manifest_to_json_data({'schema_version': 1})
        with self.assertRaises(TypeError):
            manifest_to_json_data(TrustsRegistry())

    def test_unfrozen_registry_is_rejected_without_mutation(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        handle = BackendHandle(
            path='tests.policy.thawed',
            registry=registry,
            compiler=PlanQueryCompiler(),
        )
        self.assertFalse(registry.frozen)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            build_policy_manifest([handle])
        self.assertIn('tests.policy.thawed', str(ctx.exception))
        self.assertFalse(registry.frozen)
        self.assertEqual(len(registry.records), 1)

    def test_fingerprint_is_order_independent_and_round_trips(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()

        def fill(first_document):
            registry = TrustsRegistry()
            specs = ('document', 'coded_org')
            if not first_document:
                specs = tuple(reversed(specs))
            for content in specs:
                _direct(registry, Grant, content=content)
            return registry

        left = _data([_handle(fill(True), 'tests.policy.order')])
        right = _data([_handle(fill(False), 'tests.policy.order')])
        self.assertEqual(left, right)
        registrations = left['handles'][0]['registrations']
        self.assertEqual(
            [row['fingerprint'] for row in registrations],
            sorted(row['fingerprint'] for row in registrations),
        )
        for row in registrations:
            self.assertRegex(row['fingerprint'], _FINGERPRINT)
            self.assertEqual(
                fingerprint_registration(_payload(row)),
                row['fingerprint'],
            )
            swapped = dict(reversed(list(_payload(row).items())))
            self.assertEqual(fingerprint_registration(swapped), row['fingerprint'])
            self.assertNotIn('fingerprint', _payload(row))

    def test_path_condition_along_and_target_change_fingerprint(self):
        Org, _doc, Grant, Node, Item, NodeGrant = _policy_models()
        plain = TrustsRegistry()
        _direct(plain, Grant)
        conditioned = TrustsRegistry()
        root = Ref(Grant)
        conditioned.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=Equal(root.team_org, root.repo_org),
        )
        swapped = TrustsRegistry()
        swapped.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=Equal(root.repo_org, root.team_org),
        )
        other_path = TrustsRegistry()
        _direct(other_path, Grant, content='team_org')
        to_field = TrustsRegistry()
        _direct(to_field, Grant, content='coded_org')
        along_3 = TrustsRegistry()
        node = Ref(NodeGrant)
        along_3.register(
            content=node.node.items,
            user=node.user,
            permission=node.permission,
            along=Along(node.node.parent, bound=3),
        )
        along_4 = TrustsRegistry()
        along_4.register(
            content=node.node.items,
            user=node.user,
            permission=node.permission,
            along=Along(node.node.parent, bound=4),
        )

        def fingerprint_of(registry, path):
            data = _data([_handle(registry, path)])
            return data['handles'][0]['registrations'][0]

        base = fingerprint_of(plain, 'tests.policy.base')
        changed = fingerprint_of(conditioned, 'tests.policy.cond')
        same_equal = fingerprint_of(swapped, 'tests.policy.swap')
        path_row = fingerprint_of(other_path, 'tests.policy.path')
        target_row = fingerprint_of(to_field, 'tests.policy.target')
        along_row = fingerprint_of(along_3, 'tests.policy.along3')
        along_other = fingerprint_of(along_4, 'tests.policy.along4')

        self.assertEqual(base['label'], '%s:document' % Grant._meta.label)
        self.assertEqual(
            changed['label'], '%s:document+cond' % Grant._meta.label,
        )
        self.assertEqual(changed['fingerprint'], same_equal['fingerprint'])
        self.assertEqual(
            changed['condition']['left'], ['repo_org'],
        )
        self.assertNotEqual(base['fingerprint'], changed['fingerprint'])
        self.assertNotEqual(base['fingerprint'], path_row['fingerprint'])
        self.assertNotEqual(base['fingerprint'], target_row['fingerprint'])
        self.assertEqual(target_row['content_target'], Org._meta.get_field('code').attname)
        self.assertNotEqual(along_row['fingerprint'], along_other['fingerprint'])
        self.assertEqual(
            along_row['label'],
            '%s:node__items+along:S:3' % NodeGrant._meta.label,
        )
        self.assertEqual(along_row['along']['shape'], 'S')
        self.assertEqual(along_row['along']['bound'], 3)
        self.assertEqual(along_row['along']['walk_path'], ['node'])
        self.assertEqual(along_row['along']['suffix_path'], ['items'])
        self.assertEqual(along_row['along']['walk_model'], Node._meta.label)
        self.assertEqual(along_row['content_model'], Item._meta.label)
        self.assertIsNone(along_row['along']['edge_model'])
        self.assertNotIn('walk_field', along_row['along'])
        self.assertNotIn('suffix_field', along_row['along'])

    def test_commutative_all_does_not_change_fingerprint(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        root = Ref(Grant)
        left = TrustsRegistry()
        left.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=All(
                Equal(root.team_org, root.repo_org),
                Equal(root.alt_org, root.team_org),
            ),
        )
        right = TrustsRegistry()
        right.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=All(
                Equal(root.team_org, root.alt_org),
                Equal(root.repo_org, root.team_org),
            ),
        )
        left_row = _data([_handle(left, 'tests.policy.all')])['handles'][0]['registrations'][0]
        right_row = _data([_handle(right, 'tests.policy.all')])['handles'][0]['registrations'][0]
        self.assertEqual(left_row['fingerprint'], right_row['fingerprint'])
        self.assertEqual(left_row['condition']['op'], 'all')

    def test_label_collision_uses_fingerprint_suffix(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        root = Ref(Grant)
        registry.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=Equal(root.team_org, root.repo_org),
        )
        registry.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=Equal(root.alt_org, root.repo_org),
        )
        rows = _data([_handle(registry, 'tests.policy.collision')])['handles'][0]['registrations']
        self.assertEqual(len(rows), 2)
        base = '%s:document+cond' % Grant._meta.label
        suffixes = []
        for row in rows:
            hex_digest = row['fingerprint'].split(':', 1)[1]
            self.assertEqual(row['label'], '%s#%s' % (base, hex_digest[:8]))
            suffixes.append(hex_digest[:8])
        self.assertEqual(len(set(suffixes)), 2)
        self.assertNotEqual(rows[0]['fingerprint'], rows[1]['fingerprint'])

    def test_cosmetic_source_location_is_not_identity(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()

        def build_one():
            registry = TrustsRegistry()
            _direct(registry, Grant)
            return registry

        def build_two():
            registry = TrustsRegistry()
            # Cosmetic comment and a different source line.
            _direct(registry, Grant)
            return registry

        build_one.__doc__ = 'cosmetic-a'
        build_two.__doc__ = 'cosmetic-b at %s' % __file__
        left = _data([_handle(build_one(), 'tests.policy.cosmetic')])
        right = _data([_handle(build_two(), 'tests.policy.cosmetic')])
        self.assertEqual(left, right)
        blob = json.dumps(left)
        self.assertNotIn('cosmetic-a', blob)
        self.assertNotIn('cosmetic-b', blob)
        self.assertNotIn(__file__, blob)
        self.assertNotIn('lineno', blob)
        self.assertNotIn('co_filename', blob)

    def test_multi_handle_isolation(self):
        _org, _doc, Grant, _node, _item, NodeGrant = _policy_models()
        first = TrustsRegistry()
        _direct(first, Grant)
        second = TrustsRegistry()
        root = Ref(NodeGrant)
        second.register(
            content=root.node, user=root.user, permission=root.permission,
        )
        handle_b = _handle(second, 'tests.policy.b')
        handle_a = _handle(first, 'tests.policy.a')
        combined = _data([handle_b, handle_a])
        only_a = _data([handle_a])
        self.assertEqual(
            [row['path'] for row in combined['handles']],
            ['tests.policy.a', 'tests.policy.b'],
        )
        self.assertEqual(len(only_a['handles']), 1)
        self.assertEqual(only_a['handles'][0]['path'], 'tests.policy.a')
        self.assertEqual(
            only_a['handles'][0]['registrations'][0]['fingerprint'],
            combined['handles'][0]['registrations'][0]['fingerprint'],
        )
        self.assertNotEqual(
            combined['handles'][0]['registrations'][0]['root'],
            combined['handles'][1]['registrations'][0]['root'],
        )
        self.assertNotIn(
            NodeGrant._meta.label,
            json.dumps(only_a),
        )

    def test_wrapper_object_identity_is_not_in_the_manifest(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.freeze()
        original = BackendHandle(
            path='tests.policy.wrap',
            registry=registry,
            compiler=PlanQueryCompiler(),
        )
        wrapped = BackendHandle(
            path=original.path,
            registry=original.registry,
            compiler=PlanQueryCompiler(),
        )
        self.assertIsNot(original, wrapped)
        self.assertIsNot(original.compiler, wrapped.compiler)
        self.assertEqual(_data([original]), _data([wrapped]))
        other_registry = TrustsRegistry()
        _direct(other_registry, Grant)
        other = _handle(other_registry, 'tests.policy.wrap')
        self.assertIsNot(other.registry, registry)
        self.assertEqual(_data([original]), _data([other]))

    def test_backend_compiler_change_changes_semantic_fingerprint(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()

        class OtherCompiler(PlanQueryCompiler):
            """Distinct compiler type with the same methods."""

        def snapshot(compiler, path):
            registry = TrustsRegistry()
            _direct(registry, Grant)
            return _data([_handle(registry, path, compiler=compiler)])

        base = snapshot(PlanQueryCompiler(), 'tests.policy.compiler')
        changed = snapshot(OtherCompiler(), 'tests.policy.compiler')
        moved = snapshot(PlanQueryCompiler(), 'tests.policy.other-backend')
        self.assertEqual(
            base['handles'][0]['registrations'][0]['fingerprint'],
            changed['handles'][0]['registrations'][0]['fingerprint'],
        )
        self.assertEqual(
            base['handles'][0]['compiler'],
            'trusts.core.PlanQueryCompiler',
        )
        self.assertEqual(
            changed['handles'][0]['compiler'],
            'tests.core.test_issue147.PolicyLockSnapshotTest.'
            'test_backend_compiler_change_changes_semantic_fingerprint.'
            '<locals>.OtherCompiler',
        )
        self.assertNotEqual(_semantic_digest(base), _semantic_digest(changed))
        self.assertNotEqual(_semantic_digest(base), _semantic_digest(moved))
        self.assertNotEqual(base['handles'][0]['path'], moved['handles'][0]['path'])
        self.assertEqual(
            base['handles'][0]['registrations'][0]['fingerprint'],
            moved['handles'][0]['registrations'][0]['fingerprint'],
        )

    def test_empty_relationship_handle_is_emitted(self):
        registry = TrustsRegistry()
        data = _data([_handle(registry, 'tests.policy.empty')])
        handle = data['handles'][0]
        self.assertEqual(handle['family'], 'relationship')
        self.assertEqual(handle['registrations'], [])
        self.assertEqual(handle['named_filters'], [])
        self.assertEqual(data['schema_version'], SCHEMA_VERSION)
        self.assertEqual(data['compiler_version'], COMPILER_VERSION)
        self.assertNotIn('diagnostics', data)

    def test_unsupported_family_fails_closed_for_the_whole_snapshot(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        kept = TrustsRegistry()
        _direct(kept, Grant)
        good = _handle(kept, 'tests.policy.good')
        bad_registry = TrustsRegistry()
        bad = _handle(bad_registry, 'tests.policy.fold')

        class FoldOwner(object):
            _authorization_family = 'ordered_fold'

        real = __import__(
            'trusts.apps', fromlist=['implementation_for_path'],
        ).implementation_for_path

        def family_for(path, apps_registry=None):
            if path == 'tests.policy.fold':
                return FoldOwner()
            return real(path, apps_registry)

        with patch('trusts.apps.implementation_for_path', side_effect=family_for):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([good, bad])
        message = str(ctx.exception)
        self.assertIn('tests.policy.fold', message)
        self.assertIn('ordered_fold', message)
        self.assertIn('relationship', message)
        self.assertNotIn('tests.policy.good', message)

    def test_named_filter_projects_allowlisted_constants(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'ranked', lambda u, p, o: (o.rank == 2) & (o.title != 'x'),
        )
        registry.register_permission_condition(
            Doc, 'untitled', lambda u, p, o: o.title == None,
        )
        registry.register_permission_condition(
            Doc, 'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        rows = _data([_handle(registry, 'tests.policy.filters')])['handles'][0]['named_filters']
        self.assertEqual(
            [row['code'] for row in rows],
            ['non_confidential', 'ranked', 'untitled'],
        )
        secret = rows[0]
        self.assertEqual(secret['model'], Doc._meta.label)
        self.assertEqual(secret['expr']['op'], 'ne')
        self.assertEqual(secret['expr']['left'], {
            'ref': 'object', 'path': ['confidential'],
        })
        self.assertEqual(secret['expr']['right'], {
            'const': {'type': 'bool', 'value': True},
        })
        self.assertRegex(secret['fingerprint'], _FINGERPRINT)
        untitled = rows[2]
        self.assertEqual(untitled['expr']['right'], {
            'const': {'type': 'null', 'value': None},
        })
        ranked = rows[1]
        self.assertEqual(ranked['expr']['op'], 'and')
        self.assertEqual(ranked['expr']['left']['right']['const'], {
            'type': 'int', 'value': 2,
        })
        self.assertEqual(ranked['expr']['right']['right']['const'], {
            'type': 'str', 'value': 'x',
        })

    def test_named_filter_rejects_nonportable_constants(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.conditions._records[(Doc._meta.label, 'ratio')] = ConditionRecord(
            expr=Eq(FilterRef('object', ('rank',)), Const(1.5)),
            model=Doc,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _data([_handle(registry, 'tests.policy.float')])
        self.assertIn('ratio', str(ctx.exception))
        self.assertIn('float', str(ctx.exception))

        huge = TrustsRegistry()
        _direct(huge, Grant)
        huge.register_permission_condition(
            Doc, 'big', lambda u, p, o: o.rank == (2**53),
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _data([_handle(huge, 'tests.policy.huge')])
        self.assertIn('int_dec', str(ctx.exception))

        identity = TrustsRegistry()
        _direct(identity, Grant)
        identity.conditions._records[(Doc._meta.label, 'tenant')] = ConditionRecord(
            expr=Eq(
                FilterRef('object', ('title',)),
                Const(ModelIdentity('myapp', 'doc', 9)),
            ),
            model=Doc,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _data([_handle(identity, 'tests.policy.pk')])
        self.assertIn('ModelIdentity', str(ctx.exception))
        self.assertNotIn('myapp', str(ctx.exception).split('ModelIdentity')[0])

    def test_default_renderer_profile_and_zero_sql(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        handle = _handle(registry, 'tests.policy.renderer')
        with _forbid_sql():
            data = _data([handle])
        renderer = data['handles'][0]['renderer']
        self.assertEqual(list(renderer), [
            'alias', 'engine', 'profile', 'profile_version', 'along',
        ])
        from django.db.utils import DEFAULT_DB_ALIAS
        self.assertEqual(renderer['alias'], DEFAULT_DB_ALIAS)
        self.assertEqual(renderer['alias'], 'default')
        self.assertEqual(
            renderer['engine'],
            connections['default'].settings_dict['ENGINE'],
        )
        self.assertEqual(renderer['profile'], SQLITE_JSON1_RCTE_PROFILE)
        self.assertEqual(renderer['profile_version'], 1)
        self.assertEqual(renderer['along'], ALONG_SUPPORTED)
        self.assertEqual(list(data), ['schema_version', 'compiler_version', 'handles'])
        self.assertEqual(list(data['handles'][0]['registrations'][0]), list(_REGISTRATION_KEYS))

    def test_renderer_fields_participate_in_semantic_compare(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        handle = _handle(registry, 'tests.policy.compare')
        sqlite = _data([handle])
        with _engine(
            'django.db.backends.postgresql',
            NAME='secret-db',
            PASSWORD='s3cret',
            OPTIONS={'sslmode': 'require'},
        ):
            with _forbid_sql():
                other = _data([handle])
        self.assertNotEqual(sqlite, other)
        self.assertEqual(
            sqlite['handles'][0]['registrations'],
            other['handles'][0]['registrations'],
        )
        self.assertEqual(other['handles'][0]['renderer']['engine'], 'django.db.backends.postgresql')
        self.assertEqual(
            other['handles'][0]['renderer']['profile'],
            GENERIC_UNSUPPORTED_ALONG_PROFILE,
        )
        self.assertEqual(other['handles'][0]['renderer']['along'], ALONG_UNSUPPORTED)
        matched = json.loads(json.dumps(other))
        matched['handles'][0]['renderer'] = sqlite['handles'][0]['renderer']
        self.assertEqual(matched, sqlite)
        blob = json.dumps(other)
        self.assertNotIn('secret-db', blob)
        self.assertNotIn('s3cret', blob)
        self.assertNotIn('sslmode', blob)

    def test_along_on_non_sqlite_renderer_fails_closed(self):
        _org, _doc, _grant, _node, _item, NodeGrant = _policy_models()
        registry = TrustsRegistry()
        root = Ref(NodeGrant)
        registry.register(
            content=root.node.items,
            user=root.user,
            permission=root.permission,
            along=Along(root.node.parent, bound=3),
        )
        handle = _handle(registry, 'tests.policy.along-engine')
        with _engine('django.db.backends.postgresql'):
            with _forbid_sql():
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    build_policy_manifest([handle])
        message = str(ctx.exception)
        self.assertIn('tests.policy.along-engine', message)
        self.assertIn('postgresql', message)
        self.assertIn(ALONG_UNSUPPORTED, message)
        self.assertIn('probe', message.lower())

    def test_caller_alias_is_ignored_for_the_recorded_renderer(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        handle = _handle(registry, 'tests.policy.alias')
        seen = []

        class _Default(object):
            alias = 'default'
            settings_dict = {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
                'PASSWORD': 'hunter2',
                'OPTIONS': {'sslmode': 'require'},
            }

        class _Spy(object):
            def __getitem__(self, alias):
                seen.append(alias)
                if alias != 'default':
                    raise AssertionError('caller alias was consulted: %r' % alias)
                return _Default()

        with patch('django.db.connections', _Spy()):
            data = _data([handle], alias='reports')
        self.assertEqual(seen, ['default'])
        renderer = data['handles'][0]['renderer']
        self.assertEqual(renderer['alias'], 'default')
        self.assertEqual(renderer['engine'], 'django.db.backends.sqlite3')
        self.assertEqual(renderer['profile'], SQLITE_JSON1_RCTE_PROFILE)
        blob = json.dumps(data)
        self.assertNotIn('reports', blob)
        self.assertNotIn('hunter2', blob)
        self.assertNotIn('sslmode', blob)

    def test_missing_or_malformed_default_alias_fails_contextually(self):
        registry = TrustsRegistry()
        handle = _handle(registry, 'tests.policy.alias-missing')
        with patch('django.db.utils.DEFAULT_DB_ALIAS', 'not-configured'):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('not-configured', str(ctx.exception))
        with patch('django.db.utils.DEFAULT_DB_ALIAS', ''):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('malformed', str(ctx.exception).lower())
        with patch('django.db.utils.DEFAULT_DB_ALIAS', None):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('malformed', str(ctx.exception).lower())
        with _engine(''):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('ENGINE', str(ctx.exception))
        with _engine('django.db.backends.dummy'):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('malformed', str(ctx.exception).lower())

        from django.core.exceptions import ImproperlyConfigured

        with patch(
            'django.utils.connection.BaseConnectionHandler.__getitem__',
            side_effect=ImproperlyConfigured('backend load failed'),
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('backend load failed', str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, ImproperlyConfigured)

    def test_configured_handles_are_enumerated_when_present(self):
        from django.conf import settings

        backends = tuple(getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ())
        if 'tests.myapp.backends.DocumentBackend' not in backends:
            self.skipTest('kernel document owner is not configured')
        with _forbid_sql():
            data = manifest_to_json_data(build_policy_manifest())
        paths = [handle['path'] for handle in data['handles']]
        self.assertEqual(paths, sorted(paths))
        self.assertIn('tests.myapp.backends.DocumentBackend', paths)
        self.assertIn('tests.backends.HostTrustModelBackend', paths)
        document = next(
            handle for handle in data['handles']
            if handle['path'] == 'tests.myapp.backends.DocumentBackend'
        )
        self.assertEqual(document['family'], 'relationship')
        self.assertTrue(any(
            row['label'].endswith('DocumentGrant:document')
            for row in document['registrations']
        ))
        codes = [row['code'] for row in document['named_filters']]
        self.assertIn('non_confidential', codes)
        self.assertEqual(document['renderer']['alias'], 'default')


class PolicyLockImportTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE

        self.assertIn('tests.core.test_issue147', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue147', PAIR_KERNEL_SUITE)

    def test_snapshot_symbols_do_not_gate_authorization(self):
        import trusts.backends as backends
        import trusts.query as query
        source_backend = open(backends.__file__, encoding='utf-8').read()
        source_query = open(query.__file__, encoding='utf-8').read()
        self.assertNotIn('ensure_policy_lockfile_verified', source_backend)
        self.assertNotIn('ensure_policy_lockfile_verified', source_query)
        self.assertNotIn('build_policy_manifest', source_backend)
