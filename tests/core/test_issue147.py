"""Lockfile C1 snapshot and C2 canonical document (#147).

C1: immutable finalized projection, registration fingerprints, readable
labels, unsupported-family failure, and the default-alias renderer
profile. C2: quiet UTF-8/LF serializer and strict reader, commutative
named-filter AND/OR, and the ``int`` / ``int_dec`` constant boundary.
No generate/check command, no runtime gate, no SQL.
"""

import hashlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from datetime import date
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

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


class PortableOtherCompiler(PlanQueryCompiler):
    """Module-level compiler so its identity round-trips through import."""
from trusts.policy_lock import (
    ALONG_SUPPORTED,
    ALONG_UNSUPPORTED,
    COMPILER_VERSION,
    GENERIC_UNSUPPORTED_ALONG_PROFILE,
    PolicyManifest,
    SCHEMA_VERSION,
    SQLITE_JSON1_RCTE_PROFILE,
    build_policy_manifest,
    canonicalize,
    encode_policy_document,
    fingerprint_registration,
    manifest_to_json_data,
    read_policy_document,
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


_owner_seq = 0


@contextmanager
def _installed_owner(path, family='relationship', label=None):
    """Install one strict implementation owner for a synthetic backend path."""
    global _owner_seq
    from django.apps import apps as django_apps

    import tests as tests_module
    from trusts.apps import TrustsImplementationConfig

    _owner_seq += 1
    label = label or ('policy_own_%s' % _owner_seq)
    if label in django_apps.app_configs:
        raise AssertionError('app label %r is already installed' % label)

    class Owner(TrustsImplementationConfig):
        pass

    Owner.label = label
    Owner.trusts_backend_paths = (path,)
    Owner._authorization_family = family
    owner = Owner('tests.%s' % label, tests_module)
    owner.apps = django_apps
    django_apps.app_configs[label] = owner
    try:
        yield owner
    finally:
        django_apps.app_configs.pop(label, None)


@contextmanager
def _owned(*handles):
    with ExitStack() as stack:
        seen = set()
        for handle in handles:
            if handle.path in seen:
                continue
            seen.add(handle.path)
            stack.enter_context(_installed_owner(handle.path))
        yield


def _data(handles, **kwargs):
    with _owned(*handles):
        return manifest_to_json_data(build_policy_manifest(handles, **kwargs))


def _minimal_registration_payload():
    return {
        'kind': 'any_path',
        'root': 'app.Grant',
        'user': ['user'],
        'user_model': 'auth.User',
        'user_target': 'id',
        'permission': ['permission'],
        'permission_model': 'auth.Permission',
        'permission_target': 'id',
        'content': ['document'],
        'content_model': 'app.Doc',
        'content_target': 'id',
        'condition': None,
        'along': None,
    }


def _minimal_along():
    return {
        'bound': 3,
        'shape': 'S',
        'walk_path': ['node'],
        'walk_model': 'app.Node',
        'walk_ident': 'id',
        'suffix_path': ['items'],
        'ident_family': 'integer',
        'parent_attname': 'parent_id',
        'edge_model': None,
        'edge_parent_attname': None,
        'edge_child_attname': None,
        'rewrite_attname': None,
    }


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
        with _owned(handle):
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
        with _owned(handle):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([handle])
        self.assertIn('tests.policy.thawed', str(ctx.exception))
        self.assertIn('frozen', str(ctx.exception))
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

        def snapshot(compiler, path):
            registry = TrustsRegistry()
            _direct(registry, Grant)
            return _data([_handle(registry, path, compiler=compiler)])

        from django.utils.module_loading import import_string

        base = snapshot(PlanQueryCompiler(), 'tests.policy.compiler')
        changed = snapshot(PortableOtherCompiler(), 'tests.policy.compiler')
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
            'tests.core.test_issue147.PortableOtherCompiler',
        )
        self.assertIs(
            import_string(base['handles'][0]['compiler']),
            PlanQueryCompiler,
        )
        self.assertIs(
            import_string(changed['handles'][0]['compiler']),
            PortableOtherCompiler,
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

        with _installed_owner('tests.policy.good', 'relationship'), \
                _installed_owner('tests.policy.fold', 'ordered_fold'):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([good, bad])
        message = str(ctx.exception)
        self.assertIn('tests.policy.fold', message)
        self.assertIn('ordered_fold', message)
        self.assertIn('relationship', message)
        self.assertNotIn('tests.policy.good', message)

    def test_missing_and_duplicate_owners_fail_closed(self):
        missing = _handle(TrustsRegistry(), 'tests.policy.missing-owner')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            build_policy_manifest([missing])
        message = str(ctx.exception)
        self.assertIn('tests.policy.missing-owner', message)
        self.assertIn('No implementation owns', message)
        self.assertIn('exact owner', message)

        duplicated = _handle(TrustsRegistry(), 'tests.policy.duplicate-owner')
        with _installed_owner(
            'tests.policy.duplicate-owner', 'relationship', label='policy_dup_rel',
        ), _installed_owner(
            'tests.policy.duplicate-owner', 'ordered_fold', label='policy_dup_fold',
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([duplicated])
        message = str(ctx.exception)
        self.assertIn('tests.policy.duplicate-owner', message)
        self.assertIn('multiple implementation owners', message)
        self.assertIn('policy_dup_rel', message)
        self.assertIn('policy_dup_fold', message)
        self.assertNotIn('sha256:', message)

    def test_local_compiler_identity_is_rejected(self):
        class LocalCompiler(PlanQueryCompiler):
            """Source-scoped type; not importable in another process."""

        local = _handle(
            TrustsRegistry(), 'tests.policy.local-compiler',
            compiler=LocalCompiler(),
        )
        with _owned(local):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([local])
        message = str(ctx.exception)
        self.assertIn('tests.policy.local-compiler', message)
        self.assertIn('portable', message.lower())
        self.assertIn('<locals>', message)

        dynamic = type('DynCompiler', (PlanQueryCompiler,), {})
        dyn_handle = _handle(
            TrustsRegistry(), 'tests.policy.dyn-compiler', compiler=dynamic(),
        )
        with _owned(dyn_handle):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                build_policy_manifest([dyn_handle])
        self.assertIn('tests.policy.dyn-compiler', str(ctx.exception))
        self.assertIn('portable', str(ctx.exception).lower())

    def test_fingerprint_rejects_unknown_fields_and_bad_path_types(self):
        base = _minimal_registration_payload()
        accepted = fingerprint_registration(base)
        self.assertRegex(accepted, _FINGERPRINT)
        labeled = dict(base)
        labeled['fingerprint'] = 'sha256:' + ('ab' * 32)
        labeled['label'] = 'app.Grant:document'
        self.assertEqual(fingerprint_registration(labeled), accepted)

        extra = dict(base)
        extra['source'] = 'registrations.py:12'
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(extra)
        self.assertIn('source', str(ctx.exception))
        self.assertIn('unexpected', str(ctx.exception))

        nested = dict(base)
        nested['condition'] = {
            'op': 'equal',
            'left': ['team_org'],
            'right': ['repo_org'],
            'lineno': 40,
        }
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(nested)
        self.assertIn('lineno', str(ctx.exception))
        self.assertIn('unexpected', str(ctx.exception))

        along = dict(base)
        along['along'] = dict(_minimal_along(), walk_field='node')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(along)
        self.assertIn('walk_field', str(ctx.exception))
        self.assertIn('unexpected', str(ctx.exception))

        bad_component = dict(base)
        bad_component['content'] = ['document', 1]
        coerced = dict(base)
        coerced['content'] = ['document', '1']
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(bad_component)
        self.assertIn('content', str(ctx.exception))
        self.assertIn('1', str(ctx.exception))
        self.assertNotEqual(accepted, fingerprint_registration(coerced))
        other_component = dict(base)
        other_component['content'] = ['document', 2]
        with self.assertRaises(TrustsConfigurationError) as other_ctx:
            fingerprint_registration(other_component)
        self.assertNotEqual(str(ctx.exception), str(other_ctx.exception))

        bad_equal = dict(base)
        bad_equal['condition'] = {
            'op': 'equal',
            'left': ['team_org', None],
            'right': ['repo_org'],
        }
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(bad_equal)
        self.assertIn('non-string', str(ctx.exception))
        self.assertIn('None', str(ctx.exception))

    def test_fingerprint_rejects_missing_condition_keys(self):
        base = _minimal_registration_payload()
        cases = (
            ({'op': 'all'}, 'all', 'predicates'),
            ({'op': 'equal', 'left': ['tenant']}, 'equal', 'right'),
            ({'op': 'permission_in'}, 'permission_in', 'refs'),
        )
        for condition, op, missing in cases:
            payload = dict(base)
            payload['condition'] = condition
            with self.assertRaises(TrustsConfigurationError) as ctx:
                fingerprint_registration(payload)
            message = str(ctx.exception)
            self.assertIn(op, message)
            self.assertIn(missing, message)
            self.assertIn('missing', message)
            self.assertNotIsInstance(ctx.exception, KeyError)

        both = dict(base)
        both['condition'] = {'op': 'equal'}
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(both)
        message = str(ctx.exception)
        self.assertIn('left', message)
        self.assertIn('right', message)

        nested = dict(base)
        nested['condition'] = {
            'op': 'all',
            'predicates': [{'op': 'equal', 'left': ['tenant']}],
        }
        with self.assertRaises(TrustsConfigurationError) as ctx:
            fingerprint_registration(nested)
        self.assertIn('right', str(ctx.exception))
        self.assertIn("'equal'", str(ctx.exception))

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
        self.assertNotIn('left', ranked['expr'])
        self.assertNotIn('right', ranked['expr'])
        self.assertCountEqual(
            [operand['right']['const'] for operand in ranked['expr']['operands']],
            [
                {'type': 'int', 'value': 2},
                {'type': 'str', 'value': 'x'},
            ],
        )
        self.assertEqual(
            ranked['expr']['operands'],
            sorted(
                ranked['expr']['operands'],
                key=lambda node: json.dumps(
                    node, ensure_ascii=False, sort_keys=True,
                    separators=(',', ':'),
                ),
            ),
        )

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
        with _owned(handle):
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


def _lock_bytes(handles):
    with _owned(*handles):
        manifest = build_policy_manifest(handles)
        return manifest, canonicalize(manifest)


def _filter_const(document, code):
    for handle in document['handles']:
        for row in handle['named_filters']:
            if row['code'] == code:
                return row['expr']['right']['const']
    raise AssertionError('named filter %r is missing' % code)


def _replace_filter_const(raw, code, const):
    data = json.loads(raw)
    found = False
    for handle in data['handles']:
        for row in handle['named_filters']:
            if row['code'] == code:
                row['expr']['right']['const'] = const
                found = True
    if not found:
        raise AssertionError('named filter %r is missing' % code)
    return json.dumps(data)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PolicyLockCanonicalDocumentTest(SimpleTestCase):
    """C2 quiet serializer, strict reader, and named-filter IR."""

    def test_quiet_regeneration_is_byte_stable(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'titled', lambda u, p, o: o.title == 'café',
        )
        handle = _handle(registry, 'tests.policy.quiet')
        with _owned(handle):
            manifest = build_policy_manifest([handle])
            with _forbid_sql():
                first = canonicalize(manifest)
                second = canonicalize(manifest)
                semantic = manifest_to_json_data(manifest)
        self.assertEqual(first, second)
        self.assertIsInstance(first, bytes)
        self.assertTrue(first.endswith(b'\n'))
        self.assertFalse(first.endswith(b'\n\n'))
        self.assertNotIn(b'\r', first)
        self.assertFalse(first.startswith(b'\xef\xbb\xbf'))
        self.assertIn('café'.encode('utf-8'), first)
        self.assertNotIn(b'\\u00e9', first)
        self.assertNotIn(b'"diagnostics"', first)
        self.assertEqual(read_policy_document(first), semantic)
        self.assertEqual(encode_policy_document(read_policy_document(first)), first)
        parsed = json.loads(first)
        parsed['diagnostics'] = {
            'package': '1.0.0rc1',
            'generated_at': '2020-01-01T00:00:00Z',
            'checkout': '/tmp/not-semantic',
        }
        messy = json.dumps(parsed, indent=4, ensure_ascii=False).replace('\n', '\r\n')
        self.assertIn('\r\n', messy)
        with _forbid_sql():
            reread = read_policy_document(messy)
            regenerated = encode_policy_document(reread)
        self.assertEqual(reread, semantic)
        self.assertNotIn('diagnostics', reread)
        self.assertEqual(regenerated, first)
        self.assertNotIn(b'diagnostics', regenerated)
        self.assertNotIn(b'generated_at', regenerated)
        self.assertNotIn(b'checkout', regenerated)

    def test_fresh_process_bytes_match_across_hash_seeds(self):
        parent = canonicalize(build_policy_manifest())
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__),
        )))
        source = (
            'import django\n'
            'django.setup()\n'
            'from trusts.policy_lock import build_policy_manifest, canonicalize\n'
            'import sys\n'
            'sys.stdout.buffer.write(canonicalize(build_policy_manifest()))\n'
        )
        for seed in ('0', '1'):
            env = os.environ.copy()
            env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
            env['PYTHONHASHSEED'] = seed
            env['PYTHONPATH'] = os.pathsep.join(
                [root, env['PYTHONPATH']] if env.get('PYTHONPATH') else [root]
            )
            result = subprocess.run(
                [sys.executable, '-c', source],
                cwd=root,
                env=env,
                capture_output=True,
            )
            self.assertEqual(
                result.returncode, 0,
                result.stderr.decode('utf-8', 'replace'),
            )
            self.assertEqual(result.stdout, parent)
            self.assertNotIn(b'\r', result.stdout)
            self.assertNotIn(b'"diagnostics"', result.stdout)

    def test_commutative_named_filters_encode_identically(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()

        def _row(builder, path):
            registry = TrustsRegistry()
            _direct(registry, Grant)
            registry.register_permission_condition(Doc, 'both', builder)
            data = _data([_handle(registry, path)])
            return data['handles'][0]['named_filters'][0]

        left = _row(
            lambda u, p, o: (o.rank == 1) & (o.title == 'a'),
            'tests.policy.and-left',
        )
        right = _row(
            lambda u, p, o: (o.title == 'a') & (o.rank == 1),
            'tests.policy.and-right',
        )
        self.assertEqual(left['fingerprint'], right['fingerprint'])
        self.assertEqual(left['expr'], right['expr'])
        self.assertEqual(left['expr']['op'], 'and')
        self.assertEqual(len(left['expr']['operands']), 2)

        nested_left = _row(
            lambda u, p, o: ((o.rank == 1) & (o.rank == 2)) & (o.title == 'a'),
            'tests.policy.and-nest-left',
        )
        nested_right = _row(
            lambda u, p, o: (o.title == 'a') & ((o.rank == 2) & (o.rank == 1)),
            'tests.policy.and-nest-right',
        )
        self.assertEqual(nested_left['fingerprint'], nested_right['fingerprint'])
        self.assertEqual(nested_left['expr'], nested_right['expr'])
        self.assertEqual(len(nested_left['expr']['operands']), 3)
        self.assertTrue(all(
            operand['op'] in ('eq', 'ne')
            for operand in nested_left['expr']['operands']
        ))

        or_left = _row(
            lambda u, p, o: (o.rank == 1) | (o.rank == 2) | (o.title == 'z'),
            'tests.policy.or-left',
        )
        or_right = _row(
            lambda u, p, o: (o.title == 'z') | ((o.rank == 2) | (o.rank == 1)),
            'tests.policy.or-right',
        )
        self.assertEqual(or_left['fingerprint'], or_right['fingerprint'])
        self.assertEqual(or_left['expr']['op'], 'or')
        self.assertEqual(len(or_left['expr']['operands']), 3)

        mixed = _row(
            lambda u, p, o: ((o.rank == 1) & (o.title == 'a')) | (o.rank == 3),
            'tests.policy.mixed',
        )
        swapped_and = _row(
            lambda u, p, o: (o.rank == 3) | ((o.title == 'a') & (o.rank == 1)),
            'tests.policy.mixed-swap',
        )
        self.assertEqual(mixed['fingerprint'], swapped_and['fingerprint'])
        self.assertEqual(mixed['expr']['op'], 'or')
        self.assertEqual(len(mixed['expr']['operands']), 2)
        different = _row(
            lambda u, p, o: ((o.rank == 1) | (o.title == 'a')) & (o.rank == 3),
            'tests.policy.mixed-different',
        )
        self.assertNotEqual(mixed['fingerprint'], different['fingerprint'])

    def test_reader_normalizes_commutative_document_order(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        root = Ref(Grant)
        registry = TrustsRegistry()
        registry.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=All(
                Equal(root.team_org, root.repo_org),
                Equal(root.alt_org, root.team_org),
            ),
        )
        registry.register_permission_condition(
            Doc, 'both', lambda u, p, o: (o.rank == 1) & (o.title == 'a'),
        )
        handle = _handle(registry, 'tests.policy.reorder')
        _manifest, raw = _lock_bytes([handle])
        data = json.loads(raw)
        predicates = data['handles'][0]['registrations'][0]['condition']['predicates']
        predicates.reverse()
        operands = data['handles'][0]['named_filters'][0]['expr']['operands']
        operands.reverse()
        data['handles'].reverse()
        with _forbid_sql():
            regenerated = encode_policy_document(read_policy_document(
                json.dumps(data),
            ))
        self.assertEqual(regenerated, raw)

    def test_integer_encoding_uses_int_and_int_dec(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        safe = 2**53 - 1
        outside = 2**53
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'zero', lambda u, p, o: o.rank == 0,
        )
        registry.register_permission_condition(
            Doc, 'negative', lambda u, p, o: o.rank == -1,
        )
        registry.register_permission_condition(
            Doc, 'safe', lambda u, p, o: o.rank == safe,
        )
        registry.register_permission_condition(
            Doc, 'safe_neg', lambda u, p, o: o.rank == -safe,
        )
        registry.register_permission_condition(
            Doc, 'outside', lambda u, p, o: o.rank == outside,
        )
        registry.register_permission_condition(
            Doc, 'outside_neg', lambda u, p, o: o.rank == -outside,
        )
        data = _data([_handle(registry, 'tests.policy.ints')])
        self.assertEqual(_filter_const(data, 'zero'), {'type': 'int', 'value': 0})
        self.assertEqual(_filter_const(data, 'negative'), {'type': 'int', 'value': -1})
        self.assertEqual(_filter_const(data, 'safe'), {'type': 'int', 'value': safe})
        self.assertEqual(
            _filter_const(data, 'safe_neg'), {'type': 'int', 'value': -safe},
        )
        self.assertEqual(
            _filter_const(data, 'outside'),
            {'type': 'int_dec', 'value': str(outside)},
        )
        self.assertEqual(
            _filter_const(data, 'outside_neg'),
            {'type': 'int_dec', 'value': str(-outside)},
        )
        handle = _handle(registry, 'tests.policy.ints-bytes')
        _manifest, raw = _lock_bytes([handle])
        text = raw.decode('utf-8')
        self.assertIn('"type": "int_dec"', text)
        self.assertIn('"value": "%s"' % outside, text)
        self.assertNotIn('"value": %s' % outside, text)
        self.assertEqual(encode_policy_document(read_policy_document(raw)), raw)

    def test_cross_shape_and_noncanonical_int_dec_are_rejected(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        outside = 2**53
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'outside', lambda u, p, o: o.rank == outside,
        )
        registry.register_permission_condition(
            Doc, 'small', lambda u, p, o: o.rank == 2,
        )
        _manifest, raw = _lock_bytes([
            _handle(registry, 'tests.policy.int-shape'),
        ])
        cases = (
            ('outside', {'type': 'int', 'value': outside}, 'cross-shape'),
            ('outside', {'type': 'int_dec', 'value': outside}, 'cross-shape'),
            ('small', {'type': 'int', 'value': '2'}, 'cross-shape'),
            ('small', {'type': 'int', 'value': True}, 'cross-shape'),
            ('small', {'type': 'int', 'value': 2.0}, 'cross-shape'),
            ('small', {'type': 'int_dec', 'value': '2'}, 'cross-shape'),
            ('outside', {'type': 'int_dec', 'value': '+' + str(outside)}, 'noncanonical'),
            ('outside', {'type': 'int_dec', 'value': '0' + str(outside)}, 'noncanonical'),
            ('outside', {'type': 'int_dec', 'value': '-0' + str(outside)}, 'noncanonical'),
            ('small', {'type': 'int_dec', 'value': '01'}, 'noncanonical'),
            ('small', {'type': 'int_dec', 'value': '-0'}, 'noncanonical'),
            ('small', {'type': 'int_dec', 'value': '2.0'}, 'noncanonical'),
            ('small', {'type': 'int_dec', 'value': ' 2'}, 'noncanonical'),
        )
        for code, const, needle in cases:
            mutated = _replace_filter_const(raw, code, const)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_policy_document(mutated)
            self.assertIn(needle, str(ctx.exception))
            self.assertIn(code, str(ctx.exception))

    def test_unsupported_constants_fail_closed(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        samples = (
            ('ratio', 1.5, 'float'),
            ('blob', b'\x00\x01', 'bytes'),
            ('money', Decimal('1.50'), 'Decimal'),
            ('ident', UUID('12345678-1234-5678-1234-567812345678'), 'UUID'),
            ('when', date(2020, 1, 2), 'date'),
            ('tenant', ModelIdentity('myapp', 'doc', 9), 'ModelIdentity'),
        )
        for code, value, needle in samples:
            registry = TrustsRegistry()
            _direct(registry, Grant)
            registry.conditions._records[(Doc._meta.label, code)] = ConditionRecord(
                expr=Eq(FilterRef('object', ('title',)), Const(value)),
                model=Doc,
            )
            with self.assertRaises(TrustsConfigurationError) as ctx:
                _data([_handle(registry, 'tests.policy.%s' % code)])
            message = str(ctx.exception)
            self.assertIn(code, message)
            self.assertIn(needle, message)
            self.assertIn('not portable', message)
            if needle == 'ModelIdentity':
                self.assertNotIn('myapp', message.split('ModelIdentity')[0])

    def test_unknown_fields_are_rejected_recursively(self):
        _org, Doc, Grant, _node, _item, NodeGrant = _policy_models()
        registry = TrustsRegistry()
        root = Ref(Grant)
        registry.register(
            content=root.document,
            user=root.user,
            permission=root.permission,
            condition=Equal(root.team_org, root.repo_org),
        )
        node = Ref(NodeGrant)
        registry.register(
            content=node.node.items,
            user=node.user,
            permission=node.permission,
            along=Along(node.node.parent, bound=3),
        )
        registry.register_permission_condition(
            Doc, 'ranked', lambda u, p, o: (o.rank == 2) & (o.title != 'x'),
        )
        _manifest, raw = _lock_bytes([
            _handle(registry, 'tests.policy.unknown'),
        ])
        data = json.loads(raw)

        def _reject(mutator, needle):
            cloned = json.loads(json.dumps(data))
            mutator(cloned)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_policy_document(json.dumps(cloned))
            self.assertIn(needle, str(ctx.exception))
            self.assertIn('unexpected', str(ctx.exception))

        _reject(lambda doc: doc.__setitem__('extra', 1), 'extra')
        _reject(
            lambda doc: doc['handles'][0].__setitem__('diagnostics', {}),
            'diagnostics',
        )
        _reject(
            lambda doc: doc['handles'][0].__setitem__('note', 'x'),
            'note',
        )
        _reject(
            lambda doc: doc['handles'][0]['renderer'].__setitem__('password', 'x'),
            'password',
        )
        _reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'source', 'line 1',
            ),
            'source',
        )
        def _conditioned(doc):
            for row in doc['handles'][0]['registrations']:
                if row['condition'] is not None and row['along'] is None:
                    row['condition']['note'] = True
                    return
            raise AssertionError('conditioned registration is missing')

        def _along(doc):
            for row in doc['handles'][0]['registrations']:
                if row['along'] is not None:
                    row['along']['note'] = True
                    return
            raise AssertionError('along registration is missing')

        _reject(_conditioned, 'note')
        _reject(_along, 'note')
        _reject(
            lambda doc: doc['handles'][0]['named_filters'][0].__setitem__('note', 1),
            'note',
        )
        _reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr'].__setitem__(
                'left', {'ref': 'object', 'path': ['rank']},
            ),
            'left',
        )
        _reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['operands'][0].__setitem__(
                'note', 1,
            ),
            'note',
        )
        _reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['operands'][0]['right']['const'].__setitem__(
                'base', 10,
            ),
            'base',
        )

        encoded = dict(data)
        encoded['diagnostics'] = {'kept': False}
        with self.assertRaises(TrustsConfigurationError):
            encode_policy_document(encoded)

    def test_schema_and_compiler_versions_are_strict(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        _manifest, raw = _lock_bytes([
            _handle(registry, 'tests.policy.version'),
        ])
        data = json.loads(raw)
        for key, bad in (
            ('schema_version', 2),
            ('schema_version', True),
            ('schema_version', '1'),
            ('compiler_version', 2),
            ('compiler_version', 1.0),
        ):
            cloned = dict(data)
            cloned[key] = bad
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_policy_document(json.dumps(cloned))
            self.assertIn(key, str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_policy_document('{')
        self.assertIn('JSON', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            read_policy_document(b'\xef\xbb\xbf' + raw)
        with self.assertRaises(TrustsConfigurationError):
            read_policy_document(b'\xff')

    def test_diagnostics_do_not_affect_semantic_comparison(self):
        _org, _doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        _manifest, raw = _lock_bytes([
            _handle(registry, 'tests.policy.semantic'),
        ])
        with_notes = json.loads(raw)
        with_notes['diagnostics'] = {'package': '9.9.9', 'noise': [1, {'a': True}]}
        quiet = read_policy_document(raw)
        noted = read_policy_document(json.dumps(with_notes))
        self.assertEqual(quiet, noted)
        self.assertNotIn('diagnostics', quiet)
        changed = json.loads(raw)
        changed['handles'][0]['compiler'] += '.Other'
        self.assertNotEqual(read_policy_document(json.dumps(changed)), quiet)
        tampered = json.loads(raw)
        tampered['handles'][0]['registrations'][0]['content'].append('other')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_policy_document(json.dumps(tampered))
        self.assertIn('fingerprint', str(ctx.exception))


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
