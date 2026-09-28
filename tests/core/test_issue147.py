"""Lockfile C1 snapshot seam and C2 canonical document (#147).

C1: immutable projection, fingerprints, labels, unsupported-family
failure, and the default-alias renderer profile.
C2: quiet UTF-8/LF serializer, strict reader, commutative named-filter
AND/OR, and ``int`` / ``int_dec``. No generate/check command, no
runtime gate, no SQL.
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connections, models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.conditions._ir import (
    And,
    ConditionRecord,
    Const,
    Eq,
    ModelIdentity,
    Or,
    Ref as FilterRef,
    _Ordering,
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
    fingerprint_registration,
    manifest_to_json_data,
    read_canonical_policy,
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
        self.assertEqual(
            sorted(
                (arg['right']['const']['type'], arg['right']['const']['value'])
                for arg in ranked['expr']['args']
            ),
            [('int', 2), ('str', 'x')],
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

        for value, type_name in (
            (b'\x00secret', 'bytes'),
            (Decimal('1.25'), 'Decimal'),
        ):
            other = TrustsRegistry()
            _direct(other, Grant)
            other.conditions._records[(Doc._meta.label, 'other')] = ConditionRecord(
                expr=Eq(FilterRef('object', ('title',)), Const(value)),
                model=Doc,
            )
            with self.assertRaises(TrustsConfigurationError) as ctx:
                _data([_handle(other, 'tests.policy.%s' % type_name)])
            self.assertIn(type_name, str(ctx.exception))
            self.assertNotIn('secret', str(ctx.exception))

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


def _sha(text='ab'):
    return 'sha256:' + (text * 32)


def _lock_document(expr=None):
    """Minimal semantic document. ``expr`` adds one named filter."""
    payload = _minimal_registration_payload()
    registration = {
        'fingerprint': fingerprint_registration(payload),
        'label': 'app.Grant:document',
    }
    registration.update(payload)
    named = []
    if expr is not None:
        named.append({
            'model': 'app.Doc',
            'code': 'ranked',
            'fingerprint': _sha(),
            'expr': expr,
        })
    return {
        'schema_version': SCHEMA_VERSION,
        'compiler_version': COMPILER_VERSION,
        'handles': [{
            'path': 'tests.policy.reader',
            'family': 'relationship',
            'compiler': 'trusts.core.PlanQueryCompiler',
            'renderer': {
                'alias': 'default',
                'engine': 'django.db.backends.sqlite3',
                'profile': SQLITE_JSON1_RCTE_PROFILE,
                'profile_version': 1,
                'along': ALONG_SUPPORTED,
            },
            'registrations': [registration],
            'named_filters': named,
        }],
    }


def _eq_expr(path, const):
    return {
        'op': 'eq',
        'left': {'ref': 'object', 'path': [path]},
        'right': {'const': const},
    }


_SAFE_INT = 2**53 - 1
_OUT_INT = 2**53


class PolicyLockCanonicalTest(SimpleTestCase):
    def test_quiet_bytes_regenerate_and_match_across_processes(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'titled', lambda u, p, o: o.title == 'café',
        )
        handle = _handle(registry, 'tests.policy.quiet')
        with _owned(handle):
            with _forbid_sql():
                manifest = build_policy_manifest([handle])
                blob = canonicalize(manifest)
                again = canonicalize(manifest)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(blob, again)
        self.assertTrue(blob.endswith(b'\n'))
        self.assertNotIn(b'\r', blob)
        self.assertFalse(blob.startswith(b'\xef\xbb\xbf'))
        self.assertIn('café'.encode('utf-8'), blob)
        self.assertNotIn(b'\\u00e9', blob)
        text = blob.decode('utf-8')
        self.assertTrue(text.startswith('{\n  "schema_version": 1,\n'))
        loaded = json.loads(text)
        self.assertEqual(
            list(loaded),
            ['schema_version', 'compiler_version', 'handles'],
        )
        self.assertEqual(
            list(loaded['handles'][0]),
            [
                'path', 'family', 'compiler', 'renderer',
                'registrations', 'named_filters',
            ],
        )
        self.assertEqual(
            read_canonical_policy(blob),
            manifest_to_json_data(manifest),
        )
        self.assertEqual(canonicalize(blob), blob)

        edited = json.loads(text)
        edited['diagnostics'] = {
            'generated_at': '2020-01-01T00:00:00Z',
            'checkout': '/tmp/secret-checkout',
        }
        messy = json.dumps(edited, indent=4, sort_keys=True).replace('\n', '\r\n')
        self.assertIn('\r\n', messy)
        regenerated = canonicalize(messy.encode('utf-8'))
        self.assertEqual(regenerated, blob)
        semantic = read_canonical_policy(messy)
        self.assertNotIn('diagnostics', semantic)
        self.assertNotIn(b'diagnostics', regenerated)
        self.assertNotIn(b'secret-checkout', regenerated)
        self.assertEqual(semantic, manifest_to_json_data(manifest))

        empty = canonicalize({
            'compiler_version': 1,
            'handles': [],
            'diagnostics': {'noise': True},
            'schema_version': 1,
        })
        self.assertEqual(
            empty,
            b'{\n  "schema_version": 1,\n  "compiler_version": 1,\n  "handles": []\n}\n',
        )
        self.assertEqual(canonicalize(empty), empty)

        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__),
        )))
        script = (
            'import json, os, sys\n'
            'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")\n'
            'import django\n'
            'django.setup()\n'
            'from trusts.policy_lock import canonicalize\n'
            'raw = sys.stdin.buffer.read()\n'
            'sys.stdout.buffer.write(canonicalize(json.loads(raw.decode("utf-8"))))\n'
        )
        env = os.environ.copy()
        env['PYTHONPATH'] = root + os.pathsep + env.get('PYTHONPATH', '')
        env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
        proc = subprocess.run(
            [sys.executable, '-c', script],
            input=json.dumps(json.loads(text)).encode('utf-8'),
            capture_output=True,
            cwd=root,
            env=env,
            check=False,
        )
        self.assertEqual(
            proc.returncode, 0, proc.stderr.decode('utf-8', 'replace'),
        )
        self.assertEqual(proc.stdout, blob)

    def test_diagnostics_are_top_level_only_and_do_not_mutate_input(self):
        document = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        document['diagnostics'] = {'note': 'keep out', 'nested': {'x': 1}}
        original = copy.deepcopy(document)
        semantic = read_canonical_policy(document)
        self.assertEqual(document, original)
        self.assertNotIn('diagnostics', semantic)
        self.assertNotIn(b'diagnostics', canonicalize(document))
        nested = copy.deepcopy(document)
        del nested['diagnostics']
        nested['handles'][0]['diagnostics'] = {'note': 'nope'}
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(nested)
        self.assertIn('diagnostics', str(ctx.exception))
        self.assertIn('unexpected', str(ctx.exception))

    def test_non_object_diagnostics_are_rejected(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        samples = (
            (None, 'NoneType'),
            ('note', 'str'),
            (['a'], 'list'),
            (1, 'int'),
            (1.5, 'float'),
            (True, 'bool'),
        )
        for value, type_name in samples:
            document = copy.deepcopy(base)
            document['diagnostics'] = value
            for source in (document, json.dumps(document), json.dumps(document).encode('utf-8')):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    read_canonical_policy(source)
                message = str(ctx.exception)
                self.assertIn('diagnostics', message)
                self.assertIn('object', message)
                self.assertIn(type_name, message)
                with self.assertRaises(TrustsConfigurationError):
                    canonicalize(source)
        empty = copy.deepcopy(base)
        empty['diagnostics'] = {}
        self.assertNotIn('diagnostics', read_canonical_policy(empty))
        self.assertNotIn(b'diagnostics', canonicalize(empty))
        absent = copy.deepcopy(base)
        self.assertEqual(canonicalize(absent), canonicalize(empty))

    def test_duplicate_semantic_identities_are_rejected(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        path = base['handles'][0]['path']
        fingerprint = base['handles'][0]['registrations'][0]['fingerprint']

        def reject(document, needles):
            for source in (document, json.dumps(document).encode('utf-8')):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    canonicalize(source)
                message = str(ctx.exception)
                self.assertIn('duplicates', message)
                for needle in needles:
                    self.assertIn(needle, message)
                with self.assertRaises(TrustsConfigurationError):
                    read_canonical_policy(source)

        left = copy.deepcopy(base['handles'][0])
        right = copy.deepcopy(base['handles'][0])
        right['renderer']['alias'] = 'other'
        for handles in ((left, right), (right, left)):
            document = copy.deepcopy(base)
            document['handles'] = [copy.deepcopy(item) for item in handles]
            reject(document, (path, 'handle path', 'handles[1]', 'handles[0]'))

        changed_compiler = copy.deepcopy(right)
        changed_compiler['compiler'] = 'tests.core.test_issue147.PortableOtherCompiler'
        document = copy.deepcopy(base)
        document['handles'] = [left, changed_compiler]
        reject(document, (path, 'handle path'))

        third = copy.deepcopy(left)
        third['renderer']['engine'] = 'django.db.backends.postgresql'
        document = copy.deepcopy(base)
        other_path = copy.deepcopy(left)
        other_path['path'] = 'tests.policy.other'
        document['handles'] = [left, other_path, third]
        reject(document, (path, 'handles[2]', 'handles[0]'))

        first_reg = copy.deepcopy(base['handles'][0]['registrations'][0])
        second_reg = copy.deepcopy(first_reg)
        second_reg['label'] = 'app.Grant:other'
        second_reg['content'] = ['other']
        for regs in ((first_reg, second_reg), (second_reg, first_reg)):
            document = copy.deepcopy(base)
            document['handles'][0]['registrations'] = [
                copy.deepcopy(item) for item in regs
            ]
            reject(document, (
                fingerprint,
                'registration fingerprint',
                'registrations[1]',
                'registrations[0]',
            ))

        same_reg = copy.deepcopy(first_reg)
        document = copy.deepcopy(base)
        document['handles'][0]['registrations'] = [first_reg, same_reg]
        reject(document, (fingerprint, 'registration fingerprint'))

        first_filter = copy.deepcopy(base['handles'][0]['named_filters'][0])
        second_filter = copy.deepcopy(first_filter)
        second_filter['fingerprint'] = _sha('cd')
        second_filter['expr'] = _eq_expr('title', {'type': 'str', 'value': 'x'})
        for filters in ((first_filter, second_filter), (second_filter, first_filter)):
            document = copy.deepcopy(base)
            document['handles'][0]['named_filters'] = [
                copy.deepcopy(item) for item in filters
            ]
            reject(document, (
                'app.Doc:ranked',
                'named filter',
                'named_filters[1]',
                'named_filters[0]',
            ))

        same_code = copy.deepcopy(second_filter)
        same_code['model'] = 'app.Other'
        other_model = copy.deepcopy(first_filter)
        other_model['code'] = 'titled'
        other_model['fingerprint'] = _sha('ef')
        document = copy.deepcopy(base)
        document['handles'][0]['named_filters'] = [
            first_filter, same_code, other_model,
        ]
        semantic = read_canonical_policy(document)
        codes = [
            (row['model'], row['code'])
            for row in semantic['handles'][0]['named_filters']
        ]
        self.assertEqual(codes, [
            ('app.Doc', 'ranked'),
            ('app.Doc', 'titled'),
            ('app.Other', 'ranked'),
        ])

        shared = copy.deepcopy(base)
        shared['handles'].append(copy.deepcopy(base['handles'][0]))
        shared['handles'][1]['path'] = 'tests.policy.other'
        semantic = read_canonical_policy(shared)
        self.assertEqual(
            [row['fingerprint'] for row in semantic['handles'][0]['registrations']],
            [row['fingerprint'] for row in semantic['handles'][1]['registrations']],
        )
        self.assertEqual(
            [
                (row['model'], row['code'])
                for row in semantic['handles'][0]['named_filters']
            ],
            [
                (row['model'], row['code'])
                for row in semantic['handles'][1]['named_filters']
            ],
        )

    def test_admitted_documents_have_one_canonical_byte_form(self):
        def registration(label, content, digest, predicates):
            payload = _minimal_registration_payload()
            payload['content'] = [content]
            payload['condition'] = {'op': 'all', 'predicates': predicates}
            row = {'fingerprint': digest, 'label': label}
            row.update(payload)
            return row

        def named(model, code, args, digest):
            return {
                'model': model,
                'code': code,
                'fingerprint': digest,
                'expr': {'op': 'and', 'args': args},
            }

        def handle(path, registrations, named_filters, alias):
            return {
                'path': path,
                'family': 'relationship',
                'compiler': 'trusts.core.PlanQueryCompiler',
                'renderer': {
                    'alias': alias,
                    'engine': 'django.db.backends.sqlite3',
                    'profile': SQLITE_JSON1_RCTE_PROFILE,
                    'profile_version': 1,
                    'along': ALONG_SUPPORTED,
                },
                'registrations': registrations,
                'named_filters': named_filters,
            }

        eq_team = {'op': 'equal', 'left': ['team'], 'right': ['repo']}
        perm_za = {'op': 'permission_in', 'refs': [['z'], ['a']]}
        perm_az = {'op': 'permission_in', 'refs': [['a'], ['z']]}
        arg_rank = _eq_expr('rank', {'type': 'int', 'value': 1})
        arg_title = _eq_expr('title', {'type': 'str', 'value': 'x'})

        def document(reverse):
            def order(items):
                rows = [copy.deepcopy(item) for item in items]
                if reverse:
                    rows.reverse()
                return rows

            if reverse:
                predicates = [perm_az, eq_team]
            else:
                predicates = [eq_team, perm_za]
            low_regs = order((
                registration(
                    'app.Grant:late', 'late', _sha('bb'), predicates,
                ),
                registration(
                    'app.Grant:early', 'early', _sha('aa'),
                    list(reversed(predicates)),
                ),
            ))
            high_regs = order((
                registration('app.Grant:zeta', 'zeta', _sha('dd'), [eq_team, perm_za]),
                registration('app.Grant:mid', 'mid', _sha('cc'), [perm_az, eq_team]),
            ))
            low_named = order((
                named('app.Zed', 'open', [arg_title, arg_rank], _sha('22')),
                named('app.Alpha', 'ranked', [arg_rank, arg_title], _sha('11')),
            ))
            high_named = order((
                named('app.Zed', 'visible', [arg_rank, arg_title], _sha('44')),
                named('app.Mid', 'titled', [arg_title, arg_rank], _sha('33')),
            ))
            handles = [
                handle('tests.policy.z', high_regs, high_named, 'other'),
                handle('tests.policy.a', low_regs, low_named, 'default'),
            ]
            if not reverse:
                handles.reverse()
            return {
                'schema_version': SCHEMA_VERSION,
                'compiler_version': COMPILER_VERSION,
                'handles': handles,
            }

        forward = document(False)
        backward = document(True)
        handles_only = copy.deepcopy(forward)
        handles_only['handles'].reverse()
        blobs = [
            canonicalize(forward),
            canonicalize(backward),
            canonicalize(handles_only),
            canonicalize(json.dumps(backward)),
            canonicalize(json.dumps(forward).encode('utf-8')),
        ]
        self.assertEqual(len(set(blobs)), 1)
        self.assertEqual(canonicalize(blobs[0]), blobs[0])
        semantic = read_canonical_policy(forward)
        self.assertEqual(read_canonical_policy(backward), semantic)
        self.assertEqual(
            [row['path'] for row in semantic['handles']],
            ['tests.policy.a', 'tests.policy.z'],
        )
        self.assertEqual(
            [row['path'] for row in forward['handles']],
            ['tests.policy.a', 'tests.policy.z'],
        )
        self.assertEqual(
            [row['path'] for row in backward['handles']],
            ['tests.policy.z', 'tests.policy.a'],
        )
        low = semantic['handles'][0]
        self.assertEqual(
            [row['fingerprint'] for row in low['registrations']],
            [_sha('aa'), _sha('bb')],
        )
        self.assertEqual(
            [(row['model'], row['code']) for row in low['named_filters']],
            [('app.Alpha', 'ranked'), ('app.Zed', 'open')],
        )
        for row in low['named_filters']:
            args = row['expr']['args']
            self.assertEqual(
                [arg['left']['path'] for arg in args],
                [['rank'], ['title']],
            )
        predicates = low['registrations'][0]['condition']['predicates']
        self.assertEqual(
            [row['op'] for row in predicates],
            ['equal', 'permission_in'],
        )
        self.assertEqual(predicates[1]['refs'], [['a'], ['z']])

    def test_commutative_named_filters_are_byte_stable(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()

        def build(expr, code):
            registry = TrustsRegistry()
            _direct(registry, Grant)
            registry.conditions._records[(Doc._meta.label, code)] = ConditionRecord(
                expr=expr, model=Doc,
            )
            return _handle(registry, 'tests.policy.commutative')

        def eq(name, value):
            return Eq(FilterRef('object', (name,)), Const(value))

        left_tree = And(
            And(eq('rank', 2), eq('title', 'x')),
            eq('confidential', False),
        )
        right_tree = And(
            eq('confidential', False),
            And(eq('title', 'x'), eq('rank', 2)),
        )
        or_left = Or(Or(eq('rank', 2), eq('title', 'x')), eq('confidential', False))
        or_right = Or(eq('title', 'x'), Or(eq('confidential', False), eq('rank', 2)))
        mixed = Or(And(eq('rank', 2), eq('title', 'x')), eq('confidential', False))
        handles = [
            build(left_tree, 'combo'),
            build(right_tree, 'combo'),
            build(or_left, 'combo'),
            build(or_right, 'combo'),
            build(mixed, 'combo'),
        ]
        with _owned(*handles):
            with _forbid_sql():
                blobs = [canonicalize(build_policy_manifest([item])) for item in handles]
        self.assertEqual(blobs[0], blobs[1])
        self.assertEqual(blobs[2], blobs[3])
        self.assertNotEqual(blobs[0], blobs[2])
        self.assertNotEqual(blobs[0], blobs[4])
        left_expr = json.loads(blobs[0].decode('utf-8'))['handles'][0]['named_filters'][0]['expr']
        self.assertEqual(left_expr['op'], 'and')
        self.assertNotIn('left', left_expr)
        self.assertEqual(len(left_expr['args']), 3)
        paths = [arg['left']['path'] for arg in left_expr['args']]
        self.assertEqual(paths, sorted(paths))

        a = _eq_expr('a', {'type': 'int', 'value': 1})
        b = _eq_expr('b', {'type': 'bool', 'value': True})
        c = _eq_expr('c', {'type': 'str', 'value': 'z'})
        associated = {
            'op': 'and',
            'left': {'op': 'and', 'left': c, 'right': a},
            'right': b,
        }
        unsorted = {'op': 'and', 'args': [c, b, a]}
        self.assertEqual(
            canonicalize(_lock_document(associated)),
            canonicalize(_lock_document(unsorted)),
        )
        ordered_eq = read_canonical_policy(_lock_document(
            {'op': 'eq', 'left': a['left'], 'right': c['left']},
        ))['handles'][0]['named_filters'][0]['expr']
        swapped_eq = read_canonical_policy(_lock_document(
            {'op': 'eq', 'left': c['left'], 'right': a['left']},
        ))['handles'][0]['named_filters'][0]['expr']
        self.assertNotEqual(ordered_eq, swapped_eq)
        self.assertEqual(ordered_eq['left']['path'], ['a'])
        self.assertEqual(swapped_eq['left']['path'], ['c'])

        nested_or = {
            'op': 'or',
            'left': {'op': 'and', 'args': [a, b]},
            'right': c,
        }
        flattened = read_canonical_policy(_lock_document(nested_or))
        expr = flattened['handles'][0]['named_filters'][0]['expr']
        self.assertEqual(expr['op'], 'or')
        self.assertEqual(len(expr['args']), 2)
        self.assertTrue(any(item.get('op') == 'and' for item in expr['args']))

    def test_integer_encoding_boundary(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        samples = (
            ('zero', 0, 'int', 0),
            ('safe', _SAFE_INT, 'int', _SAFE_INT),
            ('safe_neg', -_SAFE_INT, 'int', -_SAFE_INT),
            ('out', _OUT_INT, 'int_dec', str(_OUT_INT)),
            ('out_neg', -_OUT_INT, 'int_dec', '-' + str(_OUT_INT)),
        )
        for code, number, _kind, _value in samples:
            registry.register_permission_condition(
                Doc, code, lambda u, p, o, number=number: o.rank == number,
            )
        handle = _handle(registry, 'tests.policy.integers')
        with _owned(handle):
            with _forbid_sql():
                data = manifest_to_json_data(build_policy_manifest([handle]))
                blob = canonicalize(build_policy_manifest([handle]))
        rows = {
            row['code']: row['expr']['right']['const']
            for row in data['handles'][0]['named_filters']
        }
        for code, _number, kind, value in samples:
            self.assertEqual(rows[code], {'type': kind, 'value': value})
        self.assertIn(b'"type": "int_dec"', blob)
        self.assertIn(b'"value": "9007199254740992"', blob)
        self.assertIn(b'"value": "-9007199254740992"', blob)
        self.assertNotIn(b'"value": "+', blob)
        self.assertEqual(canonicalize(blob), blob)
        decoded = read_canonical_policy(blob)
        self.assertEqual(decoded, data)

    def test_reader_rejects_cross_shape_and_noncanonical_int_dec(self):
        def expr(kind, value):
            return _eq_expr('rank', {'type': kind, 'value': value})

        accepted = (
            ('int', 0),
            ('int', _SAFE_INT),
            ('int', -_SAFE_INT),
            ('int_dec', str(_OUT_INT)),
            ('int_dec', '-' + str(_OUT_INT)),
        )
        for kind, value in accepted:
            document = _lock_document(expr(kind, value))
            const = read_canonical_policy(document)['handles'][0]['named_filters'][0]['expr']['right']['const']
            self.assertEqual(const, {'type': kind, 'value': value})

        cross = (
            ('int', _OUT_INT),
            ('int', -_OUT_INT),
            ('int', True),
            ('int', str(_SAFE_INT)),
            ('int_dec', str(_SAFE_INT)),
            ('int_dec', '-' + str(_SAFE_INT)),
            ('int_dec', '0'),
            ('int_dec', _OUT_INT),
            ('int_dec', False),
        )
        for kind, value in cross:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(_lock_document(expr(kind, value)))
            self.assertIn('cross-shape', str(ctx.exception))

        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(_lock_document(expr('int', 1.0)))
        self.assertIn('float', str(ctx.exception))

        noncanonical = (
            '+' + str(_OUT_INT),
            '0' + str(_OUT_INT),
            '-0' + str(_OUT_INT),
            '-0',
            '00',
            str(_OUT_INT) + '.0',
            '9.007199254740992e15',
            ' ' + str(_OUT_INT),
            '',
            '²',
        )
        for spelling in noncanonical:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                canonicalize(_lock_document(expr('int_dec', spelling)))
            message = str(ctx.exception)
            self.assertIn('noncanonical int_dec', message)
            self.assertNotIn('cross-shape', message)

    def test_reader_rejects_unsupported_constants_and_ops(self):
        def reject(expr, needle, hidden=()):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(_lock_document(expr))
            message = str(ctx.exception)
            self.assertIn(needle, message)
            for item in hidden:
                self.assertNotIn(item, message)
            return message

        reject(
            _eq_expr('rank', {'type': 'float', 'value': 1.5}),
            'float',
        )
        reject(
            _eq_expr('title', {
                'type': 'ModelIdentity',
                'value': {'app_label': 'myapp', 'model_name': 'doc', 'pk': 9},
            }),
            'ModelIdentity',
            ('myapp', 'doc'),
        )
        reject(
            _eq_expr('title', {'type': 'bytes', 'value': 'abc'}),
            'bytes',
        )
        reject(
            _eq_expr('title', {'type': 'decimal', 'value': '1.25'}),
            'decimal',
        )
        reject(
            {'op': 'lt', 'left': {'ref': 'object', 'path': ['rank']}, 'right': {'const': {'type': 'int', 'value': 1}}},
            'lt',
        )
        reject(
            {'op': 'and', 'left': _eq_expr('a', {'type': 'int', 'value': 1}), 'right': _eq_expr('b', {'type': 'int', 'value': 2}), 'args': []},
            'both args and left/right',
        )

        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.conditions._records[(Doc._meta.label, 'lt')] = ConditionRecord(
            expr=_Ordering('lt', FilterRef('object', ('rank',)), Const(1)),
            model=Doc,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _data([_handle(registry, 'tests.policy.ordering')])
        self.assertIn('_Ordering', str(ctx.exception))

    def test_unknown_fields_are_rejected_recursively(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))

        def reject(mutate, needle):
            document = copy.deepcopy(base)
            mutate(document)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(document)
            message = str(ctx.exception)
            self.assertIn(needle, message)
            self.assertIn('unexpected', message)

        reject(lambda doc: doc.__setitem__('package_version', '1.0'), 'package_version')
        reject(
            lambda doc: doc['handles'][0].__setitem__('note', True),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['renderer'].__setitem__('PASSWORD', 's3cret'),
            'PASSWORD',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__('lineno', 4),
            'lineno',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'condition', {
                    'op': 'equal',
                    'left': ['team'],
                    'right': ['repo'],
                    'note': 'x',
                },
            ),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'condition', {
                    'op': 'all',
                    'predicates': [{
                        'op': 'equal',
                        'left': ['team'],
                        'right': ['repo'],
                        'extra': 1,
                    }],
                },
            ),
            'extra',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'along', dict(_minimal_along(), walk_field='node'),
            ),
            'walk_field',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0].__setitem__('source', 'app.py'),
            'source',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr'].__setitem__('note', 1),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['right']['const'].__setitem__('base', 10),
            'base',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['left'].__setitem__('lineno', 3),
            'lineno',
        )

        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(b'\xef\xbb\xbf{}')
        self.assertIn('BOM', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(b'\xff')
        self.assertIn('UTF-8', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy('{')
        self.assertIn('JSON', str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, json.JSONDecodeError)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': True, 'compiler_version': 1, 'handles': []})
        self.assertIn('schema_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': '1', 'compiler_version': 1, 'handles': []})
        self.assertIn('schema_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': 1, 'compiler_version': 2, 'handles': []})
        self.assertIn('compiler_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': 1, 'compiler_version': 1})
        self.assertIn('handles', str(ctx.exception))
        with self.assertRaises(TypeError):
            read_canonical_policy(build_policy_manifest([]))

        low = _lock_document()
        high = _lock_document()
        high['handles'][0]['path'] = 'tests.policy.zzz'
        scrambled = {
            'schema_version': 1,
            'compiler_version': 1,
            'handles': [high['handles'][0], low['handles'][0]],
        }
        ordered = {
            'schema_version': 1,
            'compiler_version': 1,
            'handles': [low['handles'][0], high['handles'][0]],
        }
        self.assertEqual(
            read_canonical_policy(scrambled),
            read_canonical_policy(ordered),
        )
        self.assertEqual(
            [item['path'] for item in read_canonical_policy(scrambled)['handles']],
            ['tests.policy.reader', 'tests.policy.zzz'],
        )


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
        self.assertNotIn('canonicalize', source_backend)
        self.assertNotIn('read_canonical_policy', source_backend)
        self.assertNotIn('canonicalize', source_query)
        self.assertNotIn('read_canonical_policy', source_query)
