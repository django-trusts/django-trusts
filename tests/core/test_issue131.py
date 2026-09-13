"""#131 C1: BackendHandle.register public AnyPath string API.

Handle-bound Django ``__`` paths, string condition leaves, and
``along=(path, bound)``. ``Ref`` input is TypeError. Freeze raises
before path resolution. Dual handles stay isolated. Internal
``TrustsRegistry.register(Ref)`` remains. ``register_strategy`` is
not public on the handle.
"""

from unittest.mock import patch

from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.myapp.models import Document, DocumentGrant
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    _public_path_segments,
    _resolve_path,
    _validate_condition,
    permission_in,
)


def _handle(registry=None, path='tests.core.handle-a'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


class HandleRegisterSurfaceTest(SimpleTestCase):
    def test_register_strategy_is_not_a_handle_method(self):
        self.assertFalse(hasattr(BackendHandle, 'register_strategy'))
        handle = _handle()
        self.assertFalse(hasattr(handle, 'register_strategy'))
        self.assertTrue(hasattr(handle.registry, 'register'))
        self.assertTrue(hasattr(handle.registry, 'register_strategy'))

    def test_string_register_matches_internal_ref_record(self):
        via_ref = TrustsRegistry()
        j = Ref(DocumentGrant)
        expected = via_ref.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        handle = _handle()
        record = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(record, expected)
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.user_path, ('user',))
        self.assertEqual(record.content_field, 'document')

    def test_public_ref_input_is_type_error(self):
        handle = _handle()
        j = Ref(DocumentGrant)
        with self.assertRaises(TypeError):
            handle.register(
                j,
                user='user',
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user=j.user,
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission=j.permission,
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content=j.document,
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                condition=Equal(j.user, j.permission),
            )
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                along=Along(j.document, 8),
            )
        self.assertEqual(handle.registry.records, ())

    def test_invalid_public_path_grammar_is_rejected(self):
        handle = _handle()
        for path in (
            '',
            '__user',
            'user__',
            'folder.documents',
            'team____members',
            1,
            None,
            ['user'],
        ):
            with self.subTest(path=path):
                with self.assertRaises(TrustsConfigurationError):
                    handle.register(
                        DocumentGrant,
                        user=path,
                        permission='permission',
                        content='document',
                    )
        self.assertEqual(handle.registry.records, ())

    def test_string_condition_is_not_legal_on_bare_registry(self):
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.document,
                user=j.user,
                permission=j.permission,
                condition=Equal('user', 'permission'),
            )
        self.assertEqual(registry.records, ())

    def test_duplicate_and_conflict_leave_store_unchanged(self):
        handle = _handle()
        first = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        self.assertEqual(handle.registry.records, (first,))
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            handle.register(
                DocumentGrant,
                user='permission',
                permission='user',
                content='document',
            )
        self.assertEqual(handle.registry.records, (first,))


class HandleFreezeOrderTest(SimpleTestCase):
    def test_freeze_raises_before_path_resolution(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with patch(
            'trusts.core._public_path_segments',
            wraps=_public_path_segments,
        ) as segments:
            with patch('trusts.core._resolve_path', wraps=_resolve_path) as resolve:
                with patch(
                    'trusts.core._validate_condition',
                    wraps=_validate_condition,
                ) as validate:
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        handle.register(
                            DocumentGrant,
                            user='user',
                            permission='permission',
                            content='document',
                        )
        self.assertIn('frozen', str(ctx.exception).lower())
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(registry.records, ())

    def test_freeze_wins_over_invalid_grammar(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                DocumentGrant,
                user='',
                permission='permission',
                content='document',
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, ())


class HandleIsolationTest(SimpleTestCase):
    def test_dual_handle_string_register_does_not_leak(self):
        left = _handle(path='tests.core.handle-left')
        right = _handle(path='tests.core.handle-right')
        left.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(right.registry.records, ())
        right.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(len(right.registry.records), 1)
        self.assertIsNot(left.registry.records[0], right.registry.records[0])
        self.assertEqual(left.registry.records[0], right.registry.records[0])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleConditionAndAlongTest(SimpleTestCase):
    def test_string_condition_tree_matches_ref_registration(self):
        from tests.core.test_issue98 import _gh_models, _register_team

        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        via_ref = TrustsRegistry()
        expected = _register_team(via_ref, TeamRepoGrant)
        handle = _handle()
        record = handle.register(
            TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=All(
                permission_in('team__permission_bundles__operations'),
                Equal(
                    'team__organization',
                    'repository__organization',
                ),
            ),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.user_path, ('team', 'members'))
        self.assertEqual(record.user_field, 'team__members')

    def test_along_tuple_matches_internal_along(self):
        from tests.core.test_issue92 import _node_graph_models

        _Node, _p, _r, _i, _im, _meta, _port, _link, Grant, _np = (
            _node_graph_models()
        )
        via_ref = TrustsRegistry()
        j = Ref(Grant)
        expected = via_ref.register(
            content=j.node,
            user=j.user,
            permission=j.permission,
            along=Along(j.node.parent, bound=8),
        )
        handle = _handle()
        record = handle.register(
            Grant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')
        self.assertEqual(record.along.bound, 8)
