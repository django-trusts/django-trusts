"""#131 C-methods: public relationship and named-filter APIs.

Configured-backend Django ``__`` paths, symbolic ``condition=``
builders, ``along=(path, bound)``, ``register(*, trust=...)``, and
``add_named_filter``. The earlier positional/strategy
``BackendHandle.register`` forms and
``register_permission_condition`` remain removed. ``Ref`` input and
prebuilt ``All`` / ``Equal`` / ``permission_in`` on the public handle
are TypeError. Freeze raises before path resolution. Dual backends stay
isolated. Internal ``TrustsRegistry.register(Ref)`` remains for
compiler tests. OrderedFold registration left Core in #195.
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
    def test_register_is_the_public_donation_verb(self):
        handle = _handle()
        self.assertTrue(hasattr(BackendHandle, 'register'))
        self.assertTrue(hasattr(BackendHandle, 'add_named_filter'))
        self.assertFalse(hasattr(BackendHandle, 'register_relationship'))
        self.assertFalse(hasattr(BackendHandle, 'register_permission_condition'))
        self.assertFalse(hasattr(BackendHandle, 'register_ordered_fold'))
        self.assertFalse(hasattr(BackendHandle, 'register_strategy'))
        self.assertTrue(hasattr(handle, 'register'))
        self.assertFalse(hasattr(handle, 'register_relationship'))
        self.assertFalse(hasattr(handle, 'register_permission_condition'))
        self.assertFalse(hasattr(handle, 'register_ordered_fold'))
        self.assertFalse(hasattr(handle, 'register_strategy'))
        self.assertTrue(hasattr(handle.registry, 'register'))
        self.assertFalse(hasattr(handle.registry, 'register_strategy'))
        self.assertFalse(hasattr(handle.registry, 'strategies'))

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
            trust=DocumentGrant,
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
                trust=j,
                user='user',
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user=j.user,
                permission='permission',
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission=j.permission,
                content='document',
            )
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content=j.document,
            )
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                condition=Equal(j.user, j.permission),
            )
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
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
                        trust=DocumentGrant,
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
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        self.assertEqual(handle.registry.records, (first,))
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            handle.register(
                trust=DocumentGrant,
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
                            trust=DocumentGrant,
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
                trust=DocumentGrant,
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
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(right.registry.records, ())
        right.register(
            trust=DocumentGrant,
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
            trust=TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=lambda t: (
                t.team.permission_bundles.operations.contains(t.operation)
                & (t.team.organization == t.repository.organization)
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
            trust=Grant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')
        self.assertEqual(record.along.bound, 8)


class _PredicateLog:
    def __init__(self, impl=None):
        self.impl = impl or (lambda u, p, o: o.confidential != True)
        self.calls = []

    def __call__(self, u, p, o):
        self.calls.append((u, p, o))
        return self.impl(u, p, o)


class CMethodsPublicSurfaceTest(SimpleTestCase):
    def test_two_public_methods_and_no_ordered_fold(self):
        backend = _handle()
        self.assertTrue(callable(backend.register))
        self.assertTrue(callable(backend.add_named_filter))
        self.assertFalse(hasattr(backend, 'register_relationship'))
        self.assertFalse(hasattr(backend, 'register_permission_condition'))
        self.assertFalse(hasattr(backend, 'register_ordered_fold'))
        self.assertFalse(hasattr(backend, 'register_strategy'))
        self.assertTrue(hasattr(BackendHandle, 'register'))
        self.assertFalse(hasattr(BackendHandle, 'register_relationship'))
        self.assertFalse(hasattr(BackendHandle, 'register_permission_condition'))
        self.assertFalse(hasattr(BackendHandle, 'register_ordered_fold'))
        self.assertFalse(hasattr(BackendHandle, 'register_strategy'))

    def test_register_matches_internal_ref_record(self):
        via_ref = TrustsRegistry()
        j = Ref(DocumentGrant)
        expected = via_ref.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        backend = _handle()
        record = backend.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(record, expected)
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.user_path, ('user',))
        self.assertEqual(record.content_field, 'document')

    def test_wrong_family_keywords_are_type_error(self):
        backend = _handle()
        with self.assertRaises(TypeError):
            backend.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                strategy=object(),
            )
        self.assertEqual(backend.registry.records, ())

    def test_incomplete_signatures_are_type_error(self):
        backend = _handle()
        with self.assertRaises(TypeError):
            backend.register(trust=DocumentGrant, user='user')
        with self.assertRaises(TypeError):
            backend.add_named_filter(Document, 'non_confidential')
        self.assertEqual(backend.registry.records, ())

    def test_register_ref_is_type_error(self):
        backend = _handle()
        j = Ref(DocumentGrant)
        with self.assertRaises(TypeError):
            backend.register(
                trust=j, user='user', permission='permission', content='document',
            )
        self.assertEqual(backend.registry.records, ())

    def test_duplicate_relationship_leaves_store_unchanged(self):
        backend = _handle()
        first = backend.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            backend.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        self.assertEqual(backend.registry.records, (first,))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class CMethodsRelationshipLongPathTest(SimpleTestCase):
    def test_long_relationship_path_matches_internal_ref(self):
        from tests.core.test_issue98 import _gh_models, _register_team

        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        via_ref = TrustsRegistry()
        expected = _register_team(via_ref, TeamRepoGrant)
        backend = _handle()
        record = backend.register(
            trust=TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=lambda t: (
                t.team.permission_bundles.operations.contains(t.operation)
                & (t.team.organization == t.repository.organization)
            ),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.user_path, ('team', 'members'))
        self.assertEqual(record.user_field, 'team__members')

    def test_along_tuple_on_register(self):
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
        backend = _handle()
        record = backend.register(
            trust=Grant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')
        self.assertEqual(record.along.bound, 8)

class CMethodsNamedFilterLifecycleTest(SimpleTestCase):
    def test_predicate_runs_once_at_registration(self):
        backend = _handle()
        log = _PredicateLog()
        record = backend.add_named_filter(Document, 'non_confidential', log)
        self.assertEqual(len(log.calls), 1)
        self.assertIs(
            backend.registry.get_permission_condition_record(
                Document, 'non_confidential',
            ),
            record,
        )
        self.assertEqual(len(log.calls), 1)

    def test_non_callable_predicate_is_rejected(self):
        backend = _handle()
        with self.assertRaises(TypeError):
            backend.add_named_filter(
                Document, 'non_confidential', 'not-a-predicate',
            )
        self.assertIsNone(
            backend.registry.get_permission_condition_record(
                Document, 'non_confidential',
            ),
        )


class CMethodsFreezeAndIsolationTest(SimpleTestCase):
    def test_freeze_blocks_relationship_and_filter_before_validation(self):
        registry = TrustsRegistry()
        backend = _handle(registry)
        registry.freeze()
        log = _PredicateLog()
        with patch(
            'trusts.core._public_path_segments',
            wraps=_public_path_segments,
        ) as segments:
            with patch('trusts.core._resolve_path', wraps=_resolve_path) as resolve:
                with patch(
                    'trusts.core._validate_condition',
                    wraps=_validate_condition,
                ) as validate:
                    with self.assertRaises(TrustsConfigurationError) as rel:
                        backend.register(
                            trust=DocumentGrant,
                            user='user',
                            permission='permission',
                            content='document',
                        )
                    with self.assertRaises(TrustsConfigurationError) as named:
                        backend.add_named_filter(
                            Document, 'non_confidential', log,
                        )
        self.assertIn('frozen', str(rel.exception).lower())
        self.assertIn('frozen', str(named.exception).lower())
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(log.calls, [])
        self.assertEqual(registry.records, ())
        self.assertIsNone(
            registry.get_permission_condition_record(
                Document, 'non_confidential',
            ),
        )

    def test_dual_backend_relationship_does_not_leak(self):
        left = _handle(path='tests.core.cmethods-left')
        right = _handle(path='tests.core.cmethods-right')
        left.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(right.registry.records, ())
        right.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(len(right.registry.records), 1)
