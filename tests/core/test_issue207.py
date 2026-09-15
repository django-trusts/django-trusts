"""#207: docs-first ``register(*, trust=...)`` Core contract.

Keyword-only public registration, string/callable/mixed normalization,
once-at-registration symbolic-proxy builders, fail-closed invalid
families, honest contextual typing, and ``py.typed`` / Pyright
packaging. OrderedFold stays gone.
"""

import inspect
import types
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar, get_args, get_origin, get_type_hints
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.models import Model
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps

from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    Along,
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    RegisteredRelation,
    TrustsConfigurationError,
    TrustsRegistry,
    _public_path_segments,
    _resolve_path,
    _validate_condition,
)


ROOT = Path(__file__).resolve().parents[2]


def _handle(registry=None, path='tests.core.issue207'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


class _Count:
    def __init__(self, attr):
        self.attr = attr
        self.calls = 0

    def __call__(self, trust):
        self.calls += 1
        return getattr(trust, self.attr)


class RegisterPublicSurfaceTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue207', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue207', PAIR_KERNEL_SUITE)

    def test_register_relationship_is_absent(self):
        handle = _handle()
        self.assertFalse(hasattr(BackendHandle, 'register_relationship'))
        self.assertFalse(hasattr(handle, 'register_relationship'))
        self.assertFalse(hasattr(handle.registry, 'register_relationship'))
        self.assertTrue(callable(handle.register))
        self.assertFalse(hasattr(BackendHandle, 'register_ordered_fold'))

    def test_positional_trust_is_type_error(self):
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        self.assertEqual(handle.registry.records, ())

    def test_honest_contextual_typing_does_not_prove_attributes(self):
        hints = get_type_hints(BackendHandle.register)
        trust_hint = hints['trust']
        self.assertIs(get_origin(trust_hint), type)
        type_args = get_args(trust_hint)
        self.assertEqual(len(type_args), 1)
        self.assertIsInstance(type_args[0], TypeVar)
        self.assertIs(type_args[0].__bound__, Model)
        for role in ('user', 'permission', 'content'):
            origin = get_origin(hints[role])
            self.assertIn(origin, (types.UnionType, type(str | int)))
            parts = get_args(hints[role])
            self.assertIn(str, parts)
            callable_parts = [
                part for part in parts if get_origin(part) is Callable
            ]
            self.assertEqual(len(callable_parts), 1)
            callable_args = get_args(callable_parts[0])
            self.assertEqual(callable_args[0], [type_args[0]])
            self.assertIs(callable_args[1], object)
        condition_hint = hints['condition']
        self.assertIn(
            get_origin(condition_hint),
            (types.UnionType, type(str | int)),
        )
        condition_parts = get_args(condition_hint)
        self.assertIn(type(None), condition_parts)
        condition_callables = [
            part for part in condition_parts if get_origin(part) is Callable
        ]
        self.assertEqual(len(condition_callables), 1)
        self.assertEqual(
            get_args(condition_callables[0]),
            ([type_args[0]], object),
        )
        self.assertIs(hints['return'], RegisteredRelation)
        # Python does not prove lambda attributes exist on trust=.
        self.assertNotIn('document', BackendHandle.register.__annotations__)

    def test_py_typed_marker_is_present(self):
        import trusts
        marker = Path(trusts.__file__).resolve().parent / 'py.typed'
        self.assertTrue(marker.is_file())
        self.assertTrue((ROOT / 'trusts' / 'py.typed').is_file())
        wheel = (ROOT / 'scripts' / 'verify-wheel-install.py').read_text()
        self.assertIn('trusts/py.typed', wheel)
        self.assertIn('register contextual typing', wheel)
        self.assertIn('register_relationship', wheel)
        metadata = (ROOT / 'scripts' / 'verify-package-metadata.py').read_text()
        self.assertIn('trusts/py.typed', metadata)
        pyright = (ROOT / 'scripts' / 'verify-wheel-pyright.py').read_text()
        self.assertIn('not_a_field', pyright)
        self.assertIn('AnnotatedGrant', pyright)
        self.assertIn('TrustsImplementationConfig', pyright)
        self.assertIn('configured_backend()', pyright)
        self.assertIn('condition=', pyright)
        self.assertIn('t.team == t.document', pyright)
        self.assertNotIn('from trusts.core import BackendHandle', pyright)

    def test_keyword_only_signature(self):
        signature = inspect.signature(BackendHandle.register)
        names = [name for name in signature.parameters if name != 'self']
        self.assertEqual(
            names,
            ['trust', 'user', 'permission', 'content', 'condition', 'along'],
        )
        for name in names:
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
                name,
            )


class RegisterNormalizeTest(SimpleTestCase):
    def test_strings_callables_and_mixed_normalize_equivalently(self):
        via_ref = TrustsRegistry()
        expected = via_ref.register(
            content=Ref(DocumentGrant).document,
            user=Ref(DocumentGrant).user,
            permission=Ref(DocumentGrant).permission,
        )
        strings = _handle(path='tests.core.issue207-strings').register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        callables = _handle(path='tests.core.issue207-callables').register(
            trust=DocumentGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
        )
        mixed = _handle(path='tests.core.issue207-mixed').register(
            trust=DocumentGrant,
            user=lambda t: t.user,
            permission='permission',
            content=lambda t: t.document,
        )
        self.assertEqual(strings, expected)
        self.assertEqual(callables, expected)
        self.assertEqual(mixed, expected)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_multihop_and_terminal_m2m_match_strings(self):
        from tests.core.test_issue98 import _gh_models, _register_team

        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        expected = _register_team(TrustsRegistry(), TeamRepoGrant)
        record = _handle().register(
            trust=TeamRepoGrant,
            user=lambda t: t.team.members,
            permission=lambda t: t.operation,
            content=lambda t: t.repository,
            condition=lambda t: (
                t.team.permission_bundles.operations.contains(t.operation)
                & (t.team.organization == t.repository.organization)
            ),
        )
        mixed = _handle(path='tests.core.issue207-m2m-mixed').register(
            trust=TeamRepoGrant,
            user='team__members',
            permission=lambda t: t.operation,
            content='repository',
            condition=lambda t: (
                t.team.permission_bundles.operations.contains(t.operation)
                & (t.team.organization == t.repository.organization)
            ),
        )
        self.assertEqual(record, expected)
        self.assertEqual(mixed, expected)
        self.assertEqual(record.user_path, ('team', 'members'))

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_along_and_builders_match_internal_ref(self):
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
        record = _handle().register(
            trust=Grant,
            user=lambda t: t.user,
            permission='permission',
            content=lambda t: t.node,
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_multihop_user_without_membership_fails_closed(self):
        from tests.core.test_issue98 import _gh_models

        TeamRepoGrant = _gh_models()[6]
        handle = _handle()
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                trust=TeamRepoGrant,
                user=lambda t: t.team.organization,
                permission=lambda t: t.operation,
                content=lambda t: t.repository,
            )
        self.assertEqual(handle.registry.records, ())


class RegisterOnceAtRegistrationTest(TestCase):
    def test_builders_run_once_and_never_during_projections(self):
        if 'myapp_document' not in connection.introspection.table_names():
            self.skipTest('myapp tables exist only on the kernel host')
        registry = TrustsRegistry()
        handle = _handle(registry)
        user = _Count('user')
        permission = _Count('permission')
        content = _Count('document')
        handle.register(
            trust=DocumentGrant,
            user=user,
            permission=permission,
            content=content,
        )
        self.assertEqual((user.calls, permission.calls, content.calls), (1, 1, 1))

        User = get_user_model()
        alice = User.objects.create_user('alice-207', password='x')
        document = Document.objects.create(title='once')
        ct = ContentType.objects.get_for_model(Document)
        perm, _created = Permission.objects.get_or_create(
            content_type=ct,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        DocumentGrant.objects.create(
            document=document, user=alice, permission=perm,
        )
        self.assertTrue(registry.has_permission(alice, document, perm))
        list(registry.permissions_for(alice, document))
        list(registry.filter_authorized(Document.objects.all(), alice, perm))
        self.assertEqual((user.calls, permission.calls, content.calls), (1, 1, 1))
        self.assertEqual(registry.records[0].user_path, ('user',))
        self.assertIsInstance(registry.records[0].user_field, str)


class RegisterFailClosedTest(TestCase):
    def test_invalid_builder_families_are_zero_sql_and_do_not_mutate(self):
        captured = []

        def capture(trust):
            captured.append(trust)
            return trust.user

        first = _handle(path='tests.core.issue207-capture')
        first.register(
            trust=DocumentGrant,
            user=capture,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
        )

        def boom(_trust):
            raise RuntimeError('builder exploded')

        cases = (
            ('exception', boom),
            ('missing', lambda t: t.not_a_field),
            ('empty', lambda t: t),
            ('constant-str', lambda t: 'user'),
            ('constant-int', lambda t: 1),
            ('constant-none', lambda t: None),
            ('foreign-root', lambda t: captured[0].user),
            ('magic-eq', lambda t: t.user == t.permission),
            ('magic-add', lambda t: t.user + t.permission),
            ('magic-item', lambda t: t.user['x']),
            ('magic-call', lambda t: t.user()),
            ('unsupported-shape', lambda t: t.document.title),
        )
        handle = _handle()
        for name, builder in cases:
            with self.subTest(name=name):
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        handle.register(
                            trust=DocumentGrant,
                            user=builder,
                            permission=lambda t: t.permission,
                            content=lambda t: t.document,
                        )
                self.assertEqual(handle.registry.records, ())

    def test_failed_third_role_does_not_partially_mutate(self):
        handle = _handle()
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                handle.register(
                    trust=DocumentGrant,
                    user=lambda t: t.user,
                    permission=lambda t: t.permission,
                    content=lambda t: t.not_a_field,
                )
        self.assertEqual(handle.registry.records, ())

    def test_freeze_wins_before_builder_invocation(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        calls = []

        def user(trust):
            calls.append(trust)
            return trust.user

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
                            user=user,
                            permission=lambda t: t.permission,
                            content=lambda t: t.document,
                        )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(calls, [])
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(registry.records, ())
