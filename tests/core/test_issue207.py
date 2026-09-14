"""#207: docs-first ``register(*, trust=...)`` Core contract.

Keyword-only public registration, non-executing path builders,
string/callable/mixed normalization, fail-closed invalid families,
honest contextual typing, and ``py.typed`` / Pyright packaging.
OrderedFold stays gone.
"""

import dis
import inspect
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar, get_args, get_origin, get_type_hints
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps

from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    PlanQueryCompiler,
    Ref,
    RegisteredRelation,
    TrustsConfigurationError,
    TrustsRegistry,
    _extract_builder_path,
    _public_path_segments,
    _resolve_path,
    _validate_condition,
    permission_in,
)


ROOT = Path(__file__).resolve().parents[2]


def module_user(t):
    return t.user


def module_permission(t):
    return t.permission


def module_content(t):
    return t.document


MODULE_USER = lambda t: t.user
MODULE_PERMISSION = lambda t: t.permission
MODULE_CONTENT = lambda t: t.document


def _handle(registry=None, path='tests.core.issue207'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


def _builder_opnames(fn):
    return [
        inst.opname
        for inst in dis.get_instructions(fn, adaptive=False)
        if inst.opname != 'CACHE'
    ]


def _profile_calls(fn):
    seen = []

    def profile(frame, event, arg):
        if event == 'call' and frame.f_code is fn.__code__:
            seen.append(1)

    return profile, seen


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
        self.assertIs(hints['return'], RegisteredRelation)
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
    def test_canonical_instruction_allowlist(self):
        for fn in (
            MODULE_USER,
            module_user,
            lambda t: t.team.members,
        ):
            names = _builder_opnames(fn)
            with self.subTest(fn=fn, names=names):
                self.assertEqual(names[0], 'RESUME')
                self.assertIn(names[1], ('LOAD_FAST', 'LOAD_FAST_BORROW'))
                self.assertTrue(names[2:-1])
                self.assertTrue(all(name == 'LOAD_ATTR' for name in names[2:-1]))
                self.assertEqual(names[-1], 'RETURN_VALUE')

    def test_module_level_and_function_local_normalize_equivalently(self):
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
        module_fns = _handle(path='tests.core.issue207-module-fns').register(
            trust=DocumentGrant,
            user=module_user,
            permission=module_permission,
            content=module_content,
        )
        module_lambdas = _handle(path='tests.core.issue207-module-lambdas').register(
            trust=DocumentGrant,
            user=MODULE_USER,
            permission=MODULE_PERMISSION,
            content=MODULE_CONTENT,
        )

        def local_user(t):
            return t.user

        def local_permission(t):
            return t.permission

        def local_content(t):
            return t.document

        local_fns = _handle(path='tests.core.issue207-local-fns').register(
            trust=DocumentGrant,
            user=local_user,
            permission=local_permission,
            content=local_content,
        )
        local_lambdas = _handle(path='tests.core.issue207-local-lambdas').register(
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
        self.assertTrue(local_user.__code__.co_flags & 0x10)
        self.assertNotEqual(local_user.__code__.co_flags, 3)

        class ReadyLike:
            def ready(self):
                return lambda t: t.user

        ready_lambda = ReadyLike().ready()
        self.assertTrue(ready_lambda.__code__.co_flags & 0x10)
        self.assertEqual(
            _extract_builder_path(ready_lambda, 'user'),
            'user',
        )
        self.assertEqual(strings, expected)
        self.assertEqual(module_fns, expected)
        self.assertEqual(module_lambdas, expected)
        self.assertEqual(local_fns, expected)
        self.assertEqual(local_lambdas, expected)
        self.assertEqual(mixed, expected)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_multihop_and_terminal_m2m_match_strings(self):
        from tests.core.test_issue98 import _gh_models, _register_team

        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        expected = _register_team(TrustsRegistry(), TeamRepoGrant)

        def local_user(t):
            return t.team.members

        record = _handle().register(
            trust=TeamRepoGrant,
            user=local_user,
            permission=lambda t: t.operation,
            content=lambda t: t.repository,
            condition=All(
                permission_in('team__permission_bundles__operations'),
                Equal(
                    'team__organization',
                    'repository__organization',
                ),
            ),
        )
        mixed = _handle(path='tests.core.issue207-m2m-mixed').register(
            trust=TeamRepoGrant,
            user='team__members',
            permission=lambda t: t.operation,
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


class RegisterNeverInvokeTest(TestCase):
    def test_valid_builders_are_never_invoked(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        profile, seen = _profile_calls(MODULE_USER)
        sys.setprofile(profile)
        try:
            handle.register(
                trust=DocumentGrant,
                user=MODULE_USER,
                permission=MODULE_PERMISSION,
                content=MODULE_CONTENT,
            )
        finally:
            sys.setprofile(None)
        self.assertEqual(seen, [])

        User = get_user_model()
        alice = User.objects.create_user('alice-207', password='x')
        document = Document.objects.create(title='never')
        ct = ContentType.objects.get_for_model(Document)
        perm, _created = Permission.objects.get_or_create(
            content_type=ct,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        DocumentGrant.objects.create(
            document=document, user=alice, permission=perm,
        )
        sys.setprofile(profile)
        try:
            self.assertTrue(registry.has_permission(alice, document, perm))
            list(registry.permissions_for(alice, document))
            list(registry.filter_authorized(Document.objects.all(), alice, perm))
        finally:
            sys.setprofile(None)
        self.assertEqual(seen, [])
        self.assertEqual(registry.records[0].user_path, ('user',))
        self.assertIsInstance(registry.records[0].user_field, str)

    def test_extract_does_not_call_get_instructions_when_frozen(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with patch(
            'trusts.core.dis.get_instructions',
            side_effect=AssertionError('inspected while frozen'),
        ):
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
                                user=MODULE_USER,
                                permission=MODULE_PERMISSION,
                                content=MODULE_CONTENT,
                            )
        self.assertIn('frozen', str(ctx.exception).lower())
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(registry.records, ())


class RegisterFailClosedTest(TestCase):
    def test_invalid_builder_families_are_zero_sql_and_never_run(self):
        side_calls = []

        def side_effect():
            side_calls.append(1)
            return 1

        def closed_user(t):
            attr = 'user'
            return getattr(t, attr)

        def make_closure():
            attr = 'user'
            return lambda t: getattr(t, attr)

        cases = (
            ('empty', lambda t: t),
            ('constant-str', lambda t: 'user'),
            ('constant-int', lambda t: 1),
            ('constant-none', lambda t: None),
            ('call', lambda t: t.user()),
            ('operator', lambda t: t.user + t.permission),
            ('indexing', lambda t: t['user']),
            ('tuple-select', lambda t: (side_effect(), t.user)[1]),
            ('control-flow', lambda t: t.user if t else t.permission),
            ('global', lambda t: side_effect),
            ('extra-locals', closed_user),
            ('closure', make_closure()),
            ('defaults', lambda t, extra=1: t.user),
            ('kwonly', lambda t, *, extra=1: t.user),
            ('varargs', lambda t, *args: t.user),
            ('varkw', lambda t, **kwargs: t.user),
            ('missing', lambda t: t.not_a_field),
            ('unsupported-shape', lambda t: t.document.title),
        )
        handle = _handle()
        for name, builder in cases:
            with self.subTest(name=name):
                profile, seen = _profile_calls(builder)
                sys.setprofile(profile)
                try:
                    with self.assertNumQueries(0):
                        with self.assertRaises(TrustsConfigurationError):
                            handle.register(
                                trust=DocumentGrant,
                                user=builder,
                                permission=lambda t: t.permission,
                                content=lambda t: t.document,
                            )
                finally:
                    sys.setprofile(None)
                self.assertEqual(seen, [])
                self.assertEqual(handle.registry.records, ())
        self.assertEqual(side_calls, [])

    def test_non_function_callables_are_rejected_without_calling(self):
        handle = _handle()
        calls = []

        class CallablePath:
            def __call__(self, trust):
                calls.append(1)
                return trust.user

        import operator
        for value in (CallablePath(), operator.attrgetter('user'), 1, None):
            with self.subTest(value=value):
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        handle.register(
                            trust=DocumentGrant,
                            user=value,
                            permission=lambda t: t.permission,
                            content=lambda t: t.document,
                        )
        self.assertEqual(calls, [])
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

    def test_extract_rejects_empty_and_method_load_without_calling(self):
        with self.assertRaises(TrustsConfigurationError):
            _extract_builder_path(lambda t: t, 'user')
        with self.assertRaises(TrustsConfigurationError):
            _extract_builder_path(lambda t: t.user(), 'user')
        self.assertEqual(
            _extract_builder_path(lambda t: t.team.members, 'user'),
            'team__members',
        )

    def test_function_type_gate_rejects_without_calling(self):
        async def coro(t):
            return t.user

        def gen(t):
            yield t.user

        async def async_gen(t):
            yield t.user

        for name, builder in (
            ('coroutine', coro),
            ('generator', gen),
            ('async-gen', async_gen),
        ):
            with self.subTest(name=name):
                profile, seen = _profile_calls(builder)
                sys.setprofile(profile)
                try:
                    with self.assertRaises(TrustsConfigurationError):
                        _extract_builder_path(builder, 'user')
                finally:
                    sys.setprofile(None)
                self.assertEqual(seen, [])

        with patch('inspect.getsource', side_effect=AssertionError('source')):
            self.assertEqual(_extract_builder_path(lambda t: t.user, 'user'), 'user')
