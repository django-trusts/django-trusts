"""#210: one symbolic ``condition=`` language on public ``register``.

Trust-rooted callable, invoked once after freeze. 1.0 grammar is path
``==``, collection-rooted ``.contains(member)``, and ``&``. Literal
Python ``in`` is unsupported. Lower only to private ``Equal`` /
``PermissionIn`` / ``All``. Public handle rejects prebuilt IR.
"""

import inspect
import types
from collections.abc import Callable
from typing import TypeVar, get_args, get_origin, get_type_hints
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue98 import (
    _gh_models,
    _register_direct,
    _register_team,
    _tables,
)
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.conditions._ir import Eq as IrEq
from trusts.conditions._ir import Ref as IrRef
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    PermissionIn,
    PlanQueryCompiler,
    Ref,
    RegisteredRelation,
    TrustsConfigurationError,
    TrustsRegistry,
    _normalize_public_condition,
    _public_path_segments,
    _resolve_path,
    _validate_condition,
    permission_in,
)


def _handle(registry=None, path='tests.core.issue210'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


def _team_condition(t):
    return (
        t.team.permission_bundles.operations.contains(t.operation)
        & (t.team.organization == t.repository.organization)
    )


class _CountCondition:
    def __init__(self):
        self.calls = 0

    def __call__(self, trust):
        self.calls += 1
        return _team_condition(trust)


class RegisterConditionSurfaceTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue210', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue210', PAIR_KERNEL_SUITE)

    def test_predicate_is_not_on_the_signature(self):
        signature = inspect.signature(BackendHandle.register)
        self.assertNotIn('predicate', signature.parameters)
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                predicate=lambda u, p, o: u == o.user,
            )
        self.assertEqual(handle.registry.records, ())

    def test_condition_is_contextually_typed_as_trust(self):
        hints = get_type_hints(BackendHandle.register)
        trust_hint = hints['trust']
        type_args = get_args(trust_hint)
        self.assertIsInstance(type_args[0], TypeVar)
        condition_hint = hints['condition']
        self.assertIn(
            get_origin(condition_hint),
            (types.UnionType, type(str | int)),
        )
        parts = get_args(condition_hint)
        self.assertIn(type(None), parts)
        callable_parts = [
            part for part in parts if get_origin(part) is Callable
        ]
        self.assertEqual(len(callable_parts), 1)
        self.assertEqual(
            get_args(callable_parts[0]),
            ([type_args[0]], object),
        )
        self.assertIs(hints['return'], RegisteredRelation)


class RegisterConditionGrammarTest(SimpleTestCase):
    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_org_equality_permission_ceiling_and_conjunction(self):
        TeamRepoGrant = _gh_models()[6]
        expected = _register_team(TrustsRegistry(), TeamRepoGrant)

        equality = _handle(path='tests.core.issue210-eq').register(
            trust=TeamRepoGrant,
            user=lambda t: t.team.members,
            permission=lambda t: t.operation,
            content=lambda t: t.repository,
            condition=lambda t: t.team.organization == t.repository.organization,
        )
        via_ref = TrustsRegistry()
        t = Ref(TeamRepoGrant)
        expected_eq = via_ref.register(
            content=t.repository,
            user=t.team.members,
            permission=t.operation,
            condition=Equal(t.team.organization, t.repository.organization),
        )
        self.assertEqual(equality, expected_eq)
        self.assertIsInstance(equality.condition, Equal)
        self.assertFalse(callable(equality.condition))

        ceiling = _handle(path='tests.core.issue210-in').register(
            trust=TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=lambda t: (
                t.team.permission_bundles.operations.contains(t.operation)
            ),
        )
        via_ceil = TrustsRegistry()
        expected_ceil = via_ceil.register(
            content=t.repository,
            user=t.team.members,
            permission=t.operation,
            condition=permission_in(t.team.permission_bundles.operations),
        )
        self.assertEqual(ceiling, expected_ceil)
        self.assertIsInstance(ceiling.condition, PermissionIn)
        self.assertFalse(callable(ceiling.condition))

        conjunction = _handle(path='tests.core.issue210-and').register(
            trust=TeamRepoGrant,
            user=lambda t: t.team.members,
            permission='operation',
            content=lambda t: t.repository,
            condition=_team_condition,
        )
        self.assertEqual(conjunction, expected)
        self.assertIsInstance(conjunction.condition, All)
        self.assertFalse(callable(conjunction.condition))
        self.assertEqual(len(conjunction.condition.predicates), 2)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_internal_registry_still_accepts_private_ir(self):
        TeamRepoGrant = _gh_models()[6]
        registry = TrustsRegistry()
        record = _register_team(registry, TeamRepoGrant)
        self.assertIsInstance(record.condition, All)
        self.assertEqual(registry.records, (record,))


class RegisterConditionOnceTest(TransactionTestCase):
    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_builder_runs_once_and_is_not_stored(self):
        models_ = _gh_models()
        (
            Account, Organization, Team, Operation, PermissionBundle,
            Repository, TeamRepoGrant, AccountRepoGrant,
        ) = models_
        with _tables(
            Account, Organization, Team, Operation, PermissionBundle,
            Repository, TeamRepoGrant, AccountRepoGrant,
        ):
            org = Organization.objects.create(name='once-org')
            team = Team.objects.create(organization=org, name='once-team')
            member = Account.objects.create(name='once-member')
            team.members.add(member)
            read = Operation.objects.create(code='read')
            bundle = PermissionBundle.objects.create(team=team, name='reader')
            bundle.operations.add(read)
            repo = Repository.objects.create(organization=org, title='once')
            TeamRepoGrant.objects.create(
                team=team, repository=repo, operation=read,
            )
            registry = TrustsRegistry()
            handle = _handle(registry)
            builder = _CountCondition()
            record = handle.register(
                trust=TeamRepoGrant,
                user=lambda t: t.team.members,
                permission=lambda t: t.operation,
                content=lambda t: t.repository,
                condition=builder,
            )
            self.assertEqual(builder.calls, 1)
            self.assertNotIn(builder, (record, record.condition))
            self.assertFalse(callable(record.condition))

            self.assertTrue(registry.has_permission(member, repo, read))
            list(registry.permissions_for(member, repo))
            list(registry.filter_authorized(Repository.objects.all(), member, read))
            self.assertEqual(builder.calls, 1)


class RegisterConditionRejectPublicIRTest(TestCase):
    def test_classification_does_not_invoke_application_equality(self):
        class Probe:
            def __init__(self):
                self.eq_calls = 0
                self.call_calls = 0

            def __eq__(self, other):
                self.eq_calls += 1
                if (
                    other is All
                    or other is Equal
                    or other is PermissionIn
                    or other is permission_in
                ):
                    raise AssertionError('classification invoked __eq__')
                return NotImplemented

            def __ne__(self, other):
                if (
                    other is All
                    or other is Equal
                    or other is PermissionIn
                    or other is permission_in
                ):
                    self.eq_calls += 1
                    raise AssertionError('classification invoked __ne__')
                return NotImplemented

            def __call__(self, trust):
                self.call_calls += 1
                return trust.user == trust.user

        probe = Probe()
        handle = _handle()
        record = handle.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            condition=probe,
        )
        self.assertEqual(probe.call_calls, 1)
        self.assertIsInstance(record.condition, Equal)
        self.assertFalse(callable(record.condition))

    def test_prebuilt_public_values_are_type_error(self):
        handle = _handle()
        j = Ref(DocumentGrant)
        cases = (
            ('all', All(Equal('user', 'permission'))),
            ('equal', Equal('user', 'permission')),
            ('permission_in', permission_in('permission')),
            ('equal-class', Equal),
            ('all-class', All),
            ('permission_in-class', permission_in),
            ('ref', j.user),
            ('q', Q(user=1)),
            ('string', 'user'),
            ('true', True),
            ('false', False),
            ('ir-eq', IrEq(IrRef('principal'), IrRef('object'))),
            ('int', 1),
            ('none-string-empty', ''),
        )
        for name, value in cases:
            with self.subTest(name=name):
                with self.assertNumQueries(0):
                    with self.assertRaises(TypeError):
                        handle.register(
                            trust=DocumentGrant,
                            user='user',
                            permission='permission',
                            content='document',
                            condition=value,
                        )
                self.assertEqual(handle.registry.records, ())


class RegisterConditionFailClosedTest(TestCase):
    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_invalid_families_are_zero_sql_and_do_not_mutate(self):
        TeamRepoGrant = _gh_models()[6]
        captured = []

        def capture(trust):
            captured.append(trust)
            return _team_condition(trust)

        first = _handle(path='tests.core.issue210-capture')
        first.register(
            trust=TeamRepoGrant,
            user=lambda t: t.team.members,
            permission=lambda t: t.operation,
            content=lambda t: t.repository,
            condition=capture,
        )

        def boom(_trust):
            raise RuntimeError('builder exploded')

        async def coro(trust):
            return trust.team.organization == trust.repository.organization

        def keyword_only(*, trust):
            return trust.team.organization == trust.repository.organization

        cases = (
            ('exception', boom),
            ('zero-arg', lambda: True),
            ('two-arg', lambda u, p: u == p),
            ('named-filter-arity', lambda u, p, o: u == o.owner),
            ('keyword-only', keyword_only),
            ('empty-none', lambda t: None),
            ('true', lambda t: True),
            ('bare-path', lambda t: t.team),
            ('bare-contains', lambda t: (
                t.team.permission_bundles.operations.contains
            )),
            ('foreign-root', lambda t: (
                captured[0].team.organization == t.repository.organization
            )),
            ('literal-in', lambda t: (
                t.operation in t.team.permission_bundles.operations
            )),
            ('python-and', lambda t: (
                (t.team.organization == t.repository.organization)
                and (
                    t.team.permission_bundles.operations.contains(t.operation)
                )
            )),
            ('or', lambda t: (
                (t.team.organization == t.repository.organization)
                | (
                    t.team.permission_bundles.operations.contains(t.operation)
                )
            )),
            ('ne', lambda t: t.team.organization != t.repository.organization),
            ('call', lambda t: t.team()),
            ('index', lambda t: t.team['members']),
            ('add', lambda t: t.team + t.repository),
            ('wrong-member', lambda t: (
                t.team.permission_bundles.operations.contains(t.team)
            )),
            ('missing-field', lambda t: t.not_a_field == t.repository.organization),
            ('coro', coro),
        )
        handle = _handle()
        for name, builder in cases:
            with self.subTest(name=name):
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        handle.register(
                            trust=TeamRepoGrant,
                            user=lambda t: t.team.members,
                            permission=lambda t: t.operation,
                            content=lambda t: t.repository,
                            condition=builder,
                        )
                self.assertEqual(handle.registry.records, ())

    def test_failed_condition_does_not_partially_mutate(self):
        handle = _handle()
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                handle.register(
                    trust=DocumentGrant,
                    user=lambda t: t.user,
                    permission=lambda t: t.permission,
                    content=lambda t: t.document,
                    condition=lambda t: t.user == t.not_a_field,
                )
        self.assertEqual(handle.registry.records, ())

    def test_freeze_wins_before_condition_invocation(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        calls = []

        def condition(trust):
            calls.append(trust)
            return trust.user == trust.permission

        with patch(
            'trusts.core._public_path_segments',
            wraps=_public_path_segments,
        ) as segments:
            with patch('trusts.core._resolve_path', wraps=_resolve_path) as resolve:
                with patch(
                    'trusts.core._validate_condition',
                    wraps=_validate_condition,
                ) as validate:
                    with patch(
                        'trusts.core._normalize_public_condition',
                        wraps=_normalize_public_condition,
                    ) as normalize:
                        with self.assertRaises(TrustsConfigurationError) as ctx:
                            handle.register(
                                trust=DocumentGrant,
                                user='user',
                                permission='permission',
                                content='document',
                                condition=condition,
                            )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(calls, [])
        segments.assert_not_called()
        resolve.assert_not_called()
        validate.assert_not_called()
        normalize.assert_not_called()
        self.assertEqual(registry.records, ())


class RegisterConditionUnchangedNeighborsTest(SimpleTestCase):
    def test_string_and_lambda_paths_still_match(self):
        expected = TrustsRegistry().register(
            content=Ref(DocumentGrant).document,
            user=Ref(DocumentGrant).user,
            permission=Ref(DocumentGrant).permission,
        )
        strings = _handle(path='tests.core.issue210-strings').register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        builders = _handle(path='tests.core.issue210-builders').register(
            trust=DocumentGrant,
            user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
        )
        self.assertEqual(strings, expected)
        self.assertEqual(builders, expected)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_along_named_filter_and_isolation_unchanged(self):
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
        left = _handle(path='tests.core.issue210-left')
        record = left.register(
            trust=Grant,
            user=lambda t: t.user,
            permission='permission',
            content=lambda t: t.node,
            along=('node__parent', 8),
        )
        self.assertEqual(record, expected)
        self.assertEqual(record.along.shape, 'S')

        right = _handle(path='tests.core.issue210-right')
        self.assertEqual(right.registry.records, ())
        left.add_named_filter(
            Document, 'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self.assertIsNotNone(
            left.registry.get_permission_condition_record(
                Document, 'non_confidential',
            )
        )
        self.assertIsNone(
            right.registry.get_permission_condition_record(
                Document, 'non_confidential',
            )
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RegisterConditionAuthorizationTest(TransactionTestCase):
    def setUp(self):
        (
            self.Account,
            self.Organization,
            self.Team,
            self.Operation,
            self.PermissionBundle,
            self.Repository,
            self.TeamRepoGrant,
            self.AccountRepoGrant,
        ) = _gh_models()
        self._table_cm = _tables(
            self.Account,
            self.Organization,
            self.Team,
            self.Operation,
            self.PermissionBundle,
            self.Repository,
            self.TeamRepoGrant,
            self.AccountRepoGrant,
        )
        self._table_cm.__enter__()
        self.org_a = self.Organization.objects.create(name='acme')
        self.org_b = self.Organization.objects.create(name='other')
        self.writers = self.Team.objects.create(
            organization=self.org_a, name='writers',
        )
        self.member = self.Account.objects.create(name='member')
        self.writers.members.add(self.member)
        self.read = self.Operation.objects.create(code='read')
        self.write = self.Operation.objects.create(code='write')
        self.bundle = self.PermissionBundle.objects.create(
            team=self.writers, name='reader',
        )
        self.bundle.operations.add(self.read)
        self.repo_a = self.Repository.objects.create(
            organization=self.org_a, title='repo-a',
        )
        self.repo_other = self.Repository.objects.create(
            organization=self.org_b, title='repo-other',
        )
        self.TeamRepoGrant.objects.create(
            team=self.writers, repository=self.repo_a, operation=self.read,
        )
        self.registry = TrustsRegistry()
        _register_direct(self.registry, self.AccountRepoGrant)
        handle = _handle(self.registry)
        handle.register(
            trust=self.TeamRepoGrant,
            user=lambda t: t.team.members,
            permission=lambda t: t.operation,
            content=lambda t: t.repository,
            condition=_team_condition,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_conjunction_allows_aligned_ceiling_and_denies_the_rest(self):
        with self.assertNumQueries(1):
            self.assertTrue(
                self.registry.has_permission(
                    self.member, self.repo_a, self.read,
                )
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.has_permission(
                    self.member, self.repo_a, self.write,
                )
            )
        self.TeamRepoGrant.objects.create(
            team=self.writers, repository=self.repo_other, operation=self.read,
        )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.has_permission(
                    self.member, self.repo_other, self.read,
                )
            )
        self.bundle.operations.remove(self.read)
        with self.assertNumQueries(1):
            self.assertFalse(
                self.registry.has_permission(
                    self.member, self.repo_a, self.read,
                )
            )
