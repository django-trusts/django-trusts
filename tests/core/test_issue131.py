"""#131 C1: BackendHandle.register is the public AnyPath registration API."""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue83 import _j1_models
from tests.core.test_issue98 import _gh_models
from tests.myapp.models import DocumentGrant
from trusts.core import (
    All,
    Along,
    BackendHandle,
    Equal,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    permission_in,
)


ROOT = Path(__file__).resolve().parents[2]


def _handle(registry=None):
    return BackendHandle(
        path='tests.myapp.backends.DocumentBackend',
        registry=registry if registry is not None else TrustsRegistry(),
        compiler=object(),
    )


class HandleRegisterPublicSurfaceTest(SimpleTestCase):
    def test_string_register_matches_internal_ref_record(self):
        via_ref = TrustsRegistry()
        via_handle = TrustsRegistry()
        j = Ref(DocumentGrant)
        expected = via_ref.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        got = _handle(via_handle).register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.assertEqual(got.content_path, expected.content_path)
        self.assertEqual(got.user_path, expected.user_path)
        self.assertEqual(got.permission_path, expected.permission_path)
        self.assertIs(got.content_model, expected.content_model)
        self.assertEqual(got.content_field, expected.content_field)
        self.assertEqual(got.content_target, expected.content_target)
        self.assertEqual(via_handle.records, (got,))

    def test_ref_and_along_instance_are_type_errors(self):
        handle = _handle()
        j = Ref(DocumentGrant)
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
                permission='permission',
                content='document',
                along=Along(j.document, 4),
            )

    def test_malformed_paths_rejected_before_ref_resolve(self):
        handle = _handle()
        for path in ('', '__user', 'user__', 'user.document', 'user____x'):
            with self.subTest(path=path):
                with self.assertRaises(TrustsConfigurationError):
                    handle.register(
                        DocumentGrant,
                        user=path,
                        permission='permission',
                        content='document',
                    )
        self.assertEqual(handle.registry.records, ())

    def test_freeze_wins_before_type_or_path_errors(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                DocumentGrant,
                user=Ref(DocumentGrant).user,
                permission='permission',
                content='document',
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                DocumentGrant,
                user='user.document',
                permission='permission',
                content='document',
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, ())

    def test_handles_stay_isolated(self):
        left = _handle()
        right = _handle()
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
        self.assertIsNot(left.registry.records[0], right.registry.records[0])
        self.assertEqual(len(left.registry.records), 1)
        self.assertEqual(len(right.registry.records), 1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterLongPathTest(SimpleTestCase):
    def test_long_content_path_is_length_neutral(self):
        _folder, _payload, _row, FolderGrant, _group = _j1_models()
        via_ref = TrustsRegistry()
        via_handle = TrustsRegistry()
        j = Ref(FolderGrant)
        expected = via_ref.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        got = _handle(via_handle).register(
            FolderGrant,
            user='user',
            permission='permission',
            content='folder__rows__content',
        )
        self.assertEqual(got.content_path, expected.content_path)
        self.assertEqual(got.content_path, ('folder', 'rows', 'content'))
        self.assertEqual(got.content_field, 'folder__rows__content')
        self.assertEqual(got.user_path, expected.user_path)
        self.assertEqual(got.permission_path, expected.permission_path)
        self.assertIs(got.content_model, expected.content_model)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class HandleRegisterConditionAndAlongTest(SimpleTestCase):
    def test_string_condition_tree_matches_ref_tree(self):
        models = _gh_models()
        TeamRepoGrant = models[6]
        via_ref = TrustsRegistry()
        via_handle = TrustsRegistry()
        t = Ref(TeamRepoGrant)
        expected = via_ref.register(
            content=t.repository,
            user=t.team.members,
            permission=t.operation,
            condition=All(
                permission_in(t.team.permission_bundles.operations),
                Equal(t.team.organization, t.repository.organization),
            ),
        )
        got = _handle(via_handle).register(
            TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            condition=All(
                permission_in('team__permission_bundles__operations'),
                Equal('team__organization', 'repository__organization'),
            ),
        )
        self.assertEqual(got.user_path, expected.user_path)
        self.assertEqual(got.content_path, expected.content_path)
        self.assertEqual(
            got.condition.predicates[0].refs[0]._path,
            expected.condition.predicates[0].refs[0]._path,
        )
        self.assertEqual(
            got.condition.predicates[1].left._path,
            expected.condition.predicates[1].left._path,
        )
        self.assertEqual(
            got.condition.predicates[1].right._path,
            expected.condition.predicates[1].right._path,
        )

    def test_along_tuple_matches_internal_along(self):
        User = get_user_model()

        class Node(models.Model):
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class NodeGrant(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        via_ref = TrustsRegistry()
        via_handle = TrustsRegistry()
        j = Ref(NodeGrant)
        expected = via_ref.register(
            content=j.node,
            user=j.user,
            permission=j.permission,
            along=Along(j.node.parent, bound=8),
        )
        got = _handle(via_handle).register(
            NodeGrant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        self.assertEqual(expected.along.bound, 8)
        self.assertEqual(got.along, expected.along)


class PublicExampleSurfaceTest(SimpleTestCase):
    def test_readme_rst_and_myapp_use_handle_register_only(self):
        readme = (ROOT / 'README.md').read_text()
        rst = (ROOT / 'docs' / 'source' / 'index.rst').read_text()
        apps = (ROOT / 'tests' / 'myapp' / 'apps.py').read_text()
        for text in (readme, rst, apps):
            self.assertIn('handle.register(', text)
            self.assertNotIn('from trusts.core import Ref', text)
            self.assertNotIn('handle.registry.register(', text)
        self.assertNotIn('register_strategy', readme)
        self.assertNotIn('handle.register_strategy', rst)
        migration = (ROOT / 'migrates.md').read_text()
        self.assertIn('handle.register(', migration)
        self.assertIn('along=("parent", 8)', migration)
        self.assertIn('from trusts.core import Ref', migration)
        self.assertIn('.registry.register(', migration)
