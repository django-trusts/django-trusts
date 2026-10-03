"""Explicit auth.Group registration (#246).

``group=`` ends at Django ``auth.Group``. The compiler appends
``Group.permissions``. ``permission=`` is unchanged and mutually
exclusive with ``group=``. Only explicit ``group=`` records feed
``get_group_permissions``; they also participate in ordinary
authorization. Membership shape is not a group.
"""

import re
from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    filter_authorized_scopes,
)
from trusts.policy_lock import (
    _load_policy_sql_document,
    render_policy_sql_bytes,
)
from trusts.query import AuthorizedManager


class _ProbeBackend(TrustModelBackendMixin, ModelBackend):
    """Mixin path under test. Not an installed authentication backend."""


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


def _perm(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _code(permission):
    return '%s.%s' % (
        permission.content_type.app_label,
        permission.codename,
    )


def _handle(registry=None, path='tests.core.issue246'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


def _behavior_models():
    class Folder(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Paper(models.Model):
        title = models.CharField(max_length=40)
        folder = models.ForeignKey(
            Folder, related_name='papers', null=True, on_delete=models.CASCADE,
        )

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class GroupPaperGrant(models.Model):
        group = models.ForeignKey(Group, on_delete=models.CASCADE)
        paper = models.ForeignKey(Paper, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class GroupFolderGrant(models.Model):
        group = models.ForeignKey(Group, on_delete=models.CASCADE)
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class Desk(models.Model):
        title = models.CharField(max_length=40)
        holders = models.ManyToManyField(
            get_user_model(), related_name='+', blank=True,
        )

        class Meta:
            app_label = 'trusts_tests'

    class DeskPaperGrant(models.Model):
        desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
        paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class DirectPaperGrant(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class Station(models.Model):
        title = models.CharField(max_length=40)
        group = models.ForeignKey(Group, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class StationPaperGrant(models.Model):
        station = models.ForeignKey(Station, on_delete=models.CASCADE)
        paper = models.ForeignKey(Paper, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return (
        Folder, Paper, GroupPaperGrant, GroupFolderGrant, Desk,
        DeskPaperGrant, DirectPaperGrant, Station, StationPaperGrant,
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ExplicitGroupRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue246', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue246', PAIR_KERNEL_SUITE)

    def _grant_model(self):
        class GroupPaperGrant(models.Model):
            group = models.ForeignKey(
                'auth.Group', on_delete=models.CASCADE,
            )
            paper = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        return GroupPaperGrant

    def test_permission_and_group_are_mutually_exclusive(self):
        Grant = self._grant_model()
        handle = _handle()

        def boom(_trust):
            raise AssertionError('path builder must not run')

        with self.assertRaisesRegex(
            TrustsConfigurationError, 'not both',
        ):
            handle.register(
                trust=Grant,
                user='group__user',
                permission='paper',
                group='group',
                content='paper',
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'not both',
        ):
            handle.register(
                trust=Grant,
                user=boom,
                permission=boom,
                group=boom,
                content=boom,
            )
        registry = TrustsRegistry()
        ref = Ref(Grant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'not both',
        ):
            registry.register(
                content=ref.paper,
                user=ref.group.user,
                permission=ref.paper,
                group=ref.group,
            )
        self.assertEqual(handle.registry.records, ())
        self.assertEqual(registry.records, ())

    def test_one_of_permission_or_group_is_required(self):
        Grant = self._grant_model()
        handle = _handle()
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'requires permission= or group=',
        ):
            handle.register(
                trust=Grant,
                user='group__user',
                content='paper',
            )
        with self.assertRaises(TypeError):
            handle.register(trust=Grant, user='group__user')
        registry = TrustsRegistry()
        ref = Ref(Grant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'requires permission= or group=',
        ):
            registry.register(content=ref.paper, user=ref.group.user)
        self.assertEqual(handle.registry.records, ())
        self.assertEqual(registry.records, ())

    def test_group_path_must_end_at_auth_group(self):
        class Crew(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CrewPaper(models.Model):
            crew = models.ForeignKey(Crew, on_delete=models.CASCADE)
            user = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )
            paper = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        Grant = self._grant_model()
        handle = _handle()
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'must end at auth.Group',
        ):
            handle.register(
                trust=CrewPaper,
                user='user',
                group='crew',
                content='paper',
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'do not append permissions',
        ):
            handle.register(
                trust=Grant,
                user='group__user',
                group=lambda t: t.group.permissions,
                content='paper',
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'user_set',
        ):
            handle.register(
                trust=Grant,
                user=lambda t: t.group.user_set,
                group='group',
                content='paper',
            )
        self.assertEqual(handle.registry.records, ())

    def test_public_group_registration_matches_ref_and_compiler_hop(self):
        Grant = self._grant_model()
        via_ref = TrustsRegistry()
        ref = Ref(Grant)
        expected = via_ref.register(
            content=ref.paper,
            user=ref.group.user,
            group=ref.group,
        )
        strings = _handle(path='tests.core.issue246-strings').register(
            trust=Grant,
            user='group__user',
            group='group',
            content='paper',
        )
        callables = _handle(path='tests.core.issue246-callables').register(
            trust=Grant,
            user=lambda t: t.group.user,
            group=lambda t: t.group,
            content=lambda t: t.paper,
        )
        self.assertEqual(strings, expected)
        self.assertEqual(callables, expected)
        self.assertTrue(expected.via_group)
        self.assertEqual(expected.group_path, ('group',))
        self.assertEqual(expected.group_field, 'group')
        self.assertEqual(expected.group_model._meta.label, 'auth.Group')
        self.assertEqual(expected.permission_path, ('group', 'permissions'))
        self.assertEqual(expected.permission_field, 'group__permissions')
        self.assertEqual(expected.permission_model._meta.label, 'auth.Permission')
        self.assertNotIn('permissions', expected.group_path)

        class Station(models.Model):
            group = models.ForeignKey(
                'auth.Group', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class StationGrant(models.Model):
            station = models.ForeignKey(Station, on_delete=models.CASCADE)
            paper = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        multi = _handle().register(
            trust=StationGrant,
            user='station__group__user',
            group='station__group',
            content='paper',
        )
        self.assertEqual(multi.group_path, ('station', 'group'))
        self.assertEqual(
            multi.permission_field, 'station__group__permissions',
        )
        self.assertEqual(multi.permission_model._meta.label, 'auth.Permission')

    def test_permission_registration_is_not_via_group(self):
        class Direct(models.Model):
            user = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )
            paper = models.ForeignKey(
                'auth.User', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        record = _handle().register(
            trust=Direct,
            user='user',
            permission='permission',
            content='paper',
        )
        self.assertFalse(record.via_group)
        self.assertEqual(record.permission_path, ('permission',))
        self.assertEqual(record.group_path, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ExplicitGroupAuthorizationTest(TransactionTestCase):
    def setUp(self):
        (
            self.Folder, self.Paper, self.GroupPaperGrant,
            self.GroupFolderGrant, self.Desk, self.DeskPaperGrant,
            self.DirectPaperGrant, self.Station, self.StationPaperGrant,
        ) = _behavior_models()
        self._table_cm = _tables(
            self.Folder, self.Paper, self.GroupPaperGrant,
            self.GroupFolderGrant, self.Desk, self.DeskPaperGrant,
            self.DirectPaperGrant, self.Station, self.StationPaperGrant,
        )
        self._table_cm.__enter__()
        holders = self.Desk._meta.get_field('holders')
        if not hasattr(holders, 'm2m_field_name'):
            # isolate_apps does not finish M2M contribution onto the
            # already-prepared auth user. The forward relation is still
            # the membership hop under test.
            holders.contribute_to_related_class(
                get_user_model(), holders.remote_field,
            )
        User = get_user_model()
        self.alice = User.objects.create_user('alice-246', password='x')
        self.bob = User.objects.create_user('bob-246', password='x')
        self.carol = User.objects.create_user('carol-246', password='x')
        self.change = _perm(self.Paper, 'change_paper')
        self.add = _perm(self.Paper, 'add_paper')
        self.write = _perm(self.Paper, 'write_paper')
        self.editors = Group.objects.create(name='editors-246')
        self.editors.permissions.add(self.change)
        self.editors.user_set.add(self.alice)
        self.folder_a = self.Folder.objects.create(title='A')
        self.folder_b = self.Folder.objects.create(title='B')
        self.paper_a = self.Paper.objects.create(title='A')
        self.paper_b = self.Paper.objects.create(title='B')
        self.paper_c = self.Paper.objects.create(
            title='C', folder=self.folder_a,
        )
        self.paper_d = self.Paper.objects.create(title='D')
        self.GroupPaperGrant.objects.create(
            group=self.editors, paper=self.paper_a,
        )
        self.GroupFolderGrant.objects.create(
            group=self.editors, folder=self.folder_a,
        )
        self.desk = self.Desk.objects.create(title='night')
        self.desk.holders.add(self.carol)
        self.DeskPaperGrant.objects.create(
            desk=self.desk, paper=self.paper_a, permission=self.add,
        )
        self.DirectPaperGrant.objects.create(
            user=self.alice, paper=self.paper_b, permission=self.write,
        )
        self.station = self.Station.objects.create(
            title='desk', group=self.editors,
        )
        self.StationPaperGrant.objects.create(
            station=self.station, paper=self.paper_d,
        )
        self.registry = TrustsRegistry()
        self.handle = _handle(self.registry)
        self.handle.register(
            trust=self.GroupPaperGrant,
            user=lambda t: t.group.user,
            group=lambda t: t.group,
            content=lambda t: t.paper,
        )
        self.handle.register(
            trust=self.GroupFolderGrant,
            user='group__user',
            group='group',
            content='folder__papers',
        )
        self.handle.register(
            trust=self.DeskPaperGrant,
            user='desk__holders',
            permission='permission',
            content='paper',
        )
        self.handle.register(
            trust=self.DirectPaperGrant,
            user='user',
            permission='permission',
            content='paper',
        )
        self.handle.register(
            trust=self.StationPaperGrant,
            user='station__group__user',
            group='station__group',
            content='paper',
        )
        self.backend = _ProbeBackend()
        self.change_code = _code(self.change)
        self.add_code = _code(self.add)
        self.write_code = _code(self.write)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _backend(self):
        return patch.object(
            self.backend, '_own_handle', return_value=self.handle,
        )

    def test_explicit_group_feeds_group_and_ordinary_authorization(self):
        with self._backend():
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, self.paper_a),
                {self.change_code},
            )
            self.assertEqual(
                self.backend.get_all_permissions(self.alice, self.paper_a),
                {self.change_code},
            )
            self.assertTrue(
                self.backend.has_perm(
                    self.alice, self.change_code, self.paper_a,
                ),
            )
            self.assertFalse(
                self.backend.has_perm(self.alice, self.add_code, self.paper_a),
            )
            self.assertFalse(
                self.backend.has_perm(self.bob, self.change_code, self.paper_a),
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.bob, self.paper_a),
                set(),
            )
            one = self.Paper.objects.filter(pk=self.paper_a.pk)
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, one),
                {self.change_code},
            )
            self.assertTrue(
                self.backend.has_perm(self.alice, self.change_code, one),
            )
            mixed = self.Paper.objects.filter(
                pk__in=[self.paper_a.pk, self.paper_b.pk],
            )
            self.assertFalse(
                self.backend.has_perm(self.alice, self.change_code, mixed),
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, mixed),
                set(),
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, self.paper_c),
                {self.change_code},
            )

        granted = self.registry.filter_authorized(
            self.Paper.objects.order_by('pk'), self.alice, self.change,
        )
        self.assertEqual(
            list(granted), [self.paper_a, self.paper_c, self.paper_d],
        )
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(self.handle,),
        ):
            listed = sorted(
                self.Paper.objects.authorized(self.alice, self.change),
                key=lambda row: row.pk,
            )
        self.assertEqual(listed, [self.paper_a, self.paper_c, self.paper_d])
        folders = filter_authorized_scopes(
            self.Folder.objects.order_by('pk'),
            self.alice,
            self.change,
            content=self.Paper,
            handles=(self.handle,),
        )
        self.assertEqual(list(folders), [self.folder_a])

    def test_permission_and_membership_do_not_feed_group_permissions(self):
        with self._backend():
            self.assertEqual(
                self.backend.get_all_permissions(self.carol, self.paper_a),
                {self.add_code},
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.carol, self.paper_a),
                set(),
            )
            self.assertTrue(
                self.backend.has_perm(self.carol, self.add_code, self.paper_a),
            )
            self.assertFalse(
                self.backend.has_perm(
                    self.carol, self.change_code, self.paper_a,
                ),
            )
            carol_qs = self.Paper.objects.filter(pk=self.paper_a.pk)
            self.assertEqual(
                self.backend.get_group_permissions(self.carol, carol_qs),
                set(),
            )
            self.assertEqual(
                self.backend.get_all_permissions(self.alice, self.paper_b),
                {self.write_code},
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, self.paper_b),
                set(),
            )
            self.assertTrue(
                self.backend.has_perm(
                    self.alice, self.write_code, self.paper_b,
                ),
            )
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(self.handle,),
        ):
            self.assertEqual(
                list(self.Paper.objects.authorized(self.carol, self.add)),
                [self.paper_a],
            )
            self.assertEqual(
                list(self.Paper.objects.authorized(self.alice, self.write)),
                [self.paper_b],
            )

    def test_multihop_group_path_authorizes_through_the_compiler_hop(self):
        with self._backend():
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, self.paper_d),
                {self.change_code},
            )
            self.assertTrue(
                self.backend.has_perm(
                    self.alice, self.change_code, self.paper_d,
                ),
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.bob, self.paper_d),
                set(),
            )
            self.assertFalse(
                self.backend.has_perm(
                    self.bob, self.change_code, self.paper_d,
                ),
            )

    def test_policy_sql_records_the_compiler_owned_group_hop(self):
        group_only = _handle(path='tests.core.issue246-policy-group')
        group_only.register(
            trust=self.GroupPaperGrant,
            user='group__user',
            group='group',
            content='paper',
        )
        direct_only = _handle(path='tests.core.issue246-policy-direct')
        direct_only.register(
            trust=self.DirectPaperGrant,
            user='user',
            permission='permission',
            content='paper',
        )
        grouped = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[group_only]),
        )
        direct = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[direct_only]),
        )
        group_content = grouped['backends'][0]['contents'][0]
        direct_content = direct['backends'][0]['contents'][0]
        group_trust = group_content['trusts'][0]
        self.assertEqual(group_trust['group'], {
            'path': 'group',
            'model': 'auth.Group',
            'target': 'id',
        })
        self.assertEqual(group_trust['permission'], {
            'path': 'group__permissions',
            'model': 'auth.Permission',
            'target': 'id',
        })
        self.assertNotIn('group', direct_content['trusts'][0])
        self.assertNotIn('get_group_permissions', direct_content)
        self.assertIn('get_group_permissions', group_content)
        for key in ('permitted', 'has_perm', 'get_all_permissions',
                    'get_group_permissions'):
            self.assertIn('auth_group_permissions', group_content[key]['sql'])
        self.assertNotIn(
            'auth_group_permissions',
            direct_content['has_perm']['sql'],
        )

        mixed = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        mixed_content = mixed['backends'][0]['contents'][0]
        group_sql = mixed_content['get_group_permissions']['sql']
        all_sql = mixed_content['get_all_permissions']['sql']
        self.assertIn('auth_group_permissions', group_sql)
        self.assertNotIn('deskpapergrant', group_sql)
        self.assertNotIn('directpapergrant', group_sql)
        self.assertIn('deskpapergrant', all_sql)
        self.assertIn('directpapergrant', all_sql)
        self.assertIn('auth_group_permissions', all_sql)


_GROUP_PERMISSION_ALIAS = re.compile(
    r'JOIN\s+"auth_group_permissions"\s+"([A-Za-z_][A-Za-z0-9_]*)"',
)


def _group_permission_aliases(sql):
    """Aliases Django assigned to ``auth.Group.permissions`` in ``sql``."""
    return _GROUP_PERMISSION_ALIAS.findall(sql)


def _ceiling_models():
    class CeilingFolder(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Paper(models.Model):
        title = models.CharField(max_length=40)
        folder = models.ForeignKey(
            CeilingFolder, related_name='papers', on_delete=models.CASCADE,
        )

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class CeilingGrant(models.Model):
        group = models.ForeignKey(Group, on_delete=models.CASCADE)
        folder = models.ForeignKey(CeilingFolder, on_delete=models.CASCADE)
        grants = models.ManyToManyField(Permission, related_name='+', blank=True)

        class Meta:
            app_label = 'trusts_tests'

    return CeilingFolder, Paper, CeilingGrant


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class GroupPermissionCeilingJoinTest(TransactionTestCase):
    """Local ``.contains`` on ``Group.permissions`` must not over-grant.

    One Django group holds ``read`` and ``change``. The trust's local
    permission set contains only ``read``. Condition and correlation have
    to share one ``Group.permissions`` row, so ``change`` stays denied.
    """

    def setUp(self):
        self.Folder, self.Paper, self.Grant = _ceiling_models()
        self._table_cm = _tables(self.Folder, self.Paper, self.Grant)
        self._table_cm.__enter__()
        grants = self.Grant._meta.get_field('grants')
        if not hasattr(grants, 'm2m_field_name'):
            grants.contribute_to_related_class(Permission, grants.remote_field)
        User = get_user_model()
        self.alice = User.objects.create_user('alice-ceiling', password='x')
        self.read = _perm(self.Paper, 'read_paper')
        self.change = _perm(self.Paper, 'change_paper')
        self.read_code = _code(self.read)
        self.change_code = _code(self.change)
        self.editors = Group.objects.create(name='editors-ceiling')
        self.editors.permissions.add(self.read, self.change)
        self.editors.user_set.add(self.alice)
        self.folder = self.Folder.objects.create(title='capped')
        self.paper = self.Paper.objects.create(title='capped', folder=self.folder)
        self.other = self.Paper.objects.create(
            title='other', folder=self.Folder.objects.create(title='other'),
        )
        grant = self.Grant.objects.create(group=self.editors, folder=self.folder)
        grant.grants.add(self.read)
        self.registry = TrustsRegistry()
        self.handle = _handle(self.registry, path='tests.core.issue246-ceiling')
        self.handle.register(
            trust=self.Grant,
            user=lambda t: t.group.user,
            group=lambda t: t.group,
            content=lambda t: t.folder.papers,
            condition=lambda t: t.grants.contains(t.group.permissions),
        )
        self.backend = _ProbeBackend()
        self.one = self.Paper.objects.filter(pk=self.paper.pk)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _backend(self):
        return patch.object(
            self.backend, '_own_handle', return_value=self.handle,
        )

    def _handles(self):
        return patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(self.handle,),
        )

    def _permission_codes(self, rows):
        return {_code(row) for row in rows}

    def test_has_perm_denies_change_for_instance_and_queryset(self):
        with self._backend():
            checks = (
                ('instance read', True, self.read_code, self.paper),
                ('instance change', False, self.change_code, self.paper),
                ('queryset read', True, self.read_code, self.one),
                ('queryset change', False, self.change_code, self.one),
            )
            for label, expected, code, target in checks:
                with self.subTest(label):
                    self.assertIs(
                        self.backend.has_perm(self.alice, code, target),
                        expected,
                    )

    def test_enumerations_omit_change_for_instance_and_queryset(self):
        with self._backend():
            checks = (
                ('all instance', self.backend.get_all_permissions, self.paper),
                ('group instance', self.backend.get_group_permissions, self.paper),
                ('all queryset', self.backend.get_all_permissions, self.one),
                ('group queryset', self.backend.get_group_permissions, self.one),
            )
            for label, method, target in checks:
                with self.subTest(label):
                    self.assertEqual(
                        method(self.alice, target),
                        {self.read_code},
                    )

    def test_authorized_queryset_and_scopes_omit_change(self):
        with self._handles():
            read_rows = self.Paper.objects.authorized(self.alice, self.read)
            change_rows = self.Paper.objects.authorized(self.alice, self.change)
            with self.subTest('authorized read'):
                self.assertEqual(list(read_rows), [self.paper])
            with self.subTest('authorized change'):
                self.assertEqual(list(change_rows), [])
            for label, rows in (('read', read_rows), ('change', change_rows)):
                sql = str(rows.query)
                with self.subTest(authorized_sql=label):
                    self.assertEqual(
                        len(_group_permission_aliases(sql)), 1, sql,
                    )
        read_folders = filter_authorized_scopes(
            self.Folder.objects.order_by('pk'),
            self.alice,
            self.read,
            content=self.Paper,
            handles=(self.handle,),
        )
        change_folders = filter_authorized_scopes(
            self.Folder.objects.order_by('pk'),
            self.alice,
            self.change,
            content=self.Paper,
            handles=(self.handle,),
        )
        with self.subTest('scope read'):
            self.assertEqual(list(read_folders), [self.folder])
        with self.subTest('scope change'):
            self.assertEqual(list(change_folders), [])
        for label, scoped in (
            ('read', read_folders),
            ('change', change_folders),
        ):
            sql = str(scoped.query)
            with self.subTest(scope_sql=label):
                self.assertEqual(
                    len(_group_permission_aliases(sql)), 1, sql,
                )

    def test_common_permissions_omit_change(self):
        plan = self.registry.plan_for(self.paper, user=self.alice)
        for label, target in (('instance', self.paper), ('queryset', self.one)):
            with self.subTest(label):
                self.assertEqual(
                    self._permission_codes(
                        plan.common_permissions(self.alice, target),
                    ),
                    {self.read_code},
                )

    def test_policy_sql_shares_one_group_permissions_alias(self):
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        content = document['backends'][0]['contents'][0]
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_group_permissions',
        ):
            sql = content[key]['sql']
            aliases = _group_permission_aliases(sql)
            with self.subTest(key=key):
                self.assertEqual(len(aliases), 1, sql)
                self.assertEqual(len(set(aliases)), 1, sql)
