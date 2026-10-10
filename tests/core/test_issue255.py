"""Reverse permission inquiry (#255).

One saved content object and one permission. The private compiler and
both public adapters return the same rows as ``user.has_perm`` for the
candidate user queryset. Construction is zero SQL. Evaluation is one
statement. Core does not add a blanket ``is_active`` exclusion.
"""

import uuid
from contextlib import contextmanager

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AnonymousUser, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.core.test_issue147.test_sql_export import (
    Folder,
    FolderGrant,
    _document_handle,
    _handle as _export_handle,
)
from trusts.reverse import lock_permitted_users_queryset
from tests.core.test_issue246 import _tables
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
from trusts.core import BackendHandle, PlanQueryCompiler, TrustsConfigurationError, TrustsRegistry
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import PermittedUsersManagerMixin, PermittedUsersMixin


HOST = 'tests.backends.HostTrustModelBackend'
MODEL_BACKEND = 'django.contrib.auth.backends.ModelBackend'
PERM = 'myapp.change_document'


class AlwaysGrantBackend(object):
    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return True


class SubclassedModelBackend(ModelBackend):
    """Object-blind only by inheritance. That is not an explicit declaration."""


class AuthenticationOnlyBackend(object):
    trusts_object_permissions = False

    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return False


class InactiveGrantBackend(object):
    """Grants one inactive username. No ``is_active`` SQL of its own."""

    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        if obj is None or user_obj is None:
            return False
        return getattr(user_obj, 'username', None) == 'inactive-granted-255'

    def permitted_users_predicate(self, content, perm):
        from django.db.models import Q
        return Q(username='inactive-granted-255')

    def singular_permission_accepted(self, perm):
        return isinstance(perm, Permission)


class SplitUserRouter(object):
    def db_for_read(self, model, **hints):
        if getattr(model._meta, 'label', None) == 'auth.User':
            return 'other'
        return None

    def db_for_write(self, model, **hints):
        return None

    def allow_relation(self, obj1, obj2, **hints):
        return True


class MarkedQuerySet(models.QuerySet):
    marker = 'issue255'


class MarkedUserManager(PermittedUsersManagerMixin, models.Manager):
    def get_queryset(self):
        return MarkedQuerySet(self.model, using=self._db).filter(
            username__startswith='m255-',
        )


class PlainUserManager(PermittedUsersManagerMixin, type(get_user_model().objects)):
    pass


def _permission(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _contribute_m2m(field, model):
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(model, field.remote_field)


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


def _normalized(perm):
    if isinstance(perm, Permission):
        return perm.user_perm_str
    return perm


def _assert_agrees(test, content, perm, candidates):
    found = _pks(content.get_permitted_users(perm))
    code = _normalized(perm)
    expected = set()
    for user in candidates:
        if user.has_perm(code, content):
            expected.add(user.pk)
    test.assertEqual(found, expected)
    return found


@contextmanager
def _document_registry():
    config = implementation_for_path(DOCUMENT_BACKEND)
    saved = dict(config.registries)
    registry = TrustsRegistry()
    config.registries[DOCUMENT_BACKEND] = registry
    try:
        yield registry
    finally:
        config.registries.clear()
        config.registries.update(saved)


def _handle(registry):
    return BackendHandle(
        path=DOCUMENT_BACKEND,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


class Issue255SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue255', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue255', PAIR_KERNEL_SUITE)


class Issue255PolicySqlTest(SimpleTestCase):
    def test_lockfile_adds_reverse_predicate_with_content_and_permission_binds(self):
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[_document_handle()]),
        )
        row = document['backends'][0]['contents'][0]['get_permitted_users']
        self.assertEqual(list(row), ['params', 'sql'])
        self.assertIn({'bind': 'content.id'}, row['params'])
        self.assertIn({'bind': 'permission.id'}, row['params'])
        self.assertIn('EXISTS', row['sql'])
        self.assertIn('auth_user', row['sql'])
        where = row['sql'].split(' WHERE ', 1)[1]
        self.assertIn('is_active', where)
        self.assertNotIn('is_superuser', where)

    def test_along_lockfile_records_path_bound_and_reverse_statement(self):
        class FolderPermit(models.Model):
            directory = models.ForeignKey(Folder, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'documents'

        handle = _export_handle('documents.backends.FolderBackend')
        handle.register(
            trust=FolderGrant,
            user='user',
            permission='permission',
            content='folder',
            along=('folder__parent', 2),
        )
        handle.register(
            trust=FolderPermit,
            user='user',
            permission='permission',
            content='directory',
            along=('directory__parent', 2),
        )
        folder = Folder(pk=1)
        queryset = lock_permitted_users_queryset(
            handle, folder, Permission(pk=1),
        )
        self.assertIn('WITH RECURSIVE', str(queryset.query))
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        content = document['backends'][0]['contents'][0]
        first, second = content['trusts']
        self.assertEqual(first['id'], (
            'documents__FolderGrant__folder__along_folder__parent_S_2'
        ))
        self.assertEqual(second['id'], (
            'documents__FolderPermit__directory__along_'
            'directory__parent_S_2'
        ))
        self.assertEqual(first['along'], {
            'path': 'folder__parent', 'shape': 'S', 'bound': 2,
        })
        self.assertEqual(second['along'], {
            'path': 'directory__parent', 'shape': 'S', 'bound': 2,
        })
        self.assertNotEqual(first['id'], second['id'])
        reverse = content['get_permitted_users']
        self.assertIn('WITH RECURSIVE', reverse['sql'])
        self.assertIn({'const': 2}, reverse['params'])
        self.assertIn({'bind': 'content.id'}, reverse['params'])
        self.assertIn({'bind': 'permission.id'}, reverse['params'])


class Issue255LiveDocumentTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-255', password='x')
        self.bob = User.objects.create_user('bob-255', password='x')
        self.inactive = User.objects.create_user('inactive-255', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.superuser = User.objects.create_superuser(
            'super-255', email='super-255@example.com', password='x',
        )
        self.inactive_super = User.objects.create_superuser(
            'inactive-super-255', email='inactive-super-255@example.com', password='x',
        )
        self.inactive_super.is_active = False
        self.inactive_super.save(update_fields=['is_active'])
        self.marked = User.objects.create_user('m255-marked', password='x')
        self.change = _permission(Document, 'change_document', )
        self.other = _permission(Document, 'delete_document')
        self.document = Document.objects.create(title='granted-255')
        self.secret = Document.objects.create(
            title='secret-255', confidential=True,
        )
        DocumentGrant.objects.create(
            document=self.document, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.document, user=self.inactive, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.document, user=self.marked, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        self.candidates = get_user_model()._default_manager.get_queryset()

    def test_direct_grant_instance_and_string_agree_and_are_one_query(self):
        self.assertFalse(hasattr(Document.objects, 'get_permitted_users'))
        self.assertFalse(hasattr(get_user_model().objects, 'permitted'))
        self.assertFalse(hasattr(PlainUserManager, 'get_permitted_users'))
        self.assertTrue(callable(PlainUserManager.permitted))
        self.assertTrue(callable(self.document.get_permitted_users))

        with self.assertNumQueries(0):
            by_instance = self.document.get_permitted_users(self.change)
            by_string = self.document.get_permitted_users(PERM)
        self.assertIsNone(by_instance._result_cache)
        self.assertIsNone(by_string._result_cache)
        with self.assertNumQueries(1):
            instance_rows = list(by_instance)
        with self.assertNumQueries(1):
            string_rows = list(by_string)
        self.assertEqual(
            {row.pk for row in instance_rows},
            {row.pk for row in string_rows},
        )
        self.assertIn('EXISTS', str(by_instance.query))
        self.assertIn('auth_permission', str(by_string.query))
        found = _assert_agrees(
            self, self.document, self.change, self.candidates,
        )
        _assert_agrees(self, self.document, PERM, self.candidates)
        self.assertIn(self.alice.pk, found)
        self.assertIn(self.superuser.pk, found)
        self.assertIn(self.marked.pk, found)
        self.assertNotIn(self.bob.pk, found)
        self.assertNotIn(self.inactive.pk, found)
        self.assertNotIn(self.inactive_super.pk, found)
        self.assertNotIn(AnonymousUser().pk, found)

        manager = PlainUserManager()
        manager.model = get_user_model()
        manager.name = 'objects'
        self.assertEqual(
            _pks(manager.permitted(self.document, self.change)),
            found,
        )

    def test_unrelated_permission_matches_has_perm_including_superuser(self):
        found = _assert_agrees(
            self, self.document, self.other, self.candidates,
        )
        self.assertIn(self.superuser.pk, found)
        self.assertNotIn(self.alice.pk, found)
        self.assertNotIn(self.bob.pk, found)

    def test_revocation_drops_the_user_on_the_next_evaluation(self):
        self.assertIn(
            self.alice.pk,
            _pks(self.document.get_permitted_users(self.change)),
        )
        DocumentGrant.objects.filter(
            document=self.document, user=self.alice, permission=self.change,
        ).delete()
        found = _assert_agrees(
            self, self.document, self.change, self.candidates,
        )
        self.assertNotIn(self.alice.pk, found)
        self.assertIn(self.superuser.pk, found)

    def test_named_filter_and_unknown_code_follow_the_singular_check(self):
        open_code = PERM + ':non_confidential'
        _assert_agrees(self, self.document, open_code, self.candidates)
        _assert_agrees(self, self.secret, open_code, self.candidates)
        self.assertIn(
            self.alice.pk,
            _pks(self.document.get_permitted_users(open_code)),
        )
        self.assertNotIn(
            self.alice.pk,
            _pks(self.secret.get_permitted_users(open_code)),
        )
        unknown = PERM + ':missing_filter'
        found = _assert_agrees(self, self.document, unknown, self.candidates)
        self.assertNotIn(self.alice.pk, found)
        self.assertIn(self.superuser.pk, found)

    def test_queryset_arguments_and_unsaved_content_fail_before_sql(self):
        unsaved = Document(title='unsaved-255')
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                unsaved.get_permitted_users(self.change)
            with self.assertRaises(TrustsConfigurationError):
                self.document.get_permitted_users(Permission.objects.all())
            with self.assertRaises(TrustsConfigurationError):
                self.document.get_permitted_users(Document.objects.all())
            with self.assertRaises(TrustsConfigurationError):
                PlainUserManager.permitted(
                    PlainUserManager(), Document.objects.all(), self.change,
                )
            with self.assertRaises(ValueError):
                self.document.get_permitted_users('not-a-permission')

    def test_and_or_composition_stays_lazy_and_evaluates_once(self):
        with self.assertNumQueries(0):
            both = (
                self.document.get_permitted_users(self.change)
                & self.secret.get_permitted_users(self.change)
            )
            either = (
                self.document.get_permitted_users(self.change)
                | self.document.get_permitted_users(self.other)
            )
        with self.assertNumQueries(1):
            both_pks = _pks(both)
        with self.assertNumQueries(1):
            either_pks = _pks(either)
        self.assertIn(self.superuser.pk, both_pks)
        self.assertIn(self.alice.pk, both_pks)
        self.assertNotIn(self.marked.pk, both_pks)
        self.assertIn(self.alice.pk, either_pks)
        self.assertIn(self.superuser.pk, either_pks)

    def test_custom_manager_preserves_queryset_class_and_filters(self):
        manager = MarkedUserManager()
        manager.model = get_user_model()
        manager.name = 'marked'
        with self.assertNumQueries(0):
            chosen = manager.permitted(self.document, self.change)
        self.assertIsInstance(chosen, MarkedQuerySet)
        self.assertEqual(chosen.marker, 'issue255')
        self.assertIn('m255-', str(chosen.query))
        found = _pks(chosen)
        expected = set()
        for user in manager.get_queryset():
            if user.has_perm(PERM, self.document):
                expected.add(user.pk)
        self.assertEqual(found, expected)
        self.assertIn(self.marked.pk, found)
        self.assertNotIn(self.alice.pk, found)
        content_rows = _pks(self.document.get_permitted_users(self.change))
        self.assertIn(self.alice.pk, content_rows)
        self.assertNotIsInstance(
            self.document.get_permitted_users(self.change),
            MarkedQuerySet,
        )

    def test_unsupported_backend_fails_before_sql(self):
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.AlwaysGrantBackend',
        )
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    self.document.get_permitted_users(self.change)
        self.assertIn('AlwaysGrantBackend', str(ctx.exception))

    def test_modelbackend_subclass_is_not_inferred_object_blind(self):
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.SubclassedModelBackend',
        )
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    self.document.get_permitted_users(PERM)
        self.assertIn('SubclassedModelBackend', str(ctx.exception))

    def test_explicit_authentication_only_backend_contributes_nothing(self):
        backends = (DOCUMENT_BACKEND, MODEL_BACKEND, (
            'tests.core.test_issue255.AuthenticationOnlyBackend'
        ))
        # tuple concatenation, not a nested string
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.AuthenticationOnlyBackend',
            MODEL_BACKEND,
        )
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            found = _assert_agrees(
                self, self.document, self.change, self.candidates,
            )
        self.assertIn(self.alice.pk, found)

    def test_inactive_grant_backend_is_not_removed_by_a_core_is_active_filter(self):
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.InactiveGrantBackend',
        )
        granted = get_user_model().objects.create_user(
            'inactive-granted-255', password='x',
        )
        granted.is_active = False
        granted.save(update_fields=['is_active'])
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                chosen = self.document.get_permitted_users(self.change)
            with self.assertNumQueries(1):
                found = _pks(chosen)
            candidates = get_user_model()._default_manager.get_queryset()
            expected = {
                user.pk for user in candidates
                if user.has_perm(PERM, self.document)
            }
        self.assertEqual(found, expected)
        self.assertIn(granted.pk, found)
        self.assertIn(self.alice.pk, found)
        self.assertNotIn(self.inactive.pk, found)

    def test_cross_database_router_fails_before_sql(self):
        databases = dict(settings.DATABASES)
        databases['other'] = {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
        with override_settings(
            DATABASES=databases,
            DATABASE_ROUTERS=['tests.core.test_issue255.SplitUserRouter'],
        ):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    self.document.get_permitted_users(self.change)
        self.assertIn('auth.User', str(ctx.exception))
        self.assertIn('other', str(ctx.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class Issue255RegisteredRootsTest(KernelHostRequiredMixin, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        models_ = self._models()
        (
            self.Org, self.Paper, self.Team, self.DirectGrant, self.TeamGrant,
            self.GroupGrant, self.Folder, self.FolderGrant, self.FolderPermit,
            self.UuidPaper,
            self.UuidGrant, self.UuidUser, self.UuidUserPaper, self.UuidGrantUser,
        ) = models_
        self._table_cm = _tables(*models_)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        _contribute_m2m(self.Team._meta.get_field('members'), get_user_model())
        _contribute_m2m(self.Team._meta.get_field('allowed'), Permission)
        self._registry_cm = _document_registry()
        self.registry = self._registry_cm.__enter__()
        self.addCleanup(self._registry_cm.__exit__, None, None, None)
        self.handle = _handle(self.registry)
        self._register()
        self.change = _permission(self.Paper, 'change_paper')
        self.add = _permission(self.Paper, 'add_paper')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.org = self.Org.objects.create(name='acme')
        self.other_org = self.Org.objects.create(name='other')
        self.paper = self.Paper.objects.create(title='spec', org=self.org)
        self.alice = self.User.objects.create_user('root-alice-255', password='x')
        self.bob = self.User.objects.create_user('root-bob-255', password='x')
        self.cara = self.User.objects.create_user('root-cara-255', password='x')
        self.outsider = self.User.objects.create_user('root-out-255', password='x')
        self.team = self.Team.objects.create(org=self.org, name='writers')
        self.team.members.add(self.bob)
        self.team.allowed.add(self.change)
        self.DirectGrant.objects.create(
            user=self.alice, paper=self.paper, permission=self.change,
        )
        self.DirectGrant.objects.create(
            user=self.bob, paper=self.paper, permission=self.change,
        )
        self.TeamGrant.objects.create(
            team=self.team, paper=self.paper, permission=self.change,
        )
        self.editors = Group.objects.create(name='editors-255')
        self.editors.user_set.add(self.cara)
        self.editors.permissions.add(self.add)
        self.GroupGrant.objects.create(
            group=self.editors, paper=self.paper, permission=self.add,
        )

    def _models(self):
        class Org(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Paper(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            org = models.ForeignKey(Org, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Team(models.Model):
            org = models.ForeignKey(Org, on_delete=models.CASCADE)
            name = models.CharField(max_length=40)
            members = models.ManyToManyField(
                get_user_model(), related_name='issue255_teams', blank=True,
            )
            allowed = models.ManyToManyField(
                Permission, related_name='issue255_allowed', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'

        class DirectGrant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
            paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class TeamGrant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Folder(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class FolderGrant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
            approved_user = models.ForeignKey(
                get_user_model(), null=True, on_delete=models.CASCADE,
                related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class FolderPermit(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class UuidPaper(PermittedUsersMixin, models.Model):
            id = models.UUIDField(primary_key=True, default=uuid.uuid4)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class UuidGrant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
            paper = models.ForeignKey(UuidPaper, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class UuidUserPaper(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class UuidUser(models.Model):
            id = models.UUIDField(primary_key=True, default=uuid.uuid4)
            username = models.CharField(max_length=40, unique=True)
            is_active = models.BooleanField(default=True)
            is_superuser = models.BooleanField(default=False)
            is_anonymous = AbstractBaseUser.is_anonymous
            is_authenticated = AbstractBaseUser.is_authenticated

            class Meta:
                app_label = 'trusts_tests'

            def has_perm(self, perm, obj=None):
                from django.contrib.auth.models import _user_has_perm
                if self.is_active and self.is_superuser:
                    return True
                return _user_has_perm(self, perm, obj)

        class UuidGrantUser(models.Model):
            user = models.ForeignKey(UuidUser, on_delete=models.CASCADE)
            paper = models.ForeignKey(UuidUserPaper, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        return (
            Org, Paper, Team, DirectGrant, TeamGrant, GroupGrant, Folder,
            FolderGrant, FolderPermit, UuidPaper, UuidGrant, UuidUser,
            UuidUserPaper, UuidGrantUser,
        )

    def _register(self):
        self.handle.register(
            trust=self.DirectGrant,
            user='user',
            permission='permission',
            content='paper',
        )
        self.handle.register(
            trust=self.TeamGrant,
            user='team__members',
            permission='permission',
            content='paper',
            condition=lambda trust: (
                trust.team.allowed.contains(trust.permission)
                & (trust.team.org == trust.paper.org)
            ),
        )
        self.handle.register(
            trust=self.GroupGrant,
            user=lambda trust: trust.group.user,
            group=lambda trust: trust.group,
            content='paper',
        )
        self.handle.register(
            trust=self.FolderGrant,
            user='user',
            permission='permission',
            content='folder',
            condition=lambda trust: trust.user == trust.approved_user,
            along=('folder__parent', 2),
        )
        self.handle.register(
            trust=self.FolderPermit,
            user='user',
            permission='permission',
            content='folder',
            along=('folder__parent', 1),
        )
        self.handle.register(
            trust=self.UuidGrant,
            user='user',
            permission='permission',
            content='paper',
        )
        self.handle.register(
            trust=self.UuidGrantUser,
            user='user',
            permission='permission',
            content='paper',
        )

    def test_membership_group_or_distinct_ceiling_and_revocation(self):
        candidates = self.User._default_manager.get_queryset()
        with self.assertNumQueries(0):
            chosen = self.paper.get_permitted_users(self.change)
        with self.assertNumQueries(1):
            found = _pks(chosen)
        self.assertEqual(
            found,
            {
                user.pk for user in candidates
                if user.has_perm(self.code, self.paper)
            },
        )
        self.assertIn(self.alice.pk, found)
        self.assertIn(self.bob.pk, found)
        self.assertNotIn(self.cara.pk, found)
        self.assertNotIn(self.outsider.pk, found)
        self.assertEqual(
            [row.pk for row in self.User.objects.filter(pk=self.bob.pk)],
            [self.bob.pk],
        )
        duplicated = [
            pk for pk in chosen.values_list('pk', flat=True)
        ]
        self.assertEqual(len(duplicated), len(set(duplicated)))

        mismatched = self.Paper.objects.create(title='nope', org=self.other_org)
        self.TeamGrant.objects.create(
            team=self.team, paper=mismatched, permission=self.change,
        )
        self.assertNotIn(
            self.bob.pk,
            _pks(mismatched.get_permitted_users(self.change)),
        )
        self.bob.issue255_teams.remove(self.team)
        self.DirectGrant.objects.filter(user=self.bob).delete()
        self.assertNotIn(
            self.bob.pk,
            _pks(self.paper.get_permitted_users(self.change)),
        )
        self.assertIn(
            self.cara.pk,
            _pks(self.paper.get_permitted_users(self.add)),
        )
        self.assertNotIn(
            self.alice.pk,
            _pks(self.paper.get_permitted_users(self.add)),
        )
        self.GroupGrant.objects.all().delete()
        self.assertNotIn(
            self.cara.pk,
            _pks(self.paper.get_permitted_users(self.add)),
        )

    def test_missing_ceiling_grants_nothing(self):
        self.team.allowed.clear()
        self.DirectGrant.objects.all().delete()
        found = _pks(self.paper.get_permitted_users(self.change))
        self.assertNotIn(self.bob.pk, found)
        self.assertNotIn(self.alice.pk, found)

    def test_along_reverse_agrees_at_bounds_cycles_conditions_and_or(self):
        root = self.Folder.objects.create(title='root')
        child = self.Folder.objects.create(title='child', parent=root)
        at_bound = self.Folder.objects.create(title='at-bound', parent=child)
        beyond = self.Folder.objects.create(title='beyond', parent=at_bound)
        cycle_a = self.Folder.objects.create(title='cycle-a')
        cycle_b = self.Folder.objects.create(title='cycle-b', parent=cycle_a)
        cycle_a.parent = cycle_b
        cycle_a.save(update_fields=['parent'])
        permission = _permission(self.Folder, 'change_folder')
        self.FolderGrant.objects.create(
            user=self.alice, approved_user=self.alice,
            folder=root, permission=permission,
        )
        self.FolderGrant.objects.create(
            user=self.bob, approved_user=self.alice,
            folder=root, permission=permission,
        )
        inactive = self.User.objects.create_user(
            'root-inactive-255', password='x', is_active=False,
        )
        self.FolderGrant.objects.create(
            user=inactive, approved_user=inactive,
            folder=root, permission=permission,
        )
        self.FolderPermit.objects.create(
            user=self.cara, folder=child, permission=permission,
        )
        self.FolderPermit.objects.create(
            user=self.outsider, folder=cycle_a, permission=permission,
        )
        candidates = self.User._default_manager.get_queryset()
        for folder in (root, child, at_bound, beyond, cycle_a, cycle_b):
            with self.subTest(folder=folder.title):
                with self.assertNumQueries(1):
                    found = _pks(folder.get_permitted_users(permission))
                expected = {
                    user.pk for user in candidates
                    if user.has_perm(permission.user_perm_str, folder)
                }
                self.assertEqual(found, expected)
        self.assertIn(
            self.alice.pk,
            _pks(at_bound.get_permitted_users(permission)),
        )
        self.assertNotIn(
            self.alice.pk,
            _pks(beyond.get_permitted_users(permission)),
        )
        self.assertNotIn(
            self.bob.pk,
            _pks(root.get_permitted_users(permission)),
        )
        self.assertNotIn(
            inactive.pk,
            _pks(root.get_permitted_users(permission)),
        )
        self.assertIn(
            self.cara.pk,
            _pks(at_bound.get_permitted_users(permission)),
        )
        self.assertIn(
            self.outsider.pk,
            _pks(cycle_b.get_permitted_users(permission)),
        )

    def test_uuid_content_primary_key_agrees(self):
        paper = self.UuidPaper.objects.create(title='uuid-paper')
        permission = _permission(self.UuidPaper, 'change_uuidpaper')
        code = '%s.%s' % (
            permission.content_type.app_label, permission.codename,
        )
        self.UuidGrant.objects.create(
            user=self.alice, paper=paper, permission=permission,
        )
        self.assertIsInstance(paper.pk, uuid.UUID)
        with self.assertNumQueries(1):
            found = _pks(paper.get_permitted_users(permission))
        expected = {
            user.pk for user in self.User._default_manager.get_queryset()
            if user.has_perm(code, paper)
        }
        self.assertEqual(found, expected)
        self.assertIn(self.alice.pk, found)
        self.assertEqual(
            _pks(paper.get_permitted_users(code)),
            found,
        )

    def test_uuid_user_manager_adapter_and_content_adapter_boundary(self):
        paper = self.UuidUserPaper.objects.create(title='uuid-user-paper')
        permission = _permission(self.UuidUserPaper, 'change_uuiduserpaper')
        code = '%s.%s' % (
            permission.content_type.app_label, permission.codename,
        )
        person = self.UuidUser.objects.create(
            username='uuid-person-255', is_active=True, is_superuser=False,
        )
        self.UuidGrantUser.objects.create(
            user=person, paper=paper, permission=permission,
        )
        class UuidManager(PermittedUsersManagerMixin, models.Manager):
            pass

        uuid_manager = UuidManager()
        uuid_manager.model = self.UuidUser
        uuid_manager.name = 'objects'
        with self.assertNumQueries(0):
            chosen = uuid_manager.permitted(paper, permission)
        self.assertIs(chosen.model, self.UuidUser)
        with self.assertNumQueries(1):
            found = _pks(chosen)
        self.assertIn(person.pk, found)
        self.assertIsInstance(person.pk, uuid.UUID)
        expected = {
            row.pk for row in self.UuidUser.objects.all()
            if row.has_perm(code, paper)
        }
        self.assertEqual(found, expected)
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                paper.get_permitted_users(permission)
        self.assertIn(self.UuidUser._meta.label, str(ctx.exception))
