"""Reverse permission inquiry (#255).

One saved content object and one permission. The private compiler and
both public adapters return the same rows as ``user.has_perm`` for the
candidate user queryset. Construction is zero SQL. Evaluation is one
statement. Core does not add an ``is_active`` exclusion around a custom
reverse predicate. ``skip_is_active=True`` is passed only to the
Trusts-owned mixin method.
"""

import re
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
from tests.myapp.backends import DocumentBackend
from trusts.plan.users import lock_permitted_users_queryset
from tests.core.test_issue246 import _tables
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
from trusts.plan.handles import BackendHandle
from trusts.plan.relations import PlanQueryCompiler
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import TrustsRegistry
from trusts.inspect.snapshot import (
    _compile_queryset,
    _load_policy_sql_document,
    render_policy_sql_bytes,
)
from trusts.query import (
    PermittedManager,
    PermittedUsersManagerMixin,
    PermittedUsersMixin,
)


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

    calls = 0

    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        if obj is None or user_obj is None:
            return False
        return getattr(user_obj, 'username', None) == 'inactive-granted-255'

    def permitted_users_predicate(self, content, perm):
        type(self).calls += 1
        from django.db.models import Q
        return Q(username='inactive-granted-255')

    def singular_permission_accepted(self, perm):
        return isinstance(perm, Permission)


class StarInactiveGrantBackend(object):
    """``**kwargs`` is not an explicit audit parameter."""

    calls = 0

    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return False

    def permitted_users_predicate(self, content, perm, **kwargs):
        type(self).calls += 1
        from django.db.models import Q
        return Q(username='star-granted-255')

    def singular_permission_accepted(self, perm):
        return isinstance(perm, Permission)


class ModeAwareGrantBackend(object):
    """Names ``skip_is_active`` and records the value it receives."""

    received = 'unset'

    def authenticate(self, request, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return False

    def permitted_users_predicate(self, content, perm, *, skip_is_active=False):
        type(self).received = skip_is_active
        from django.db.models import Q
        return Q(username__startswith='mode-aware-')

    def singular_permission_accepted(self, perm):
        return isinstance(perm, Permission)


class ModeAwareQuerySet(models.QuerySet):
    marker = 'issue255-candidates'


class ModeAwareManager(PermittedUsersManagerMixin, models.Manager):
    def get_queryset(self):
        return ModeAwareQuerySet(self.model, using=self._db).filter(
            username__in=(
                'mode-aware-inactive',
                'mode-aware-active',
                'other-inactive',
            ),
        )


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


def _object_backend_allows(user, code, content):
    """Trusts and other backend contributions, not ``PermissionsMixin.has_perm``.

    An active superuser's native ``has_perm`` returns before any backend.
    Reverse membership follows the backends, including a registered
    override, and does not treat that early return as a grant.
    """
    from django.contrib.auth import get_backends

    return any(
        backend.has_perm(user, code, content)
        for backend in get_backends()
    )


def _assert_agrees(test, content, perm, candidates):
    found = _pks(content.get_permitted_users(perm))
    code = _normalized(perm)
    expected = {
        user.pk for user in candidates
        if _object_backend_allows(user, code, content)
    }
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
        self.assertIn('$content.id', row['params'])
        self.assertIn('$permission.id', row['params'])
        self.assertIn('EXISTS', row['sql'])
        self.assertIn('auth_user', row['sql'])
        where_at = row['sql'].upper().find('WHERE')
        self.assertGreaterEqual(where_at, 0)
        where = row['sql'][where_at:]
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
        for key in ('permitted', 'has_perm', 'get_all_permissions'):
            forward = content[key]
            self.assertIn('WITH RECURSIVE', forward['sql'])
            self.assertEqual(forward['sql'].count('WITH RECURSIVE'), 2)
            self.assertEqual(
                forward['sql'].count('%s'), len(forward['params']),
            )
        self.assertEqual(content['permitted']['params'], [
            '$user.id',
            '$permission.id',
            'user.is_active=True',
            '$along_bound=2',
            '$content.app_label="documents"',
            '$content.model="folder"',
            '$along_match=True',
            'skip_is_active=False',
        ])
        self.assertEqual(content['has_perm']['params'], [
            '$user.id',
            '$permission.id',
            '$content.id',
            'user.is_active=True',
            '$along_bound=2',
            '$content.app_label="documents"',
            '$content.model="folder"',
            '$along_match=True',
            'skip_is_active=False',
        ])
        self.assertEqual(content['get_all_permissions']['params'], [
            '$user.id',
            '$content.id',
            'user.is_active=True',
            '$along_bound=2',
            '$content.app_label="documents"',
            '$content.model="folder"',
            '$along_match=True',
            'skip_is_active=False',
        ])
        # One ordered list for the ORed reverse statement. Both walks
        # share one bind row. Permission and content come first, then
        # the depth ceiling and content type. ``is_active`` and
        # ``skip_is_active`` stay in that one statement.
        self.assertEqual(reverse['params'], [
            '$permission.id',
            '$content.id',
            'user.is_active=True',
            '$along_bound=2',
            '$content.app_label="documents"',
            '$content.model="folder"',
            '$along_match=True',
            'skip_is_active=False',
            '$along_match=True',
            '$along_match=True',
        ])
        self.assertEqual(
            [
                index for index, param in enumerate(reverse['params'])
                if param == '$along_bound=2'
            ],
            [3],
        )
        self.assertEqual(reverse['params'].count('user.is_active=True'), 1)
        self.assertEqual(reverse['sql'].count('%s'), len(reverse['params']))
        self.assertEqual(reverse['sql'].count('WITH RECURSIVE'), 2)
        for part in reverse['sql'].split('WITH RECURSIVE')[1:]:
            body = re.split(r'\)\s*SELECT DISTINCT', part, maxsplit=1)[0]
            self.assertNotIn('auth_user', body.lower())
            self.assertNotIn('json_', body.lower())
        self.assertIn('"user_id" = ("auth_user"."id")', reverse['sql'])
        self.assertEqual(document['schema_version'], 1)

    def test_two_self_fk_along_edges_keep_distinct_walks(self):
        class WalkNode(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            mentor = models.ForeignKey(
                'self', null=True, related_name='mentees',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'documents'

        class ParentGrant(models.Model):
            node = models.ForeignKey(WalkNode, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'documents'

        class MentorGrant(models.Model):
            node = models.ForeignKey(WalkNode, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'documents'

        handle = _export_handle('documents.backends.WalkNodeBackend')
        handle.register(
            trust=ParentGrant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 8),
        )
        handle.register(
            trust=MentorGrant,
            user='user',
            permission='permission',
            content='node',
            along=('node__mentor', 8),
        )
        content = _assert_along_lock(self, handle, (
            {'path': 'node__parent', 'shape': 'S', 'bound': 8},
            {'path': 'node__mentor', 'shape': 'S', 'bound': 8},
        ))
        permitted = content['permitted']['sql']
        self.assertIn('parent_id', permitted)
        self.assertIn('mentor_id', permitted)
        self.assertIn('documents_parentgrant', permitted)
        self.assertIn('documents_mentorgrant', permitted)
        self.assertEqual(content['permitted']['params'], [
            '$user.id',
            '$permission.id',
            'user.is_active=True',
            '$along_bound=8',
            '$content.app_label="documents"',
            '$content.model="walknode"',
            '$along_match=True',
            'skip_is_active=False',
        ])

    def test_along_reverse_uuid_to_field_binds_content_ident(self):
        class UuidNode(models.Model):
            ident = models.UUIDField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='ident', null=True,
                related_name='uuid_children', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'documents'

        class UuidNodeGrant(models.Model):
            node = models.ForeignKey(
                UuidNode, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'documents'

        handle = _export_handle('documents.backends.UuidNodeBackend')
        handle.register(
            trust=UuidNodeGrant,
            user='user',
            permission='permission',
            content='node',
            along=('node__parent', 2),
        )
        record = handle.build_registry().plan_for(UuidNode).records[0]
        self.assertEqual(record.content_target, 'ident')
        self.assertNotEqual(
            record.content_target, UuidNode._meta.pk.attname,
        )
        self.assertEqual(record.along.walk_ident, 'ident')
        self.assertEqual(record.along.ident_family, 'uuid')
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        self.assertEqual(document['schema_version'], 1)
        reverse = document['backends'][0]['contents'][0]['get_permitted_users']
        self.assertIn('WITH RECURSIVE', reverse['sql'])
        self.assertIn(
            '"ident" = ("trusts_bind"."content_ident")', reverse['sql'],
        )
        self.assertIn('"user_id" = ("auth_user"."id")', reverse['sql'])
        self.assertEqual(reverse['params'], [
            '$permission.id',
            '$content.ident',
            'user.is_active=True',
            '$along_bound=2',
            '$content.app_label="documents"',
            '$content.model="uuidnode"',
            '$along_match=True',
            'skip_is_active=False',
            '$along_match=True',
        ])
        self.assertNotIn('$content.id', reverse['params'])
        self.assertTrue(all(isinstance(param, str) for param in reverse['params']))
        self.assertEqual(
            [
                index for index, param in enumerate(reverse['params'])
                if param == '$along_bound=2'
            ],
            [3],
        )

    def test_content_pk_literal_stays_const_beside_an_along_reverse(self):
        handle = _export_handle('documents.backends.LiteralFolderBackend')
        handle.register(
            trust=FolderGrant,
            user='user',
            permission='permission',
            content='folder',
            along=('folder__parent', 2),
        )
        record = handle.build_registry().plan_for(Folder).records[0]
        _sql, params = _compile_queryset(
            FolderGrant.objects.filter(folder__pk=5),
            'default',
            record=record,
            expr=None,
            records=(record,),
            reverse_users=True,
        )
        self.assertEqual(params, [{'const': 5, 'hint': 'id'}])
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        reverse = document['backends'][0]['contents'][0]['get_permitted_users']
        self.assertIn('$content.id', reverse['params'])
        self.assertFalse(any(
            param.endswith('=5') for param in reverse['params']
        ))


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
        self.assertNotIn(self.superuser.pk, found)
        self.assertTrue(self.superuser.has_perm(PERM, self.document))
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

    def test_unrelated_permission_follows_backends_not_has_perm(self):
        found = _assert_agrees(
            self, self.document, self.other, self.candidates,
        )
        self.assertNotIn(self.superuser.pk, found)
        self.assertTrue(self.superuser.has_perm(self.other.user_perm_str, self.document))
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
        self.assertNotIn(self.superuser.pk, found)

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
        self.assertNotIn(self.superuser.pk, found)

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
        self.assertNotIn(self.superuser.pk, both_pks)
        self.assertIn(self.alice.pk, both_pks)
        self.assertNotIn(self.marked.pk, both_pks)
        self.assertIn(self.alice.pk, either_pks)
        self.assertNotIn(self.superuser.pk, either_pks)

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
        expected = {
            user.pk for user in manager.get_queryset()
            if _object_backend_allows(user, PERM, self.document)
        }
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
        """A custom predicate is not wrapped in ``is_active``.

        Trusts guarantees the ``is_active`` check only for its own grants.
        The inactive custom grant stays, in agreement with ``has_perm``.
        The inactive Trusts-owned grant is included only with
        ``skip_is_active=True``. The custom hook is not required to accept
        that keyword, and the call does not raise.
        """
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.InactiveGrantBackend',
        )
        granted = get_user_model().objects.create_user(
            'inactive-granted-255', password='x',
        )
        granted.is_active = False
        granted.save(update_fields=['is_active'])
        InactiveGrantBackend.calls = 0
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                chosen = self.document.get_permitted_users(self.change)
                widened = self.document.get_permitted_users(
                    self.change, skip_is_active=True,
                )
            with self.assertNumQueries(1):
                found = _pks(chosen)
            with self.assertNumQueries(1):
                widened_pks = _pks(widened)
            candidates = get_user_model()._default_manager.get_queryset()
            expected = {
                user.pk for user in candidates
                if _object_backend_allows(user, PERM, self.document)
            }
        self.assertEqual(found, expected)
        self.assertEqual(InactiveGrantBackend.calls, 2)
        self.assertIn(granted.pk, found)
        self.assertIn(self.alice.pk, found)
        self.assertNotIn(self.inactive.pk, found)
        self.assertIn(granted.pk, widened_pks)
        self.assertIn(self.alice.pk, widened_pks)
        self.assertIn(self.inactive.pk, widened_pks)

    def test_legacy_reverse_hook_is_called_without_skip_is_active(self):
        """A custom hook is called without ``skip_is_active``.

        ``skip_is_active=True`` does not raise and does not pass the
        keyword. The inactive user named by the predicate stays in the
        result.
        """
        InactiveGrantBackend.calls = 0
        StarInactiveGrantBackend.calls = 0
        star_user = get_user_model().objects.create_user(
            'star-granted-255', password='x',
        )
        star_user.is_active = False
        star_user.save(update_fields=['is_active'])
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.InactiveGrantBackend',
            'tests.core.test_issue255.StarInactiveGrantBackend',
        )
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                self.document.get_permitted_users(
                    self.change, skip_is_active=True,
                )
        self.assertEqual(InactiveGrantBackend.calls, 1)
        self.assertEqual(StarInactiveGrantBackend.calls, 1)
        star_only = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.StarInactiveGrantBackend',
        )
        with override_settings(AUTHENTICATION_BACKENDS=star_only):
            with self.assertNumQueries(0):
                widened = self.document.get_permitted_users(
                    self.change, skip_is_active=True,
                )
            with self.assertNumQueries(0):
                chosen = self.document.get_permitted_users(self.change)
        self.assertEqual(StarInactiveGrantBackend.calls, 3)
        found = _pks(chosen)
        widened_pks = _pks(widened)
        self.assertIn(star_user.pk, found)
        self.assertIn(star_user.pk, widened_pks)
        self.assertIn(self.alice.pk, found)

    def test_mode_aware_reverse_hook_is_called_without_skip_is_active(self):
        """A custom hook is called without ``skip_is_active``.

        Naming the parameter does not make Trusts pass it. The candidate
        queryset filter still applies. The Trusts-owned grant uses
        ``skip_is_active=True`` on its own branch.
        """
        User = get_user_model()
        inactive = User.objects.create_user('mode-aware-inactive', password='x')
        inactive.is_active = False
        inactive.save(update_fields=['is_active'])
        active = User.objects.create_user('mode-aware-active', password='x')
        outside = User.objects.create_user('mode-aware-outside', password='x')
        outside.is_active = False
        outside.save(update_fields=['is_active'])
        other = User.objects.create_user('other-inactive', password='x')
        other.is_active = False
        other.save(update_fields=['is_active'])
        ModeAwareGrantBackend.received = 'unset'
        backends = settings.AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue255.ModeAwareGrantBackend',
        )
        listing = ModeAwareManager()
        listing.model = User
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            with self.assertNumQueries(0):
                default_qs = listing.permitted(self.document, self.change)
            self.assertIs(ModeAwareGrantBackend.received, False)
            ModeAwareGrantBackend.received = 'unset'
            with self.assertNumQueries(0):
                audited_qs = listing.permitted(
                    self.document, self.change, skip_is_active=True,
                )
            self.assertIs(ModeAwareGrantBackend.received, False)
            unfiltered = self.document.get_permitted_users(
                self.change, skip_is_active=True,
            )
        self.assertIsInstance(default_qs, ModeAwareQuerySet)
        self.assertIsInstance(audited_qs, ModeAwareQuerySet)
        self.assertEqual(default_qs.marker, 'issue255-candidates')
        default_names = set(default_qs.values_list('username', flat=True))
        audited_names = set(audited_qs.values_list('username', flat=True))
        self.assertEqual(
            default_names, {'mode-aware-inactive', 'mode-aware-active'},
        )
        self.assertEqual(
            audited_names, {'mode-aware-inactive', 'mode-aware-active'},
        )
        self.assertIn(active.pk, _pks(audited_qs))
        self.assertNotIn(outside.pk, _pks(audited_qs))
        self.assertNotIn(other.pk, _pks(audited_qs))
        self.assertIn(outside.pk, _pks(unfiltered))
        self.assertIn(self.inactive.pk, _pks(unfiltered))

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
                if _object_backend_allows(user, self.code, self.paper)
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
                    if _object_backend_allows(
                        user, permission.user_perm_str, folder,
                    )
                }
                self.assertEqual(found, expected)
                locked = _pks(lock_permitted_users_queryset(
                    self.handle, folder, permission,
                ))
                self.assertEqual(locked, found)
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
        sql = str(at_bound.get_permitted_users(permission).query)
        self.assertIn('WITH RECURSIVE', sql.upper())
        self.assertIn('approved_user_id', sql)
        self.assertIn('parent_id', sql)

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
        self.assertEqual(found, {self.alice.pk})
        self.assertIn(self.alice.pk, found)
        self.assertEqual(
            _pks(paper.get_permitted_users(code)),
            found,
        )

    def test_uuid_user_manager_adapter_and_content_adapter_boundary(self):
        paper = self.UuidUserPaper.objects.create(title='uuid-user-paper')
        permission = _permission(self.UuidUserPaper, 'change_uuiduserpaper')
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
        self.assertEqual(found, {person.pk})
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                paper.get_permitted_users(permission)
        self.assertIn(self.UuidUser._meta.label, str(ctx.exception))


def _user_manager():
    manager = PlainUserManager()
    manager.model = get_user_model()
    manager.name = 'objects'
    return manager


def _reverse_agrees(test, handle, content, perm, candidates):
    code = perm.user_perm_str
    with test.assertNumQueries(1):
        found = _pks(content.get_permitted_users(perm))
    expected = {
        user.pk for user in candidates
        if _object_backend_allows(user, code, content)
    }
    test.assertEqual(found, expected)
    test.assertEqual(_pks(_user_manager().permitted(content, perm)), found)
    test.assertEqual(
        _pks(lock_permitted_users_queryset(handle, content, perm)),
        found,
    )
    return found


def _assert_along_lock(test, handle, specs, *, group=False):
    document = _load_policy_sql_document(
        render_policy_sql_bytes(handles=[handle]),
    )
    test.assertEqual(document['schema_version'], 1)
    content = document['backends'][0]['contents'][0]
    trusts = content['trusts']
    test.assertEqual(
        [row['along'] for row in trusts],
        [
            {'path': spec['path'], 'shape': spec['shape'], 'bound': spec['bound']}
            for spec in specs
        ],
    )
    for row, spec in zip(trusts, specs):
        test.assertIn(
            '__along_%s_%s_%s' % (spec['path'], spec['shape'], spec['bound']),
            row['id'],
        )
        if len(specs) > 1:
            test.assertIs(row['or_group'], True)
    keys = (
        'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
    )
    if group:
        keys = keys + ('get_group_permissions',)
    else:
        test.assertNotIn('get_group_permissions', content)
    for key in keys:
        block = content[key]
        test.assertEqual(
            block['sql'].upper().count('WITH RECURSIVE'), len(specs),
        )
        for spec in specs:
            test.assertIn(
                '$along_bound=%s' % spec['bound'], block['params'],
            )
    users = content['get_permitted_users']
    test.assertIn('$content.id', users['params'])
    test.assertIn('("auth_user"."id")', users['sql'])
    if len(specs) > 1:
        test.assertRegex(users['sql'], r'\bOR\b')
    return content


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongReverseSurfaceTest(KernelHostRequiredMixin, TransactionTestCase):
    """Reverse Along on a non-PK UUID target, on ``group=``, and on a terminal M2M."""

    def test_uuid_to_field_reverse_agrees_at_bound_and_one_past(self):
        User = get_user_model()

        class UuidNode(PermittedUsersMixin, models.Model):
            ident = models.UUIDField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='ident', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class UuidNodeGrant(models.Model):
            node = models.ForeignKey(
                UuidNode, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(UuidNode, UuidNodeGrant):
            with _document_registry() as registry:
                handle = _handle(registry)
                record = handle.register(
                    trust=UuidNodeGrant,
                    user='user',
                    permission='permission',
                    content='node',
                    along=('node__parent', 1),
                )
                self.assertEqual(record.content_target, 'ident')
                self.assertNotEqual(
                    record.content_target, UuidNode._meta.pk.attname,
                )
                alice = User.objects.create_user('uuid-along-alice', password='x')
                bob = User.objects.create_user('uuid-along-bob', password='x')
                inactive = User.objects.create_user(
                    'uuid-along-inactive', password='x',
                )
                inactive.is_active = False
                inactive.save(update_fields=['is_active'])
                permission = _permission(UuidNode, 'change_uuidnode')
                root = UuidNode.objects.create(ident=uuid.uuid4())
                child = UuidNode.objects.create(ident=uuid.uuid4(), parent=root)
                past = UuidNode.objects.create(ident=uuid.uuid4(), parent=child)
                UuidNodeGrant.objects.create(
                    user=alice, node=root, permission=permission,
                )
                UuidNodeGrant.objects.create(
                    user=inactive, node=root, permission=permission,
                )
                UuidNodeGrant.objects.create(
                    user=bob, node=past, permission=permission,
                )
                candidates = User._default_manager.get_queryset()
                root_users = _reverse_agrees(
                    self, handle, root, permission, candidates,
                )
                child_users = _reverse_agrees(
                    self, handle, child, permission, candidates,
                )
                past_users = _reverse_agrees(
                    self, handle, past, permission, candidates,
                )
                self.assertIn(alice.pk, root_users)
                self.assertIn(alice.pk, child_users)
                self.assertNotIn(alice.pk, past_users)
                self.assertNotIn(inactive.pk, root_users)
                self.assertIn(bob.pk, past_users)
                self.assertNotIn(bob.pk, child_users)

    def test_group_along_agrees_at_bound_and_one_past(self):
        User = get_user_model()

        class Desk(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )
            objects = PermittedManager()

            class Meta:
                app_label = 'trusts_tests'

        class DeskGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Desk, DeskGrant):
            with _document_registry() as registry:
                handle = _handle(registry)
                record = handle.register(
                    trust=DeskGrant,
                    user=lambda trust: trust.group.user,
                    group=lambda trust: trust.group,
                    content='desk',
                    along=('desk__parent', 1),
                )
                self.assertTrue(record.via_group)
                self.assertIsNotNone(record.along)
                locked = _assert_along_lock(self, handle, (
                    {'path': 'desk__parent', 'shape': 'S', 'bound': 1},
                ), group=True)
                self.assertEqual(locked['trusts'][0]['group']['path'], 'group')
                alice = User.objects.create_user('desk-alice', password='x')
                outsider = User.objects.create_user('desk-out', password='x')
                inactive = User.objects.create_user('desk-inactive', password='x')
                inactive.is_active = False
                inactive.save(update_fields=['is_active'])
                superuser = User.objects.create_superuser(
                    'desk-super', email='desk-super@example.com', password='x',
                )
                permission = _permission(Desk, 'change_desk')
                editors = Group.objects.create(name='desk-editors')
                editors.permissions.add(permission)
                editors.user_set.add(alice, inactive)
                root = Desk.objects.create(title='root')
                child = Desk.objects.create(title='child', parent=root)
                past = Desk.objects.create(title='past', parent=child)
                DeskGrant.objects.create(group=editors, desk=root)
                candidates = User._default_manager.get_queryset()
                root_users = _reverse_agrees(
                    self, handle, root, permission, candidates,
                )
                child_users = _reverse_agrees(
                    self, handle, child, permission, candidates,
                )
                past_users = _reverse_agrees(
                    self, handle, past, permission, candidates,
                )
                self.assertEqual(root_users, {alice.pk})
                self.assertEqual(child_users, {alice.pk})
                self.assertEqual(past_users, set())
                self.assertNotIn(superuser.pk, root_users)
                self.assertTrue(superuser.has_perm(permission.user_perm_str, past))
                self.assertNotIn(inactive.pk, root_users)
                self.assertNotIn(outsider.pk, root_users)
                code = permission.user_perm_str
                backend = DocumentBackend()
                self.assertEqual(
                    backend.get_group_permissions(alice, child), {code},
                )
                self.assertEqual(
                    backend.get_group_permissions(alice, past), set(),
                )
                self.assertEqual(
                    backend.get_group_permissions(outsider, child), set(),
                )
                self.assertEqual(
                    set(Desk.objects.permitted(code, alice)), {root, child},
                )

    def test_terminal_m2m_permission_along_agrees_at_bound_and_one_past(self):
        User = get_user_model()

        class Shelf(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )
            objects = PermittedManager()

            class Meta:
                app_label = 'trusts_tests'

        class ShelfStamp(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            shelf = models.ForeignKey(Shelf, on_delete=models.CASCADE)
            permissions = models.ManyToManyField(
                Permission, related_name='+', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Shelf, ShelfStamp):
            _contribute_m2m(
                ShelfStamp._meta.get_field('permissions'), Permission,
            )
            with _document_registry() as registry:
                handle = _handle(registry)
                record = handle.register(
                    trust=ShelfStamp,
                    user='user',
                    permission='permissions',
                    content='shelf',
                    along=('shelf__parent', 1),
                )
                self.assertFalse(record.via_group)
                self.assertEqual(record.permission_path, ('permissions',))
                self.assertIs(record.permission_model, Permission)
                self.assertIsNotNone(record.along)
                _assert_along_lock(self, handle, (
                    {'path': 'shelf__parent', 'shape': 'S', 'bound': 1},
                ))
                alice = User.objects.create_user('shelf-alice', password='x')
                bob = User.objects.create_user('shelf-bob', password='x')
                inactive = User.objects.create_user('shelf-inactive', password='x')
                inactive.is_active = False
                inactive.save(update_fields=['is_active'])
                superuser = User.objects.create_superuser(
                    'shelf-super', email='shelf-super@example.com', password='x',
                )
                permission = _permission(Shelf, 'change_shelf')
                other = _permission(Shelf, 'add_shelf')
                root = Shelf.objects.create(title='root')
                child = Shelf.objects.create(title='child', parent=root)
                past = Shelf.objects.create(title='past', parent=child)
                alice_stamp = ShelfStamp.objects.create(user=alice, shelf=root)
                alice_stamp.permissions.add(permission)
                bob_stamp = ShelfStamp.objects.create(user=bob, shelf=root)
                bob_stamp.permissions.add(other)
                inactive_stamp = ShelfStamp.objects.create(
                    user=inactive, shelf=root,
                )
                inactive_stamp.permissions.add(permission)
                candidates = User._default_manager.get_queryset()
                root_users = _reverse_agrees(
                    self, handle, root, permission, candidates,
                )
                child_users = _reverse_agrees(
                    self, handle, child, permission, candidates,
                )
                past_users = _reverse_agrees(
                    self, handle, past, permission, candidates,
                )
                self.assertEqual(root_users, {alice.pk})
                self.assertEqual(child_users, {alice.pk})
                self.assertEqual(past_users, set())
                self.assertNotIn(superuser.pk, past_users)
                self.assertNotIn(bob.pk, root_users)
                self.assertNotIn(inactive.pk, root_users)
                code = permission.user_perm_str
                backend = DocumentBackend()
                self.assertIn(code, backend.get_all_permissions(alice, child))
                self.assertNotIn(code, backend.get_all_permissions(alice, past))
                self.assertNotIn(code, backend.get_all_permissions(bob, child))
                self.assertEqual(
                    backend.get_group_permissions(alice, child), set(),
                )
                self.assertEqual(
                    set(Shelf.objects.permitted(code, alice)), {root, child},
                )

    def test_suffix_content_reverse_agrees_at_bound_and_one_past(self):
        User = get_user_model()

        class Cabinet(models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class SheetGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Cabinet, Sheet, SheetGrant):
            with _document_registry() as registry:
                handle = _handle(registry)
                record = handle.register(
                    trust=SheetGrant,
                    user='user',
                    permission='permission',
                    content='cabinet__sheets',
                    along=('cabinet__parent', 1),
                )
                self.assertTrue(record.along.suffix_path)
                self.assertIs(record.content_model, Sheet)
                self.assertIs(record.along.walk_model, Cabinet)
                alice = User.objects.create_user('sheet-alice', password='x')
                outsider = User.objects.create_user('sheet-out', password='x')
                permission = _permission(Sheet, 'change_sheet')
                root = Cabinet.objects.create(title='root')
                child = Cabinet.objects.create(title='child', parent=root)
                past = Cabinet.objects.create(title='past', parent=child)
                on_root = Sheet.objects.create(title='on-root', cabinet=root)
                on_child = Sheet.objects.create(title='on-child', cabinet=child)
                on_past = Sheet.objects.create(title='on-past', cabinet=past)
                SheetGrant.objects.create(
                    user=alice, cabinet=root, permission=permission,
                )
                candidates = User._default_manager.get_queryset()
                root_users = _reverse_agrees(
                    self, handle, on_root, permission, candidates,
                )
                child_users = _reverse_agrees(
                    self, handle, on_child, permission, candidates,
                )
                past_users = _reverse_agrees(
                    self, handle, on_past, permission, candidates,
                )
                self.assertEqual(root_users, {alice.pk})
                self.assertEqual(child_users, {alice.pk})
                self.assertEqual(past_users, set())
                self.assertNotIn(outsider.pk, root_users)

    def test_shape_c_reverse_agrees_at_bound_and_one_past(self):
        User = get_user_model()

        class Branch(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class BranchGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Branch, BranchGrant):
            with _document_registry() as registry:
                handle = _handle(registry)
                record = handle.register(
                    trust=BranchGrant,
                    user='user',
                    permission='permission',
                    content='branch',
                    along=('branch__children', 1),
                )
                self.assertEqual(record.along.shape, 'C')
                self.assertFalse(record.along.suffix_path)
                alice = User.objects.create_user('branch-alice', password='x')
                outsider = User.objects.create_user('branch-out', password='x')
                permission = _permission(Branch, 'change_branch')
                root = Branch.objects.create(title='root')
                mid = Branch.objects.create(title='mid', parent=root)
                leaf = Branch.objects.create(title='leaf', parent=mid)
                BranchGrant.objects.create(
                    user=alice, branch=leaf, permission=permission,
                )
                candidates = User._default_manager.get_queryset()
                leaf_users = _reverse_agrees(
                    self, handle, leaf, permission, candidates,
                )
                mid_users = _reverse_agrees(
                    self, handle, mid, permission, candidates,
                )
                root_users = _reverse_agrees(
                    self, handle, root, permission, candidates,
                )
                self.assertEqual(leaf_users, {alice.pk})
                self.assertEqual(mid_users, {alice.pk})
                self.assertEqual(root_users, set())
                self.assertNotIn(outsider.pk, leaf_users)

    def test_shape_s_or_shape_c_on_one_content_model(self):
        User = get_user_model()

        class Place(PermittedUsersMixin, models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            objects = PermittedManager()

            class Meta:
                app_label = 'trusts_tests'

        class North(models.Model):
            place = models.ForeignKey(Place, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class South(models.Model):
            place = models.ForeignKey(Place, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Place, North, South):
            with _document_registry() as registry:
                handle = _handle(registry)
                handle.register(
                    trust=North,
                    user='user',
                    permission='permission',
                    content='place',
                    along=('place__parent', 1),
                )
                handle.register(
                    trust=South,
                    user='user',
                    permission='permission',
                    content='place',
                    along=('place__children', 1),
                )
                _assert_along_lock(self, handle, (
                    {'path': 'place__parent', 'shape': 'S', 'bound': 1},
                    {'path': 'place__children', 'shape': 'C', 'bound': 1},
                ))
                alice = User.objects.create_user('place-alice', password='x')
                bob = User.objects.create_user('place-bob', password='x')
                inactive = User.objects.create_user(
                    'place-inactive', password='x',
                )
                inactive.is_active = False
                inactive.save(update_fields=['is_active'])
                superuser = User.objects.create_superuser(
                    'place-super', email='place-super@example.com', password='x',
                )
                permission = _permission(Place, 'change_place')
                code = permission.user_perm_str
                root = Place.objects.create()
                mid = Place.objects.create(parent=root)
                leaf = Place.objects.create(parent=mid)
                past = Place.objects.create(parent=leaf)
                North.objects.create(place=mid, user=alice, permission=permission)
                South.objects.create(place=mid, user=bob, permission=permission)
                North.objects.create(
                    place=mid, user=inactive, permission=permission,
                )
                candidates = User._default_manager.get_queryset()
                on_leaf = _reverse_agrees(
                    self, handle, leaf, permission, candidates,
                )
                on_root = _reverse_agrees(
                    self, handle, root, permission, candidates,
                )
                on_mid = _reverse_agrees(
                    self, handle, mid, permission, candidates,
                )
                on_past = _reverse_agrees(
                    self, handle, past, permission, candidates,
                )
                self.assertIn(alice.pk, on_leaf)
                self.assertNotIn(bob.pk, on_leaf)
                self.assertIn(bob.pk, on_root)
                self.assertNotIn(alice.pk, on_root)
                self.assertIn(alice.pk, on_mid)
                self.assertIn(bob.pk, on_mid)
                self.assertNotIn(alice.pk, on_past)
                self.assertNotIn(bob.pk, on_past)
                self.assertNotIn(inactive.pk, on_mid)
                self.assertNotIn(superuser.pk, on_past)
                self.assertTrue(superuser.has_perm(code, past))
                self.assertEqual(
                    set(Place.objects.permitted(code, alice)), {mid, leaf},
                )
                self.assertEqual(
                    set(Place.objects.permitted(code, bob)), {root, mid},
                )
