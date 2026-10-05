"""Content-type mismatch is a denial on every shared projection (#267).

A group that contains both an organization permission and a repository
permission must not grant the repository permission on the organization,
or the organization permission on the repository. The shared grant
compares ``Permission.content_type`` to the protected object's content
identity. It does not read the codename. A permission terminal with no
``content_type`` foreign key keeps primary-key identity.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import HttpRequest
from django.test import TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.decorators import (
    _declared_authorization_guards,
    authorization_required,
)
from trusts.policy_lock import (
    _load_policy_sql_document,
    render_policy_sql_bytes,
)
from trusts.query import (
    AuthorizedManager,
    PermittedUsersManagerMixin,
    PermittedUsersMixin,
)


class _ListedBackend(TrustModelBackendMixin, ModelBackend):
    handle = None

    def _own_handle(self):
        handle = type(self).handle
        if handle is None:
            raise TrustsConfigurationError('probe handle is unset')
        return handle


@contextmanager
def _installed(handle):
    _ListedBackend.handle = handle
    with override_settings(AUTHENTICATION_BACKENDS=(
        'tests.core.test_issue267._ListedBackend',
    )), patch(
        'trusts.apps._relationship_implementation_handles',
        return_value=(handle,),
    ):
        try:
            yield
        finally:
            _ListedBackend.handle = None


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


def _perm(model, codename, *, proxy=False):
    ct = ContentType.objects.get_for_model(model, for_concrete_model=not proxy)
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


def _handle(path):
    return BackendHandle(
        path=path,
        registry=TrustsRegistry(),
        compiler=PlanQueryCompiler(),
    )


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


class _PermittedUsers(PermittedUsersManagerMixin):
    def __init__(self, model):
        self.model = model
        self.name = 'objects'

    def get_queryset(self):
        return self.model._default_manager.get_queryset()


def _owner_models():
    class Organization(PermittedUsersMixin, models.Model):
        name = models.CharField(max_length=40)
        owner_group = models.ForeignKey(Group, on_delete=models.CASCADE)

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_organization'

    class OrganizationProxy(Organization):
        class Meta:
            proxy = True
            app_label = 'trusts_tests'

    class Repository(PermittedUsersMixin, models.Model):
        organization = models.ForeignKey(
            Organization, related_name='repositories', on_delete=models.CASCADE,
        )
        name = models.CharField(max_length=40)

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_repository'

    class Team(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_team'

    class Widget(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_widget'

    class OrganizationOwnership(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_ownership'

    return {
        'Organization': Organization,
        'OrganizationProxy': OrganizationProxy,
        'Repository': Repository,
        'Team': Team,
        'Widget': Widget,
        'OrganizationOwnership': OrganizationOwnership,
    }


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ContentTypeMismatchMatrixTest(TransactionTestCase):
    def setUp(self):
        models_ = _owner_models()
        self.Organization = models_['Organization']
        self.OrganizationProxy = models_['OrganizationProxy']
        self.Repository = models_['Repository']
        self.Team = models_['Team']
        self.Widget = models_['Widget']
        self.Ownership = models_['OrganizationOwnership']
        self._tables = _tables(
            self.Organization, self.Repository, self.Team, self.Widget,
            self.Ownership,
        )
        self._tables.__enter__()
        self.addCleanup(self._tables.__exit__, None, None, None)
        User = get_user_model()
        self.owner = User.objects.create_user('owner-267', password='x')
        self.other = User.objects.create_user('other-267', password='x')
        self.inactive = User.objects.create_user('idle-267', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.manage = _perm(self.Organization, 'manage_organization')
        self.read = _perm(self.Repository, 'read_repository')
        self.write = _perm(self.Repository, 'write_repository')
        self.admin = _perm(self.Repository, 'admin_repository')
        self.publish = _perm(self.Repository, 'can_publish')
        self.operate = _perm(
            self.OrganizationProxy, 'operate_organization', proxy=True,
        )
        self.manage_code = _code(self.manage)
        self.read_code = _code(self.read)
        self.publish_code = _code(self.publish)
        self.operate_code = _code(self.operate)
        self.repo_codes = {
            self.read_code,
            _code(self.write),
            _code(self.admin),
            self.publish_code,
        }
        self.group = Group.objects.create(name='owners-267')
        self.group.permissions.add(
            self.manage, self.read, self.write, self.admin,
            self.publish, self.operate,
        )
        self.acme = self.Organization.objects.create(
            name='acme', owner_group=self.group,
        )
        self.foreign = self.Organization.objects.create(
            name='foreign', owner_group=self.group,
        )
        self.specs = self.Repository.objects.create(
            organization=self.acme, name='specs',
        )
        self.foreign_repo = self.Repository.objects.create(
            organization=self.foreign, name='foreign-repo',
        )
        self.team = self.Team.objects.create(name='unrelated')
        self.widget = self.Widget.objects.create(name='unregistered')
        self.Ownership.objects.create(
            user=self.owner, organization=self.acme,
        )
        self.handle = _handle('tests.core.issue267-owner')
        with self.assertNumQueries(0):
            self.handle.register(
                trust=self.Ownership,
                user='user',
                permission='organization__owner_group__permissions',
                content='organization',
            )
            self.handle.register(
                trust=self.Ownership,
                user='user',
                permission='organization__owner_group__permissions',
                content='organization__repositories',
            )
        self.users = _PermittedUsers(User)

    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue267', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue267', PAIR_KERNEL_SUITE)

    def test_same_model_grants_and_crossed_pairs_deny(self):
        cases = (
            (self.manage_code, self.manage, self.acme, True),
            (self.read_code, self.read, self.specs, True),
            (self.read_code, self.read, self.acme, False),
            (self.manage_code, self.manage, self.specs, False),
            (self.manage_code, self.manage, self.team, False),
            (self.read_code, self.read, self.widget, False),
        )
        with _installed(self.handle):
            for code, permission, obj, expected in cases:
                with self.subTest(code=code, obj=obj._meta.model_name):
                    queries = 0 if obj in (self.team, self.widget) else 1
                    with self.assertNumQueries(queries):
                        self.assertIs(self.owner.has_perm(code, obj), expected)
                    with self.assertNumQueries(queries):
                        self.assertIs(
                            self.owner.has_perm(permission, obj), expected,
                        )
                    self.assertIs(
                        self.handle.registry.has_permission(
                            self.owner, obj, permission,
                        ),
                        expected,
                    )

    def test_enumeration_drops_the_other_models_codenames(self):
        with _installed(self.handle):
            self.assertEqual(
                self.owner.get_all_permissions(self.acme),
                {self.manage_code},
            )
            self.assertEqual(
                self.owner.get_all_permissions(self.specs),
                self.repo_codes,
            )
            self.assertEqual(self.owner.get_all_permissions(self.team), set())
            self.assertEqual(self.owner.get_all_permissions(self.widget), set())
            self.assertEqual(
                self.owner.get_group_permissions(self.acme), set(),
            )
            self.assertEqual(
                self.other.get_all_permissions(self.acme), set(),
            )
            self.assertEqual(
                self.inactive.get_all_permissions(self.acme), set(),
            )
            self.assertFalse(self.inactive.has_perm(self.manage_code, self.acme))

    def test_authorized_and_reverse_agree_with_has_perm(self):
        with _installed(self.handle):
            self.assertEqual(
                list(self.Organization.objects.authorized(
                    self.owner, self.manage,
                )),
                [self.acme],
            )
            self.assertEqual(
                list(self.Repository.objects.authorized(self.owner, self.read)),
                [self.specs],
            )
            self.assertEqual(
                list(self.Organization.objects.authorized(
                    self.owner, self.read,
                )),
                [],
            )
            self.assertEqual(
                list(self.Repository.objects.authorized(
                    self.owner, self.manage,
                )),
                [],
            )
            self.assertEqual(
                list(self.handle.registry.filter_authorized(
                    self.Team.objects.all(), self.owner, self.manage,
                )),
                [],
            )
            self.assertEqual(
                list(self.handle.registry.filter_authorized(
                    self.Widget.objects.all(), self.owner, self.read,
                )),
                [],
            )
            for obj, permission, expected in (
                (self.acme, self.manage, ['owner-267']),
                (self.specs, self.read, ['owner-267']),
                (self.acme, self.read, []),
                (self.specs, self.manage, []),
            ):
                with self.subTest(obj=obj.name, perm=permission.codename):
                    self.assertEqual(
                        list(obj.get_permitted_users(permission).values_list(
                            'username', flat=True,
                        )),
                        expected,
                    )
                    self.assertEqual(
                        list(obj.get_permitted_users(_code(permission)).values_list(
                            'username', flat=True,
                        )),
                        expected,
                    )
                    self.assertEqual(
                        list(self.users.permitted(obj, permission).values_list(
                            'username', flat=True,
                        )),
                        expected,
                    )
            for obj, permission in (
                (self.team, self.manage),
                (self.widget, self.read),
            ):
                with self.subTest(unregistered=obj.name):
                    self.assertEqual(
                        list(self.users.permitted(obj, permission).values_list(
                            'username', flat=True,
                        )),
                        [],
                    )

    def test_custom_codename_stays_a_same_model_instance_grant(self):
        with _installed(self.handle):
            self.assertTrue(
                self.owner.has_perm(self.publish, self.specs),
            )
            self.assertFalse(
                self.owner.has_perm(self.publish, self.acme),
            )
            self.assertIn(
                self.publish_code, self.owner.get_all_permissions(self.specs),
            )
            self.assertNotIn(
                self.publish_code, self.owner.get_all_permissions(self.acme),
            )
            self.assertEqual(
                list(self.Repository.objects.authorized(
                    self.owner, self.publish,
                )),
                [self.specs],
            )
            self.assertEqual(
                list(self.Organization.objects.authorized(
                    self.owner, self.publish,
                )),
                [],
            )
            self.assertEqual(
                list(self.specs.get_permitted_users(self.publish).values_list(
                    'username', flat=True,
                )),
                ['owner-267'],
            )
            self.assertEqual(
                list(self.acme.get_permitted_users(self.publish).values_list(
                    'username', flat=True,
                )),
                [],
            )

    def test_foreign_object_stays_denied(self):
        with _installed(self.handle):
            self.assertFalse(self.owner.has_perm(self.manage_code, self.foreign))
            self.assertFalse(
                self.owner.has_perm(self.read_code, self.foreign_repo),
            )
            self.assertEqual(
                list(self.Organization.objects.authorized(
                    self.other, self.manage,
                )),
                [],
            )

    def test_proxy_uses_its_own_content_type(self):
        proxy = self.OrganizationProxy.objects.get(pk=self.acme.pk)
        with _installed(self.handle):
            self.assertTrue(self.owner.has_perm(self.operate, proxy))
            self.assertFalse(self.owner.has_perm(self.manage, proxy))
            self.assertFalse(self.owner.has_perm(self.operate, self.acme))
            self.assertFalse(
                self.owner.has_perm(self.manage_code, proxy),
            )
            self.assertEqual(
                self.owner.get_all_permissions(proxy),
                {self.operate_code},
            )
            self.assertEqual(
                list(self.OrganizationProxy.objects.authorized(
                    self.owner, self.operate,
                )),
                [proxy],
            )
            self.assertEqual(
                list(self.Organization.objects.authorized(
                    self.owner, self.operate,
                )),
                [],
            )

    def test_authorization_required_denies_the_crossed_pair(self):
        allowed = authorization_required(
            self.Organization, self.manage_code,
        )(lambda request, pk: 'ok')
        denied = authorization_required(
            self.Organization, self.read_code,
        )(lambda request, pk: 'ok')
        repo_allowed = authorization_required(
            self.Repository, self.read_code,
        )(lambda request, pk: 'ok')
        repo_denied = authorization_required(
            self.Repository, self.manage_code,
        )(lambda request, pk: 'ok')
        publish_allowed = authorization_required(
            self.Repository, self.publish_code,
        )(lambda request, pk: 'ok')
        publish_denied = authorization_required(
            self.Organization, self.publish_code,
        )(lambda request, pk: 'ok')
        missing = authorization_required(
            self.Widget, 'trusts_tests.view_widget',
        )(lambda request, pk: 'ok')
        try:
            with _installed(self.handle):
                self.assertEqual(
                    allowed(_request(self.owner), pk=self.acme.pk), 'ok',
                )
                with self.assertRaises(PermissionDenied):
                    denied(_request(self.owner), pk=self.acme.pk)
                self.assertEqual(
                    repo_allowed(_request(self.owner), pk=self.specs.pk), 'ok',
                )
                with self.assertRaises(PermissionDenied):
                    repo_denied(_request(self.owner), pk=self.specs.pk)
                self.assertEqual(
                    publish_allowed(_request(self.owner), pk=self.specs.pk),
                    'ok',
                )
                with self.assertRaises(PermissionDenied):
                    publish_denied(_request(self.owner), pk=self.acme.pk)
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        missing(_request(self.owner), pk=self.widget.pk)
        finally:
            for model, permission in (
                (self.Organization, self.manage_code),
                (self.Organization, self.read_code),
                (self.Repository, self.read_code),
                (self.Repository, self.manage_code),
                (self.Repository, self.publish_code),
                (self.Organization, self.publish_code),
                (self.Widget, 'trusts_tests.view_widget'),
            ):
                try:
                    _declared_authorization_guards.remove((model, permission, ()))
                except ValueError:
                    pass

    def test_active_superuser_has_perm_stays_outside_the_predicate(self):
        User = get_user_model()
        root = User.objects.create_superuser(
            'root-267', password='x', email='root-267@example.com',
        )
        with _installed(self.handle):
            with self.assertNumQueries(0):
                self.assertTrue(root.has_perm(self.read_code, self.acme))
            self.assertNotIn(
                self.read_code, root.get_all_permissions(self.acme),
            )
            self.assertEqual(
                list(self.Organization.objects.authorized(root, self.read)),
                [],
            )

    def test_policy_sql_requires_the_protected_models_content_type(self):
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        by_model = {
            row['model']: row for row in document['backends'][0]['contents']
        }
        org = by_model['trusts_tests.Organization']
        repo = by_model['trusts_tests.Repository']
        for content, model_name in ((org, 'organization'), (repo, 'repository')):
            for key in (
                'permitted', 'has_perm', 'get_all_permissions',
                'get_permitted_users',
            ):
                sql = content[key]['sql']
                params = content[key]['params']
                with self.subTest(model=model_name, key=key):
                    self.assertIn('django_content_type', sql)
                    self.assertIn({'const': 'trusts_tests'}, params)
                    self.assertIn({'const': model_name}, params)
                    self.assertEqual(
                        sql.lower().count('join "auth_group_permissions"'),
                        1,
                        sql,
                    )


def _terminal_models():
    class Organization(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_plain_organization'

    class Repository(models.Model):
        organization = models.ForeignKey(
            Organization, related_name='repositories', on_delete=models.CASCADE,
        )
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_plain_repository'

    class Operation(models.Model):
        code = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_operation'

    class OperationGrant(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        operation = models.ForeignKey(Operation, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_operation_grant'

    class TypedPermit(models.Model):
        content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
        codename = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_typed_permit'

    class TypedGrant(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        permit = models.ForeignKey(TypedPermit, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_typed_grant'

    class DirectGrant(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue267_direct_grant'

    return {
        'Organization': Organization,
        'Repository': Repository,
        'Operation': Operation,
        'OperationGrant': OperationGrant,
        'TypedPermit': TypedPermit,
        'TypedGrant': TypedGrant,
        'DirectGrant': DirectGrant,
    }


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionTerminalIdentityTest(TransactionTestCase):
    def setUp(self):
        models_ = _terminal_models()
        self.Organization = models_['Organization']
        self.Repository = models_['Repository']
        self.Operation = models_['Operation']
        self.OperationGrant = models_['OperationGrant']
        self.TypedPermit = models_['TypedPermit']
        self.TypedGrant = models_['TypedGrant']
        self.DirectGrant = models_['DirectGrant']
        self._tables = _tables(
            self.Organization, self.Repository, self.Operation,
            self.OperationGrant, self.TypedPermit, self.TypedGrant,
            self.DirectGrant,
        )
        self._tables.__enter__()
        self.addCleanup(self._tables.__exit__, None, None, None)
        User = get_user_model()
        self.owner = User.objects.create_user('owner-267b', password='x')
        self.org = self.Organization.objects.create(name='acme')
        self.repo = self.Repository.objects.create(
            organization=self.org, name='specs',
        )

    def test_terminal_without_content_type_keeps_primary_key_identity(self):
        operation = self.Operation.objects.create(code='review')
        self.OperationGrant.objects.create(
            user=self.owner,
            organization=self.org,
            repository=self.repo,
            operation=operation,
        )
        registry = TrustsRegistry()
        with self.assertNumQueries(0):
            registry.register(
                content=self._ref(self.OperationGrant).organization,
                user=self._ref(self.OperationGrant).user,
                permission=self._ref(self.OperationGrant).operation,
            )
            registry.register(
                content=self._ref(self.OperationGrant).repository,
                user=self._ref(self.OperationGrant).user,
                permission=self._ref(self.OperationGrant).operation,
            )
        self.assertTrue(
            registry.has_permission(self.owner, self.org, operation),
        )
        self.assertTrue(
            registry.has_permission(self.owner, self.repo, operation),
        )
        handle = BackendHandle(
            path='tests.core.issue267-operation',
            registry=registry,
            compiler=PlanQueryCompiler(),
        )
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        for content in document['backends'][0]['contents']:
            self.assertNotIn('django_content_type', content['has_perm']['sql'])

    def test_terminal_with_content_type_denies_the_crossed_row(self):
        org_ct = ContentType.objects.get_for_model(self.Organization)
        repo_ct = ContentType.objects.get_for_model(self.Repository)
        org_permit = self.TypedPermit.objects.create(
            content_type=org_ct, codename='manage_organization',
        )
        repo_permit = self.TypedPermit.objects.create(
            content_type=repo_ct, codename='read_repository',
        )
        self.TypedGrant.objects.create(
            user=self.owner,
            organization=self.org,
            repository=self.repo,
            permit=repo_permit,
        )
        self.TypedGrant.objects.create(
            user=self.owner,
            organization=self.org,
            repository=self.repo,
            permit=org_permit,
        )
        registry = TrustsRegistry()
        grant = self._ref(self.TypedGrant)
        registry.register(
            content=grant.organization,
            user=grant.user,
            permission=grant.permit,
        )
        registry.register(
            content=grant.repository,
            user=grant.user,
            permission=grant.permit,
        )
        self.assertTrue(registry.has_permission(self.owner, self.org, org_permit))
        self.assertTrue(registry.has_permission(self.owner, self.repo, repo_permit))
        self.assertFalse(
            registry.has_permission(self.owner, self.org, repo_permit),
        )
        self.assertFalse(
            registry.has_permission(self.owner, self.repo, org_permit),
        )

    def test_direct_permission_fk_denies_a_different_content_type(self):
        manage = _perm(self.Organization, 'manage_organization')
        read = _perm(self.Repository, 'read_repository')
        self.DirectGrant.objects.create(
            user=self.owner, organization=self.org, permission=manage,
        )
        self.DirectGrant.objects.create(
            user=self.owner, organization=self.org, permission=read,
        )
        registry = TrustsRegistry()
        grant = self._ref(self.DirectGrant)
        registry.register(
            content=grant.organization,
            user=grant.user,
            permission=grant.permission,
        )
        self.assertTrue(registry.has_permission(self.owner, self.org, manage))
        self.assertFalse(registry.has_permission(self.owner, self.org, read))

    def _ref(self, model):
        from trusts.core import Ref
        return Ref(model)
