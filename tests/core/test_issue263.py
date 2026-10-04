"""Terminal many-to-many ``permission=`` collections (issue #263).

``permission=`` stays one direct single-valued hop, or gains zero or
more forward single-valued hops and exactly one terminal forward
many-to-many to ``auth.Permission``. A reverse many-to-many, a
non-permission terminal, and a non-PK through target fail closed at
registration with zero SQL. An intermediate many-to-many also still
fails closed; that shape is deferred, not a permanent rejection. The
record shape is unchanged, ``via_group`` stays false, and the
collection does not contribute to ``get_group_permissions()``.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
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
    """Settings-listed probe. The test installs ``handle`` for one block."""

    handle = None

    def _own_handle(self):
        handle = type(self).handle
        if handle is None:
            raise TrustsConfigurationError('probe handle is unset')
        return handle


@contextmanager
def _listed(handle):
    _ListedBackend.handle = handle
    with override_settings(AUTHENTICATION_BACKENDS=(
        'tests.core.test_issue263._ListedBackend',
    )):
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


def _contribute_m2m(field, model):
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(model, field.remote_field)


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


def _handle(registry=None, path='tests.core.issue263'):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


def _collection_models():
    class Organization(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_organization'

    class Repository(PermittedUsersMixin, models.Model):
        organization = models.ForeignKey(
            Organization, related_name='repositories', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_repository'

    class TeamPermission(models.Model):
        team = models.ForeignKey('Team', on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        note = models.CharField(max_length=20, blank=True, default='')

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_team_permission'

    class Team(models.Model):
        organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
        name = models.CharField(max_length=40)
        members = models.ManyToManyField(
            get_user_model(), related_name='+', blank=True,
        )
        permissions = models.ManyToManyField(
            Permission, through=TeamPermission, related_name='+', blank=True,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_team'

    class TeamRepositoryAccess(models.Model):
        team = models.ForeignKey(Team, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_access'

    class DirectGrant(models.Model):
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_direct_grant'

    class GroupGrant(models.Model):
        group = models.ForeignKey(Group, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue263_group_grant'

    return {
        'Organization': Organization,
        'Repository': Repository,
        'TeamPermission': TeamPermission,
        'Team': Team,
        'TeamRepositoryAccess': TeamRepositoryAccess,
        'DirectGrant': DirectGrant,
        'GroupGrant': GroupGrant,
    }


def _pks(rows):
    return [row.pk for row in rows]


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionCollectionRegistrationTest(TestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue263', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue263', PAIR_KERNEL_SUITE)

    def test_direct_and_prefixed_collections_register_with_zero_sql(self):
        models_ = _collection_models()
        Team = models_['Team']
        Access = models_['TeamRepositoryAccess']
        Repository = models_['Repository']
        User = get_user_model()
        registry = TrustsRegistry()
        team = Ref(Team)
        access = Ref(Access)

        with self.assertNumQueries(0):
            direct = registry.register(
                content=team.organization.repositories,
                user=team.members,
                permission=team.permissions,
            )
            prefixed = registry.register(
                content=access.repository,
                user=access.team.members,
                permission=access.team.permissions,
            )
            strings = _handle().register(
                trust=Team,
                user='members',
                permission='permissions',
                content='organization__repositories',
            )
            calls = _handle(path='tests.core.issue263-call').register(
                trust=Access,
                user=lambda row: row.team.members,
                permission=lambda row: row.team.permissions,
                content=lambda row: row.repository,
            )

        self.assertFalse(direct.via_group)
        self.assertEqual(direct.group_path, ())
        self.assertIs(direct.permission_model, Permission)
        self.assertEqual(direct.permission_path, ('permissions',))
        self.assertEqual(direct.permission_field, 'permissions')
        self.assertEqual(direct.permission_target, Permission._meta.pk.attname)
        self.assertEqual(direct.user_path, ('members',))
        self.assertIs(direct.user_model, User)
        self.assertEqual(direct.content_path, ('organization', 'repositories'))
        self.assertIs(direct.content_model, Repository)
        self.assertEqual(strings, direct)

        self.assertFalse(prefixed.via_group)
        self.assertEqual(prefixed.permission_path, ('team', 'permissions'))
        self.assertEqual(prefixed.permission_field, 'team__permissions')
        self.assertEqual(
            prefixed.permission_target, Permission._meta.pk.attname,
        )
        self.assertEqual(prefixed.user_path, ('team', 'members'))
        self.assertEqual(prefixed.user_field, 'team__members')
        self.assertIs(prefixed.content_model, Repository)
        self.assertEqual(calls, prefixed)

        class Desk(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class DeskLink(models.Model):
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        link = Ref(DeskLink)
        with self.assertNumQueries(0):
            two_hops = TrustsRegistry().register(
                content=link.repository,
                user=link.desk.team.members,
                permission=link.desk.team.permissions,
            )
        self.assertEqual(
            two_hops.permission_path, ('desk', 'team', 'permissions'),
        )
        self.assertEqual(
            two_hops.permission_field, 'desk__team__permissions',
        )
        self.assertEqual(two_hops.user_path, ('desk', 'team', 'members'))
        self.assertFalse(two_hops.via_group)

    def test_direct_fk_and_group_records_stay_unchanged(self):
        models_ = _collection_models()
        DirectGrant = models_['DirectGrant']
        GroupGrant = models_['GroupGrant']
        direct_ref = Ref(DirectGrant)
        group_ref = Ref(GroupGrant)
        with self.assertNumQueries(0):
            direct = TrustsRegistry().register(
                content=direct_ref.repository,
                user=direct_ref.user,
                permission=direct_ref.permission,
            )
            grouped = TrustsRegistry().register(
                content=group_ref.repository,
                user=group_ref.group.user,
                group=group_ref.group,
            )
        self.assertFalse(direct.via_group)
        self.assertEqual(direct.permission_path, ('permission',))
        self.assertEqual(direct.permission_field, 'permission')
        self.assertIs(direct.permission_model, Permission)
        self.assertEqual(direct.permission_target, Permission._meta.pk.attname)
        self.assertEqual(direct.group_path, ())
        self.assertTrue(grouped.via_group)
        self.assertEqual(grouped.group_path, ('group',))
        self.assertIs(grouped.group_model, Group)
        self.assertEqual(grouped.permission_path, ('group', 'permissions'))
        self.assertEqual(grouped.permission_field, 'group__permissions')
        self.assertIs(grouped.permission_model, Permission)

    def test_wrong_terminal_and_intermediate_m2m_still_fail_closed(self):
        # Intermediate many-to-many stays fail-closed. Support for that
        # shape is deferred; this assertion is not a permanent limitation.
        models_ = _collection_models()
        Team = models_['Team']
        Access = models_['TeamRepositoryAccess']
        Repository = models_['Repository']
        kept = TrustsRegistry()
        team = Ref(Team)
        with self.assertNumQueries(0):
            existing = kept.register(
                content=team.organization.repositories,
                user=team.members,
                permission=team.permissions,
            )

        class Bundle(models.Model):
            permissions = models.ManyToManyField(
                Permission, related_name='+', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Holder(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE,
            )
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )
            bundles = models.ManyToManyField(
                Bundle, related_name='+', blank=True,
            )
            permissions = models.ManyToManyField(
                Permission, related_name='+', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Tag(models.Model):
            name = models.CharField(max_length=20, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class Tagged(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE,
            )
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField(Tag, related_name='+', blank=True)

            class Meta:
                app_label = 'trusts_tests'

        class Slip(models.Model):
            code = models.CharField(max_length=20, unique=True)

            class Meta:
                app_label = 'trusts_tests'

        class SlipLink(models.Model):
            crew = models.ForeignKey('Crew', on_delete=models.CASCADE)
            slip = models.ForeignKey(
                Slip, to_field='code', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Crew(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE,
            )
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )
            slips = models.ManyToManyField(
                Slip, through=SlipLink, related_name='+', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'

        holder = Ref(Holder)
        tagged = Ref(Tagged)
        crew = Ref(Crew)
        access = Ref(Access)
        grant = Ref(models_['GroupGrant'])
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'intermediate multi-valued',
            ):
                kept.register(
                    content=holder.repository,
                    user=holder.user,
                    permission=holder.bundles.permissions,
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'intermediate multi-valued',
            ):
                kept.register(
                    content=holder.repository,
                    user=holder.user,
                    permission=holder.permissions.content_type,
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'not auth\.Permission',
            ):
                kept.register(
                    content=tagged.repository,
                    user=tagged.user,
                    permission=tagged.tags,
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'reverse',
            ):
                kept.register(
                    content=grant.repository,
                    user=grant.group.user,
                    permission=grant.group.user,
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'resolved comparison field',
            ):
                kept.register(
                    content=crew.repository,
                    user=crew.user,
                    permission=crew.slips,
                )
            with self.assertRaisesRegex(
                TrustsConfigurationError, r'direct single-valued',
            ):
                kept.register(
                    content=access.repository,
                    user=access.team.members,
                    permission=access.team.organization,
                )
        self.assertEqual(kept.records, (existing,))

    def test_duplicate_collection_registration_does_not_mutate(self):
        Team = _collection_models()['Team']
        registry = TrustsRegistry()
        team = Ref(Team)
        with self.assertNumQueries(0):
            first = registry.register(
                content=team.organization.repositories,
                user=team.members,
                permission=team.permissions,
            )
            with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
                registry.register(
                    content=team.organization.repositories,
                    user=team.members,
                    permission=team.permissions,
                )
        self.assertEqual(registry.records, (first,))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionCollectionAuthorizationTest(TransactionTestCase):
    def setUp(self):
        self.models = _collection_models()
        self.Organization = self.models['Organization']
        self.Repository = self.models['Repository']
        self.TeamPermission = self.models['TeamPermission']
        self.Team = self.models['Team']
        self.Access = self.models['TeamRepositoryAccess']
        self.DirectGrant = self.models['DirectGrant']
        self.GroupGrant = self.models['GroupGrant']
        self._table_cm = _tables(
            self.Organization,
            self.Repository,
            self.Team,
            self.TeamPermission,
            self.Access,
            self.DirectGrant,
            self.GroupGrant,
        )
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        _contribute_m2m(self.Team._meta.get_field('members'), get_user_model())
        _contribute_m2m(self.Team._meta.get_field('permissions'), Permission)
        User = get_user_model()
        self.alice = User.objects.create_user('alice-263', password='x')
        self.bob = User.objects.create_user('bob-263', password='x')
        self.cara = User.objects.create_user('cara-263', password='x')
        self.inactive = User.objects.create_user('inactive-263', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.read = _perm(self.Repository, 'read_repository')
        self.change = _perm(self.Repository, 'change_repository')
        self.delete = _perm(self.Repository, 'delete_repository')
        self.add = _perm(self.Repository, 'add_repository')
        self.read_code = _code(self.read)
        self.change_code = _code(self.change)
        self.delete_code = _code(self.delete)
        self.add_code = _code(self.add)
        self.acme = self.Organization.objects.create(name='acme')
        self.other = self.Organization.objects.create(name='other')
        self.spec = self.Repository.objects.create(
            organization=self.acme, title='spec',
        )
        self.notes = self.Repository.objects.create(
            organization=self.acme, title='notes',
        )
        self.secret = self.Repository.objects.create(
            organization=self.other, title='secret',
        )
        self.writers = self.Team.objects.create(
            organization=self.acme, name='writers',
        )
        self.writers.members.add(self.alice, self.inactive)
        self._link(self.writers, self.read, 'a')
        self._link(self.writers, self.read, 'b')
        self._link(self.writers, self.change, 'once')
        self.limited = self.Team.objects.create(
            organization=self.acme, name='limited',
        )
        self.limited.members.add(self.cara)
        self._link(self.limited, self.read, 'cara')
        self.removers = self.Team.objects.create(
            organization=self.acme, name='removers',
        )
        self.removers.members.add(self.bob)
        self._link(self.removers, self.delete, 'bob')
        self.access_spec = self.Access.objects.create(
            team=self.writers, repository=self.spec,
        )
        self.Access.objects.create(team=self.writers, repository=self.spec)
        self.org_handle = _handle(
            TrustsRegistry(), path='tests.core.issue263-org',
        )
        self.org_handle.register(
            trust=self.Team,
            user='members',
            permission='permissions',
            content='organization__repositories',
        )
        self.access_handle = _handle(
            TrustsRegistry(), path='tests.core.issue263-access',
        )
        self.access_handle.register(
            trust=self.Access,
            user='team__members',
            permission='team__permissions',
            content='repository',
        )
        self.classic = _handle(
            TrustsRegistry(), path='tests.core.issue263-classic',
        )
        self.classic.register(
            trust=self.DirectGrant,
            user='user',
            permission='permission',
            content='repository',
        )
        self.classic.register(
            trust=self.GroupGrant,
            user='group__user',
            group='group',
            content='repository',
        )
        self.DirectGrant.objects.create(
            user=self.alice, repository=self.secret, permission=self.read,
        )
        self.editors = Group.objects.create(name='editors-263')
        self.editors.permissions.add(self.add)
        self.editors.user_set.add(self.alice)
        self.GroupGrant.objects.create(group=self.editors, repository=self.spec)
        self.permitted_manager = _PermittedUsers(User)

    def _link(self, team, permission, note):
        return self.TeamPermission.objects.create(
            team=team, permission=permission, note=note,
        )

    def _authorized(self, handle, user, permission):
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(handle,),
        ):
            return list(
                self.Repository.objects.authorized(user, permission).order_by('pk'),
            )

    def _assert_unique(self, rows, expected):
        pks = _pks(rows)
        self.assertEqual(pks, list(dict.fromkeys(pks)))
        self.assertEqual(pks, _pks(expected))

    def test_org_collection_agrees_across_permission_surfaces(self):
        handle = self.org_handle
        both = self.Repository.objects.filter(
            pk__in=[self.spec.pk, self.notes.pk],
        ).order_by('pk')
        mixed = self.Repository.objects.filter(
            pk__in=[self.spec.pk, self.secret.pk],
        )
        with _listed(handle):
            for user, codes, denied in (
                (self.alice, {self.read_code, self.change_code}, {self.delete_code}),
                (self.bob, {self.delete_code}, {self.read_code, self.change_code}),
                (self.cara, {self.read_code}, {self.change_code, self.delete_code}),
                (self.inactive, set(), {self.read_code, self.change_code}),
            ):
                for repo in (self.spec, self.notes):
                    self.assertEqual(
                        user.get_all_permissions(repo), codes, user.username,
                    )
                    self.assertEqual(
                        user.get_group_permissions(repo), set(), user.username,
                    )
                    for code in codes:
                        self.assertTrue(user.has_perm(code, repo))
                        self.assertTrue(
                            _ListedBackend().has_perm(user, code, repo),
                        )
                    for code in denied:
                        self.assertFalse(user.has_perm(code, repo))
                self.assertEqual(user.get_all_permissions(both), codes)
                self.assertEqual(user.get_all_permissions(mixed), set())
                self.assertIs(
                    user.has_perm(self.read_code, both),
                    self.read_code in codes,
                )
                self.assertFalse(user.has_perm(self.read_code, mixed))
                self.assertFalse(user.has_perm(self.read_code, self.secret))

            self.assertTrue(
                handle.registry.has_permission(self.alice, self.spec, self.read),
            )
            self.assertTrue(
                handle.registry.has_permission(
                    self.alice, self.notes, self.change,
                ),
            )
            self.assertFalse(
                handle.registry.has_permission(
                    self.alice, self.spec, self.delete,
                ),
            )
            self.assertFalse(
                handle.registry.has_permission(self.bob, self.spec, self.read),
            )

            read_users = self.spec.get_permitted_users(self.read)
            read_by_code = self.spec.get_permitted_users(self.read_code)
            self.assertIsNone(read_users._result_cache)
            self.assertIn('DISTINCT', str(read_users.query).upper())
            self.assertEqual(
                set(read_users.values_list('pk', flat=True)),
                set(read_by_code.values_list('pk', flat=True)),
            )
            self.assertEqual(
                set(read_users.values_list('pk', flat=True)),
                {self.alice.pk, self.cara.pk},
            )
            self.assertEqual(
                set(self.permitted_manager.permitted(
                    self.spec, self.read,
                ).values_list('pk', flat=True)),
                {self.alice.pk, self.cara.pk},
            )
            self.assertEqual(
                set(self.spec.get_permitted_users(self.delete).values_list(
                    'pk', flat=True,
                )),
                {self.bob.pk},
            )
            self.assertNotIn(
                self.inactive.pk,
                set(self.spec.get_permitted_users(self.read_code).values_list(
                    'pk', flat=True,
                )),
            )

        self._assert_unique(
            self._authorized(handle, self.alice, self.read),
            [self.spec, self.notes],
        )
        self._assert_unique(
            self._authorized(handle, self.alice, self.change),
            [self.spec, self.notes],
        )
        self._assert_unique(
            self._authorized(handle, self.alice, self.delete),
            [],
        )
        self._assert_unique(
            self._authorized(handle, self.bob, self.delete),
            [self.spec, self.notes],
        )
        self._assert_unique(
            self._authorized(handle, self.bob, self.read),
            [],
        )
        self._assert_unique(
            self._authorized(handle, self.inactive, self.read),
            [self.spec, self.notes],
        )
        granted_sql = str(
            self._authorized_qs(handle, self.alice, self.read).query,
        )
        self.assertIn('DISTINCT', granted_sql.upper())
        self.assertIn(self.TeamPermission._meta.db_table, granted_sql)
        self.assertIn(
            self.Team._meta.get_field('members').m2m_db_table(),
            granted_sql,
        )

    def _authorized_qs(self, handle, user, permission):
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(handle,),
        ):
            return self.Repository.objects.authorized(user, permission)

    def test_prefixed_access_does_not_cross_members_or_permissions(self):
        handle = self.access_handle
        with _listed(handle):
            self.assertEqual(
                self.alice.get_all_permissions(self.spec),
                {self.read_code, self.change_code},
            )
            self.assertEqual(self.alice.get_all_permissions(self.notes), set())
            self.assertEqual(self.bob.get_all_permissions(self.spec), set())
            self.assertEqual(self.cara.get_all_permissions(self.spec), set())
            self.assertEqual(
                self.alice.get_group_permissions(self.spec), set(),
            )
            self.assertTrue(self.alice.has_perm(self.read_code, self.spec))
            self.assertTrue(self.alice.has_perm(self.change_code, self.spec))
            self.assertFalse(self.alice.has_perm(self.delete_code, self.spec))
            self.assertFalse(self.alice.has_perm(self.read_code, self.notes))
            self.assertFalse(self.bob.has_perm(self.delete_code, self.spec))
            self.assertEqual(
                set(self.spec.get_permitted_users(self.read).values_list(
                    'pk', flat=True,
                )),
                {self.alice.pk},
            )
            self.assertEqual(
                set(self.notes.get_permitted_users(self.read_code).values_list(
                    'pk', flat=True,
                )),
                set(),
            )
        rows = self._authorized(handle, self.alice, self.read)
        self._assert_unique(rows, [self.spec])
        self._assert_unique(
            self._authorized(handle, self.alice, self.change),
            [self.spec],
        )
        self._assert_unique(
            self._authorized(handle, self.bob, self.delete),
            [],
        )
        enumerated = list(handle.registry.permissions_for(self.alice, self.spec))
        self.assertEqual(
            {_code(row) for row in enumerated},
            {self.read_code, self.change_code},
        )
        self.assertEqual(len(enumerated), 2)

    def test_removing_membership_revokes_only_that_user(self):
        handle = self.org_handle
        with _listed(handle):
            self.assertTrue(self.alice.has_perm(self.change_code, self.notes))
            self.writers.members.remove(self.alice)
            self.assertFalse(self.alice.has_perm(self.change_code, self.notes))
            self.assertFalse(self.alice.has_perm(self.read_code, self.spec))
            self.assertTrue(self.cara.has_perm(self.read_code, self.spec))
            self.assertNotIn(
                self.alice.pk,
                set(self.spec.get_permitted_users(self.read).values_list(
                    'pk', flat=True,
                )),
            )
        self._assert_unique(
            self._authorized(handle, self.alice, self.change),
            [],
        )

    def test_direct_fk_and_group_behavior_stay_unchanged(self):
        handle = self.classic
        with _listed(handle):
            self.assertTrue(self.alice.has_perm(self.read_code, self.secret))
            self.assertFalse(self.alice.has_perm(self.read_code, self.spec))
            self.assertEqual(
                self.alice.get_all_permissions(self.secret),
                {self.read_code},
            )
            self.assertEqual(
                self.alice.get_group_permissions(self.secret), set(),
            )
            self.assertEqual(
                self.alice.get_group_permissions(self.spec),
                {self.add_code},
            )
            self.assertEqual(
                self.alice.get_all_permissions(self.spec),
                {self.add_code},
            )
            self.assertTrue(self.alice.has_perm(self.add_code, self.spec))
            self.assertFalse(self.bob.has_perm(self.add_code, self.spec))
            self.assertTrue(
                handle.registry.has_permission(
                    self.alice, self.secret, self.read,
                ),
            )
            self.assertEqual(
                set(self.secret.get_permitted_users(self.read).values_list(
                    'pk', flat=True,
                )),
                {self.alice.pk},
            )
            self.assertEqual(
                set(self.spec.get_permitted_users(self.add).values_list(
                    'pk', flat=True,
                )),
                {self.alice.pk},
            )
        self._assert_unique(
            self._authorized(handle, self.alice, self.read),
            [self.secret],
        )
        self._assert_unique(
            self._authorized(handle, self.alice, self.add),
            [self.spec],
        )

    def test_policy_sql_describes_the_collection_without_a_group_leg(self):
        org = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.org_handle]),
        )
        access = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.access_handle]),
        )
        classic = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.classic]),
        )
        org_content = org['backends'][0]['contents'][0]
        access_content = access['backends'][0]['contents'][0]
        classic_content = classic['backends'][0]['contents'][0]
        org_trust = org_content['trusts'][0]
        access_trust = access_content['trusts'][0]
        self.assertEqual(org_trust['permission'], {
            'path': 'permissions',
            'model': 'auth.Permission',
            'target': Permission._meta.pk.attname,
        })
        self.assertEqual(org_trust['user']['path'], 'members')
        self.assertEqual(
            org_trust['content']['path'], 'organization__repositories',
        )
        self.assertNotIn('group', org_trust)
        self.assertNotIn('get_group_permissions', org_content)
        self.assertEqual(access_trust['permission'], {
            'path': 'team__permissions',
            'model': 'auth.Permission',
            'target': Permission._meta.pk.attname,
        })
        self.assertEqual(access_trust['user']['path'], 'team__members')
        self.assertNotIn('group', access_trust)
        self.assertNotIn('get_group_permissions', access_content)
        through = self.TeamPermission._meta.db_table
        for content in (org_content, access_content):
            for key in (
                'permitted', 'has_perm', 'get_all_permissions',
                'get_permitted_users',
            ):
                self.assertIn(through, content[key]['sql'])
            # Row-returning lookups collapse duplicate through rows.
            # has_perm is EXISTS … LIMIT 1, so a repeated membership
            # cannot yield a second result row.
            self.assertIn('EXISTS', content['has_perm']['sql'].upper())
            for key in (
                'permitted', 'get_all_permissions', 'get_permitted_users',
            ):
                self.assertIn('DISTINCT', content[key]['sql'].upper())
        self.assertIn('get_group_permissions', classic_content)
        by_path = {
            row['permission']['path']: row
            for row in classic_content['trusts']
        }
        self.assertEqual(by_path['permission']['permission']['path'], 'permission')
        self.assertNotIn('group', by_path['permission'])
        self.assertEqual(by_path['group__permissions']['group']['path'], 'group')
        self.assertIn(
            'auth_group_permissions',
            classic_content['get_group_permissions']['sql'],
        )
        self.assertNotIn(through, classic_content['get_group_permissions']['sql'])
        self.assertNotIn(through, classic_content['has_perm']['sql'])
        self.assertIn(
            'auth_group_permissions', classic_content['has_perm']['sql'],
        )


class _PermittedUsers(PermittedUsersManagerMixin):
    def __init__(self, model):
        self.model = model
        self.name = 'objects'

    def get_queryset(self):
        return self.model._default_manager.get_queryset()
