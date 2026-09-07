"""Recovery tests for issue #8: list APIs, authorization, auto_modeladmin.

Does not close #8. Covers the core milestone: APIs, auth holes, cross-trust
group scope, inactive principals, and opt-in admin registration.
"""

from django.contrib import admin
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import Client, TestCase

from trusts.admin import register_auto_modeladmins
from trusts.authorization import (
    AuthorizationDenied,
    add_group_member,
    associate_group_with_trust,
    can_administer_content,
    can_manage_group_membership,
    create_team,
    disassociate_group_from_trust,
    grant_trustee,
    refuse_group_permission_write,
    revoke_trustee,
)
from trusts.models import (
    Content,
    PermissionConditionNotQueryable,
    Role,
    Trust,
    TrustUserPermission,
)
from trusts.tests import (
    ContentModelMixin,
    create_test_users,
    get_or_create_root_user,
    reload_test_users,
)
from tests.models import AutoAdminCategory, AutoAdminJunction, Category, ManualAdminCategory


class Issue8FixtureMixin(ContentModelMixin):
    def setUp(self):
        super(Issue8FixtureMixin, self).setUp()
        self.org = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Org A')
        self.org.save()
        self.org_b = Trust(settlor=self.user1, trust=Trust.objects.get_root(), title='Org B')
        self.org_b.save()
        self.content = self.create_content(self.org)
        self.content_b = self.create_content(self.org_b)


class PermittedQuerySetTest(Issue8FixtureMixin, TestCase):
    def _direct_pks(self, perm, user):
        return set(
            obj.pk for obj in Category.objects.all()
            if user.has_perm(self.get_perm_code(perm), obj)
        )

    def _assert_list_direct_parity(self, perm, user):
        qs = Category.objects.permitted(perm.codename, user)
        self.assertEqual(set(qs.values_list('pk', flat=True)), self._direct_pks(perm, user))
        sql = str(qs.query)
        self.assertTrue(
            'JOIN' in sql.upper() or 'EXISTS' in sql.upper() or 'trusts_trustuserpermission' in sql,
            'permitted() must filter in SQL, not in Python. SQL was: %s' % sql,
        )
        # Pagination wraps the filtered QuerySet.
        self.assertEqual(list(qs[:50]), list(qs))

    def test_trustee_list_direct_parity_and_sql(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_read
        ).save()
        reload_test_users(self)
        self._assert_list_direct_parity(self.perm_read, self.user)
        self.assertIn(self.content.pk, Category.objects.permitted('read', self.user).values_list('pk', flat=True))
        self.assertNotIn(self.content_b.pk, Category.objects.permitted('read', self.user).values_list('pk', flat=True))

    def test_group_permissions_path(self):
        self.perm_read.group_set.add(self.group)
        self.user.groups.add(self.group)
        self.org.groups.add(self.group)
        reload_test_users(self)
        self._assert_list_direct_parity(self.perm_read, self.user)

    def test_role_derived_grants_included(self):
        call_command('update_roles_permissions')
        self.group.user_set.add(self.user)
        self.org.groups.add(self.group)
        Role.objects.get(name='public').groups.add(self.group)
        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content))
        qs = Category.objects.permitted('read_category', self.user)
        self.assertIn(self.content.pk, qs.values_list('pk', flat=True))
        self._assert_list_direct_parity(self.perm_read, self.user)

    def test_inactive_principal_empty(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_read
        ).save()
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)
        self.assertFalse(Category.objects.permitted('read', self.user).exists())
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), self.content))

    def test_get_permission_uses_configured_model(self):
        from django.contrib.auth.models import Permission as AuthPermission
        from trusts import get_permission_model

        self.assertIs(get_permission_model(), AuthPermission)
        perm = Category.objects.get_permission('read')
        self.assertEqual(perm.codename, 'read_category')
        self.assertEqual(Category.objects.get_permission('read_category').pk, perm.pk)
        self.assertEqual(
            Category.objects.get_permission('trusts_tests.read_category').pk, perm.pk
        )

    def test_grant_and_revoke(self):
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content))
        self.content.grant('change', self.user)
        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_change), self.content))
        self.content.revoke('change', self.user)
        reload_test_users(self)
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content))

    def test_conditioned_perm_fails_closed(self):
        """A :condition must not silently return every unconditioned grant.

        Reproduces the #20 review: register an always-false condition,
        grant the underlying read, then compare has_perm vs permitted.
        """
        Content.register_permission_condition(
            Category, 'never', lambda user, perm, obj: False
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_read
        ).save()
        reload_test_users(self)
        unconditioned = self.get_perm_code(self.perm_read)
        conditioned = '%s:never' % unconditioned
        self.assertTrue(self.user.has_perm(unconditioned, self.content))
        self.assertFalse(self.user.has_perm(conditioned, self.content))
        with self.assertRaises(PermissionConditionNotQueryable):
            Category.objects.permitted(conditioned, self.user)
        with self.assertRaises(PermissionConditionNotQueryable):
            Category.objects.permitted('read_category:own', self.user)
        # Unconditioned path still lists the granted row only.
        self.assertEqual(
            set(Category.objects.permitted(unconditioned, self.user).values_list('pk', flat=True)),
            {self.content.pk},
        )


class FilterByUserContentPermTest(Issue8FixtureMixin, TestCase):
    def test_filter_by_user_perm_name_still_discovered(self):
        # The historical PR renamed this test and dropped discovery. Master
        # kept the original name; this asserts it is still a real test.
        from trusts.tests import TrustTest
        self.assertTrue(callable(TrustTest.test_filter_by_user_perm))

    def test_create_under_trust_requires_named_grant(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_add
        ).save()
        reload_test_users(self)
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category', exclude_root=True
        )
        pks = set(trusts.values_list('pk', flat=True))
        self.assertIn(self.org.pk, pks)
        self.assertNotIn(self.org_b.pk, pks)
        self.assertNotIn(Trust.objects.get_root().pk, pks)

    def test_settlor_shortcut_is_not_a_grant(self):
        # user is settlor of org but has no add grant.
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add', exclude_root=True
        )
        self.assertNotIn(self.org.pk, trusts.values_list('pk', flat=True))

    def test_does_not_query_parent_trust_relations(self):
        # Grant add on the parent (root) must not list the child org.
        root = Trust.objects.get_root()
        TrustUserPermission(
            trust=root, entity=self.user, permission=self.perm_add
        ).save()
        reload_test_users(self)
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category', exclude_root=False
        )
        self.assertIn(root.pk, trusts.values_list('pk', flat=True))
        self.assertNotIn(self.org.pk, trusts.values_list('pk', flat=True))

    def test_inactive_user_empty(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_add
        ).save()
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)
        self.assertFalse(
            Trust.objects.filter_by_user_content_perm(
                self.user, Category, 'add'
            ).exists()
        )

    def test_role_path_included(self):
        call_command('update_roles_permissions')
        admin_role = Role.objects.get(name='admin')
        self.group.user_set.add(self.user)
        self.org.groups.add(self.group)
        admin_role.groups.add(self.group)
        reload_test_users(self)
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category'
        )
        self.assertIn(self.org.pk, trusts.values_list('pk', flat=True))

    def test_conditioned_perm_fails_closed(self):
        Content.register_permission_condition(
            Category, 'never', lambda user, perm, obj: False
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_add
        ).save()
        reload_test_users(self)
        unconditioned = self.get_perm_code(self.perm_add)
        conditioned = '%s:never' % unconditioned
        with self.assertRaises(PermissionConditionNotQueryable):
            Trust.objects.filter_by_user_content_perm(
                self.user, Category, conditioned
            )
        with self.assertRaises(PermissionConditionNotQueryable):
            Trust.objects.filter_by_user_content_perm(
                self.user, Category, 'add_category:own'
            )
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, unconditioned, exclude_root=True
        )
        self.assertEqual(set(trusts.values_list('pk', flat=True)), {self.org.pk})


class AuthorizationTest(Issue8FixtureMixin, TestCase):
    def test_reader_cannot_grant_or_mutate(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_read
        ).save()
        reload_test_users(self)
        self.assertFalse(can_administer_content(self.user, self.content))
        before = TrustUserPermission.objects.filter(trust=self.org).count()
        with self.assertRaises(AuthorizationDenied):
            grant_trustee(self.user, self.content, self.user1, 'change')
        with self.assertRaises(AuthorizationDenied):
            revoke_trustee(self.user, self.content, self.user, 'read')
        with self.assertRaises(AuthorizationDenied):
            associate_group_with_trust(self.user, self.content, self.group)
        self.assertEqual(TrustUserPermission.objects.filter(trust=self.org).count(), before)
        self.assertFalse(self.org.groups.filter(pk=self.group.pk).exists())

    def test_change_can_grant_and_revoke(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)
        grant_trustee(self.user, self.content, self.user1, 'read')
        self.assertTrue(
            TrustUserPermission.objects.filter(
                trust=self.org, entity=self.user1, permission=self.perm_read
            ).exists()
        )
        revoke_trustee(self.user, self.content, self.user1, 'read')
        self.assertFalse(
            TrustUserPermission.objects.filter(
                trust=self.org, entity=self.user1, permission=self.perm_read
            ).exists()
        )

    def test_membership_alone_cannot_add_team_members(self):
        self.org.groups.add(self.group)
        self.user.groups.add(self.group)
        reload_test_users(self)
        self.assertFalse(can_manage_group_membership(self.user, self.group))
        with self.assertRaises(AuthorizationDenied):
            add_group_member(self.user, self.group, self.user1)
        self.assertFalse(self.group.user_set.filter(pk=self.user1.pk).exists())

    def test_unknown_entity_id_does_not_mutate(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)
        before = TrustUserPermission.objects.filter(trust=self.org).count()
        with self.assertRaises(AuthorizationDenied):
            grant_trustee(self.user, self.content, 99999, 'read')
        with self.assertRaises(AuthorizationDenied):
            associate_group_with_trust(self.user, self.content, 99999)
        self.assertEqual(TrustUserPermission.objects.filter(trust=self.org).count(), before)
        self.assertEqual(self.org.groups.count(), 0)

    def test_revoke_foreign_trustee_id_is_out_of_scope(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        other_tup = TrustUserPermission(
            trust=self.org_b, entity=self.user1, permission=self.perm_read
        )
        other_tup.save()
        reload_test_users(self)
        with self.assertRaises(AuthorizationDenied):
            revoke_trustee(self.user, self.content, self.user1, 'read')
        self.assertTrue(
            TrustUserPermission.objects.filter(pk=other_tup.pk).exists()
        )

    def test_shared_group_permissions_are_not_project_local(self):
        """Two trusts share a group. Group.permissions must not be written.

        Associating the group with org A (or granting a trustee on A) must
        not change has_perm on org B. Writing Group.permissions would leak.
        """
        shared = Group.objects.create(name='shared-writers')
        self.org.groups.add(shared)
        self.org_b.groups.add(shared)
        shared.user_set.add(self.user1)

        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)

        associate_group_with_trust(self.user, self.content, shared)
        self.assertFalse(self.user1.has_perm(self.get_perm_code(self.perm_change), self.content))
        self.assertFalse(self.user1.has_perm(self.get_perm_code(self.perm_change), self.content_b))

        with self.assertRaises(AuthorizationDenied):
            refuse_group_permission_write()

        # Demonstrate the leak that the old UI would have caused:
        shared.permissions.add(self.perm_change)
        reload_test_users(self)
        self.assertTrue(self.user1.has_perm(self.get_perm_code(self.perm_change), self.content))
        self.assertTrue(self.user1.has_perm(self.get_perm_code(self.perm_change), self.content_b))

    def test_shared_group_membership_requires_admin_on_every_trust(self):
        shared = Group.objects.create(name='shared-members')
        self.org.groups.add(shared)
        self.org_b.groups.add(shared)
        change_trust = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=change_trust
        ).save()
        reload_test_users(self)
        self.assertFalse(can_manage_group_membership(self.user, shared))
        with self.assertRaises(AuthorizationDenied):
            add_group_member(self.user, shared, self.user1)
        self.assertFalse(shared.user_set.filter(pk=self.user1.pk).exists())

        TrustUserPermission(
            trust=self.org_b, entity=self.user, permission=change_trust
        ).save()
        reload_test_users(self)
        add_group_member(self.user, shared, self.user1)
        self.assertTrue(shared.user_set.filter(pk=self.user1.pk).exists())

    def test_create_team_requires_trust_admin(self):
        with self.assertRaises(AuthorizationDenied):
            create_team(self.user, self.org, 'No Admin Team')
        self.assertFalse(Group.objects.filter(name='No Admin Team').exists())

        change_trust = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=change_trust
        ).save()
        reload_test_users(self)
        group = create_team(self.user, self.org, 'Admin Team')
        self.assertTrue(self.org.groups.filter(pk=group.pk).exists())
        self.assertTrue(group.user_set.filter(pk=self.user.pk).exists())

    def test_disassociate_rejects_group_not_on_trust(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        other = Group.objects.create(name='other-team')
        self.org_b.groups.add(other)
        reload_test_users(self)
        with self.assertRaises(AuthorizationDenied):
            disassociate_group_from_trust(self.user, self.content, other)
        self.assertTrue(self.org_b.groups.filter(pk=other.pk).exists())


class TeamViewAuthorizationTest(Issue8FixtureMixin, TestCase):
    def setUp(self):
        super(TeamViewAuthorizationTest, self).setUp()
        self.client = Client()
        self.client.force_login(self.user)
        self.group = Group.objects.create(name='View Team')
        self.org.groups.add(self.group)
        self.user.groups.add(self.group)

    def test_member_get_and_post_denied(self):
        url = '/teams/%s/' % self.group.pk
        self.assertEqual(self.client.get(url).status_code, 403)
        r = self.client.post(url, {'user': self.user1.pk})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(self.group.user_set.filter(pk=self.user1.pk).exists())

    def test_admin_can_add_member(self):
        change_trust = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=change_trust
        ).save()
        reload_test_users(self)
        self.client.force_login(self.user)
        url = '/teams/%s/' % self.group.pk
        self.assertEqual(self.client.get(url).status_code, 200)
        r = self.client.post(url, {'user': self.user1.pk})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(self.group.user_set.filter(pk=self.user1.pk).exists())

    def test_post_unknown_user_does_not_mutate(self):
        change_trust = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=change_trust
        ).save()
        reload_test_users(self)
        self.client.force_login(self.user)
        members_before = set(self.group.user_set.values_list('pk', flat=True))
        r = self.client.post('/teams/%s/' % self.group.pk, {'user': 99999})
        self.assertNotEqual(r.status_code, 302)
        self.assertEqual(
            set(self.group.user_set.values_list('pk', flat=True)), members_before
        )


class AutoModelAdminTest(TestCase):
    def test_opt_in_content_and_junction_registered(self):
        register_auto_modeladmins(admin.site)
        self.assertTrue(admin.site.is_registered(AutoAdminCategory))
        self.assertTrue(admin.site.is_registered(AutoAdminJunction))
        self.assertFalse(admin.site.is_registered(ManualAdminCategory))
        self.assertFalse(admin.site.is_registered(Category))
        # Core models remain explicitly registered, not via the flag.
        self.assertTrue(admin.site.is_registered(Trust))
