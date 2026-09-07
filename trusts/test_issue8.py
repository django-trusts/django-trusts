"""#8 recovery tests. Discovered by `python -m tests.runtests` (trusts app)."""

from django.contrib import admin
from django.contrib.auth.models import Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import TestCase

from tests.models import Category, TestGroupJunction
from trusts.models import Role, Trust, TrustUserPermission
from trusts.query import get_model_permission, user_can_manage_group
from trusts.tests import ContentModelMixin, reload_test_users


class PermittedQuerySetTest(ContentModelMixin, TestCase):
    def test_get_permission_uses_configured_model(self):
        permission = Category.objects.get_permission('read_category')
        expected = Permission.objects.get_by_natural_key(
            'read_category', Category._meta.app_label, Category._meta.model_name
        )
        self.assertEqual(permission.pk, expected.pk)
        self.assertEqual(
            get_model_permission(Category, 'trusts_tests.read_category:own').pk,
            expected.pk,
        )

    def test_grant_and_permitted_trustee(self):
        trust = Trust(settlor=self.user, title='owned', trust=Trust.objects.get_root())
        trust.save()
        allowed = self.create_content(trust)
        denied_trust = Trust(settlor=self.user1, title='other', trust=Trust.objects.get_root())
        denied_trust.save()
        denied = self.create_content(denied_trust)

        allowed.grant('read_category', self.user)
        reload_test_users(self)

        qs = Category.objects.permitted('read_category', self.user)
        self.assertTrue(qs.filter(pk=allowed.pk).exists())
        self.assertFalse(qs.filter(pk=denied.pk).exists())
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), allowed))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), denied))

    def test_permitted_includes_role_grants(self):
        call_command('update_roles_permissions')
        trust = Trust(settlor=self.user, title='role trust', trust=Trust.objects.get_root())
        trust.save()
        content = self.create_content(trust)
        self.group.user_set.add(self.user)
        trust.groups.add(self.group)
        Role.objects.get(name='public').groups.add(self.group)
        reload_test_users(self)

        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content))
        self.assertTrue(Category.objects.permitted('read_category', self.user).filter(pk=content.pk).exists())
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content))
        self.assertFalse(Category.objects.permitted('change_category', self.user).filter(pk=content.pk).exists())

    def test_permitted_inactive_matches_has_perm(self):
        trust = Trust(settlor=self.user, title='inactive', trust=Trust.objects.get_root())
        trust.save()
        content = self.create_content(trust)
        content.grant('read_category', self.user)
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)

        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), content))
        self.assertFalse(Category.objects.permitted('read_category', self.user).filter(pk=content.pk).exists())

    def test_permitted_filters_before_pagination(self):
        denied_trust = Trust(settlor=self.user1, title='first', trust=Trust.objects.get_root())
        denied_trust.save()
        denied = self.create_content(denied_trust)
        allowed_trust = Trust(settlor=self.user, title='second', trust=Trust.objects.get_root())
        allowed_trust.save()
        allowed = self.create_content(allowed_trust)
        allowed.grant('read_category', self.user)
        reload_test_users(self)

        first_unfiltered = list(Category.objects.order_by('pk')[:1])
        self.assertEqual(first_unfiltered[0].pk, denied.pk)
        page = list(Category.objects.permitted('read_category', self.user).order_by('pk')[:1])
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0].pk, allowed.pk)


class FilterByUserContentPermTest(ContentModelMixin, TestCase):
    def test_filter_by_user_content_perm_create_under_trust(self):
        granted = Trust(settlor=self.user, title='can add', trust=Trust.objects.get_root())
        granted.save()
        TrustUserPermission.objects.get_or_create(
            trust=granted, entity=self.user, permission=self.perm_add
        )
        settlor_only = Trust(settlor=self.user, title='settlor only', trust=Trust.objects.get_root())
        settlor_only.save()
        other = Trust(settlor=self.user1, title='other org', trust=Trust.objects.get_root())
        other.save()
        reload_test_users(self)

        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category'
        )
        pks = set(trusts.values_list('pk', flat=True))
        self.assertIn(granted.pk, pks)
        self.assertNotIn(settlor_only.pk, pks)
        self.assertNotIn(other.pk, pks)
        self.assertNotIn(Trust.objects.get_root().pk, pks)

    def test_filter_by_user_content_perm_inactive(self):
        granted = Trust(settlor=self.user, title='inactive add', trust=Trust.objects.get_root())
        granted.save()
        TrustUserPermission.objects.get_or_create(
            trust=granted, entity=self.user, permission=self.perm_add
        )
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)
        self.assertEqual(
            Trust.objects.filter_by_user_content_perm(self.user, Category, 'add_category').count(),
            0,
        )

    def test_filter_by_user_content_perm_exclude_root(self):
        root = Trust.objects.get_root()
        TrustUserPermission.objects.get_or_create(
            trust=root, entity=self.user, permission=self.perm_add
        )
        reload_test_users(self)
        excluded = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category', exclude_root=True
        )
        included = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'add_category', exclude_root=False
        )
        self.assertFalse(excluded.filter(pk=root.pk).exists())
        self.assertTrue(included.filter(pk=root.pk).exists())


class AutoModelAdminTest(TestCase):
    def test_opt_in_content_registered(self):
        self.assertIn(Category, admin.site._registry)

    def test_junction_without_flag_not_auto_registered(self):
        self.assertNotIn(TestGroupJunction, admin.site._registry)


class TeamViewAuthorizationTest(ContentModelMixin, TestCase):
    def setUp(self):
        super(TeamViewAuthorizationTest, self).setUp()
        self.team = Group.objects.create(name='Acme')
        self.other = Group.objects.create(name='Other')
        self.member = User.objects.create_user('member', 'm@example.com', 'pass')
        self.member.groups.add(self.team)
        self.outsider = User.objects.create_user('outsider', 'o@example.com', 'pass')
        self.trust = Trust(settlor=self.user, title='acme trust', trust=Trust.objects.get_root())
        self.trust.save()
        self.trust.groups.add(self.team)
        change = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission.objects.get_or_create(
            trust=self.trust, entity=self.user, permission=change
        )

    def test_newteam_creates_and_enrolls_creator(self):
        self.assertTrue(self.client.login(username=self.username, password=self.password))
        response = self.client.post('/teams/new/', {'name': 'Created Team'})
        team = Group.objects.get(name='Created Team')
        self.assertEqual(response.status_code, 302)
        self.assertIn(team, self.user.groups.all())
        self.assertFalse(user_can_manage_group(self.user, team))

    def test_non_member_cannot_view(self):
        self.assertTrue(self.client.login(username='outsider', password='pass'))
        response = self.client.get('/teams/%s/' % self.team.pk)
        self.assertEqual(response.status_code, 403)

    def test_member_can_view_but_cannot_add(self):
        recruit = User.objects.create_user('recruit', 'r@example.com', 'pass')
        self.assertTrue(self.client.login(username='member', password='pass'))
        response = self.client.get('/teams/%s/' % self.team.pk)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Members')
        self.assertNotContains(response, 'Add member')
        posted = self.client.post('/teams/%s/' % self.team.pk, {'user': recruit.pk})
        self.assertEqual(posted.status_code, 403)
        self.assertFalse(recruit.groups.filter(pk=self.team.pk).exists())

    def test_trustee_change_can_add_member(self):
        recruit = User.objects.create_user('hire', 'h@example.com', 'pass')
        self.user.groups.add(self.team)
        self.assertTrue(self.client.login(username=self.username, password=self.password))
        response = self.client.get('/teams/%s/' % self.team.pk)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Add member')
        posted = self.client.post('/teams/%s/' % self.team.pk, {'user': recruit.pk})
        self.assertEqual(posted.status_code, 302)
        self.assertTrue(recruit.groups.filter(pk=self.team.pk).exists())

    def test_post_does_not_mutate_unauthorized_group(self):
        recruit = User.objects.create_user('nope', 'n@example.com', 'pass')
        self.assertTrue(self.client.login(username=self.username, password=self.password))
        posted = self.client.post('/teams/%s/' % self.other.pk, {'user': recruit.pk})
        self.assertEqual(posted.status_code, 403)
        self.assertFalse(recruit.groups.filter(pk=self.other.pk).exists())

    def test_shared_group_does_not_write_group_permissions(self):
        other_trust = Trust(settlor=self.user1, title='shared group other', trust=Trust.objects.get_root())
        other_trust.save()
        other_trust.groups.add(self.team)
        before = list(self.team.permissions.values_list('pk', flat=True))
        self.user.groups.add(self.team)
        self.assertTrue(self.client.login(username=self.username, password=self.password))
        recruit = User.objects.create_user('keep', 'k@example.com', 'pass')
        self.client.post('/teams/%s/' % self.team.pk, {'user': recruit.pk})
        self.team.refresh_from_db()
        self.assertEqual(before, list(self.team.permissions.values_list('pk', flat=True)))
        content_a = self.create_content(self.trust)
        content_b = self.create_content(other_trust)
        content_a.grant('read_category', self.user)
        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content_a))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), content_b))
