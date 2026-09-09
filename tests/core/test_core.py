import unittest

from unittest.mock import Mock

from django.db import IntegrityError
from django.db.models import F
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, TransactionTestCase
from django.http.request import HttpRequest

from trusts.zero.models import Trust, Role, RolePermission, TrustUserPermission
from trusts.zero.backends import TrustModelBackend
from trusts.zero.decorators import permission_required, P, K, G, O
from tests.support import (
    ContentModel,
    ContentModelMixin,
    JunctionModelMixin,
    TrustAsContentMixin,
    create_test_users,
    enable_local_group_grant,
    get_or_create_root_user,
    reload_test_users,
)


class TrustTest(TestCase):
    ROOT_PK = getattr(settings, 'TRUSTS_ROOT_PK', 1)
    SETTLOR_PK = getattr(settings, 'TRUSTS_ROOT_SETTLOR', None)

    def setUp(self):
        super(TrustTest, self).setUp()

        call_command('create_trust_root')

        get_or_create_root_user(self)

        create_test_users(self)

    def get_perm_code(self, perm):
        return '%s.%s' % (
            perm.content_type.app_label, perm.codename
         )

    def test_root(self):
        root = Trust.objects.get_root()
        self.assertEqual(root.pk, self.ROOT_PK)
        self.assertEqual(root.pk, root.trust.pk)
        self.assertEqual(Trust.objects.filter(trust=F('id')).count(), 1)

    def test_trust_unique_together_title_settlor(self):
        # Create `Title A` for user
        self.trust = Trust(settlor=self.user, title='Title A', trust=Trust.objects.get_root())
        self.trust.save()

        # Create `Title A` for user1
        self.trust1 = Trust(settlor=self.user1, title='Title A', trust=Trust.objects.get_root())
        self.trust1.save()

        # Empty string title should be allowed (reserved for settlor_default)
        self.trust = Trust(settlor=self.user, title='', trust=Trust.objects.get_root())
        self.trust.save()

        # Create `Title A` for user, again (should fail)
        try:
            self.trust2 = Trust(settlor=self.user, title='Title A', trust=Trust.objects.get_root())
            self.trust2.save()
            self.fail('Expected IntegrityError not raised.')
        except IntegrityError as ie:
            pass

    def test_read_permissions_added(self):
        ct = ContentType.objects.get_for_model(Trust)
        self.assertIsNotNone(Permission.objects.get(
            content_type=ct,
            codename='%s_%s' % ('read', ct.model)
        ))

    def test_filter_by_user_perm(self):
        self.trust1, created = Trust.objects.get_or_create_settlor_default(self.user)

        self.trust2 = Trust(settlor=self.user, title='Title 0A', trust=Trust.objects.get_root())
        self.trust2.save()
        tup = TrustUserPermission(trust=self.trust2, entity=self.user, permission=Permission.objects.first())
        tup.save()

        self.trust3 = Trust(settlor=self.user, title='Title 0B', trust=Trust.objects.get_root())
        self.trust3.save()

        self.trust4 = Trust(settlor=self.user1, title='Title 1A', trust=Trust.objects.get_root())
        self.trust4.save()
        tup = TrustUserPermission(trust=self.trust4, entity=self.user, permission=Permission.objects.first())
        tup.save()

        self.trust5 = Trust(settlor=self.user1, title='Title 1B', trust=Trust.objects.get_root())
        self.trust5.save()
        self.group = Group(name='Group A')
        self.group.save()
        self.user.groups.add(self.group)

        self.trust5.groups.add(self.group)

        self.trust6 = Trust(settlor=self.user1, title='Title 1C', trust=Trust.objects.get_root())
        self.trust6.save()

        trusts = Trust.objects.filter_by_user_perm(self.user)
        trust_pks = [t.pk for t in trusts]
        self.assertEqual(trusts.count(), 3)
        self.assertTrue(self.trust2.id in trust_pks)
        self.assertTrue(self.trust4.id in trust_pks)
        self.assertTrue(self.trust5.id in trust_pks)

    def test_change_trust(self):
        self.trust1 = Trust(settlor=self.user, title='Title 0A', trust=Trust.objects.get_root())
        self.trust1.save()

        self.trust2 = Trust(settlor=self.user1, title='Title 1A', trust=Trust.objects.get_root())
        self.trust2.save()

        try:
            self.trust2.trust = self.trust1
            self.trust2.full_clean()
            self.fail('Expected ValidationError not raised.')
        except ValidationError as ve:
            pass

    def test_own_condition_requires_settlor(self):
        """The :own condition is settlor-only and does not leak across users."""
        trust = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Owned Trust')
        trust.save()
        change = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(trust=trust, entity=self.user, permission=change).save()
        TrustUserPermission(trust=trust, entity=self.user1, permission=change).save()

        reload_test_users(self)
        child = Trust(settlor=self.user, title='Child of owned', trust=trust)
        child.save()
        # Permissions resolve via the parent trust; :own is evaluated on the object.
        self.assertTrue(self.user.has_perm('trusts.change_trust', child))
        self.assertTrue(self.user.has_perm('trusts.change_trust:own', child))
        self.assertTrue(self.user1.has_perm('trusts.change_trust', child))
        self.assertFalse(self.user1.has_perm('trusts.change_trust:own', child))

class DecoratorsTest(TestCase):
    def setUp(self):
        super(DecoratorsTest, self).setUp()

        call_command('create_trust_root')

        get_or_create_root_user(self)

        create_test_users(self)

        self.request = HttpRequest()
        setattr(self.request, 'user', self.user)
        self.request.META['SERVER_NAME'] = 'beedesk.com'
        self.request.META['SERVER_PORT'] = 80

    def test_permission_required(self):
        self.group = Group(name='Group A')
        self.group.save()

        # test a) has_perms() == False
        mock = Mock(return_value='Response')
        has_perms = Mock(return_value=False)
        self.user.has_perms = has_perms

        decorated_func = permission_required(
            'auth.read_group',
            fieldlookups_kwargs={'pk': 'pk'},
            raise_exception=False
        )(mock)
        response = decorated_func(self.request, pk=self.group.pk)

        self.assertFalse(mock.called)
        self.assertTrue(response.status_code, 403)
        self.assertTrue(has_perms.called)
        self.assertEqual(has_perms.call_args[0][0], ('auth.read_group',))
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.group.pk)

        # test b) has_perms() == True
        mock = Mock(return_value='Response')
        has_perms = Mock(return_value=True)
        self.user.has_perms = has_perms

        decorated_func = permission_required(
            'auth.read_group',
            fieldlookups_kwargs={'pk': 'pk'}
        )(mock)
        response = decorated_func(self.request, pk=self.group.pk)

        self.assertTrue(mock.called)
        mock.assert_called_with(self.request, pk=self.group.pk)
        self.assertEqual(response, 'Response')
        self.assertEqual(has_perms.call_args[0][0], ('auth.read_group',))
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.group.pk)

    def test_permission_required_P(self):
        self.group = Group(name='Group B')
        self.group.save()

        # test a) has_perms() == False, single P used
        mock = Mock(return_value='Response')
        has_perms = Mock(return_value=False)
        self.user.has_perms = has_perms

        decorated_func = permission_required(
            P('auth.read_group', fieldlookups_kwargs={'pk': 'pk'}),
            raise_exception=False
        )(mock)
        response = decorated_func(self.request, pk=self.group.pk)

        self.assertFalse(mock.called)
        self.assertTrue(response.status_code, 403)
        self.assertTrue(has_perms.called)
        self.assertEqual(has_perms.call_args[0][0], ('auth.read_group',))
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.group.pk)

        # test d) has_perms() == True, P & P used
        mock = Mock(return_value='Response')
        has_perms = Mock(return_value=True)
        self.user.has_perms = has_perms

        decorated_func = permission_required(
            P('auth.read_group', fieldlookups_kwargs={'pk': 'pk'}) &
            P('auth.add_group', fieldlookups_kwargs={'pk': 'pk'}),
            raise_exception=False
        )(mock)
        response = decorated_func(self.request, pk=self.group.pk)

        self.assertTrue(mock.called)
        mock.assert_called_with(self.request, pk=self.group.pk)
        self.assertEqual(response, 'Response')
        self.assertEqual(has_perms.call_args[0][0], ('auth.add_group',))
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.group.pk)


class TrustContentTestMixin(ContentModel):
    def assertIsIterable(self, obj, msg='Not an iterable'):
        return self.assertTrue(hasattr(obj, '__iter__'))

    def test_unknown_content(self):
        self.trust = Trust(settlor=self.user, trust=Trust.objects.get_root())
        self.trust.save()

        perm = TrustModelBackend().get_group_permissions(self.user, {})
        self.assertIsNotNone(perm)
        self.assertIsIterable(perm)
        self.assertEqual(len(perm), 0)

        trusts = Trust.objects.filter_by_content(self.user)
        self.assertEqual(trusts.count(), 0)

    def test_user_not_in_group_has_no_perm(self):
        self.trust = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='trust 1')
        self.trust.save()

        self.content = self.create_content(self.trust)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)

        reload_test_users(self)

        self.perm_change.group_set.add(self.group)
        self.perm_change.save()

        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertFalse(had)

    def test_user_in_group_has_no_perm(self):
        self.trust = Trust(settlor=self.user, trust=Trust.objects.get_root())
        self.trust.save()

        self.content = self.create_content(self.trust)

        self.test_user_not_in_group_has_no_perm()

        reload_test_users(self)

        self.user.groups.add(self.group)

        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertFalse(had)

    def test_user_in_group_has_perm(self):
        self.trust = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='a title')
        self.trust.save()
        self.content = self.create_content(self.trust)

        self.trust1 = Trust(settlor=self.user1, trust=Trust.objects.get_root())
        self.trust1.save()

        self.test_user_in_group_has_no_perm()

        reload_test_users(self)

        enable_local_group_grant(self.trust, self.group, self.perm_change)

        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertTrue(had)

        had = self.user.has_perm(self.get_perm_code(self.perm_add), self.content)
        self.assertFalse(had)

    def test_has_perm(self):
        self.trust = Trust(settlor=self.user, trust=Trust.objects.get_root())
        self.trust.save()
        self.content = self.create_content(self.trust)

        self.trust1 = Trust(settlor=self.user1, trust=Trust.objects.get_root())
        self.trust1.save()

        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertFalse(had)
        had = self.user.has_perm(self.get_perm_code(self.perm_add), self.content)
        self.assertFalse(had)

        trust = Trust(settlor=self.user, title='Test trusts')
        trust.save()

        reload_test_users(self)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertFalse(had)

        tup = TrustUserPermission(trust=self.trust, entity=self.user, permission=self.perm_change)
        tup.save()

        reload_test_users(self)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        self.assertTrue(had)

    def test_has_perm_disallow_no_perm_content(self):
        self.test_has_perm()

        self.content1 = self.create_content(self.trust1)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), self.content1)
        self.assertFalse(had)

    def test_has_perm_disallow_no_perm_perm(self):
        self.test_has_perm()

        had = self.user.has_perm(self.get_perm_code(self.perm_add), self.content)
        self.assertFalse(had)

    def test_get_or_create_default_trust(self):
        trust, created = Trust.objects.get_or_create_settlor_default(self.user)
        content = self.create_content(trust)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), content)
        self.assertFalse(had)

        tup = TrustUserPermission(trust=trust, entity=self.user, permission=self.perm_change)
        tup.save()

        reload_test_users(self)
        had = self.user.has_perm(self.get_perm_code(self.perm_change), content)
        self.assertTrue(had)

    def test_has_perm_queryset(self):
        self.test_has_perm()

        self.content1 = self.create_content(self.trust)

        reload_test_users(self)
        content_model = self.content_model if hasattr(self, 'content_model') else self.model
        qs = content_model.objects.filter(pk__in=[self.content.pk, self.content1.pk])
        had = self.user.has_perm(self.get_perm_code(self.perm_change), qs)
        self.assertTrue(had)

    def test_mixed_trust_queryset(self):
        self.test_has_perm()

        self.content1 = self.create_content(self.trust1)
        self.content2 = self.create_content(self.trust)

        reload_test_users(self)
        qs = self.model.objects.all()
        had = self.user.has_perm(self.get_perm_code(self.perm_change), qs)

        self.assertFalse(had)

    def test_organization_isolation_denies_cross_trust_access(self):
        """Users authorized in one organization must be denied in another.

        A trust is the organization boundary. Granting change on Org A must
        not grant change on Org B, including mixed QuerySet checks.
        """
        org_a = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Org A')
        org_a.save()
        org_b = Trust(settlor=self.user1, trust=Trust.objects.get_root(), title='Org B')
        org_b.save()

        content_a = self.create_content(org_a)
        content_b = self.create_content(org_b)

        TrustUserPermission(trust=org_a, entity=self.user, permission=self.perm_change).save()
        TrustUserPermission(trust=org_b, entity=self.user1, permission=self.perm_change).save()

        reload_test_users(self)

        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_change), content_a))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content_b))
        self.assertTrue(self.user1.has_perm(self.get_perm_code(self.perm_change), content_b))
        self.assertFalse(self.user1.has_perm(self.get_perm_code(self.perm_change), content_a))

        content_model = self.content_model if hasattr(self, 'content_model') else self.model
        mixed = content_model.objects.filter(pk__in=[content_a.pk, content_b.pk])
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), mixed))
        self.assertFalse(self.user1.has_perm(self.get_perm_code(self.perm_change), mixed))

    def test_denied_access_without_grant(self):
        """A user with no trustee/group grant is denied on organization content."""
        org = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Denied Org')
        org.save()
        content = self.create_content(org)

        reload_test_users(self)
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content))
        self.assertFalse(self.user1.has_perm(self.get_perm_code(self.perm_change), content))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_add), content))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_delete), content))

    def test_read_permissions_added(self):
        ct = ContentType.objects.get_for_model(self.model)
        self.assertIsNotNone(Permission.objects.get(
            content_type=ct,
            codename='%s_%s' % ('read', ct.model)
        ))


class RoleTestMixin(object):
    def get_perm_codename(self, action):
        return '%s_%s' % (action, self.model_name.lower())

    def test_roles_in_meta(self):
        self.assertIsNotNone(self.get_model_roles())

    def test_roles_unique(self):
        self.role = Role(name='abc')
        self.role.save()
        rp = RolePermission(role=self.role, permission=self.perm_change)
        rp.save()

        rp = RolePermission(role=self.role, permission=self.perm_delete)
        rp.save()

        try:
            rp = RolePermission(role=self.role, permission=self.perm_change)
            rp.save()

            self.fail('Duplicate is not detected')
        except IntegrityError:
            pass

    def test_has_perm(self):
        get_or_create_root_user(self)
        reload_test_users(self)

        self.trust, created = Trust.objects.get_or_create_settlor_default(settlor=self.user)

        call_command('update_roles_permissions')

        self.content1 = self.create_content(self.trust)
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change)))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read)))

        self.group.user_set.add(self.user)
        self.trust.groups.add(self.group)
        Role.objects.get(name='public').groups.add(self.group)
        enable_local_group_grant(self.trust, self.group, self.perm_read)

        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

    def test_has_perm_diff_roles_on_contents(self):
        self.test_has_perm()

        content2 = self.create_content(self.trust)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content2))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content2))

        # diff trust, same group, same role
        trust3 = Trust(settlor=self.user, title='trust 3')
        trust3.save()
        content3 = self.create_content(trust3)

        reload_test_users(self)
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), content3))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content3))
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

        trust3.groups.add(self.group)
        enable_local_group_grant(trust3, self.group, self.perm_read)

        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content3))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content3))

        # make sure trust does not affect one another
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

        # diff trust, diff group, stronger role, not in group
        trust4 = Trust(settlor=self.user, title='trust 4')
        trust4.save()
        content4 = self.create_content(trust4)
        group4 = Group(name='admin group')
        group4.save()
        Role.objects.get(name='admin').groups.add(group4)

        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content3))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content3))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_read), content4))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), content4))

        # make sure trust does not affect one another
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

    def test_has_perm_diff_group_on_contents(self):
        self.test_has_perm()

        # same trust, diff role, in different group
        group3 = Group(name='write group')
        group3.save()
        Role.objects.get(name='write').groups.add(group3)
        enable_local_group_grant(self.trust, group3, self.perm_change)

        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertFalse(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

        group3.user_set.add(self.user)

        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

        content3 = self.create_content(self.trust)

        reload_test_users(self)

        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), content3))
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_change), content3))
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_read), self.content1))
        self.assertTrue(self.user.has_perm(self.get_perm_code(self.perm_change), self.content1))

    def test_management_command_create_roles(self):
        self.assertEqual(Role.objects.count(), 0)
        self.assertEqual(RolePermission.objects.count(), 0)

        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 3)
        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 9)

        rp = Role.objects.get(name='public')
        ra = Role.objects.get(name='admin')
        rw = Role.objects.get(name='write')

        self.assertEqual(rp.permissions.filter(content_type__app_label=self.app_label).count(), 2)
        self.assertEqual(ra.permissions.filter(content_type__app_label=self.app_label).count(), 4)

        ra.permissions.filter(content_type__app_label=self.app_label).get(codename=self.get_perm_codename('add_topic_to'))
        ra.permissions.filter(content_type__app_label=self.app_label).get(codename=self.get_perm_codename('read'))
        ra.permissions.filter(content_type__app_label=self.app_label).get(codename=self.get_perm_codename('add'))
        ra.permissions.filter(content_type__app_label=self.app_label).get(codename=self.get_perm_codename('change'))

        self.assertEqual(rp.permissions.filter(content_type__app_label=self.app_label).filter(codename=self.get_perm_codename('add_topic_to')).count(), 1)
        self.assertEqual(rp.permissions.filter(content_type__app_label=self.app_label).filter(codename=self.get_perm_codename('add')).count(), 0)
        self.assertEqual(rp.permissions.filter(content_type__app_label=self.app_label).filter(codename=self.get_perm_codename('change')).count(), 0)

        # Make change and ensure we add items
        self.append_model_roles('read', (self.get_perm_codename('read'),))
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 4)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 10)

        rr = Role.objects.get(name='read')
        self.assertEqual(rr.permissions.filter(content_type__app_label=self.app_label).count(), 1)
        self.assertEqual(rr.permissions.filter(content_type__app_label=self.app_label).filter(codename=self.get_perm_codename('read')).count(), 1)

        # Add
        self.remove_model_roles('write')
        self.append_model_roles('write', (self.get_perm_codename('change'), self.get_perm_codename('add'), self.get_perm_codename('add_topic_to'), self.get_perm_codename('read'),))
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 4)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 11)

        # Remove
        self.remove_model_roles('write')
        self.append_model_roles('write', (self.get_perm_codename('change'), self.get_perm_codename('read'), ))
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 4)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 9)

        # Remove 2
        self.remove_model_roles('write')
        self.remove_model_roles('read')
        self.append_model_roles('write', (self.get_perm_codename('change'), ))
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 3)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 7)

        # Run again
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 3)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 7)

        # Add empty
        self.append_model_roles('read', ())
        call_command('update_roles_permissions')

        rs = Role.objects.all()
        self.assertEqual(rs.count(), 4)

        rp = RolePermission.objects.filter(permission__content_type__app_label=self.app_label)
        self.assertEqual(rp.count(), 7)


class TrustJunctionTestCase(TrustContentTestMixin, JunctionModelMixin, TransactionTestCase):
    @unittest.expectedFailure
    def test_read_permissions_added(self):
        super(TrustJunctionTestCase, self).test_read_permissions_added()


class TrustContentTestCase(TrustContentTestMixin, ContentModelMixin, TransactionTestCase):
    pass


class TrustAsContentTestCase(TrustContentTestMixin, TrustAsContentMixin, TestCase):
    pass


class RoleContentTestCase(RoleTestMixin, ContentModelMixin, TransactionTestCase):
    pass


class RoleJunctionTestCase(RoleTestMixin, JunctionModelMixin, TransactionTestCase):
    pass


class DecoratorExpressionTest(ContentModelMixin, TestCase):
    def setUp(self):
        super(DecoratorExpressionTest, self).setUp()

        self.trust1 = Trust(settlor=self.user, trust=Trust.objects.get_root())
        self.trust1.save()
        
        self.trust2 = Trust(settlor=self.user1, trust=Trust.objects.get_root())
        self.trust2.save()
        
        self.content1 = self.create_content(self.trust1)
        self.content2 = self.create_content(self.trust2)

        tup = TrustUserPermission(trust=self.trust1, entity=self.user, permission=self.perm_change)
        tup.save()

        tup = TrustUserPermission(trust=self.trust1, entity=self.user, permission=self.perm_delete)
        tup.save()
        
        tup = TrustUserPermission(trust=self.trust2, entity=self.user, permission=self.perm_change)
        tup.save()

        reload_test_users(self)

        request = HttpRequest()
        setattr(request, 'user', self.user)
        request.META['SERVER_NAME'] = 'beedesk.com'
        request.META['SERVER_PORT'] = 80
        self.request = request

    def test_P(self):
        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertTrue(mock.called)

        p = P(self.get_perm_code(self.perm_delete), fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertFalse(mock.called)

    def test_P_K(self):
        p = P(self.get_perm_code(self.perm_change), pk=K('pk'))
        has_perms = Mock(return_value=False)
        self.user.has_perms = has_perms
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)
        self.assertTrue(has_perms.called)
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.content1.pk)

        has_perms = Mock(return_value=True)
        self.user.has_perms = has_perms
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertTrue(mock.called)
        self.assertTrue(has_perms.called)
        obj = has_perms.call_args[0][1]
        self.assertEqual(obj.first().pk, self.content2.pk)

    def test_P_G(self):
        p = P(self.get_perm_code(self.perm_change), pk=G('content'))
        has_perms = Mock(return_value=True)
        self.user.has_perms = has_perms
        self.request.GET = {'content': self.content1.pk}
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request)
        self.assertTrue(mock.called)
        self.assertTrue(has_perms.called)
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.content1.pk)

    def test_P_O(self):
        p = P(self.get_perm_code(self.perm_change), pk=O('content'))
        has_perms = Mock(return_value=True)
        self.user.has_perms = has_perms
        self.request.POST = {'content': self.content1.pk}
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request)
        self.assertTrue(mock.called)
        self.assertTrue(has_perms.called)
        obj = has_perms.call_args[0][1]
        self.assertIsNotNone(obj)
        self.assertEqual(obj.count(), 1)
        self.assertEqual(obj.first().pk, self.content1.pk)

    def test_P_and(self):
        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) & \
            P(self.get_perm_code(self.perm_delete), fieldlookups_kwargs={'pk': 'pk'})

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertFalse(mock.called)

        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) & \
            P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

    def test_P_or(self):
        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) | \
            P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) | \
            P(self.get_perm_code(self.perm_delete), fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertTrue(mock.called)

        p = P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'}) | \
            P('auth.falsefalseperm_group', fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

    def test_P_complex(self):
        p = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) | \
            (P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'}) &
             P('admin.change_all'))
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertTrue(mock.called)

        p = (P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'}) |
             P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'})) & \
            P('admin.change_all')
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content2.pk)
        self.assertFalse(mock.called)

        p1 = P(self.get_perm_code(self.perm_change), fieldlookups_kwargs={'pk': 'pk'})
        p2 = P(self.get_perm_code(self.perm_delete), fieldlookups_kwargs={'pk': 'pk'})
        p3 = P('auth.falseperm_group', fieldlookups_kwargs={'pk': 'pk'})
        p4 = P('auth.falsefalseperm_group', fieldlookups_kwargs={'pk': 'pk'})
        mock = Mock(return_value='Response')
        permission_required(p1, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p2, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p3, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

        mock = Mock(return_value='Response')
        permission_required(p4, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

        p = (p1 | p3) & (p2 | p4)
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        p = (p1 & p3) | (p2 & p4)
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertFalse(mock.called)

        p = (p1 & p2) | (p3 & p4)
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)

        p = (p1 & p3) | (p2 & p4) | p1
        mock = Mock(return_value='Response')
        permission_required(p, raise_exception=False)(mock)(self.request, pk=self.content1.pk)
        self.assertTrue(mock.called)
