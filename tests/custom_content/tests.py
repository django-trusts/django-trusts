"""End-to-end custom AUTH_USER_MODEL (issue #26).

Loaded only under ``tests.custom_settings`` (selected **before** migrate).
Not discovered by the default ``tests.runtests`` suite. Group and
Permission are Django's ``auth`` models.
"""

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import connection
from django.test import TestCase

from tests.custom_auth.models import CustomUser
from tests.custom_content.models import Item
from trusts import get_entity_model, get_group_model, get_permission_model
from trusts.authorization import (
    AuthorizationDenied,
    associate_group_with_trust,
    grant_trust_group_permission,
    grant_trustee,
    revoke_trust_group_permission,
    set_trust_group_permissions,
)
from trusts.models import (
    Role,
    RolePermission,
    Trust,
    TrustGroup,
    TrustGroupPermission,
    TrustUserPermission,
)


def _sqlite_fk_tables(table):
    with connection.cursor() as cursor:
        cursor.execute('PRAGMA foreign_key_list(%s)' % connection.ops.quote_name(table))
        return {row[2] for row in cursor.fetchall()}


class CustomUserInstallTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command('create_trust_root')
        call_command('update_roles_permissions', verbosity=0)

    def setUp(self):
        super(CustomUserInstallTest, self).setUp()
        self.user = CustomUser.objects.create_user('daniel', 'daniel@example.com', 'pass')
        self.other = CustomUser.objects.create_user('other', 'other@example.com', 'pass')
        self.org = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Org A')
        self.org.save()
        self.item = Item(trust=self.org, name='item-a')
        self.item.save()
        item_ct = ContentType.objects.get_for_model(Item)
        self.perm_read = Permission.objects.get(content_type=item_ct, codename='read_item')
        self.perm_change = Permission.objects.get(
            content_type=item_ct, codename='change_item'
        )
        self.group = Group.objects.create(name='team-a')

    def _reload(self):
        self.user = CustomUser.objects.get(pk=self.user.pk)
        self.other = CustomUser.objects.get(pk=self.other.pk)
        self.item = Item.objects.get(pk=self.item.pk)

    def _code(self, perm):
        return '%s.%s' % (perm.content_type.app_label, perm.codename)

    def _assert_parity(self, perm, user):
        direct = set(
            obj.pk for obj in Item.objects.all()
            if user.has_perm(self._code(perm), obj)
        )
        listed = set(Item.objects.permitted(perm.codename, user).values_list('pk', flat=True))
        self.assertEqual(listed, direct)

    def test_entity_is_custom_user_group_and_permission_are_auth(self):
        self.assertIs(get_entity_model(), CustomUser)
        self.assertIs(get_group_model(), Group)
        self.assertIs(get_permission_model(), Permission)
        self.assertIs(
            Trust._meta.get_field('settlor').remote_field.model, CustomUser
        )
        self.assertIs(
            TrustUserPermission._meta.get_field('entity').remote_field.model, CustomUser
        )
        self.assertIs(
            TrustUserPermission._meta.get_field('permission').remote_field.model,
            Permission,
        )
        self.assertIs(TrustGroup._meta.get_field('group').remote_field.model, Group)
        self.assertIs(
            TrustGroupPermission._meta.get_field('permission').remote_field.model,
            Permission,
        )
        self.assertIs(Role._meta.get_field('groups').remote_field.model, Group)
        self.assertIs(Role._meta.get_field('permissions').remote_field.model, Permission)
        self.assertIs(
            RolePermission._meta.get_field('permission').remote_field.model,
            Permission,
        )

    def test_fresh_schema_fks_target_custom_user_and_auth_tables(self):
        self.assertIn(CustomUser._meta.db_table, _sqlite_fk_tables('trusts_trust'))
        self.assertIn(
            CustomUser._meta.db_table, _sqlite_fk_tables('trusts_trustuserpermission')
        )
        self.assertIn('auth_permission', _sqlite_fk_tables('trusts_trustuserpermission'))
        self.assertIn('auth_group', _sqlite_fk_tables('trusts_trust_groups'))
        self.assertIn('auth_permission', _sqlite_fk_tables('trusts_trustgrouppermission'))
        self.assertIn('auth_permission', _sqlite_fk_tables('trusts_rolepermission'))
        self.assertIn('auth_group', _sqlite_fk_tables('trusts_role_groups'))
        self.assertNotIn('auth_user', _sqlite_fk_tables('trusts_trust'))
        self.assertNotIn('auth_user', _sqlite_fk_tables('trusts_trustuserpermission'))

    def test_trustee_grant_uses_custom_user(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_read
        ).save()
        self._reload()
        self.assertTrue(self.user.has_perm(self._code(self.perm_read), self.item))
        self.assertFalse(self.other.has_perm(self._code(self.perm_read), self.item))
        self._assert_parity(self.perm_read, self.user)
        self._assert_parity(self.perm_read, self.other)

    def test_direct_group_permissions_are_global_ceiling(self):
        self.group.permissions.add(self.perm_read)
        self.group.user_set.add(self.user)
        self.org.grant_group_permission(self.group, self.perm_read)
        self._reload()
        self.assertTrue(self.user.has_perm(self._code(self.perm_read), self.item))
        self._assert_parity(self.perm_read, self.user)

    def test_role_derived_ceiling_uses_auth_group_and_permission(self):
        role = Role.objects.get(name='public')
        self.assertTrue(
            RolePermission.objects.filter(
                role=role, permission=self.perm_read
            ).exists()
        )
        self.assertIsInstance(role.permissions.get(pk=self.perm_read.pk), Permission)
        role.groups.add(self.group)
        self.group.user_set.add(self.user)
        self.org.grant_group_permission(self.group, self.perm_read)
        self._reload()
        self.assertTrue(self.user.has_perm(self._code(self.perm_read), self.item))
        self._assert_parity(self.perm_read, self.user)
        self.assertFalse(self.group.permissions.filter(pk=self.perm_read.pk).exists())

    def test_trustgroup_grant_set_revoke_and_authorization_helpers(self):
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        self.group.permissions.add(self.perm_read, self.perm_change)
        self._reload()
        associate_group_with_trust(self.user, self.item, self.group)
        self.assertTrue(
            TrustGroup.objects.filter(trust=self.org, group=self.group).exists()
        )
        self._reload()
        self.assertFalse(self.other.has_perm(self._code(self.perm_read), self.item))
        grant_trust_group_permission(self.user, self.item, self.group, self.perm_read)
        self.group.user_set.add(self.other)
        self._reload()
        self.assertTrue(self.other.has_perm(self._code(self.perm_read), self.item))
        set_trust_group_permissions(
            self.user, self.item, self.group, [self.perm_read, self.perm_change]
        )
        self._reload()
        self.assertTrue(self.other.has_perm(self._code(self.perm_change), self.item))
        revoke_trust_group_permission(self.user, self.item, self.group, self.perm_change)
        self._reload()
        self.assertFalse(self.other.has_perm(self._code(self.perm_change), self.item))
        self._assert_parity(self.perm_read, self.other)
        self._assert_parity(self.perm_change, self.other)

    def test_mismatched_model_instances_fail_closed(self):
        self.group.permissions.add(self.perm_read)
        with self.assertRaises(ValidationError) as ctx:
            self.org.grant_group_permission(self.group, self.org)
        self.assertEqual(ctx.exception.code, 'mismatched_permission_model')
        self.assertFalse(
            TrustGroup.objects.filter(trust=self.org, group=self.group).exists()
        )
        with self.assertRaises(ValidationError):
            self.org.associate_group(self.user)
        with self.assertRaises(ValidationError):
            self.item.grant('read', self.group)
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        self._reload()
        with self.assertRaises(AuthorizationDenied):
            grant_trustee(self.user, self.item, self.group, 'read')
        with self.assertRaises(AuthorizationDenied):
            associate_group_with_trust(self.user, self.item, self.user)
