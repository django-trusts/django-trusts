"""End-to-end custom entity/group/permission models (issue #26).

Loaded only under ``tests.custom_settings`` (selected **before** migrate).
Not discovered by the default ``tests.runtests`` suite.
"""

from django.contrib.auth.models import Group as AuthGroup
from django.contrib.auth.models import Permission as AuthPermission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import connection
from django.test import TestCase

from tests.custom_auth.models import CustomGroup, CustomPermission, CustomUser
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
from trusts.utils import sync_configured_permissions


def _sqlite_fk_tables(table):
    with connection.cursor() as cursor:
        cursor.execute('PRAGMA foreign_key_list(%s)' % connection.ops.quote_name(table))
        return {row[2] for row in cursor.fetchall()}


class CustomModelInstallTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command('create_trust_root')
        sync_configured_permissions()
        call_command('update_roles_permissions', verbosity=0)

    def setUp(self):
        super(CustomModelInstallTest, self).setUp()
        self.user = CustomUser.objects.create_user('daniel', 'daniel@example.com', 'pass')
        self.other = CustomUser.objects.create_user('other', 'other@example.com', 'pass')
        self.org = Trust(settlor=self.user, trust=Trust.objects.get_root(), title='Org A')
        self.org.save()
        self.item = Item(trust=self.org, name='item-a')
        self.item.save()
        self.perm_read = CustomPermission.objects.get_by_natural_key(
            'read_item', 'custom_content', 'item'
        )
        self.perm_change = CustomPermission.objects.get_by_natural_key(
            'change_item', 'custom_content', 'item'
        )
        self.group = CustomGroup.objects.create(name='team-a')

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

    def test_configured_models_are_custom(self):
        self.assertIs(get_entity_model(), CustomUser)
        self.assertIs(get_group_model(), CustomGroup)
        self.assertIs(get_permission_model(), CustomPermission)
        self.assertIs(
            Trust._meta.get_field('settlor').remote_field.model, CustomUser
        )
        self.assertIs(
            TrustUserPermission._meta.get_field('entity').remote_field.model, CustomUser
        )
        self.assertIs(
            TrustUserPermission._meta.get_field('permission').remote_field.model,
            CustomPermission,
        )
        self.assertIs(TrustGroup._meta.get_field('group').remote_field.model, CustomGroup)
        self.assertIs(
            TrustGroupPermission._meta.get_field('permission').remote_field.model,
            CustomPermission,
        )
        self.assertIs(Role._meta.get_field('groups').remote_field.model, CustomGroup)
        self.assertIs(
            Role._meta.get_field('permissions').remote_field.model, CustomPermission
        )
        self.assertIs(
            RolePermission._meta.get_field('permission').remote_field.model,
            CustomPermission,
        )

    def test_fresh_schema_fks_target_configured_tables(self):
        self.assertIn(CustomUser._meta.db_table, _sqlite_fk_tables('trusts_trust'))
        self.assertIn(
            CustomUser._meta.db_table, _sqlite_fk_tables('trusts_trustuserpermission')
        )
        self.assertIn(
            CustomPermission._meta.db_table,
            _sqlite_fk_tables('trusts_trustuserpermission'),
        )
        self.assertIn(CustomGroup._meta.db_table, _sqlite_fk_tables('trusts_trust_groups'))
        self.assertIn(
            CustomPermission._meta.db_table,
            _sqlite_fk_tables('trusts_trustgrouppermission'),
        )
        self.assertIn(
            CustomPermission._meta.db_table, _sqlite_fk_tables('trusts_rolepermission')
        )
        self.assertIn(CustomGroup._meta.db_table, _sqlite_fk_tables('trusts_role_groups'))
        self.assertNotIn('auth_user', _sqlite_fk_tables('trusts_trustuserpermission'))
        self.assertNotIn('auth_permission', _sqlite_fk_tables('trusts_rolepermission'))
        self.assertNotIn('auth_group', _sqlite_fk_tables('trusts_role_groups'))

    def test_trustee_grant_uses_configured_entity(self):
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
        self.assertFalse(
            AuthGroup.objects.filter(pk=self.group.pk).exists()
            and AuthGroup.objects.get(pk=self.group.pk).permissions.filter(
                pk=self.perm_read.pk
            ).exists()
        )
        self.assertFalse(self.user.groups.filter(name='team-a').exists())

    def test_role_derived_ceiling_does_not_use_auth_models(self):
        role = Role.objects.get(name='public')
        self.assertTrue(
            RolePermission.objects.filter(
                role=role, permission=self.perm_read
            ).exists()
        )
        self.assertIsInstance(role.permissions.get(pk=self.perm_read.pk), CustomPermission)
        role.groups.add(self.group)
        self.group.user_set.add(self.user)
        self.org.grant_group_permission(self.group, self.perm_read)
        self._reload()
        self.assertTrue(self.user.has_perm(self._code(self.perm_read), self.item))
        self._assert_parity(self.perm_read, self.user)
        self.assertFalse(self.group.permissions.filter(pk=self.perm_read.pk).exists())
        self.assertFalse(
            AuthPermission.objects.filter(
                content_type=self.perm_read.content_type,
                codename=self.perm_read.codename,
            ).filter(group__user=self.user).exists()
        )

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
        auth_perm = AuthPermission.objects.get(
            content_type=self.perm_read.content_type,
            codename=self.perm_read.codename,
        )
        auth_group = AuthGroup.objects.create(name='auth-only')
        self.group.permissions.add(self.perm_read)
        with self.assertRaises(ValidationError) as ctx:
            self.org.grant_group_permission(self.group, auth_perm)
        self.assertEqual(ctx.exception.code, 'mismatched_permission_model')
        self.assertFalse(
            TrustGroupPermission.objects.filter(permission_id=auth_perm.pk).exists()
        )
        with self.assertRaises(ValidationError):
            self.org.associate_group(auth_group)
        with self.assertRaises(ValidationError):
            self.item.grant('read', auth_group)
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        self._reload()
        with self.assertRaises(AuthorizationDenied):
            grant_trustee(self.user, self.item, auth_group, 'read')
        with self.assertRaises(AuthorizationDenied):
            associate_group_with_trust(self.user, self.item, auth_group)
