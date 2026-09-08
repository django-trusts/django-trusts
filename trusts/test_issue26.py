"""Default-model regression for issue #26 custom-model contract."""

from django.contrib.auth.models import Group, Permission, User
from django.core.exceptions import ValidationError
from django.test import TestCase

from trusts.checks import (
    CHECK_ID_AUTH_GROUP_CUSTOM_PERMISSION,
    CHECK_ID_ENTITY_NOT_USER,
    CHECK_ID_GROUP_PERMISSIONS,
    CHECK_ID_GROUP_USER,
    CHECK_ID_PERMISSION_SHAPE,
    check_configured_auth_models,
)
from trusts.models import (
    Role,
    RolePermission,
    Trust,
    TrustGroup,
    TrustGroupPermission,
    TrustUserPermission,
    _resolve_configured_permission,
)
from trusts.test_issue8 import Issue8FixtureMixin


class DefaultConfiguredModelContractTest(Issue8FixtureMixin, TestCase):
    def test_role_and_grant_tables_use_configured_auth_models(self):
        self.assertIs(Trust._meta.get_field('settlor').remote_field.model, User)
        self.assertIs(Trust._meta.get_field('groups').remote_field.model, Group)
        self.assertIs(TrustUserPermission._meta.get_field('entity').remote_field.model, User)
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

    def test_mismatched_permission_instance_is_not_coerced_by_pk(self):
        with self.assertRaises(ValidationError) as ctx:
            _resolve_configured_permission(self.org)
        self.assertEqual(ctx.exception.code, 'mismatched_permission_model')
        self.group.permissions.add(self.perm_read)
        with self.assertRaises(ValidationError):
            self.org.grant_group_permission(self.group, self.org)
        self.assertFalse(
            TrustGroup.objects.filter(trust=self.org, group=self.group).exists()
        )

    def test_configured_auth_model_checks_pass(self):
        messages = check_configured_auth_models(None)
        ids = {m.id for m in messages}
        self.assertFalse(
            ids & {
                CHECK_ID_ENTITY_NOT_USER,
                CHECK_ID_GROUP_PERMISSIONS,
                CHECK_ID_GROUP_USER,
                CHECK_ID_PERMISSION_SHAPE,
                CHECK_ID_AUTH_GROUP_CUSTOM_PERMISSION,
            }
        )
