"""Default-model regression for issue #26 custom-user contract."""

from io import StringIO

from django.contrib.auth.models import Group, Permission, User
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase, override_settings

from tests.models import Category, Organization
from trusts.zero import (
    get_entity_model,
    get_group_model,
    get_permission_model,
    supported_group_contract,
    supported_permission_contract,
)
from trusts.zero.authorization import AuthorizationDenied, grant_trustee
from trusts.zero.checks import (
    CHECK_ID_ENTITY_NOT_USER,
    CHECK_ID_GROUP_NOT_AUTH,
    CHECK_ID_GROUP_SETTING_DEPRECATED,
    CHECK_ID_PERMISSION_NOT_AUTH,
    CHECK_ID_PERMISSION_SETTING_DEPRECATED,
    check_configured_auth_models,
)
from trusts.zero.models import (
    Role,
    RolePermission,
    Trust,
    TrustGroup,
    TrustGroupPermission,
    TrustUserPermission,
    _resolve_configured_permission,
)
from tests.regressions.test_issue_8 import Issue8FixtureMixin
from tests.support import enable_local_group_grant, reload_test_users


def _run_manage_py_check():
    out = StringIO()
    err = StringIO()
    call_command('check', stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


_SILENCE_E003 = ['trusts.E003', 'fields.W342']
_SILENCE_E004 = ['trusts.E004', 'fields.W342']
_SILENCE_E005 = ['trusts.E005', 'fields.W342']


class DefaultConfiguredModelContractTest(Issue8FixtureMixin, TestCase):
    def test_role_and_grant_tables_use_auth_models(self):
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
                CHECK_ID_GROUP_NOT_AUTH,
                CHECK_ID_PERMISSION_NOT_AUTH,
                CHECK_ID_GROUP_SETTING_DEPRECATED,
                CHECK_ID_PERMISSION_SETTING_DEPRECATED,
            }
        )

    @override_settings(TRUSTS_ENTITY_MODEL='trusts_tests.Organization')
    def test_mismatched_entity_setting_is_e003(self):
        messages = check_configured_auth_models(None)
        ids = [m.id for m in messages]
        self.assertIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertNotIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)

    @override_settings(TRUSTS_GROUP_MODEL='trusts_tests.Organization')
    def test_mismatched_group_setting_is_e004(self):
        messages = check_configured_auth_models(None)
        ids = [m.id for m in messages]
        self.assertIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertNotIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)

    @override_settings(TRUSTS_PERMISSION_MODEL='trusts_tests.Organization')
    def test_mismatched_permission_setting_is_e005(self):
        messages = check_configured_auth_models(None)
        ids = [m.id for m in messages]
        self.assertIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertNotIn(CHECK_ID_GROUP_NOT_AUTH, ids)

    @override_settings(TRUSTS_GROUP_MODEL='missing_app.NotAGroup')
    def test_uninstalled_group_model_is_e004_not_e003(self):
        messages = check_configured_auth_models(None)
        ids = [m.id for m in messages]
        self.assertIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertNotIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertTrue(any('NotAGroup' in m.msg for m in messages))

    @override_settings(TRUSTS_PERMISSION_MODEL='missing_app.NotAPermission')
    def test_uninstalled_permission_model_is_e005_not_e003(self):
        messages = check_configured_auth_models(None)
        ids = [m.id for m in messages]
        self.assertIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertNotIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertTrue(any('NotAPermission' in m.msg for m in messages))

    @override_settings(
        TRUSTS_ENTITY_MODEL='missing_app.NotAnEntity',
        TRUSTS_GROUP_MODEL='missing_app.NotAGroup',
        TRUSTS_PERMISSION_MODEL='missing_app.NotAPermission',
    )
    def test_lookup_failures_use_distinct_check_ids(self):
        ids = sorted(m.id for m in check_configured_auth_models(None))
        self.assertEqual(
            ids,
            [
                CHECK_ID_ENTITY_NOT_USER,
                CHECK_ID_GROUP_NOT_AUTH,
                CHECK_ID_PERMISSION_NOT_AUTH,
            ],
        )

    def test_silenced_e003_mismatched_entity_cannot_grant_or_query(self):
        self.content.grant('read', self.user)
        self.content.grant('change', self.user)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
        )

        with override_settings(
            TRUSTS_ENTITY_MODEL='trusts_tests.Organization',
            SILENCED_SYSTEM_CHECKS=_SILENCE_E003,
        ):
            self.assertIs(get_entity_model(), Organization)
            _run_manage_py_check()
            with self.assertRaises(ValidationError) as grant_ctx:
                self.content.grant('change', self.user)
            self.assertEqual(grant_ctx.exception.code, 'unsupported_entity_model')
            with self.assertRaises(ValidationError) as org_ctx:
                org = Organization.objects.create(name='Acme', manager=self.user)
                self.content.grant('read', org)
            self.assertEqual(org_ctx.exception.code, 'unsupported_entity_model')
            with self.assertRaises(AuthorizationDenied):
                grant_trustee(self.user, self.content, self.user1, 'read')
            self.assertFalse(
                TrustUserPermission.objects.filter(
                    trust=self.org, entity=self.user1, permission=self.perm_read
                ).exists()
            )
            reload_test_users(self)
            self.assertFalse(
                self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
            )
            self.assertFalse(
                Category.objects.permitted('read', self.user).exists()
            )

    def test_silenced_e003_does_not_leave_group_authorization_live(self):
        self.group.permissions.add(self.perm_read)
        self.group.user_set.add(self.user)
        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
        )
        self.assertTrue(
            Category.objects.permitted('read', self.user).filter(pk=self.content.pk).exists()
        )

        with override_settings(
            TRUSTS_ENTITY_MODEL='trusts_tests.Organization',
            SILENCED_SYSTEM_CHECKS=_SILENCE_E003,
        ):
            _run_manage_py_check()
            reload_test_users(self)
            self.assertFalse(
                self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
            )
            self.assertFalse(
                Category.objects.permitted('read', self.user).exists()
            )

    def test_silenced_e004_wrong_group_cannot_grant_or_query(self):
        self.group.permissions.add(self.perm_read)
        self.group.user_set.add(self.user)
        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
        )

        with override_settings(
            TRUSTS_GROUP_MODEL='trusts_tests.Organization',
            SILENCED_SYSTEM_CHECKS=_SILENCE_E004,
        ):
            self.assertFalse(supported_group_contract())
            self.assertIs(get_group_model(), Group)
            _run_manage_py_check()
            with self.assertRaises(ValidationError) as ctx:
                self.org.associate_group(self.group)
            self.assertEqual(ctx.exception.code, 'unsupported_group_model')
            reload_test_users(self)
            self.assertFalse(
                self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
            )
            self.assertFalse(
                Category.objects.permitted('read', self.user).exists()
            )

    def test_silenced_e005_wrong_permission_cannot_grant_or_query(self):
        self.content.grant('read', self.user)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
        )

        with override_settings(
            TRUSTS_PERMISSION_MODEL='trusts_tests.Organization',
            SILENCED_SYSTEM_CHECKS=_SILENCE_E005,
        ):
            self.assertFalse(supported_permission_contract())
            self.assertIs(get_permission_model(), Permission)
            _run_manage_py_check()
            with self.assertRaises(ValidationError) as ctx:
                self.content.grant('change', self.user)
            self.assertEqual(ctx.exception.code, 'unsupported_permission_model')
            reload_test_users(self)
            self.assertFalse(
                self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
            )
            self.assertFalse(
                Category.objects.permitted('read', self.user).exists()
            )
