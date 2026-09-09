"""Deprecation of TRUSTS_GROUP_MODEL / TRUSTS_PERMISSION_MODEL (issue #33)."""

import importlib
from io import StringIO

from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.test import TestCase, override_settings

from tests.models import Organization
from trusts.zero import (
    AUTH_GROUP_MODEL,
    AUTH_PERMISSION_MODEL,
    GROUP_MODEL_NAME,
    PERMISSION_MODEL_NAME,
    get_group_model,
    get_permission_model,
    group_model_setting_overridden,
    permission_model_setting_overridden,
    supported_group_contract,
    supported_permission_contract,
)
from trusts.zero.checks import (
    CHECK_ID_ENTITY_NOT_USER,
    CHECK_ID_GROUP_NOT_AUTH,
    CHECK_ID_GROUP_SETTING_DEPRECATED,
    CHECK_ID_PERMISSION_NOT_AUTH,
    CHECK_ID_PERMISSION_SETTING_DEPRECATED,
    REMOVAL_RELEASE,
    check_configured_auth_models,
)
from trusts.zero.models import (
    Role,
    RolePermission,
    Trust,
    TrustGroup,
    TrustGroupPermission,
    TrustUserPermission,
)
from tests.regressions.test_issue_8 import Issue8FixtureMixin


def _run_manage_py_check():
    out = StringIO()
    err = StringIO()
    call_command('check', stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


def _check_ids():
    return [m.id for m in check_configured_auth_models(None)]


def _messages_for(check_id):
    return [m for m in check_configured_auth_models(None) if m.id == check_id]


class DeprecatedGroupPermissionSettingsTest(Issue8FixtureMixin, TestCase):
    def test_default_config_has_no_group_permission_diagnostics(self):
        self.assertFalse(group_model_setting_overridden())
        self.assertFalse(permission_model_setting_overridden())
        self.assertTrue(supported_group_contract())
        self.assertTrue(supported_permission_contract())
        ids = set(_check_ids())
        self.assertFalse(
            ids & {
                CHECK_ID_GROUP_NOT_AUTH,
                CHECK_ID_PERMISSION_NOT_AUTH,
                CHECK_ID_GROUP_SETTING_DEPRECATED,
                CHECK_ID_PERMISSION_SETTING_DEPRECATED,
            }
        )
        output = _run_manage_py_check()
        self.assertNotIn('trusts.E004', output)
        self.assertNotIn('trusts.E005', output)
        self.assertNotIn('trusts.W002', output)
        self.assertNotIn('trusts.W003', output)

    def test_getters_and_field_targets_are_auth_models(self):
        self.assertEqual(GROUP_MODEL_NAME, AUTH_GROUP_MODEL)
        self.assertEqual(PERMISSION_MODEL_NAME, AUTH_PERMISSION_MODEL)
        self.assertIs(get_group_model(), Group)
        self.assertIs(get_permission_model(), Permission)
        self.assertIs(Trust._meta.get_field('groups').remote_field.model, Group)
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

    @override_settings(TRUSTS_GROUP_MODEL='auth.Group')
    def test_explicit_auth_group_setting_is_w002(self):
        self.assertTrue(group_model_setting_overridden())
        self.assertTrue(supported_group_contract())
        ids = _check_ids()
        self.assertIn(CHECK_ID_GROUP_SETTING_DEPRECATED, ids)
        self.assertNotIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        messages = _messages_for(CHECK_ID_GROUP_SETTING_DEPRECATED)
        self.assertTrue(any(REMOVAL_RELEASE in m.msg for m in messages))
        self.assertTrue(any('deprecated' in m.msg.lower() for m in messages))

    @override_settings(TRUSTS_PERMISSION_MODEL='auth.Permission')
    def test_explicit_auth_permission_setting_is_w003(self):
        self.assertTrue(permission_model_setting_overridden())
        self.assertTrue(supported_permission_contract())
        ids = _check_ids()
        self.assertIn(CHECK_ID_PERMISSION_SETTING_DEPRECATED, ids)
        self.assertNotIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        messages = _messages_for(CHECK_ID_PERMISSION_SETTING_DEPRECATED)
        self.assertTrue(any(REMOVAL_RELEASE in m.msg for m in messages))
        self.assertTrue(any('deprecated' in m.msg.lower() for m in messages))

    @override_settings(TRUSTS_GROUP_MODEL='trusts_tests.Organization')
    def test_nonstandard_group_setting_is_e004_not_warning(self):
        self.assertFalse(supported_group_contract())
        self.assertIs(get_group_model(), Group)
        self.assertEqual(GROUP_MODEL_NAME, AUTH_GROUP_MODEL)
        self.assertIs(Trust._meta.get_field('groups').remote_field.model, Group)
        ids = _check_ids()
        self.assertIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_GROUP_SETTING_DEPRECATED, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        messages = _messages_for(CHECK_ID_GROUP_NOT_AUTH)
        self.assertTrue(any(REMOVAL_RELEASE in m.msg for m in messages))
        self.assertTrue(any('deprecated' in m.msg.lower() for m in messages))
        self.assertTrue(any('Organization' in m.msg for m in messages))

    @override_settings(TRUSTS_PERMISSION_MODEL='trusts_tests.Organization')
    def test_nonstandard_permission_setting_is_e005_not_warning(self):
        self.assertFalse(supported_permission_contract())
        self.assertIs(get_permission_model(), Permission)
        self.assertEqual(PERMISSION_MODEL_NAME, AUTH_PERMISSION_MODEL)
        self.assertIs(
            TrustUserPermission._meta.get_field('permission').remote_field.model,
            Permission,
        )
        ids = _check_ids()
        self.assertIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_PERMISSION_SETTING_DEPRECATED, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        messages = _messages_for(CHECK_ID_PERMISSION_NOT_AUTH)
        self.assertTrue(any(REMOVAL_RELEASE in m.msg for m in messages))
        self.assertTrue(any('deprecated' in m.msg.lower() for m in messages))
        self.assertTrue(any('Organization' in m.msg for m in messages))

    @override_settings(TRUSTS_GROUP_MODEL='missing_app.NotAGroup')
    def test_uninstalled_group_setting_is_e004(self):
        ids = _check_ids()
        self.assertIn(CHECK_ID_GROUP_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertTrue(any('NotAGroup' in m.msg for m in _messages_for(CHECK_ID_GROUP_NOT_AUTH)))

    @override_settings(TRUSTS_PERMISSION_MODEL='missing_app.NotAPermission')
    def test_uninstalled_permission_setting_is_e005(self):
        ids = _check_ids()
        self.assertIn(CHECK_ID_PERMISSION_NOT_AUTH, ids)
        self.assertNotIn(CHECK_ID_ENTITY_NOT_USER, ids)
        self.assertTrue(
            any('NotAPermission' in m.msg for m in _messages_for(CHECK_ID_PERMISSION_NOT_AUTH))
        )

    def test_historical_migrations_import_pinned_auth_names(self):
        Initial = importlib.import_module('trusts.zero.migrations.0001_initial').Migration
        TrustGroupMigration = importlib.import_module(
            'trusts.zero.migrations.0002_trustgroup'
        ).Migration

        self.assertEqual(GROUP_MODEL_NAME, 'auth.Group')
        self.assertEqual(PERMISSION_MODEL_NAME, 'auth.Permission')

        trust_op = next(op for op in Initial.operations if getattr(op, 'name', None) == 'Trust')
        trust_fields = dict(trust_op.fields)
        self.assertEqual(trust_fields['groups'].remote_field.model, 'auth.Group')
        tup_op = next(
            op for op in Initial.operations
            if getattr(op, 'name', None) == 'TrustUserPermission'
        )
        self.assertEqual(
            dict(tup_op.fields)['permission'].remote_field.model, 'auth.Permission'
        )
        role_op = next(op for op in Initial.operations if getattr(op, 'name', None) == 'Role')
        role_fields = dict(role_op.fields)
        self.assertEqual(role_fields['groups'].remote_field.model, 'auth.Group')
        self.assertEqual(role_fields['permissions'].remote_field.model, 'auth.Permission')

        state_ops = TrustGroupMigration.operations[0].state_operations
        tg_op = next(op for op in state_ops if getattr(op, 'name', None) == 'TrustGroup')
        self.assertEqual(dict(tg_op.fields)['group'].remote_field.model, 'auth.Group')
        tgp_op = next(
            op for op in TrustGroupMigration.operations
            if getattr(op, 'name', None) == 'TrustGroupPermission'
        )
        self.assertEqual(
            dict(tgp_op.fields)['permission'].remote_field.model, 'auth.Permission'
        )

        loader = MigrationLoader(connection)
        self.assertIn(('trusts', '0001_initial'), loader.disk_migrations)
        self.assertIn(('trusts', '0002_trustgroup'), loader.disk_migrations)
        self.assertEqual(
            {name for app, name in loader.applied_migrations if app == 'trusts'},
            {'0001_initial', '0002_trustgroup'},
        )

    def test_nonstandard_setting_does_not_retarget_role_or_trustgroup(self):
        with override_settings(
            TRUSTS_GROUP_MODEL='trusts_tests.Organization',
            TRUSTS_PERMISSION_MODEL='trusts_tests.Organization',
        ):
            self.assertIs(get_group_model(), Group)
            self.assertIs(get_permission_model(), Permission)
            self.assertIsNot(get_group_model(), Organization)
            self.assertIs(TrustGroup._meta.get_field('group').remote_field.model, Group)
            self.assertIs(Role._meta.get_field('groups').remote_field.model, Group)
            self.assertIs(Role._meta.get_field('permissions').remote_field.model, Permission)
