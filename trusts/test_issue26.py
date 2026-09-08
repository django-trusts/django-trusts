"""Default-model regression for issue #26 custom-model contract."""

from django.contrib.auth.models import Group, Permission, User
from django.core.exceptions import ValidationError
from django.db import connection, models
from django.test import TestCase

from trusts.checks import (
    CHECK_ID_AUTH_GROUP_CUSTOM_PERMISSION,
    CHECK_ID_ENTITY_NOT_USER,
    CHECK_ID_GROUP_PERMISSIONS,
    CHECK_ID_GROUP_USER,
    CHECK_ID_PERMISSION_SHAPE,
    check_configured_auth_models,
    configured_auth_model_messages,
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
from trusts.utils import lookup_relation, related_model_of, same_concrete_model


class _OtherPrincipal(models.Model):
    name = models.CharField(max_length=40)

    class Meta:
        app_label = 'trusts_tests'


class _ScalarUserGroup(models.Model):
    user = models.IntegerField()
    permissions = models.ManyToManyField(
        Permission, related_name='+', related_query_name='group',
    )

    class Meta:
        app_label = 'trusts_tests'


class _WrongModelUserGroup(models.Model):
    user = models.ForeignKey(
        _OtherPrincipal, on_delete=models.CASCADE, related_name='+',
    )
    permissions = models.ManyToManyField(
        Permission, related_name='+', related_query_name='group',
    )

    class Meta:
        app_label = 'trusts_tests'


class _WrongPermQueryGroup(models.Model):
    permissions = models.ManyToManyField(
        Permission, related_name='+', related_query_name='team',
    )

    class Meta:
        app_label = 'trusts_tests'


class _ScalarContentTypePermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=40)
    codename = models.CharField(max_length=100)

    class Meta:
        app_label = 'trusts_tests'


class _WrongModelContentTypePermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='+',
    )
    codename = models.CharField(max_length=100)

    class Meta:
        app_label = 'trusts_tests'


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


class ConfiguredModelConventionShapeTest(Issue8FixtureMixin, TestCase):
    def _ids(self, group_model, permission_model=Permission, entity=User):
        return {
            m.id for m in configured_auth_model_messages(
                entity, group_model, permission_model,
            )
        }

    def test_scalar_user_field_is_e005(self):
        self.assertIsNone(lookup_relation(_ScalarUserGroup, 'user'))
        self.assertIn(CHECK_ID_GROUP_USER, self._ids(_ScalarUserGroup))

    def test_wrong_model_user_relation_is_e005(self):
        rel = lookup_relation(_WrongModelUserGroup, 'user')
        self.assertIsNotNone(rel)
        self.assertFalse(same_concrete_model(related_model_of(rel), User))
        self.assertIn(CHECK_ID_GROUP_USER, self._ids(_WrongModelUserGroup))

    def test_permissions_wrong_reverse_query_name_is_e004(self):
        self.assertIn(CHECK_ID_GROUP_PERMISSIONS, self._ids(_WrongPermQueryGroup))

    def test_content_type_must_be_contenttype_relation(self):
        self.assertIn(
            CHECK_ID_PERMISSION_SHAPE,
            {
                m.id for m in configured_auth_model_messages(
                    User, Group, _ScalarContentTypePermission,
                )
            },
        )
        self.assertIn(
            CHECK_ID_PERMISSION_SHAPE,
            {
                m.id for m in configured_auth_model_messages(
                    User, Group, _WrongModelContentTypePermission,
                )
            },
        )

    def test_wrong_model_user_fk_pk_collision_cannot_grant(self):
        """A FK named user to another model would match User by pk; E005 rejects it.

        Trusts authorization uses AUTH_USER_MODEL membership on the configured
        group, not this field. The colliding OtherPrincipal must not become a
        Trusts grant.
        """
        with connection.schema_editor() as editor:
            editor.create_model(_OtherPrincipal)
            editor.create_model(_WrongModelUserGroup)
        try:
            other = _OtherPrincipal.objects.create(pk=self.user.pk, name='collide')
            rogue = _WrongModelUserGroup.objects.create(user=other)
            self.assertTrue(
                _WrongModelUserGroup.objects.filter(user=self.user).filter(
                    pk=rogue.pk
                ).exists(),
                'Django FK prep uses .pk; a same-pk User must not be treated '
                'as membership of an OtherPrincipal relation.',
            )
            self.assertIn(CHECK_ID_GROUP_USER, self._ids(_WrongModelUserGroup))
            self.assertFalse(
                self.user.has_perm(self.get_perm_code(self.perm_read), self.content),
            )
            self.assertFalse(
                TrustGroup.objects.filter(
                    group__user=self.user, trust=self.org,
                ).exists(),
            )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(_WrongModelUserGroup)
                editor.delete_model(_OtherPrincipal)
