"""Acceptance tests for issue #23: fail-closed per-Trust group intersection."""

from io import StringIO

from django.contrib.auth.models import AnonymousUser, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import connection
from django.test import TestCase

from trusts.zero import get_group_model, get_permission_model
from trusts.zero.authorization import (
    AuthorizationDenied,
    associate_group_with_trust,
    grant_trust_group_permission,
    grant_trustee,
)
from trusts.zero.models import (
    Role,
    Trust,
    TrustGroup,
    TrustGroupPermission,
    TrustUserPermission,
)
from tests.regressions.test_issue_8 import Issue8FixtureMixin
from tests.support import enable_local_group_grant, reload_test_users
from tests.models import Category


class TrustGroupIntersectionTest(Issue8FixtureMixin, TestCase):
    def setUp(self):
        super(TrustGroupIntersectionTest, self).setUp()
        self.user.groups.add(self.group)
        self.perm_read.group_set.add(self.group)
        self.perm_change.group_set.add(self.group)

    def _has_read(self, user, obj):
        return user.has_perm(self.get_perm_code(self.perm_read), obj)

    def _has_change(self, user, obj):
        return user.has_perm(self.get_perm_code(self.perm_change), obj)

    def test_01_no_trustgroup_denies(self):
        reload_test_users(self)
        self.assertFalse(TrustGroup.objects.filter(trust=self.org, group=self.group).exists())
        self.assertFalse(self._has_read(self.user, self.content))
        self.assertNotIn(
            self.content.pk,
            Category.objects.permitted('read', self.user).values_list('pk', flat=True),
        )

    def test_02_trustgroup_without_local_denies(self):
        self.org.groups.add(self.group)
        reload_test_users(self)
        self.assertTrue(TrustGroup.objects.filter(trust=self.org, group=self.group).exists())
        self.assertFalse(
            TrustGroupPermission.objects.filter(
                trustgroup__trust=self.org, trustgroup__group=self.group
            ).exists()
        )
        self.assertFalse(self._has_read(self.user, self.content))

    def test_03_local_without_global_ceiling_denies(self):
        other = Group.objects.create(name='no-ceiling')
        other.user_set.add(self.user)
        self.org.groups.add(other)
        tg = TrustGroup.objects.get(trust=self.org, group=other)
        with self.assertRaises(ValidationError):
            tg.grant_permission(self.perm_read)
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO trusts_trustgrouppermission (trustgroup_id, permission_id) '
                'VALUES (%s, %s)',
                [tg.pk, self.perm_read.pk],
            )
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user, self.content))
        self.assertNotIn(
            self.content.pk,
            Category.objects.permitted('read', self.user).values_list('pk', flat=True),
        )

    def test_03b_permissions_add_outside_ceiling_rejected(self):
        other = Group.objects.create(name='no-ceiling-add')
        self.org.groups.add(other)
        tg = TrustGroup.objects.get(trust=self.org, group=other)
        with self.assertRaises(ValidationError):
            tg.permissions.add(self.perm_read)

    def test_04_global_and_local_allows(self):
        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.assertFalse(self._has_change(self.user, self.content))

    def test_05_same_group_different_local_grants_per_trust(self):
        enable_local_group_grant(self.org, self.group, self.perm_change)
        enable_local_group_grant(self.org_b, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_change(self.user, self.content))
        self.assertFalse(self._has_read(self.user, self.content))
        self.assertTrue(self._has_read(self.user, self.content_b))
        self.assertFalse(self._has_change(self.user, self.content_b))

    def test_06_removing_either_layer_revokes(self):
        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))

        self.org.revoke_group_permission(self.group, self.perm_read)
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user, self.content))

        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))

        self.group.permissions.remove(self.perm_read)
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user, self.content))

    def test_07_two_groups_combine_without_widening(self):
        g_read = Group.objects.create(name='readers')
        g_change = Group.objects.create(name='writers')
        g_read.permissions.add(self.perm_read)
        g_change.permissions.add(self.perm_change)
        self.user.groups.add(g_read, g_change)
        enable_local_group_grant(self.org, g_read, self.perm_read)
        enable_local_group_grant(self.org, g_change, self.perm_change)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.assertTrue(self._has_change(self.user, self.content))

        self.user.groups.remove(g_change)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.assertFalse(self._has_change(self.user, self.content))

        g_read.permissions.add(self.perm_change)
        reload_test_users(self)
        # Ceiling widened on readers, but local grant is still read-only.
        self.assertFalse(self._has_change(self.user, self.content))

        self.user.groups.add(g_change)
        reload_test_users(self)
        self.assertTrue(self._has_change(self.user, self.content))
        self.user.groups.remove(g_change)
        reload_test_users(self)
        self.assertFalse(self._has_change(self.user, self.content))

    def test_08_direct_trustee_unchanged(self):
        TrustUserPermission(
            trust=self.org, entity=self.user1, permission=self.perm_read
        ).save()
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user1, self.content))
        self.assertFalse(self._has_read(self.user1, self.content_b))
        self.assertNotIn(
            self.user1.pk,
            Group.objects.filter(pk=self.group.pk).values_list('user', flat=True),
        )

    def test_09_role_derived_ceiling(self):
        call_command('update_roles_permissions')
        role_group = Group.objects.create(name='role-public')
        role_group.user_set.add(self.user1)
        Role.objects.get(name='public').groups.add(role_group)
        self.org.groups.add(role_group)
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user1, self.content))
        enable_local_group_grant(self.org, role_group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user1, self.content))
        self.assertFalse(self._has_change(self.user1, self.content))

    def test_10_inactive_and_anonymous_denied(self):
        enable_local_group_grant(self.org, self.group, self.perm_read)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.user.is_active = False
        self.user.save()
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user, self.content))
        self.assertFalse(Category.objects.permitted('read', self.user).exists())
        anon = AnonymousUser()
        self.assertFalse(self._has_read(anon, self.content))
        self.assertFalse(Category.objects.permitted('read', anon).exists())

    def test_11_has_perm_permitted_parity(self):
        enable_local_group_grant(self.org, self.group, self.perm_read)
        TrustUserPermission(
            trust=self.org_b, entity=self.user, permission=self.perm_read
        ).save()
        reload_test_users(self)
        direct = set(
            obj.pk for obj in Category.objects.all()
            if self.user.has_perm(self.get_perm_code(self.perm_read), obj)
        )
        listed = set(Category.objects.permitted('read', self.user).values_list('pk', flat=True))
        self.assertEqual(direct, listed)
        self.assertEqual(direct, {self.content.pk, self.content_b.pk})
        sql = str(Category.objects.permitted('read', self.user).query)
        self.assertTrue(
            'JOIN' in sql.upper() or 'EXISTS' in sql.upper(),
            'permitted() must filter in SQL. SQL was: %s' % sql,
        )
        trusts = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'read', exclude_root=True
        )
        self.assertEqual(set(trusts.values_list('pk', flat=True)), {self.org.pk, self.org_b.pk})

    def test_12_legacy_association_preserves_rows_but_grants_nothing(self):
        self.org.groups.add(self.group)
        reload_test_users(self)
        self.assertTrue(self.org.groups.filter(pk=self.group.pk).exists())
        tg = TrustGroup.objects.get(trust=self.org, group=self.group)
        self.assertEqual(tg.permissions.count(), 0)
        self.assertFalse(self._has_read(self.user, self.content))
        self.assertFalse(self._has_change(self.user, self.content))
        self.assertFalse(
            Trust.objects.filter_by_user_content_perm(
                self.user, Category, 'read', exclude_root=True
            ).filter(pk=self.org.pk).exists()
        )

    def test_13_grandfather_dry_run_and_apply(self):
        self.org.groups.add(self.group)
        reload_test_users(self)
        self.assertFalse(self._has_read(self.user, self.content))

        dry = StringIO()
        call_command('grandfather_trust_group_permissions', '--dry-run', stdout=dry)
        report = dry.getvalue()
        self.assertIn('mode=dry-run', report)
        self.assertIn('trust_id=%s' % self.org.pk, report)
        self.assertIn('group_id=%s' % self.group.pk, report)
        self.assertIn('permission_id=%s' % self.perm_read.pk, report)
        self.assertIn('permission_id=%s' % self.perm_change.pk, report)
        self.assertFalse(
            TrustGroupPermission.objects.filter(
                trustgroup__trust=self.org, trustgroup__group=self.group
            ).exists()
        )
        self.assertFalse(self._has_read(self.user, self.content))

        applied = StringIO()
        call_command('grandfather_trust_group_permissions', '--apply', stdout=applied)
        self.assertIn('mode=apply', applied.getvalue())
        self.assertTrue(
            TrustGroupPermission.objects.filter(
                trustgroup__trust=self.org,
                trustgroup__group=self.group,
                permission=self.perm_read,
            ).exists()
        )
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.assertTrue(self._has_change(self.user, self.content))

        again = StringIO()
        call_command('grandfather_trust_group_permissions', '--dry-run', stdout=again)
        self.assertIn('tuples=0', again.getvalue())

    def test_14_later_global_ceiling_is_not_silently_local(self):
        enable_local_group_grant(self.org, self.group, self.perm_read)
        extra = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Category),
            codename='add_category',
        )
        self.group.permissions.add(extra)
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        self.assertFalse(self.user.has_perm(self.get_perm_code(extra), self.content))
        self.assertNotIn(
            extra.pk,
            TrustGroup.objects.get(trust=self.org, group=self.group).permissions.values_list(
                'pk', flat=True
            ),
        )
        enable_local_group_grant(self.org, self.group, extra)
        reload_test_users(self)
        self.assertTrue(self.user.has_perm(self.get_perm_code(extra), self.content))

    def test_15_configured_group_and_permission_models(self):
        self.assertIs(TrustGroup._meta.get_field('group').remote_field.model, get_group_model())
        self.assertIs(
            TrustGroupPermission._meta.get_field('permission').remote_field.model,
            get_permission_model(),
        )
        self.assertIs(
            TrustGroup._meta.get_field('permissions').remote_field.model,
            get_permission_model(),
        )

    def _outside_ceiling_perm(self):
        return Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Category),
            codename='delete_category',
        )

    def _assert_unassociated(self, group=None):
        group = group if group is not None else self.group
        self.assertFalse(TrustGroup.objects.filter(trust=self.org, group=group).exists())
        self.assertFalse(self.org.groups.filter(pk=group.pk).exists())

    def test_rejected_grant_does_not_create_association(self):
        extra = self._outside_ceiling_perm()
        self._assert_unassociated()
        with self.assertRaises(ValidationError):
            self.org.grant_group_permission(self.group, extra)
        self._assert_unassociated()

    def test_rejected_set_permissions_does_not_create_association(self):
        extra = self._outside_ceiling_perm()
        self._assert_unassociated()
        with self.assertRaises(ValidationError):
            self.org.set_group_permissions(self.group, [self.perm_read, extra])
        self._assert_unassociated()

    def test_rejected_associate_with_permissions_does_not_create_association(self):
        extra = self._outside_ceiling_perm()
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)
        self._assert_unassociated()
        with self.assertRaises(AuthorizationDenied):
            associate_group_with_trust(
                self.user, self.content, self.group, permissions=[extra]
            )
        self._assert_unassociated()

    def test_rejected_grant_keeps_existing_association(self):
        extra = self._outside_ceiling_perm()
        self.org.groups.add(self.group)
        with self.assertRaises(ValidationError):
            self.org.grant_group_permission(self.group, extra)
        self.assertTrue(TrustGroup.objects.filter(trust=self.org, group=self.group).exists())
        self.assertEqual(
            TrustGroup.objects.get(trust=self.org, group=self.group).permissions.count(),
            0,
        )

    def test_application_api_rejects_outside_ceiling_and_authorization_wraps(self):
        extra = self._outside_ceiling_perm()
        with self.assertRaises(ValidationError):
            self.org.grant_group_permission(self.group, extra)
        TrustUserPermission(
            trust=self.org, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)
        associate_group_with_trust(self.user, self.content, self.group)
        with self.assertRaises(AuthorizationDenied):
            grant_trust_group_permission(self.user, self.content, self.group, extra)
        grant_trust_group_permission(self.user, self.content, self.group, 'read')
        reload_test_users(self)
        self.assertTrue(self._has_read(self.user, self.content))
        grant_trustee(self.user, self.content, self.user1, 'change')
        reload_test_users(self)
        self.assertTrue(self._has_change(self.user1, self.content))
