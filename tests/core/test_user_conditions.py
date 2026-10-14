"""Named user conditions compiled into permission SQL (#312)."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TestCase, TransactionTestCase

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts._bind_once import bind_once
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    granted,
)


def _permission(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct, codename=codename, defaults={'name': codename},
    )
    return permission


class UserConditionSuiteTest(TestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_user_conditions', KERNEL_SUITE)
        self.assertIn('tests.core.test_user_conditions', PAIR_KERNEL_SUITE)


class UserConditionRegistrationTest(TransactionTestCase):
    def test_registration_walk_replace_and_remove(self):
        class Note(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(Note)
            editor.create_model(Grant)
        try:
            User = get_user_model()
            alice = User.objects.create_user('cond-alice', password='x')
            inactive = User.objects.create_user('cond-inactive', password='x')
            inactive.is_active = False
            inactive.is_superuser = True
            inactive.save(update_fields=['is_active', 'is_superuser'])
            note = Note.objects.create(title='n')
            read = _permission(Note, 'read_note_user_condition')
            Grant.objects.create(note=note, user=alice, permission=read)
            Grant.objects.create(note=note, user=inactive, permission=read)

            registry = TrustsRegistry()
            grant = Ref(Grant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            registry.register_user_condition(
                'staff', lambda u: u.is_active & u.is_superuser,
            )
            replaced = registry.register_user_condition(
                'staff', lambda u: ~u.is_superuser, on=('user',),
            )
            self.assertEqual(replaced.on, 'user')
            both = registry.register_user_condition(
                'either', lambda u: u.is_staff, on=('user', 'sponsor'),
            )
            self.assertEqual(both.on, '*')
            registry.register_user_condition('either', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.register_user_condition('missing', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.register_user_condition(
                    'bad', lambda u: u.is_authenticated,
                )
            with self.assertRaises(TrustsConfigurationError):
                registry.register_user_condition('nope', lambda u: u.username)
            with self.assertRaises(TrustsConfigurationError):
                registry.register_user_condition(
                    'where', lambda u: u.is_active, on='group',
                )

            active_sql = str(registry.permissions_for(alice, note).query)
            self.assertIn('is_active', active_sql)
            self.assertIn('is_superuser', active_sql)
            skipped = registry.permissions_for(
                inactive, note, skip_staff=True, skip_is_active=True,
            )
            self.assertEqual(
                set(skipped.values_list('pk', flat=True)), {read.pk},
            )
            self.assertNotIn('is_superuser', str(skipped.query))
            self.assertNotIn('is_active', str(skipped.query))

            registry.register_user_condition('is_active', None)
            registry.register_user_condition('staff', None)
            allowed = registry.permissions_for(inactive, note)
            self.assertEqual(
                set(allowed.values_list('pk', flat=True)), {read.pk},
            )
            self.assertNotIn('is_active', str(allowed.query))

            with self.assertRaises(TypeError):
                registry.permissions_for(alice, note, allow_inactive=True)
            registry.freeze()
            with self.assertRaises(TrustsConfigurationError):
                registry.register_user_condition(
                    'again', lambda u: u.is_active,
                )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Grant)
                editor.delete_model(Note)


class UserOverrideTest(TransactionTestCase):
    def test_checked_user_override_or_ordinary_grant(self):
        class Note(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Link(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(Note)
            editor.create_model(Grant)
            editor.create_model(Link)
        try:
            User = get_user_model()
            holder = User.objects.create_user('over-holder', password='x')
            superuser = User.objects.create_superuser(
                'over-super', password='x', email='s@example.com',
            )
            inactive = User.objects.create_superuser(
                'over-inactive', password='x', email='i@example.com',
            )
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            delegate = User.objects.create_user('over-delegate', password='x')
            note = Note.objects.create(title='n')
            read = _permission(Note, 'read_note_user_override')
            other = _permission(User, 'view_user_override_other')
            Grant.objects.create(note=note, user=holder, permission=read)
            Link.objects.create(note=note, delegate=delegate, sponsor=superuser)

            registry = TrustsRegistry()
            grant = Ref(Grant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            link = Ref(Link)
            registry.register_delegation(
                content=link.note, delegate=link.delegate, sponsor=link.sponsor,
            )
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override(
                    'superuser', lambda u: u.is_superuser, on='sponsor',
                )
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override(
                    'superuser', lambda u: u.is_superuser, on='*',
                )
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('missing', None)
            registry.set_user_override(
                'superuser',
                lambda u: u.is_active & u.is_superuser,
            )
            replaced = registry.set_user_override(
                'staff', lambda u: u.is_staff, on='user',
            )
            self.assertEqual(replaced.name, 'staff')
            registry.set_user_override(
                'superuser',
                lambda u: u.is_active & u.is_superuser,
            )

            allowed = registry.permissions_for(superuser, note)
            allowed_ids = set(allowed.values_list('pk', flat=True))
            self.assertIn(read.pk, allowed_ids)
            self.assertNotIn(other.pk, allowed_ids)
            self.assertIn('is_superuser', str(allowed.query))
            self.assertTrue(registry.has_permission(superuser, note, read))
            self.assertFalse(registry.has_permission(superuser, note, other))
            self.assertEqual(
                set(registry.permissions_for(holder, note).values_list(
                    'pk', flat=True,
                )),
                {read.pk},
            )
            self.assertFalse(registry.has_permission(delegate, note, read))
            self.assertEqual(
                list(registry.permissions_for(inactive, note)), [],
            )
            skipped = registry.permissions_for(
                inactive, note, skip_is_active=True,
            )
            self.assertEqual(list(skipped), [])
            self.assertIn('is_superuser', str(skipped.query))
            without = registry.permissions_for(
                superuser, note, skip_superuser=True,
            )
            self.assertEqual(list(without), [])
            self.assertNotIn('is_superuser', str(without.query))

            handle = BackendHandle(
                'user-override', registry, PlanQueryCompiler(),
            )

            def holds(user):
                predicate = granted((handle,), note, user, read)
                if predicate is None:
                    return False
                return bind_once(Note.objects.filter(
                    pk=note.pk,
                ).filter(predicate)).exists()

            self.assertTrue(holds(superuser))
            self.assertTrue(holds(holder))
            self.assertFalse(holds(delegate))
            Grant.objects.create(note=note, user=superuser, permission=read)
            self.assertTrue(holds(delegate))
            Grant.objects.filter(user=superuser).delete()

            registry.set_user_override('superuser', None)
            self.assertFalse(registry.has_permission(superuser, note, read))
            self.assertTrue(registry.has_permission(holder, note, read))
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', None)
            registry.freeze()
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override(
                    'superuser', lambda u: u.is_superuser,
                )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Link)
                editor.delete_model(Grant)
                editor.delete_model(Note)
