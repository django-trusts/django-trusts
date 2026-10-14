"""Named user conditions compiled into permission SQL (#312)."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TestCase, TransactionTestCase

from tests.core import KernelHostRequiredMixin
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document
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
            grant = Ref(Grant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
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

            open_registry = TrustsRegistry()
            open_registry.register_user_condition('is_active', None)
            open_registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            allowed = open_registry.permissions_for(inactive, note)
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
            registry.set_user_override('superuser', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', None)
            registry.set_user_override(
                'superuser',
                lambda u: u.is_active & u.is_superuser,
            )
            grant = Ref(Grant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            link = Ref(Link)
            registry.register_delegation(
                content=link.note, delegate=link.delegate, sponsor=link.sponsor,
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

            plain = TrustsRegistry()
            plain.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            plain.register_delegation(
                content=link.note, delegate=link.delegate, sponsor=link.sponsor,
            )
            self.assertFalse(plain.has_permission(superuser, note, read))
            self.assertTrue(plain.has_permission(holder, note, read))
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', None)
            self.assertEqual(registry._user_override.name, 'superuser')
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


class UserConditionTargetTest(TransactionTestCase):
    def test_on_selects_checked_user_or_ordinary_sponsor(self):
        class TargetNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class TargetGrant(models.Model):
            note = models.ForeignKey(TargetNote, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class TargetLink(models.Model):
            note = models.ForeignKey(TargetNote, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(TargetNote)
            editor.create_model(TargetGrant)
            editor.create_model(TargetLink)
        try:
            User = get_user_model()
            staff = User.objects.create_user('tgt-staff', password='x')
            staff.is_staff = True
            staff.save(update_fields=['is_staff'])
            plain = User.objects.create_user('tgt-plain', password='x')
            actor = User.objects.create_user('tgt-actor', password='x')
            superuser = User.objects.create_superuser(
                'tgt-super', password='x', email='t@example.com',
            )
            inactive = User.objects.create_user('tgt-inactive', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            note = TargetNote.objects.create(title='n')
            read = _permission(TargetNote, 'read_target_note')
            for user in (staff, plain, superuser, inactive):
                TargetGrant.objects.create(note=note, user=user, permission=read)

            grant = Ref(TargetGrant)
            link = Ref(TargetLink)

            def open_registry(configure):
                registry = TrustsRegistry()
                configure(registry)
                registry.register(
                    content=grant.note,
                    user=grant.user,
                    permission=grant.permission,
                )
                registry.register_delegation(
                    content=link.note,
                    delegate=link.delegate,
                    sponsor=link.sponsor,
                )
                return registry

            def holds(handle, user, **skip):
                predicate = granted((handle,), note, user, read, **skip)
                if predicate is None:
                    return False
                return bind_once(TargetNote.objects.filter(
                    pk=note.pk,
                ).filter(predicate)).exists()

            def sql_for(handle, user, **skip):
                predicate = granted((handle,), note, user, read, **skip)
                return str(bind_once(TargetNote.objects.filter(
                    pk=note.pk,
                ).filter(predicate)).query)

            staff_delegate = User.objects.create_user('tgt-staff-del', password='x')
            staff_delegate.is_staff = True
            staff_delegate.save(update_fields=['is_staff'])
            staff_registry = open_registry(
                lambda registry: registry.register_user_condition(
                    'staff', lambda u: u.is_staff, on='user',
                ),
            )
            staff_handle = BackendHandle(
                'user-target-staff', staff_registry, PlanQueryCompiler(),
            )
            TargetLink.objects.create(
                note=note, delegate=staff_delegate, sponsor=plain,
            )
            self.assertTrue(holds(staff_handle, staff))
            self.assertFalse(holds(staff_handle, plain))
            self.assertTrue(holds(staff_handle, staff_delegate))
            self.assertFalse(holds(staff_handle, actor))
            delegated_sql = sql_for(staff_handle, staff_delegate)
            self.assertIn('is_staff', delegated_sql)
            self.assertNotIn('sponsor__is_staff', delegated_sql)
            self.assertIn('delegate', delegated_sql)
            own = str(staff_registry.permissions_for(staff, note).query)
            self.assertIn('is_staff', own)

            sponsor_registry = open_registry(
                lambda registry: registry.register_user_condition(
                    'sponsor_not_super', lambda u: ~u.is_superuser, on='sponsor',
                ),
            )
            sponsor_handle = BackendHandle(
                'user-target-sponsor', sponsor_registry, PlanQueryCompiler(),
            )
            TargetLink.objects.all().delete()
            TargetLink.objects.create(
                note=note, delegate=actor, sponsor=superuser,
            )
            self.assertFalse(holds(sponsor_handle, actor))
            sponsor_sql = sql_for(sponsor_handle, actor)
            self.assertIn('is_superuser', sponsor_sql)
            self.assertNotIn('delegate__is_superuser', sponsor_sql)
            TargetLink.objects.all().delete()
            TargetLink.objects.create(
                note=note, delegate=actor, sponsor=plain,
            )
            self.assertTrue(holds(sponsor_handle, actor))
            self.assertTrue(holds(sponsor_handle, superuser))
            checked = str(sponsor_registry.permissions_for(superuser, note).query)
            self.assertNotIn('is_superuser', checked)

            user_active = open_registry(
                lambda registry: registry.register_user_condition(
                    'is_active', lambda u: u.is_active, on='user',
                ),
            )
            user_handle = BackendHandle(
                'user-target-active-user', user_active, PlanQueryCompiler(),
            )
            TargetLink.objects.all().delete()
            TargetLink.objects.create(
                note=note, delegate=actor, sponsor=inactive,
            )
            self.assertTrue(holds(user_handle, actor))
            self.assertFalse(holds(user_handle, inactive))
            sponsor_active = open_registry(
                lambda registry: registry.register_user_condition(
                    'is_active', lambda u: u.is_active, on='sponsor',
                ),
            )
            sponsor_active_handle = BackendHandle(
                'user-target-active-sponsor', sponsor_active, PlanQueryCompiler(),
            )
            self.assertTrue(holds(sponsor_active_handle, inactive))
            self.assertFalse(holds(sponsor_active_handle, actor))
            both_active = open_registry(
                lambda registry: registry.register_user_condition(
                    'is_active', lambda u: u.is_active, on='*',
                ),
            )
            both_handle = BackendHandle(
                'user-target-active-both', both_active, PlanQueryCompiler(),
            )
            self.assertFalse(holds(both_handle, actor))
            self.assertFalse(holds(both_handle, inactive))
            self.assertTrue(holds(both_handle, actor, skip_is_active=True))
            self.assertTrue(holds(both_handle, inactive, skip_is_active=True))
            skipped_sql = sql_for(both_handle, actor, skip_is_active=True)
            self.assertNotIn('is_active', skipped_sql)

            removed = open_registry(
                lambda registry: registry.register_user_condition('is_active', None),
            )
            removed_handle = BackendHandle(
                'user-target-removed', removed, PlanQueryCompiler(),
            )
            self.assertTrue(holds(removed_handle, inactive))
            self.assertTrue(holds(removed_handle, actor))
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(TargetLink)
                editor.delete_model(TargetGrant)
                editor.delete_model(TargetNote)


class UserRuleOrderTest(TestCase):
    def test_rules_after_registration_raise_and_leave_rules_unchanged(self):
        class OrderNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class OrderGrant(models.Model):
            note = models.ForeignKey(OrderNote, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class OrderLink(models.Model):
            note = models.ForeignKey(OrderNote, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        registry.register_user_condition('staff', lambda u: u.is_staff)
        grant = Ref(OrderGrant)
        registry.register(
            content=grant.note, user=grant.user, permission=grant.permission,
        )
        names = tuple(rule.name for rule in registry.user_conditions())
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.register_user_condition(
                'extra', lambda u: u.is_superuser,
            )
        self.assertIn('before', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            registry.register_user_condition('staff', None)
        with self.assertRaises(TrustsConfigurationError):
            registry.set_user_override(
                'superuser', lambda u: u.is_superuser,
            )
        self.assertEqual(
            tuple(rule.name for rule in registry.user_conditions()), names,
        )
        self.assertIsNone(registry._user_override)
        self.assertEqual(len(registry.records), 1)

        delegation_only = TrustsRegistry()
        link = Ref(OrderLink)
        delegation_only.register_delegation(
            content=link.note, delegate=link.delegate, sponsor=link.sponsor,
        )
        with self.assertRaises(TrustsConfigurationError):
            delegation_only.register_user_condition(
                'staff', lambda u: u.is_staff,
            )
        with self.assertRaises(TrustsConfigurationError):
            delegation_only.set_user_override(
                'superuser', lambda u: u.is_superuser,
            )
        self.assertIsNone(delegation_only._user_conditions)
        self.assertIsNone(delegation_only._user_override)
        self.assertEqual(len(delegation_only.delegations), 1)

    def test_failed_register_does_not_mutate(self):
        class FitNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class OtherNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class BarePrincipal(models.Model):
            label = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class FitGrant(models.Model):
            note = models.ForeignKey(FitNote, on_delete=models.CASCADE)
            other = models.ForeignKey(OtherNote, on_delete=models.CASCADE)
            user = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )
            bare = models.ForeignKey(
                BarePrincipal, related_name='+', on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE,
            )
            other_permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class BareGrant(models.Model):
            note = models.ForeignKey(FitNote, on_delete=models.CASCADE)
            user = models.ForeignKey(BarePrincipal, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class FitLink(models.Model):
            note = models.ForeignKey(FitNote, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                'auth.User', related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class BareLink(models.Model):
            note = models.ForeignKey(FitNote, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                BarePrincipal, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                BarePrincipal, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        registry.register_user_condition(
            'superuser', lambda u: u.is_superuser,
        )
        fit = Ref(FitGrant)
        registry.register(
            content=fit.note, user=fit.user, permission=fit.permission,
        )
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=fit.other, user=fit.bare, permission=fit.other_permission,
            )
        self.assertEqual(len(registry._order), 1)
        self.assertEqual(list(registry._by_root), [FitGrant])
        self.assertEqual(len(registry._by_root[FitGrant]), 1)
        self.assertEqual(registry._delegation_order, [])
        self.assertEqual(registry._delegations_by_root, {})

        fresh = TrustsRegistry()
        fresh.register_user_condition('superuser', lambda u: u.is_superuser)
        bare = Ref(BareGrant)
        with self.assertRaises(TrustsConfigurationError):
            fresh.register(
                content=bare.note, user=bare.user, permission=bare.permission,
            )
        self.assertEqual(fresh._order, [])
        self.assertEqual(fresh._by_root, {})

        override_only = TrustsRegistry()
        override_only.set_user_override(
            'superuser', lambda u: u.is_superuser,
        )
        with self.assertRaises(TrustsConfigurationError):
            override_only.register(
                content=bare.note, user=bare.user, permission=bare.permission,
            )
        self.assertEqual(override_only._order, [])
        self.assertEqual(override_only._by_root, {})
        self.assertEqual(override_only._user_override.name, 'superuser')

        delegated = TrustsRegistry()
        delegated.register_user_condition(
            'staff', lambda u: u.is_staff, on='sponsor',
        )
        fit_link = Ref(FitLink)
        delegated.register_delegation(
            content=fit_link.note,
            delegate=fit_link.delegate,
            sponsor=fit_link.sponsor,
        )
        bare_link = Ref(BareLink)
        with self.assertRaises(TrustsConfigurationError):
            delegated.register_delegation(
                content=bare_link.note,
                delegate=bare_link.delegate,
                sponsor=bare_link.sponsor,
            )
        self.assertEqual(len(delegated._delegation_order), 1)
        self.assertEqual(list(delegated._delegations_by_root), [FitLink])
        self.assertNotIn(BareLink, delegated._delegations_by_root)
        self.assertEqual(delegated._order, [])

        empty_delegation = TrustsRegistry()
        empty_delegation.register_user_condition(
            'staff', lambda u: u.is_staff, on='sponsor',
        )
        with self.assertRaises(TrustsConfigurationError):
            empty_delegation.register_delegation(
                content=bare_link.note,
                delegate=bare_link.delegate,
                sponsor=bare_link.sponsor,
            )
        self.assertEqual(empty_delegation._delegation_order, [])
        self.assertEqual(empty_delegation._delegations_by_root, {})


class SkipKeywordTest(TransactionTestCase):
    def test_custom_condition_skip_keyword(self):
        class SkipNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class SkipGrant(models.Model):
            note = models.ForeignKey(SkipNote, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(SkipNote)
            editor.create_model(SkipGrant)
        try:
            User = get_user_model()
            alice = User.objects.create_user('skip-alice', password='x')
            note = SkipNote.objects.create(title='n')
            read = _permission(SkipNote, 'read_note_skip_keyword')
            SkipGrant.objects.create(note=note, user=alice, permission=read)
            registry = TrustsRegistry()
            registry.register_user_condition(
                'staff', lambda u: u.is_superuser,
            )
            grant = Ref(SkipGrant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )

            denied = registry.permissions_for(alice, note)
            self.assertEqual(list(denied), [])
            self.assertIn('is_superuser', str(denied.query))
            skipped = registry.permissions_for(alice, note, skip_staff=True)
            self.assertEqual(
                set(skipped.values_list('pk', flat=True)), {read.pk},
            )
            self.assertNotIn('is_superuser', str(skipped.query))
            self.assertIn('is_active', str(skipped.query))
            self.assertTrue(
                registry.has_permission(alice, note, read, skip_staff=True),
            )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(SkipGrant)
                editor.delete_model(SkipNote)

    def test_unknown_skip_keyword_raises(self):
        class UnknownNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class UnknownGrant(models.Model):
            note = models.ForeignKey(UnknownNote, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(UnknownNote)
            editor.create_model(UnknownGrant)
        try:
            User = get_user_model()
            alice = User.objects.create_user('skip-unknown', password='x')
            inactive = User.objects.create_user('skip-unknown-off', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            note = UnknownNote.objects.create(title='n')
            read = _permission(UnknownNote, 'read_note_unknown_skip')
            UnknownGrant.objects.create(note=note, user=alice, permission=read)
            registry = TrustsRegistry()
            grant = Ref(UnknownGrant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            for value in (True, False):
                with self.assertRaises(TypeError) as ctx:
                    registry.permissions_for(alice, note, skip_nope=value)
                self.assertIn('skip_nope', str(ctx.exception))
            with self.assertRaises(TypeError) as ctx:
                registry.permissions_for(inactive, note, skip_nope=True)
            self.assertIn('skip_nope', str(ctx.exception))

            removed = TrustsRegistry()
            removed.register_user_condition('is_active', None)
            removed.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            with self.assertRaises(TypeError) as ctx:
                removed.permissions_for(alice, note, skip_is_active=True)
            self.assertIn('skip_is_active', str(ctx.exception))
            with self.assertRaises(TypeError) as ctx:
                registry.permissions_for(alice, note, skip_superuser=True)
            self.assertIn('skip_superuser', str(ctx.exception))
            self.assertEqual(
                set(removed.permissions_for(alice, note).values_list(
                    'pk', flat=True,
                )),
                {read.pk},
            )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(UnknownGrant)
                editor.delete_model(UnknownNote)

    def test_override_skip_keyword_follows_the_current_name(self):
        class OverrideNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class OverrideGrant(models.Model):
            note = models.ForeignKey(OverrideNote, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with connection.schema_editor() as editor:
            editor.create_model(OverrideNote)
            editor.create_model(OverrideGrant)
        try:
            User = get_user_model()
            staff = User.objects.create_user('skip-ov-staff', password='x')
            staff.is_staff = True
            staff.save(update_fields=['is_staff'])
            superuser = User.objects.create_user('skip-ov-super', password='x')
            superuser.is_superuser = True
            superuser.is_staff = False
            superuser.save(update_fields=['is_superuser', 'is_staff'])
            note = OverrideNote.objects.create(title='n')
            read = _permission(OverrideNote, 'read_note_override_skip')
            registry = TrustsRegistry()
            registry.set_user_override(
                'superuser', lambda u: u.is_superuser,
            )
            registry.set_user_override('staff', lambda u: u.is_staff)
            grant = Ref(OverrideGrant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            allowed = registry.permissions_for(staff, note)
            self.assertEqual(
                set(allowed.values_list('pk', flat=True)), {read.pk},
            )
            self.assertIn('is_staff', str(allowed.query))
            skipped = registry.permissions_for(staff, note, skip_staff=True)
            self.assertEqual(list(skipped), [])
            self.assertNotIn('is_staff', str(skipped.query))
            self.assertEqual(list(registry.permissions_for(superuser, note)), [])
            with self.assertRaises(TypeError) as ctx:
                registry.permissions_for(staff, note, skip_superuser=True)
            self.assertIn('skip_superuser', str(ctx.exception))
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(OverrideGrant)
                editor.delete_model(OverrideNote)


class SkipKeywordNameTest(TestCase):
    def test_condition_name_must_be_an_identifier(self):
        registry = TrustsRegistry()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.register_user_condition(
                'not-a-name', lambda u: u.is_active,
            )
        self.assertIn('identifier', str(ctx.exception))
        self.assertIsNone(registry._user_conditions)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.register_user_condition('flags', lambda u: u.is_active)
        self.assertIn('collides', str(ctx.exception))
        self.assertIsNone(registry._user_conditions)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('user', lambda u: u.is_superuser)
        self.assertIn('collides', str(ctx.exception))
        self.assertIsNone(registry._user_override)
        registry.register_user_condition('staff', lambda u: u.is_staff)
        self.assertEqual(
            tuple(rule.name for rule in registry.user_conditions()),
            ('is_active', 'staff'),
        )

    def test_condition_and_override_cannot_share_a_name(self):
        registry = TrustsRegistry()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('is_active', lambda u: u.is_superuser)
        self.assertIn('collides', str(ctx.exception))
        self.assertIsNone(registry._user_override)
        registry.register_user_condition('staff', lambda u: u.is_staff)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('staff', lambda u: u.is_staff)
        self.assertIn('collides', str(ctx.exception))
        self.assertIsNone(registry._user_override)
        registry.set_user_override('superuser', lambda u: u.is_superuser)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.register_user_condition(
                'superuser', lambda u: u.is_superuser,
            )
        self.assertIn('collides', str(ctx.exception))
        self.assertEqual(registry._user_override.name, 'superuser')
        self.assertNotIn(
            'superuser',
            tuple(rule.name for rule in registry.user_conditions()),
        )
        with self.assertRaises(TrustsConfigurationError):
            registry.set_user_override('staff', lambda u: u.is_staff)
        self.assertEqual(registry._user_override.name, 'superuser')
        opened = TrustsRegistry()
        opened.register_user_condition('is_active', None)
        opened.set_user_override('is_active', lambda u: u.is_superuser)
        self.assertEqual(opened._user_override.name, 'is_active')


class SkipKeywordInquiryTest(KernelHostRequiredMixin, TestCase):
    def test_unknown_skip_keyword_on_inquiry_apis(self):
        from django.contrib.auth.models import Permission as AuthPermission

        from trusts.query import PermittedQuerySet

        User = get_user_model()
        alice = User.objects.create_user('skip-inquiry', password='x')
        ct = ContentType.objects.get_for_model(Document)
        change, _created = AuthPermission.objects.get_or_create(
            content_type=ct, codename='change_document',
            defaults={'name': 'change'},
        )
        document = Document.objects.create(title='skip-inquiry')
        backend = DocumentBackend()
        with self.assertRaises(TypeError) as ctx:
            backend.has_perm(alice, 'myapp.change_document', document, skip_nope=True)
        self.assertIn('skip_nope', str(ctx.exception))
        with self.assertRaises(TypeError):
            Document.objects.authorized(alice, change, skip_nope=False)
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertRaises(TypeError):
            permitted.permitted(change, alice, skip_nope=True)
        with self.assertRaises(TypeError):
            document.get_permitted_users(change, skip_nope=True)
        self.assertFalse(
            backend.has_perm(
                AnonymousUser(), 'myapp.change_document', document,
                skip_nope=True,
            ),
        )
