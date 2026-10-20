"""Named user conditions compiled into permission SQL (#312)."""
from trusts.backends import TrustModelBackendMixin
import inspect
from asgiref.sync import async_to_sync
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import HttpRequest
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import path, reverse
from tests.support import render_configured_policy, configured_catalog, built_registries, built_catalog
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.plan.rewrites import bind_once
from tests.support import scoped_permitted_content as filter_by_permitted_content
from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import RegistryFactory
from trusts.plan.contents import granted
from trusts.decorators import _declared_authorization_guards, authorization_required
from trusts.inspect.snapshot import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import PermittedQuerySet, PermittedUsersManagerMixin
urlpatterns = [path('admin/', admin.site.urls)]

def _permission(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(content_type=ct, codename=codename, defaults={'name': codename})
    return permission

class UserConditionSuiteTest(TestCase):

    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_user_conditions', KERNEL_SUITE)
        self.assertIn('tests.core.test_user_conditions', PAIR_KERNEL_SUITE)

class UserConditionRegistrationTest(TransactionTestCase):

    def test_is_active_name_does_not_bypass_expression_validation(self):
        for expr in (lambda u: u.username, lambda u: u.is_authenticated, lambda u: u.does_not_exist):
            with self.subTest(expr=expr):
                registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        registry.set_user_condition('is_active', expr)
                self.assertIsNone(registry.build().user_conditions)

    def test_tuple_targets_are_rejected_without_mutation(self):
        for target in ((), ('user',), ('sponsor',), ('user', 'sponsor')):
            with self.subTest(target=target):
                registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        registry.set_user_condition('staff', lambda u: u.is_staff, on=target)
                self.assertIsNone(registry.build().user_conditions)

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
            read = _permission(Note, 'read_note_user_condition_note')
            Grant.objects.create(note=note, user=alice, permission=read)
            Grant.objects.create(note=note, user=inactive, permission=read)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            registry.set_user_condition('staff', lambda u: u.is_active & u.is_superuser)
            replaced = registry.set_user_condition('staff', lambda u: ~u.is_superuser, on='user')
            self.assertEqual(replaced.on, 'user')
            both = registry.set_user_condition('either', lambda u: u.is_staff, on='*')
            self.assertEqual(both.on, '*')
            registry.set_user_condition('either', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_condition('missing', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_condition('bad', lambda u: u.is_authenticated)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_condition('nope', lambda u: u.username)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_condition('where', lambda u: u.is_active, on='group')
            grant = Ref(Grant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            active_sql = str(built_catalog(registry).permissions_for(alice, note).query)
            self.assertIn('is_active', active_sql)
            self.assertIn('is_superuser', active_sql)
            plain = built_catalog(registry).permissions_for(alice, note)
            skipped = built_catalog(registry).permissions_for(inactive, note, skip_staff=True, skip_is_active=True)
            self.assertEqual(set(skipped.values_list('pk', flat=True)), {read.pk})
            self.assertEqual(skipped.query.sql_with_params()[0], plain.query.sql_with_params()[0])
            self.assertIn('is_superuser', str(skipped.query))
            self.assertIn('is_active', str(skipped.query))
            open_registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            open_registry.set_user_condition('is_active', None)
            open_registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            allowed = built_catalog(open_registry).permissions_for(inactive, note)
            self.assertEqual(set(allowed.values_list('pk', flat=True)), {read.pk})
            self.assertNotIn('is_active', str(allowed.query))
            with self.assertRaises(TypeError):
                built_catalog(registry).permissions_for(alice, note, allow_inactive=True)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_condition('again', lambda u: u.is_active)
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Grant)
                editor.delete_model(Note)

class PreRegistrationPlanFragmentTest(TransactionTestCase):
    """A plan built before registration must not keep a stale rule."""

    def test_add_replace_and_remove_after_plan_for(self):

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
            plain = User.objects.create_user('frag-plain', password='x')
            staff = User.objects.create_user('frag-staff', password='x')
            staff.is_staff = True
            staff.save(update_fields=['is_staff'])
            staff_only = User.objects.create_user('frag-staff-only', password='x')
            staff_only.is_staff = True
            staff_only.save(update_fields=['is_staff'])
            superuser = User.objects.create_superuser('frag-super', password='x', email='frag@example.com')
            inactive = User.objects.create_user('frag-inactive', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            note = Note.objects.create(title='n')
            read = _permission(Note, 'read_note_plan_fragment_note')
            for holder in (plain, staff, inactive):
                Grant.objects.create(note=note, user=holder, permission=read)
            grant = Ref(Grant)

            def register(registry):
                registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            preview = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            built = built_catalog(preview)
            self.assertIsNotNone(built.plan_for(Note, user=plain).user_rules)
            added = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            added.set_user_condition('staff', lambda u: u.is_staff)
            register(added)
            self.assertFalse(built_catalog(added).has_perm(plain, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertIn('is_staff', str(built_catalog(added).permissions_for(plain, note).query))
            replaced = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            replaced.set_user_condition('staff', lambda u: u.is_staff)
            replaced.set_user_condition('staff', lambda u: u.is_superuser)
            register(replaced)
            self.assertFalse(built_catalog(replaced).has_perm(staff, '%s.%s' % (read.content_type.app_label, read.codename), note))
            replaced_sql = str(built_catalog(replaced).permissions_for(staff, note).query)
            self.assertIn('is_superuser', replaced_sql)
            self.assertNotIn('is_staff', replaced_sql)
            removed = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            removed.set_user_condition('is_active', None)
            register(removed)
            self.assertTrue(built_catalog(removed).has_perm(inactive, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertNotIn('is_active', str(built_catalog(removed).permissions_for(inactive, note).query))
            override = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            override.set_user_override('superuser', lambda u: u.is_superuser)
            register(override)
            self.assertTrue(built_catalog(override).has_perm(superuser, '%s.%s' % (read.content_type.app_label, read.codename), note))
            replaced_override = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            replaced_override.set_user_override('staff', lambda u: u.is_staff)
            replaced_override.set_user_override('superuser', lambda u: u.is_superuser)
            register(replaced_override)
            self.assertFalse(built_catalog(replaced_override).has_perm(staff_only, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertTrue(built_catalog(replaced_override).has_perm(superuser, '%s.%s' % (read.content_type.app_label, read.codename), note))
            cleared = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            cleared.set_user_override('superuser', lambda u: u.is_superuser)
            cleared.set_user_override('superuser', None)
            register(cleared)
            self.assertFalse(built_catalog(cleared).has_perm(superuser, '%s.%s' % (read.content_type.app_label, read.codename), note))
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
            delegate = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        with connection.schema_editor() as editor:
            editor.create_model(Note)
            editor.create_model(Grant)
            editor.create_model(Link)
        try:
            User = get_user_model()
            holder = User.objects.create_user('over-holder', password='x')
            superuser = User.objects.create_superuser('over-super', password='x', email='s@example.com')
            inactive = User.objects.create_superuser('over-inactive', password='x', email='i@example.com')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            delegate = User.objects.create_user('over-delegate', password='x')
            note = Note.objects.create(title='n')
            read = _permission(Note, 'read_note_user_override_note')
            other = _permission(User, 'view_user_override_other_user')
            Grant.objects.create(note=note, user=holder, permission=read)
            Link.objects.create(note=note, delegate=delegate, sponsor=superuser)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', lambda u: u.is_superuser, on='sponsor')
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', lambda u: u.is_superuser, on='*')
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('missing', None)
            registry.set_user_override('superuser', lambda u: u.is_active & u.is_superuser)
            replaced = registry.set_user_override('staff', lambda u: u.is_staff, on='user')
            self.assertEqual(replaced.name, 'staff')
            registry.set_user_override('superuser', lambda u: u.is_active & u.is_superuser)
            registry.set_user_override('superuser', None)
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', None)
            registry.set_user_override('superuser', lambda u: u.is_active & u.is_superuser)
            grant = Ref(Grant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            link = Ref(Link)
            registry.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
            allowed = built_catalog(registry).permissions_for(superuser, note)
            allowed_ids = set(allowed.values_list('pk', flat=True))
            self.assertIn(read.pk, allowed_ids)
            self.assertNotIn(other.pk, allowed_ids)
            self.assertIn('is_superuser', str(allowed.query))
            self.assertTrue(built_catalog(registry).has_perm(superuser, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertFalse(built_catalog(registry).has_perm(superuser, '%s.%s' % (other.content_type.app_label, other.codename), note))
            self.assertEqual(set(built_catalog(registry).permissions_for(holder, note).values_list('pk', flat=True)), {read.pk})
            self.assertFalse(built_catalog(registry).has_perm(delegate, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertEqual(list(built_catalog(registry).permissions_for(inactive, note)), [])
            skipped = built_catalog(registry).permissions_for(inactive, note, skip_is_active=True)
            self.assertEqual(list(skipped), [])
            self.assertIn('is_superuser', str(skipped.query))
            without = built_catalog(registry).permissions_for(superuser, note, skip_superuser=True)
            self.assertEqual(list(without), [])
            self.assertEqual(without.query.sql_with_params()[0], allowed.query.sql_with_params()[0])
            self.assertIn('is_superuser', str(without.query))
            registry.path = 'user-override'
            handle = registry

            def holds(user):
                predicate = granted(built_catalog(handle), note, user, read)
                if predicate is None:
                    return False
                return bind_once(Note.objects.filter(pk=note.pk).filter(predicate)).exists()
            self.assertTrue(holds(superuser))
            self.assertTrue(holds(holder))
            self.assertFalse(holds(delegate))
            Grant.objects.create(note=note, user=superuser, permission=read)
            self.assertTrue(holds(delegate))
            Grant.objects.filter(user=superuser).delete()
            plain = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            plain.register(content=grant.note, user=grant.user, permission=grant.permission)
            plain.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
            self.assertFalse(built_catalog(plain).has_perm(superuser, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertTrue(built_catalog(plain).has_perm(holder, '%s.%s' % (read.content_type.app_label, read.codename), note))
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', None)
            self.assertEqual(registry.build().user_override.name, 'superuser')
            with self.assertRaises(TrustsConfigurationError):
                registry.set_user_override('superuser', lambda u: u.is_superuser)
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
            delegate = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)

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
            superuser = User.objects.create_superuser('tgt-super', password='x', email='t@example.com')
            inactive = User.objects.create_user('tgt-inactive', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            note = TargetNote.objects.create(title='n')
            read = _permission(TargetNote, 'read_target_note_targetnote')
            for user in (staff, plain, superuser, inactive):
                TargetGrant.objects.create(note=note, user=user, permission=read)
            grant = Ref(TargetGrant)
            link = Ref(TargetLink)

            def open_registry(configure):
                registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
                configure(registry)
                registry.register(content=grant.note, user=grant.user, permission=grant.permission)
                registry.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
                return registry

            def holds(handle, user, **skip):
                from trusts.plan.relations import user_skip_params
                inquiry = user_skip_params(user, skip, subjects=built_registries((handle,)))
                predicate = granted(built_catalog(handle), note, user, read, skipped=inquiry.values)
                if predicate is None:
                    return False
                return bind_once(TargetNote.objects.filter(pk=note.pk).filter(predicate)).exists()

            def sql_for(handle, user, **skip):
                from trusts.plan.relations import user_skip_params
                inquiry = user_skip_params(user, skip, subjects=built_registries((handle,)))
                predicate = granted(built_catalog(handle), note, user, read, skipped=inquiry.values)
                return bind_once(TargetNote.objects.filter(pk=note.pk).filter(predicate)).query.sql_with_params()[0]
            staff_delegate = User.objects.create_user('tgt-staff-del', password='x')
            staff_delegate.is_staff = True
            staff_delegate.save(update_fields=['is_staff'])
            staff_registry = open_registry(lambda registry: registry.set_user_condition('staff', lambda u: u.is_staff, on='user'))
            staff_registry.path = 'user-target-staff'
            staff_handle = staff_registry
            TargetLink.objects.create(note=note, delegate=staff_delegate, sponsor=plain)
            self.assertTrue(holds(staff_handle, staff))
            self.assertFalse(holds(staff_handle, plain))
            self.assertTrue(holds(staff_handle, staff_delegate))
            self.assertFalse(holds(staff_handle, actor))
            delegated_sql = sql_for(staff_handle, staff_delegate)
            self.assertIn('is_staff', delegated_sql)
            self.assertNotIn('sponsor__is_staff', delegated_sql)
            self.assertIn('delegate', delegated_sql)
            own = str(built_catalog(staff_registry).permissions_for(staff, note).query)
            self.assertIn('is_staff', own)
            sponsor_registry = open_registry(lambda registry: registry.set_user_condition('sponsor_not_super', lambda u: ~u.is_superuser, on='sponsor'))
            sponsor_registry.path = 'user-target-sponsor'
            sponsor_handle = sponsor_registry
            TargetLink.objects.all().delete()
            TargetLink.objects.create(note=note, delegate=actor, sponsor=superuser)
            self.assertFalse(holds(sponsor_handle, actor))
            sponsor_sql = sql_for(sponsor_handle, actor)
            self.assertIn('is_superuser', sponsor_sql)
            self.assertNotIn('delegate__is_superuser', sponsor_sql)
            TargetLink.objects.all().delete()
            TargetLink.objects.create(note=note, delegate=actor, sponsor=plain)
            self.assertTrue(holds(sponsor_handle, actor))
            self.assertTrue(holds(sponsor_handle, superuser))
            user_active = open_registry(lambda registry: registry.set_user_condition('is_active', lambda u: u.is_active, on='user'))
            user_active.path = 'user-target-active-user'
            user_handle = user_active
            TargetLink.objects.all().delete()
            TargetLink.objects.create(note=note, delegate=actor, sponsor=inactive)
            self.assertTrue(holds(user_handle, actor))
            self.assertFalse(holds(user_handle, inactive))
            sponsor_active = open_registry(lambda registry: registry.set_user_condition('is_active', lambda u: u.is_active, on='sponsor'))
            sponsor_active.path = 'user-target-active-sponsor'
            sponsor_active_handle = sponsor_active
            self.assertTrue(holds(sponsor_active_handle, inactive))
            self.assertFalse(holds(sponsor_active_handle, actor))
            both_active = open_registry(lambda registry: registry.set_user_condition('is_active', lambda u: u.is_active, on='*'))
            both_active.path = 'user-target-active-both'
            both_handle = both_active
            self.assertFalse(holds(both_handle, actor))
            self.assertFalse(holds(both_handle, inactive))
            self.assertTrue(holds(both_handle, actor, skip_is_active=True))
            self.assertTrue(holds(both_handle, inactive, skip_is_active=True))
            skipped_sql = sql_for(both_handle, actor, skip_is_active=True)
            self.assertEqual(skipped_sql, sql_for(both_handle, actor))
            self.assertIn('is_active', skipped_sql)
            removed = open_registry(lambda registry: registry.set_user_condition('is_active', None))
            removed.path = 'user-target-removed'
            removed_handle = removed
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
            delegate = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        registry.set_user_condition('staff', lambda u: u.is_staff)
        grant = Ref(OrderGrant)
        registry.register(content=grant.note, user=grant.user, permission=grant.permission)
        names = tuple((rule.name for rule in registry.user_conditions()))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_condition('extra', lambda u: u.is_superuser)
        self.assertIn('before', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            registry.set_user_condition('staff', None)
        with self.assertRaises(TrustsConfigurationError):
            registry.set_user_override('superuser', lambda u: u.is_superuser)
        self.assertEqual(tuple((rule.name for rule in registry.user_conditions())), names)
        self.assertIsNone(registry.build().user_override)
        self.assertEqual(len(registry.records), 1)
        delegation_only = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        link = Ref(OrderLink)
        delegation_only.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
        with self.assertRaises(TrustsConfigurationError):
            delegation_only.set_user_condition('staff', lambda u: u.is_staff)
        with self.assertRaises(TrustsConfigurationError):
            delegation_only.set_user_override('superuser', lambda u: u.is_superuser)
        missed = delegation_only.build()
        self.assertIsNone(missed.user_conditions)
        self.assertIsNone(missed.user_override)
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
            user = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
            bare = models.ForeignKey(BarePrincipal, related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, related_name='+', on_delete=models.CASCADE)
            other_permission = models.ForeignKey(Permission, related_name='+', on_delete=models.CASCADE)

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
            delegate = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class BareLink(models.Model):
            note = models.ForeignKey(FitNote, on_delete=models.CASCADE)
            delegate = models.ForeignKey(BarePrincipal, related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey(BarePrincipal, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        registry.set_user_condition('superuser', lambda u: u.is_superuser)
        fit = Ref(FitGrant)
        registry.register(content=fit.note, user=fit.user, permission=fit.permission)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(content=fit.other, user=fit.bare, permission=fit.other_permission)
        shape = registry.build()
        self.assertEqual([record.root for record in shape.records], [FitGrant])
        self.assertEqual(shape.delegations, ())
        fresh = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        fresh.set_user_condition('superuser', lambda u: u.is_superuser)
        bare = Ref(BareGrant)
        with self.assertRaises(TrustsConfigurationError):
            fresh.register(content=bare.note, user=bare.user, permission=bare.permission)
        self.assertEqual(fresh.build().records, ())
        override_only = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        override_only.set_user_override('superuser', lambda u: u.is_superuser)
        with self.assertRaises(TrustsConfigurationError):
            override_only.register(content=bare.note, user=bare.user, permission=bare.permission)
        kept = override_only.build()
        self.assertEqual(kept.records, ())
        self.assertEqual(kept.user_override.name, 'superuser')
        delegated = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        delegated.set_user_condition('staff', lambda u: u.is_staff, on='sponsor')
        fit_link = Ref(FitLink)
        delegated.register_delegation(content=fit_link.note, delegate=fit_link.delegate, sponsor=fit_link.sponsor)
        bare_link = Ref(BareLink)
        with self.assertRaises(TrustsConfigurationError):
            delegated.register_delegation(content=bare_link.note, delegate=bare_link.delegate, sponsor=bare_link.sponsor)
        linked = delegated.build()
        self.assertEqual([record.root for record in linked.delegations], [FitLink])
        self.assertEqual(linked.records, ())
        empty_delegation = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        empty_delegation.set_user_condition('staff', lambda u: u.is_staff, on='sponsor')
        with self.assertRaises(TrustsConfigurationError):
            empty_delegation.register_delegation(content=bare_link.note, delegate=bare_link.delegate, sponsor=bare_link.sponsor)
        self.assertEqual(empty_delegation.build().delegations, ())

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
            read = _permission(SkipNote, 'read_note_skip_keyword_skipnote')
            SkipGrant.objects.create(note=note, user=alice, permission=read)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            registry.set_user_condition('staff', lambda u: u.is_superuser)
            grant = Ref(SkipGrant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            denied = built_catalog(registry).permissions_for(alice, note)
            with self.assertNumQueries(1):
                self.assertEqual(list(denied), [])
            skipped = built_catalog(registry).permissions_for(alice, note, skip_staff=True)
            self.assertEqual(set(skipped.values_list('pk', flat=True)), {read.pk})
            self.assertEqual(skipped.query.sql_with_params()[0], denied.query.sql_with_params()[0])
            self.assertIn('is_superuser', str(skipped.query))
            self.assertIn('is_active', str(skipped.query))
            self.assertTrue(built_catalog(registry).has_perm(alice, '%s.%s' % (read.content_type.app_label, read.codename), note, skip_staff=True))
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
            read = _permission(UnknownNote, 'read_note_unknown_skip_unknownnote')
            UnknownGrant.objects.create(note=note, user=alice, permission=read)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            grant = Ref(UnknownGrant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            for value in (True, False):
                with self.assertRaises(TypeError) as ctx:
                    built_catalog(registry).permissions_for(alice, note, skip_nope=value)
                self.assertIn('skip_nope', str(ctx.exception))
            with self.assertRaises(TypeError) as ctx:
                built_catalog(registry).permissions_for(inactive, note, skip_nope=True)
            self.assertIn('skip_nope', str(ctx.exception))
            removed = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            removed.set_user_condition('is_active', None)
            removed.register(content=grant.note, user=grant.user, permission=grant.permission)
            with self.assertRaises(TypeError) as ctx:
                built_catalog(removed).permissions_for(alice, note, skip_is_active=True)
            self.assertIn('skip_is_active', str(ctx.exception))
            with self.assertRaises(TypeError) as ctx:
                built_catalog(registry).permissions_for(alice, note, skip_superuser=True)
            self.assertIn('skip_superuser', str(ctx.exception))
            self.assertEqual(set(built_catalog(removed).permissions_for(alice, note).values_list('pk', flat=True)), {read.pk})
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
            read = _permission(OverrideNote, 'read_note_override_skip_overridenote')
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            registry.set_user_override('superuser', lambda u: u.is_superuser)
            registry.set_user_override('staff', lambda u: u.is_staff)
            grant = Ref(OverrideGrant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            allowed = built_catalog(registry).permissions_for(staff, note)
            self.assertEqual(set(allowed.values_list('pk', flat=True)), {read.pk})
            self.assertIn('is_staff', str(allowed.query))
            skipped = built_catalog(registry).permissions_for(staff, note, skip_staff=True)
            self.assertEqual(list(skipped), [])
            self.assertEqual(skipped.query.sql_with_params()[0], allowed.query.sql_with_params()[0])
            self.assertIn('is_staff', str(skipped.query))
            self.assertEqual(list(built_catalog(registry).permissions_for(superuser, note)), [])
            with self.assertRaises(TypeError) as ctx:
                built_catalog(registry).permissions_for(staff, note, skip_superuser=True)
            self.assertIn('skip_superuser', str(ctx.exception))
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(OverrideGrant)
                editor.delete_model(OverrideNote)

class SkipKeywordNameTest(TestCase):

    def test_condition_name_must_be_an_identifier(self):
        registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_condition('not-a-name', lambda u: u.is_active)
        self.assertIn('identifier', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_condition('flags', lambda u: u.is_active)
        self.assertIn('collides', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('user', lambda u: u.is_superuser)
        self.assertIn('collides', str(ctx.exception))
        registry.set_user_condition('staff', lambda u: u.is_staff)
        shape = registry.build()
        self.assertIsNone(shape.user_override)
        self.assertEqual(
            tuple(rule.name for rule in shape.user_conditions),
            ('is_active', 'staff'),
        )

    def test_condition_and_override_cannot_share_a_name(self):
        registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('is_active', lambda u: u.is_superuser)
        self.assertIn('collides', str(ctx.exception))
        registry.set_user_condition('staff', lambda u: u.is_staff)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_override('staff', lambda u: u.is_staff)
        self.assertIn('collides', str(ctx.exception))
        registry.set_user_override('superuser', lambda u: u.is_superuser)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.set_user_condition('superuser', lambda u: u.is_superuser)
        self.assertIn('collides', str(ctx.exception))
        self.assertNotIn('superuser', tuple((rule.name for rule in registry.user_conditions())))
        with self.assertRaises(TrustsConfigurationError):
            registry.set_user_override('staff', lambda u: u.is_staff)
        self.assertEqual(registry.build().user_override.name, 'superuser')
        opened = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        opened.set_user_condition('is_active', None)
        opened.set_user_override('is_active', lambda u: u.is_superuser)
        self.assertEqual(opened.build().user_override.name, 'is_active')

class SkipKeywordInquiryTest(KernelHostRequiredMixin, TestCase):

    def test_unknown_skip_keyword_on_inquiry_apis(self):
        from django.contrib.auth.models import Permission as AuthPermission
        from trusts.query import PermittedQuerySet
        User = get_user_model()
        alice = User.objects.create_user('skip-inquiry', password='x')
        ct = ContentType.objects.get_for_model(Document)
        change, _created = AuthPermission.objects.get_or_create(content_type=ct, codename='change_document', defaults={'name': 'change'})
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
        self.assertFalse(backend.has_perm(AnonymousUser(), 'myapp.change_document', document, skip_nope=True))

class StaffSurfaceTest(KernelHostRequiredMixin, TestCase):
    """A custom staff condition is enforced and skippable on each inquiry."""

    def setUp(self):
        from django.apps import apps
        from trusts.backends import catalogs
        self.config = apps.get_app_config('myapp')
        self.original = catalogs.get(DocumentBackend)
        self.original_sentinel = getattr(self.config, '_document_grant_registry_id', None)
        registry = RegistryFactory(cls=TrustModelBackendMixin, path=DOCUMENT_BACKEND, user_model=get_user_model())
        registry.set_user_condition('staff', lambda u: u.is_staff)
        registry.set_user_override('superuser', lambda u: u.is_superuser)
        _donate_document(registry)
        self.saved_catalog = _seal_document_factory(registry)
        self.registry = registry
        User = get_user_model()
        self.plain = User.objects.create_user('surf-plain', password='x')
        self.staff = User.objects.create_user('surf-staff', password='x')
        self.staff.is_staff = True
        self.staff.save(update_fields=['is_staff'])
        self.superuser = User.objects.create_superuser('surf-super', password='x', email='s@example.com')
        self.change = _permission(Document, 'change_document')
        self.doc = Document.objects.create(title='surf')
        self.other = Document.objects.create(title='other')
        DocumentGrant.objects.create(document=self.doc, user=self.plain, permission=self.change)
        DocumentGrant.objects.create(document=self.doc, user=self.staff, permission=self.change)
        self.backend = DocumentBackend()
        self.perm = 'myapp.change_document'

    def tearDown(self):
        _restore_document_registry(self.config, self.original, self.original_sentinel, self.saved_catalog)

    def test_staff_is_enforced_and_skippable(self):
        with self.assertNumQueries(1):
            self.assertFalse(self.backend.has_perm(self.plain, self.perm, self.doc))
        self.assertTrue(self.backend.has_perm(self.staff, self.perm, self.doc))
        self.assertTrue(self.backend.has_perm(self.plain, self.perm, self.doc, skip_staff=True))
        self.assertFalse(self.backend.has_perm(self.staff, self.perm, self.other))
        with self.assertNumQueries(1):
            self.assertFalse(Document.objects.authorized(self.plain, self.change).exists())
        self.assertEqual(set(Document.objects.authorized(self.staff, self.change).values_list('pk', flat=True)), {self.doc.pk})
        self.assertEqual(set(Document.objects.authorized(self.plain, self.change, skip_staff=True).values_list('pk', flat=True)), {self.doc.pk})
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertNumQueries(1):
            self.assertFalse(permitted.permitted(self.change, self.plain).exists())
        self.assertEqual(set(permitted.permitted(self.change, self.staff).values_list('pk', flat=True)), {self.doc.pk})
        self.assertEqual(set(permitted.permitted(self.change, self.plain, skip_staff=True).values_list('pk', flat=True)), {self.doc.pk})
        handle = configured_catalog(DOCUMENT_BACKEND)
        denied = handle.permissions_for(self.plain, self.doc)
        self.assertIn('is_staff', str(denied.query))
        self.assertEqual(list(denied), [])
        held = handle.permissions_for(self.staff, self.doc)
        self.assertIn(self.change.pk, set(held.values_list('pk', flat=True)))
        self.assertIn('is_staff', str(held.query))
        skipped = handle.permissions_for(self.plain, self.doc, skip_staff=True)
        self.assertIn(self.change.pk, set(skipped.values_list('pk', flat=True)))
        self.assertEqual(skipped.query.sql_with_params()[0], denied.query.sql_with_params()[0])
        self.assertIn('is_staff', str(skipped.query))
        self.assertNotIn(self.plain.pk, set(self.doc.get_permitted_users(self.change).values_list('pk', flat=True)))
        included = set(self.doc.get_permitted_users(self.change, skip_staff=True).values_list('pk', flat=True))
        self.assertIn(self.plain.pk, included)
        self.assertIn(self.staff.pk, included)
        skipped_users = self.doc.get_permitted_users(self.change, skip_staff=True)
        denied_shape = self.doc.get_permitted_users(self.change)
        self.assertEqual(skipped_users.query.sql_with_params()[0], denied_shape.query.sql_with_params()[0])
        where = str(skipped_users.query).split('WHERE', 1)[-1]
        self.assertIn('is_staff', where)
        denied_users = self.doc.get_permitted_users(self.change)
        self.assertIn('is_staff', str(denied_users.query).split('WHERE', 1)[-1])

    def test_skip_superuser_drops_the_override_and_keeps_the_grant(self):
        self.assertTrue(self.backend.has_perm(self.superuser, self.perm, self.doc))
        self.assertFalse(self.backend.has_perm(self.superuser, self.perm, self.doc, skip_superuser=True))
        self.assertTrue(self.backend.has_perm(self.staff, self.perm, self.doc, skip_superuser=True))
        self.assertFalse(Document.objects.authorized(self.superuser, self.change, skip_superuser=True).exists())
        self.assertTrue(Document.objects.authorized(self.superuser, self.change).filter(pk=self.doc.pk).exists())
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        self.assertFalse(permitted.permitted(self.change, self.superuser, skip_superuser=True).exists())
        self.assertTrue(permitted.permitted(self.change, self.superuser).filter(pk=self.doc.pk).exists())

    def test_lockfile_records_staff_and_the_override(self):
        handle = configured_catalog(DOCUMENT_BACKEND)
        raw = render_configured_policy(self.registry)
        self.assertIn(b'user.is_staff=True', raw)
        self.assertIn(b'user.is_superuser=True', raw)
        self.assertIn(b'skip_is_active=False', raw)
        self.assertIn(b'skip_staff=False', raw)
        self.assertIn(b'skip_superuser=False', raw)
        from trusts.plan.users import lock_permitted_users_queryset
        queryset = lock_permitted_users_queryset(handle, self.doc, self.change)
        sql = str(queryset.query)
        self.assertIn('is_staff', sql)
        self.assertIn('is_superuser', sql)

class StaffPrefixFilterTest(TransactionTestCase):

    def test_prefix_filter_enforces_and_skips_staff(self):

        class Scope(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class Payload(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class Row(models.Model):
            scope = models.ForeignKey(Scope, related_name='rows', on_delete=models.CASCADE)
            content = models.ForeignKey(Payload, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            scope = models.ForeignKey(Scope, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        with connection.schema_editor() as editor:
            editor.create_model(Scope)
            editor.create_model(Payload)
            editor.create_model(Row)
            editor.create_model(Grant)
        try:
            User = get_user_model()
            plain = User.objects.create_user('pref-plain', password='x')
            staff = User.objects.create_user('pref-staff', password='x')
            staff.is_staff = True
            staff.save(update_fields=['is_staff'])
            scope = Scope.objects.create(title='s')
            payload = Payload.objects.create(title='p')
            Row.objects.create(scope=scope, content=payload)
            read = _permission(Payload, 'read_payload_staff_payload')
            Grant.objects.create(scope=scope, user=plain, permission=read)
            Grant.objects.create(scope=scope, user=staff, permission=read)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            registry.set_user_condition('staff', lambda u: u.is_staff, on='user')
            grant = Ref(Grant)
            registry.register(content=grant.scope.rows.content, user=grant.user, permission=grant.permission)
            registry.path = 'staff-prefix'
            handle = registry
            denied = filter_by_permitted_content(Scope.objects.all(), plain, read, content=payload, registry=built_catalog(handle))
            with self.assertNumQueries(1):
                self.assertFalse(denied.exists())
            self.assertEqual(set(filter_by_permitted_content(Scope.objects.all(), staff, read, content=payload, registry=built_catalog(handle)).values_list('pk', flat=True)), {scope.pk})
            self.assertEqual(set(filter_by_permitted_content(Scope.objects.all(), plain, read, content=payload, registry=built_catalog(handle), skip_staff=True).values_list('pk', flat=True)), {scope.pk})
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Grant)
                editor.delete_model(Row)
                editor.delete_model(Payload)
                editor.delete_model(Scope)

def _seal_document_factory(factory):
    """The test filled ``factory``. Pass that built registry into Catalog."""
    from trusts.backends import catalogs
    previous = catalogs.get(DocumentBackend)
    family = DocumentBackend.family if previous is None else previous.family
    catalogs[DocumentBackend] = built_catalog(factory, cls=DocumentBackend, path=DOCUMENT_BACKEND, family=family)
    return previous

def _restore_document_catalog(previous):
    from trusts.backends import catalogs
    if previous is None:
        catalogs.pop(DocumentBackend, None)
    else:
        catalogs[DocumentBackend] = previous
_CATALOG_UNSET = object()

def _donate_document(registry):
    """Same rows DocumentConfig.ready writes onto an open recorder."""
    from tests.myapp.models import Document, DocumentDelegation, DocumentGrant

    registry.register_public(
        trust=DocumentGrant, user='user', permission='permission',
        content='document',
    )
    registry.register_public(
        trust=DocumentDelegation, delegate='delegate', sponsor='sponsor',
        content='document',
        condition=lambda relationship, permission: (
            relationship.allowed_permissions.contains(permission)
        ),
    )
    registry.register_permission_condition(
        Document, 'non_confidential',
        lambda u, p, o: o.confidential != True,
    )

def _restore_document_registry(config, original, sentinel, saved_catalog=_CATALOG_UNSET):
    if saved_catalog is not _CATALOG_UNSET:
        _restore_document_catalog(saved_catalog)
    config._document_grant_registry_id = sentinel

def _install_document_registry(*, override):
    from django.apps import apps
    from trusts.backends import catalogs
    config = apps.get_app_config('myapp')
    original = catalogs.get(DocumentBackend)
    sentinel = getattr(config, '_document_grant_registry_id', None)
    registry = RegistryFactory(cls=TrustModelBackendMixin, path=DOCUMENT_BACKEND, user_model=get_user_model())
    if override:
        registry.set_user_override('superuser', lambda u: u.is_active & u.is_superuser)
    _donate_document(registry)
    saved_catalog = _seal_document_factory(registry)
    return (config, original, sentinel, registry, saved_catalog)

def _inquiry_flags(backend, handle, user, doc, change, perm, **flags):
    """Trusts-owned inquiry results for one checked user.

    Native ``user.has_perm`` is not one of these results.
    """
    permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
    listed = handle.permissions_for(user, doc, **flags)
    return {'has_perm': backend.has_perm(user, perm, doc, **flags), 'authorized': Document.objects.authorized(user, change, **flags).filter(pk=doc.pk).exists(), 'permitted': permitted.permitted(change, user, **flags).filter(pk=doc.pk).exists(), 'reverse': user.pk in set(doc.get_permitted_users(change, **flags).values_list('pk', flat=True)), 'enumerated': perm in backend.get_all_permissions(user, doc, **flags), 'permissions_for': change.pk in set(listed.values_list('pk', flat=True))}

class SuperuserSurfaceTest(KernelHostRequiredMixin, TestCase):
    """Active and inactive superusers, with and without the override."""

    def setUp(self):
        User = get_user_model()
        self.active = User.objects.create_superuser('surf-active-super', password='x', email='active-super@example.com')
        self.dormant = User.objects.create_superuser('surf-dormant-super', password='x', email='dormant-super@example.com')
        self.dormant.is_active = False
        self.dormant.save(update_fields=['is_active'])
        self.peer = User.objects.create_user('surf-peer-super', password='x')
        self.change = _permission(Document, 'change_document')
        self.doc = Document.objects.create(title='super-surface')
        self.perm = 'myapp.change_document'
        self.backend = DocumentBackend()
        DocumentGrant.objects.create(document=self.doc, user=self.dormant, permission=self.change)
        DocumentGrant.objects.create(document=self.doc, user=self.peer, permission=self.change)

    def _expect(self, handle, user, allowed, **flags):
        flags_out = _inquiry_flags(self.backend, handle, user, self.doc, self.change, self.perm, **flags)
        self.assertEqual(set(flags_out.values()), {allowed})

    def test_without_override_superuser_is_an_ordinary_principal(self):
        config, original, sentinel, registry, saved_catalog = _install_document_registry(override=False)
        self.addCleanup(_restore_document_registry, config, original, sentinel, saved_catalog)
        handle = configured_catalog(DOCUMENT_BACKEND)
        self.assertIsNone(registry.build().user_override)
        raw = render_configured_policy(registry)
        document = _load_policy_sql_document(raw)
        for content in document['backends'][0]['contents']:
            for row in content.values():
                if not isinstance(row, dict) or 'sql' not in row:
                    continue
                self.assertNotIn('is_superuser', row['sql'].split('WHERE', 1)[-1])
                self.assertNotIn('is_superuser', ' '.join(row['params']))
        where = str(self.doc.get_permitted_users(self.change).query)
        where = where.split('WHERE', 1)[-1]
        self.assertNotIn('is_superuser', where)
        self.assertTrue(self.active.has_perm(self.perm, self.doc))
        self._expect(handle, self.active, False)
        self._expect(handle, self.dormant, False)
        self._expect(handle, self.dormant, True, skip_is_active=True)
        self._expect(handle, self.peer, True)
        DocumentGrant.objects.create(document=self.doc, user=self.active, permission=self.change)
        self._expect(handle, self.active, True)

    def test_with_override_active_superuser_passes_without_a_grant(self):
        config, original, sentinel, registry, saved_catalog = _install_document_registry(override=True)
        self.addCleanup(_restore_document_registry, config, original, sentinel, saved_catalog)
        handle = configured_catalog(DOCUMENT_BACKEND)
        self.assertEqual(registry.build().user_override.name, 'superuser')
        raw = render_configured_policy(registry)
        self.assertIn(b'user.is_superuser=True', raw)
        where = str(self.doc.get_permitted_users(self.change).query)
        self.assertIn('is_superuser', where.split('WHERE', 1)[-1])
        self.assertTrue(self.active.has_perm(self.perm, self.doc))
        with self.assertRaises(TypeError):
            self.active.has_perm(self.perm, self.doc, skip_superuser=True)
        self._expect(handle, self.active, True)
        self._expect(handle, self.active, False, skip_superuser=True)
        self._expect(handle, self.dormant, False)
        self._expect(handle, self.dormant, True, skip_is_active=True)
        self._expect(handle, self.peer, True)

def _guard_request(user):
    request = HttpRequest()
    request.user = user
    return request

class AuthorizationRequiredSuperuserTest(KernelHostRequiredMixin, TestCase):
    """The view guard follows the override. It does not copy ``has_perm``."""

    def setUp(self):
        User = get_user_model()
        self.active = User.objects.create_superuser('guard-active-super', password='x', email='guard-active@example.com')
        self.dormant = User.objects.create_superuser('guard-dormant-super', password='x', email='guard-dormant@example.com')
        self.dormant.is_active = False
        self.dormant.save(update_fields=['is_active'])
        self.change = _permission(Document, 'change_document')
        self.doc = Document.objects.create(title='guard-super')
        self.perm = 'myapp.change_document'
        DocumentGrant.objects.create(document=self.doc, user=self.dormant, permission=self.change)

    def _view(self, **flags):

        @authorization_required(Document, self.perm, **flags)
        def view(request, pk):
            return 'ok'
        entry = (Document, self.perm, ())
        self.addCleanup(self._forget_guard, entry)
        return view

    def _forget_guard(self, entry):
        try:
            _declared_authorization_guards.remove(entry)
        except ValueError:
            pass

    def test_without_override_active_superuser_needs_a_grant(self):
        config, original, sentinel, registry, saved_catalog = _install_document_registry(override=False)
        self.addCleanup(_restore_document_registry, config, original, sentinel, saved_catalog)
        self.assertIsNone(registry.build().user_override)
        view = self._view()
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(_guard_request(self.active), pk=self.doc.pk)
        self.assertTrue(self.active.has_perm(self.perm, self.doc))
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(_guard_request(self.dormant), pk=self.doc.pk)
        audited = self._view(skip_is_active=True)
        self.assertEqual(audited(_guard_request(self.dormant), pk=self.doc.pk), 'ok')
        DocumentGrant.objects.create(document=self.doc, user=self.active, permission=self.change)
        with self.assertNumQueries(1):
            self.assertEqual(view(_guard_request(self.active), pk=self.doc.pk), 'ok')

    def test_override_allows_active_superuser_without_a_grant(self):
        config, original, sentinel, registry, saved_catalog = _install_document_registry(override=True)
        self.addCleanup(_restore_document_registry, config, original, sentinel, saved_catalog)
        self.assertEqual(registry.build().user_override.name, 'superuser')
        view = self._view()
        with self.assertNumQueries(1):
            self.assertEqual(view(_guard_request(self.active), pk=self.doc.pk), 'ok')
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(_guard_request(self.dormant), pk=self.doc.pk)

    def test_skip_superuser_drops_the_override(self):
        config, original, sentinel, registry, saved_catalog = _install_document_registry(override=True)
        self.addCleanup(_restore_document_registry, config, original, sentinel, saved_catalog)
        self.assertEqual(registry.build().user_override.name, 'superuser')
        plain = self._view()
        skipped = self._view(skip_superuser=True)
        self.assertEqual(plain(_guard_request(self.active), pk=self.doc.pk), 'ok')
        with self.assertRaises(PermissionDenied):
            skipped(_guard_request(self.active), pk=self.doc.pk)
        DocumentGrant.objects.create(document=self.doc, user=self.active, permission=self.change)
        self.assertEqual(skipped(_guard_request(self.active), pk=self.doc.pk), 'ok')

class SuperuserPrefixFilterTest(TransactionTestCase):

    def test_prefix_filter_follows_the_override(self):

        class PrefixScope(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class PrefixPayload(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class PrefixRow(models.Model):
            scope = models.ForeignKey(PrefixScope, related_name='rows', on_delete=models.CASCADE)
            content = models.ForeignKey(PrefixPayload, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class PrefixGrant(models.Model):
            scope = models.ForeignKey(PrefixScope, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        with connection.schema_editor() as editor:
            editor.create_model(PrefixScope)
            editor.create_model(PrefixPayload)
            editor.create_model(PrefixRow)
            editor.create_model(PrefixGrant)
        try:
            User = get_user_model()
            active = User.objects.create_superuser('pref-active-super', password='x', email='pref-active-super@example.com')
            dormant = User.objects.create_superuser('pref-dormant-super', password='x', email='pref-dormant-super@example.com')
            dormant.is_active = False
            dormant.save(update_fields=['is_active'])
            peer = User.objects.create_user('pref-peer-super', password='x')
            scope = PrefixScope.objects.create(title='s')
            payload = PrefixPayload.objects.create(title='p')
            PrefixRow.objects.create(scope=scope, content=payload)
            read = _permission(PrefixPayload, 'read_payload_super_prefixpayload')
            PrefixGrant.objects.create(scope=scope, user=dormant, permission=read)
            PrefixGrant.objects.create(scope=scope, user=peer, permission=read)

            def allows(user, *, override, **flags):
                registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
                if override:
                    registry.set_user_override('superuser', lambda u: u.is_active & u.is_superuser)
                grant = Ref(PrefixGrant)
                registry.register(content=grant.scope.rows.content, user=grant.user, permission=grant.permission)
                registry.path = 'super-prefix'
                handle = registry
                chosen = filter_by_permitted_content(PrefixScope.objects.all(), user, read, content=payload, registry=built_catalog(handle), **flags)
                return chosen.filter(pk=scope.pk).exists()
            self.assertFalse(allows(active, override=False))
            self.assertTrue(allows(peer, override=False))
            self.assertFalse(allows(dormant, override=False))
            self.assertTrue(allows(dormant, override=False, skip_is_active=True))
            self.assertTrue(allows(active, override=True))
            self.assertFalse(allows(active, override=True, skip_superuser=True))
            self.assertFalse(allows(dormant, override=True))
            self.assertTrue(allows(dormant, override=True, skip_is_active=True))
            self.assertTrue(allows(peer, override=True))
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(PrefixGrant)
                editor.delete_model(PrefixRow)
                editor.delete_model(PrefixPayload)
                editor.delete_model(PrefixScope)

class PlainUserWithoutSuperuserTest(KernelHostRequiredMixin, TransactionTestCase):

    def test_user_model_without_is_superuser_matches_when_no_rule_names_it(self):

        class PlainPrincipal(models.Model):
            username = models.CharField(max_length=40, unique=True)
            is_active = models.BooleanField(default=True)
            is_anonymous = AbstractBaseUser.is_anonymous
            is_authenticated = AbstractBaseUser.is_authenticated

            class Meta:
                app_label = 'trusts_tests'

        class PlainNote(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class PlainNoteGrant(models.Model):
            user = models.ForeignKey(PlainPrincipal, on_delete=models.CASCADE)
            note = models.ForeignKey(PlainNote, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        self.assertFalse(any((field.name == 'is_superuser' for field in PlainPrincipal._meta.local_fields)))
        from django.apps import apps
        from trusts.backends import catalogs
        config = apps.get_app_config('myapp')
        original = catalogs.get(DocumentBackend)
        sentinel = getattr(config, '_document_grant_registry_id', None)
        saved_catalog = original
        with connection.schema_editor() as editor:
            editor.create_model(PlainPrincipal)
            editor.create_model(PlainNote)
            editor.create_model(PlainNoteGrant)
        try:
            registry = RegistryFactory(cls=TrustModelBackendMixin, path=DOCUMENT_BACKEND, user_model=get_user_model())
            registry.register_public(trust=PlainNoteGrant, user='user', permission='permission', content='note')
            _seal_document_factory(registry)
            permission = _permission(PlainNote, 'change_plainnote')
            note = PlainNote.objects.create(title='plain')
            holder = PlainPrincipal.objects.create(username='holder-plain', is_active=True)
            outsider = PlainPrincipal.objects.create(username='outsider-plain', is_active=True)
            quiet = PlainPrincipal.objects.create(username='quiet-plain', is_active=False)
            PlainNoteGrant.objects.create(user=holder, note=note, permission=permission)
            PlainNoteGrant.objects.create(user=quiet, note=note, permission=permission)
            self.assertTrue(built_catalog(registry).has_perm(holder, '%s.%s' % (permission.content_type.app_label, permission.codename), note))
            self.assertFalse(built_catalog(registry).has_perm(outsider, '%s.%s' % (permission.content_type.app_label, permission.codename), note))
            self.assertFalse(built_catalog(registry).has_perm(quiet, '%s.%s' % (permission.content_type.app_label, permission.codename), note))

            class PlainManager(PermittedUsersManagerMixin, models.Manager):
                pass
            manager = PlainManager()
            manager.model = PlainPrincipal
            manager.name = 'objects'
            found = set(manager.permitted(note, permission).values_list('pk', flat=True))
            self.assertEqual(found, {holder.pk})
            sql = str(manager.permitted(note, permission).query)
            self.assertNotIn('is_superuser', sql)
            self.assertIn('is_active', sql)
        finally:
            _restore_document_registry(config, original, sentinel, saved_catalog)
            with connection.schema_editor() as editor:
                editor.delete_model(PlainNoteGrant)
                editor.delete_model(PlainNote)
                editor.delete_model(PlainPrincipal)

class UserModelWithoutIsActiveColumnTest(TransactionTestCase):
    """A user model with no ``is_active`` column."""

    def _create(self, label):
        module = __name__

        def meta():
            return type('Meta', (), {'app_label': 'trusts_tests'})
        user_model = type('%sUser' % label, (AbstractBaseUser,), {'__module__': module, 'username': models.CharField(max_length=40, unique=True), 'USERNAME_FIELD': 'username', 'Meta': meta()})
        note_model = type('%sNote' % label, (models.Model,), {'__module__': module, 'title': models.CharField(max_length=40), 'Meta': meta()})
        grant_model = type('%sGrant' % label, (models.Model,), {'__module__': module, 'user': models.ForeignKey(user_model, on_delete=models.CASCADE), 'note': models.ForeignKey(note_model, on_delete=models.CASCADE), 'permission': models.ForeignKey(Permission, on_delete=models.CASCADE), 'Meta': meta()})
        link_model = type('%sLink' % label, (models.Model,), {'__module__': module, 'note': models.ForeignKey(note_model, on_delete=models.CASCADE), 'delegate': models.ForeignKey(user_model, related_name='+', on_delete=models.CASCADE), 'sponsor': models.ForeignKey(user_model, related_name='+', on_delete=models.CASCADE), 'Meta': meta()})
        self.assertNotIn('is_active', [field.name for field in user_model._meta.concrete_fields])
        self.assertIs(user_model.is_active, True)
        with connection.schema_editor() as editor:
            editor.create_model(user_model)
            editor.create_model(note_model)
            editor.create_model(grant_model)
            editor.create_model(link_model)
        return (user_model, note_model, grant_model, link_model)

    def _drop(self, user_model, note_model, grant_model, link_model):
        with connection.schema_editor() as editor:
            editor.delete_model(link_model)
            editor.delete_model(grant_model)
            editor.delete_model(note_model)
            editor.delete_model(user_model)

    def test_non_boolean_is_active_is_not_the_default(self):
        """A non-boolean ``is_active`` column is not the built-in condition."""
        from trusts.plan.standards import builtin_user_conditions

        def meta():
            return type('Meta', (), {'app_label': 'trusts_tests'})
        user_model = type('TextActiveUser', (AbstractBaseUser,), {'__module__': __name__, 'username': models.CharField(max_length=40, unique=True), 'is_active': models.CharField(max_length=8, default='yes'), 'USERNAME_FIELD': 'username', 'Meta': meta()})
        note_model = type('TextActiveNote', (models.Model,), {'__module__': __name__, 'title': models.CharField(max_length=40), 'Meta': meta()})
        grant_model = type('TextActiveGrant', (models.Model,), {'__module__': __name__, 'user': models.ForeignKey(user_model, on_delete=models.CASCADE), 'note': models.ForeignKey(note_model, on_delete=models.CASCADE), 'permission': models.ForeignKey(Permission, on_delete=models.CASCADE), 'Meta': meta()})
        self.assertEqual(builtin_user_conditions(user_model), ())
        registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
        grant = Ref(grant_model)
        with self.assertNumQueries(0):
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
        self.assertEqual(len(registry.records), 1)

    def test_explicit_is_active_requires_a_boolean_field(self):
        """Only the implicit default is optional when the field is absent."""
        user_model, note_model, grant_model, link_model = self._create('Replaced')
        try:
            rejected = RegistryFactory(cls=TrustModelBackendMixin, user_model=user_model)
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    rejected.set_user_condition(
                        'is_active', lambda u: u.is_active,
                    )
            self.assertIsNone(rejected.build().user_conditions)
            self.assertEqual(len(rejected.records), 0)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            registry.set_user_condition('is_active', lambda u: u.is_active)
            grant, link = (Ref(grant_model), Ref(link_model))
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    registry.register(content=grant.note, user=grant.user, permission=grant.permission)
                with self.assertRaises(TrustsConfigurationError):
                    registry.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
            self.assertEqual(len(registry.records), 0)
            self.assertEqual(len(registry.delegations), 0)
        finally:
            self._drop(user_model, note_model, grant_model, link_model)

    def test_without_an_is_active_condition_inquiries_still_match(self):
        """Forward, reverse, and sponsor checks run with no activity column.

        The registry never sets an ``is_active`` condition, and this model
        has no such field, so the default condition is not added.
        """
        from trusts.plan.users import lock_permitted_users_queryset
        user_model, note_model, grant_model, link_model = self._create('Open')
        try:
            holder = user_model.objects.create(username='columnless-holder', password='x')
            sponsor = user_model.objects.create(username='columnless-sponsor', password='x')
            delegate = user_model.objects.create(username='columnless-delegate', password='x')
            outsider = user_model.objects.create(username='columnless-outsider', password='x')
            note = note_model.objects.create(title='columnless')
            permission = _permission(note_model, 'change_columnlessnote_opennote')
            grant_model.objects.create(user=holder, note=note, permission=permission)
            grant_model.objects.create(user=sponsor, note=note, permission=permission)
            link_model.objects.create(note=note, delegate=delegate, sponsor=sponsor)
            registry = RegistryFactory(cls=TrustModelBackendMixin, user_model=get_user_model())
            grant = Ref(grant_model)
            link = Ref(link_model)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            registry.register_delegation(content=link.note, delegate=link.delegate, sponsor=link.sponsor)
            catalog = built_catalog(registry)
            self.assertIsNone(catalog.user_conditions)
            self.assertTrue(catalog.has_perm(holder, '%s.%s' % (permission.content_type.app_label, permission.codename), note))
            self.assertTrue(built_catalog(registry).has_perm(sponsor, '%s.%s' % (permission.content_type.app_label, permission.codename), note))
            self.assertFalse(built_catalog(registry).has_perm(outsider, '%s.%s' % (permission.content_type.app_label, permission.codename), note))
            forward_sql = str(built_catalog(registry).permissions_for(holder, note).query)
            self.assertNotIn('is_active', forward_sql)
            registry.path = 'columnless'
            handle = registry
            predicate = granted(built_catalog(handle), note, delegate, permission)
            self.assertIsNotNone(predicate)
            matched = bind_once(note_model.objects.filter(pk=note.pk).filter(predicate))
            self.assertTrue(matched.exists())
            self.assertNotIn('is_active', matched.query.sql_with_params()[0])
            denied = granted(built_catalog(handle), note, outsider, permission)
            if denied is not None:
                self.assertFalse(bind_once(note_model.objects.filter(pk=note.pk).filter(denied)).exists())
            found = set(lock_permitted_users_queryset(built_catalog(handle), note, permission).values_list('pk', flat=True))
            self.assertEqual(found, {holder.pk, sponsor.pk, delegate.pk})
            reverse_sql = str(lock_permitted_users_queryset(built_catalog(handle), note, permission).query)
            self.assertNotIn('is_active', reverse_sql)
        finally:
            self._drop(user_model, note_model, grant_model, link_model)
_STOCK_CALLS = (('has_perm', ('auth.view_user',), {'skip_is_active': True}), ('ahas_perm', ('auth.view_user',), {'skip_is_active': True}), ('has_perms', (['auth.view_user'],), {'skip_superuser': True}), ('ahas_perms', (['auth.view_user'],), {'skip_superuser': True}), ('has_module_perms', ('auth',), {'skip_is_active': True}), ('ahas_module_perms', ('auth',), {'skip_is_active': True}), ('get_user_permissions', (), {'skip_is_active': True}), ('aget_user_permissions', (), {'skip_is_active': True}), ('get_group_permissions', (), {'skip_is_active': True}), ('aget_group_permissions', (), {'skip_is_active': True}), ('get_all_permissions', (), {'skip_is_active': True}), ('aget_all_permissions', (), {'skip_is_active': True}))

@override_settings(ROOT_URLCONF='tests.core.test_user_conditions')
class StockPermissionBoundaryTest(KernelHostRequiredMixin, TestCase):

    def test_stock_methods_async_variants_and_admin_stay_unchanged(self):
        User = get_user_model()
        root = User.objects.create_superuser('stock-root', password='x', email='stock-root@example.com')
        dormant = User.objects.create_superuser('stock-dormant', password='x', email='stock-dormant@example.com')
        dormant.is_active = False
        dormant.save(update_fields=['is_active'])
        doc = Document.objects.create(title='stock-boundary')
        code = 'myapp.change_document'
        self.assertTrue(root.has_perm(code, doc))
        self.assertTrue(root.has_perm('auth.view_user'))
        self.assertTrue(root.has_perms([code]))
        self.assertTrue(root.has_module_perms('auth'))
        self.assertFalse(dormant.has_perm(code, doc))
        self.assertFalse(dormant.has_module_perms('auth'))
        self.assertFalse(DocumentBackend().has_perm(root, code, doc))
        self.assertEqual(async_to_sync(root.ahas_perm)(code, doc), root.has_perm(code, doc))
        self.assertEqual(async_to_sync(root.ahas_perms)([code]), root.has_perms([code]))
        self.assertEqual(async_to_sync(root.ahas_module_perms)('auth'), root.has_module_perms('auth'))
        self.assertEqual(async_to_sync(root.aget_all_permissions)(doc), root.get_all_permissions(doc))
        self.assertEqual(async_to_sync(root.aget_user_permissions)(), root.get_user_permissions())
        self.assertEqual(async_to_sync(root.aget_group_permissions)(doc), root.get_group_permissions(doc))
        self.assertEqual(async_to_sync(dormant.ahas_perm)(code, doc), False)
        for name, args, kwargs in _STOCK_CALLS:
            method = getattr(root, name)
            self.assertNotIn('skip_is_active', inspect.signature(method).parameters)
            invoke = async_to_sync(method) if name.startswith('a') else method
            with self.assertRaises(TypeError):
                invoke(*args, **kwargs)
        self.client.force_login(root)
        self.assertEqual(self.client.get(reverse('admin:index')).status_code, 200)
        self.assertEqual(self.client.get(reverse('admin:auth_user_changelist')).status_code, 200)
        self.client.force_login(dormant)
        self.assertEqual(self.client.get(reverse('admin:index')).status_code, 302)
