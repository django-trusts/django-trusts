"""Inactive users on Trusts inquiries (#284).

Default Trusts inquiries deny a user whose ``is_active`` is false.
``skip_is_active=True`` skips only that built-in check. Anonymous and
unauthenticated users stay denied when it is true. Superuser shortcuts
and explicit conditions stay in place.
"""
import datetime
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import Q
from django.test import TestCase, TransactionTestCase
from django.test.utils import isolate_apps, override_settings
from tests.core import KernelHostRequiredMixin, kernel_host_listed
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentDelegation, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from tests.support import scoped_permitted_content as filter_by_permitted_content, built_catalog
from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import RegistryFactory
from trusts.query import AuthorizedQuerySet, PermittedQuerySet, PermittedUsersManagerMixin, PermittedUsersMixin
from tests.support import install_class_handle

PERM = 'myapp.change_document'

def _permission(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(content_type=ct, codename=codename, defaults={'name': codename})
    return permission

def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))

class Issue284SuiteRegistrationTest(TestCase):

    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue284', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue284', PAIR_KERNEL_SUITE)

class InactiveInquiryLiveTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-284', password='x')
        self.sponsor = User.objects.create_user('sponsor-284', password='x')
        self.delegate = User.objects.create_user('delegate-284', password='x')
        self.superuser = User.objects.create_superuser('super-284', email='super-284@example.com', password='x')
        self.inactive_super = User.objects.create_superuser('inactive-super-284', email='inactive-super-284@example.com', password='x')
        self.inactive_super.is_active = False
        self.inactive_super.save(update_fields=['is_active'])
        self.change = _permission(Document, 'change_document')
        self.open_doc = Document.objects.create(title='open-284', confidential=False)
        self.secret = Document.objects.create(title='secret-284', confidential=True)
        DocumentGrant.objects.create(document=self.open_doc, user=self.alice, permission=self.change)
        DocumentGrant.objects.create(document=self.secret, user=self.alice, permission=self.change)
        DocumentGrant.objects.create(document=self.open_doc, user=self.sponsor, permission=self.change)
        relationship = DocumentDelegation.objects.create(document=self.open_doc, delegate=self.delegate, sponsor=self.sponsor)
        relationship.allowed_permissions.add(self.change)
        self.backend = DocumentBackend()

    def _deactivate(self, user):
        user.is_active = False
        user.save(update_fields=['is_active'])

    def test_content_enumeration_and_boolean_with_skip_is_active(self):
        self._deactivate(self.alice)
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertNumQueries(5):
            self.assertFalse(Document.objects.authorized(self.alice, self.change).exists())
            self.assertEqual(_pks(permitted.permitted(self.change, self.alice)), set())
            self.assertFalse(self.alice.has_perm(PERM, self.open_doc))
            self.assertFalse(self.backend.has_perm(self.alice, PERM, self.open_doc))
            self.assertEqual(self.backend.get_all_permissions(self.alice, self.open_doc), set())
            self.assertEqual(self.backend.get_group_permissions(self.alice, self.open_doc), set())
        self.assertEqual(_pks(Document.objects.authorized(self.alice, self.change, skip_is_active=True)), {self.open_doc.pk, self.secret.pk})
        self.assertEqual(_pks(permitted.permitted(self.change, self.alice, skip_is_active=True)), {self.open_doc.pk, self.secret.pk})
        self.assertEqual(_pks(permitted.permitted(PERM, self.alice, conditions=('non_confidential',), skip_is_active=True)), {self.open_doc.pk})
        self.assertTrue(self.backend.has_perm(self.alice, PERM, self.open_doc, skip_is_active=True))
        self.assertIn(PERM, self.backend.get_all_permissions(self.alice, self.open_doc, skip_is_active=True))
        self.assertFalse(self.alice.has_perm(PERM, self.open_doc))
        with self.assertRaises(TypeError):
            self.alice.has_perm(PERM, self.open_doc, skip_is_active=True)

    def test_anonymous_stays_denied_with_skip_is_active(self):
        anonymous = AnonymousUser()
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertNumQueries(0):
            self.assertEqual(_pks(permitted.permitted(self.change, anonymous, skip_is_active=True)), set())
            self.assertFalse(self.backend.has_perm(anonymous, PERM, self.open_doc, skip_is_active=True))
            with patch('trusts.compile.catalogs.granted') as compiled:
                denied = Document.objects.authorized(anonymous, self.change)
                audited = Document.objects.authorized(anonymous, self.change, skip_is_active=True)
                self.assertEqual(_pks(denied), set())
                self.assertEqual(_pks(audited), set())
            compiled.assert_not_called()

    def test_superuser_shortcut_is_unchanged(self):
        self.assertTrue(self.superuser.has_perm(PERM, self.open_doc))
        self.assertFalse(Document.objects.authorized(self.superuser, self.change).exists())
        self.assertFalse(self.inactive_super.has_perm(PERM, self.open_doc))
        self.assertFalse(self.backend.has_perm(self.inactive_super, PERM, self.open_doc, skip_is_active=True))
        self.assertFalse(Document.objects.authorized(self.inactive_super, self.change, skip_is_active=True).exists())

    def test_user_list_includes_inactive_grant_only_with_skip_is_active(self):
        self._deactivate(self.alice)

        class Listing(PermittedUsersManagerMixin, type(get_user_model().objects)):
            pass
        listing = Listing()
        listing.model = get_user_model()
        default_users = _pks(self.open_doc.get_permitted_users(self.change))
        audited_users = _pks(self.open_doc.get_permitted_users(self.change, skip_is_active=True))
        via_manager = _pks(listing.permitted(self.open_doc, self.change, skip_is_active=True))
        self.assertNotIn(self.alice.pk, default_users)
        self.assertIn(self.sponsor.pk, default_users)
        self.assertIn(self.alice.pk, audited_users)
        self.assertEqual(via_manager, audited_users)
        self.assertNotIn(self.superuser.pk, default_users)
        self.assertTrue(self.superuser.has_perm(PERM, self.open_doc))
        self.assertNotIn(self.inactive_super.pk, default_users)
        self.assertNotIn(self.inactive_super.pk, audited_users)

    def test_inactive_delegate_and_sponsor_fail_closed_unless_skip_is_active(self):
        self._deactivate(self.delegate)
        self.assertFalse(self.delegate.has_perm(PERM, self.open_doc))
        self.assertTrue(self.backend.has_perm(self.delegate, PERM, self.open_doc, skip_is_active=True))
        self.assertNotIn(self.delegate, set(self.open_doc.get_permitted_users(self.change)))
        self.assertIn(self.delegate, set(self.open_doc.get_permitted_users(self.change, skip_is_active=True)))
        self.delegate.is_active = True
        self.delegate.save(update_fields=['is_active'])
        self._deactivate(self.sponsor)
        self.assertFalse(self.delegate.has_perm(PERM, self.open_doc))
        self.assertTrue(self.backend.has_perm(self.delegate, PERM, self.open_doc, skip_is_active=True))
        self.assertNotIn(self.delegate, set(self.open_doc.get_permitted_users(self.change)))
        self.assertIn(self.delegate, set(self.open_doc.get_permitted_users(self.change, skip_is_active=True)))

    def test_skip_is_active_flag_must_be_a_bool_before_sql(self):
        with self.assertNumQueries(0):
            with self.assertRaises(TypeError):
                Document.objects.authorized(self.alice, self.change, skip_is_active=1)
            with self.assertRaises(TypeError):
                self.open_doc.get_permitted_users(self.change, skip_is_active=1)
            with self.assertRaises(TypeError):
                self.backend.has_perm(self.alice, PERM, self.open_doc, skip_is_active='yes')

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class InactiveRegistryInquiryTest(TransactionTestCase):

    def test_registry_and_scopes_deny_inactive_users_and_keep_schemaless_holders(self):
        User = get_user_model()

        class Note(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Folder(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Row(models.Model):
            folder = models.ForeignKey('Folder', related_name='rows', on_delete=models.CASCADE)
            note = models.ForeignKey('Note', related_name='rows', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Account(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class NoteGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class AccountGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            account = models.ForeignKey(Account, on_delete=models.CASCADE)
            action = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class FolderGrant(models.Model):
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        with connection.schema_editor() as editor:
            for model in (Note, Folder, Row, Account, NoteGrant, AccountGrant, FolderGrant):
                editor.create_model(model)
        try:
            alice = User.objects.create_user('alice-reg-284', password='x')
            inactive = User.objects.create_user('inactive-reg-284', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            read = _permission(Note, 'read_note_284_note')
            note = Note.objects.create(title='n')
            folder = Folder.objects.create(title='f')
            Row.objects.create(folder=folder, note=note)
            NoteGrant.objects.create(note=note, user=alice, permission=read)
            NoteGrant.objects.create(note=note, user=inactive, permission=read)
            account = Account.objects.create(name='acct')
            AccountGrant.objects.create(note=note, account=account, action=read)
            FolderGrant.objects.create(folder=folder, user=alice, permission=read)
            FolderGrant.objects.create(folder=folder, user=inactive, permission=read)
            registry = RegistryFactory()
            grant = Ref(NoteGrant)
            registry.register(content=grant.note, user=grant.user, permission=grant.permission)
            self.assertEqual(_pks(built_catalog(registry).permissions_for(alice, note)), {read.pk})
            self.assertTrue(built_catalog(registry).has_perm(alice, '%s.%s' % (read.content_type.app_label, read.codename), note))
            self.assertEqual(_pks(built_catalog(registry).filter_authorized(Note.objects.all(), alice, read)), {note.pk})
            with self.assertNumQueries(3):
                self.assertEqual(list(built_catalog(registry).permissions_for(inactive, note)), [])
                self.assertFalse(built_catalog(registry).has_perm(inactive, '%s.%s' % (read.content_type.app_label, read.codename), note))
                self.assertFalse(built_catalog(registry).filter_authorized(Note.objects.all(), inactive, read).exists())
            self.assertEqual(_pks(built_catalog(registry).permissions_for(inactive, note, skip_is_active=True)), {read.pk})
            self.assertTrue(built_catalog(registry).has_perm(inactive, '%s.%s' % (read.content_type.app_label, read.codename), note, skip_is_active=True))
            self.assertEqual(_pks(built_catalog(registry).filter_authorized(Note.objects.all(), inactive, read, skip_is_active=True)), {note.pk})
            account_registry = RegistryFactory()
            account_grant = Ref(AccountGrant)
            account_registry.register(content=account_grant.note, user=account_grant.account, permission=account_grant.action)
            self.assertEqual(_pks(built_catalog(account_registry).permissions_for(account, note)), {read.pk})
            self.assertTrue(built_catalog(account_registry).has_perm(account, '%s.%s' % (read.content_type.app_label, read.codename), note))
            account_sql = str(built_catalog(account_registry).permissions_for(account, note).query)
            self.assertNotIn('is_active', account_sql)
            active_sql = str(built_catalog(registry).permissions_for(alice, note).query)
            self.assertIn('"is_active"', active_sql)
            skipped = built_catalog(registry).permissions_for(inactive, note, skip_is_active=True)
            self.assertEqual(_pks(skipped), {read.pk})
            self.assertEqual(skipped.query.sql_with_params()[0], built_catalog(registry).permissions_for(alice, note).query.sql_with_params()[0])
            self.assertIn('is_active', str(skipped.query))
            scope_registry = RegistryFactory()
            scope_grant = Ref(FolderGrant)
            scope_registry.register(content=scope_grant.folder.rows.note, user=scope_grant.user, permission=scope_grant.permission)
            handle = scope_registry
            self.assertEqual(_pks(filter_by_permitted_content(Folder.objects.all(), alice, read, content=Note, registry=built_catalog(handle))), {folder.pk})
            with self.assertNumQueries(1):
                self.assertFalse(filter_by_permitted_content(Folder.objects.all(), inactive, read, content=Note, registry=built_catalog(handle)).exists())
            self.assertEqual(_pks(filter_by_permitted_content(Folder.objects.all(), inactive, read, content=Note, registry=built_catalog(handle), skip_is_active=True)), {folder.pk})
        finally:
            with connection.schema_editor() as editor:
                for model in (FolderGrant, AccountGrant, NoteGrant, Account, Row, Folder, Note):
                    editor.delete_model(model)

    def test_model_backed_anonymous_and_unauthenticated_are_denied_in_both_modes(self):

        class Note(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Folder(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Row(models.Model):
            folder = models.ForeignKey('Folder', related_name='identity_rows', on_delete=models.CASCADE)
            note = models.ForeignKey('Note', related_name='identity_rows', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class LocalUser(models.Model):
            name = models.CharField(max_length=40)
            is_anonymous = models.BooleanField(default=False)
            is_authenticated = models.BooleanField(default=True)
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'

        class Bare(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class LocalUserGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            holder = models.ForeignKey(LocalUser, on_delete=models.CASCADE)
            action = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class FolderGrant(models.Model):
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            holder = models.ForeignKey(LocalUser, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
        models_ = (Note, Folder, Row, LocalUser, Bare, LocalUserGrant, FolderGrant)
        with connection.schema_editor() as editor:
            for model in models_:
                editor.create_model(model)
        try:
            read = _permission(Note, 'read_note_identity_284_note')
            note = Note.objects.create(title='n')
            folder = Folder.objects.create(title='f')
            Row.objects.create(folder=folder, note=note)
            visible = LocalUser.objects.create(name='visible')
            anonymous = LocalUser.objects.create(name='anonymous', is_anonymous=True)
            guest = LocalUser.objects.create(name='guest', is_authenticated=False)
            bare = Bare.objects.create(name='bare')
            for holder in (visible, anonymous, guest):
                LocalUserGrant.objects.create(note=note, holder=holder, action=read)
                FolderGrant.objects.create(folder=folder, holder=holder, permission=read)
            with patch('trusts.compile.catalogs.granted', return_value=Q(pk=note.pk)) as compiled:
                kept = AuthorizedQuerySet(Note).authorized(bare, read)
                self.assertEqual(_pks(kept), {note.pk})
            compiled.assert_called()
            with patch('trusts.compile.catalogs.granted') as compiled:
                with self.assertNumQueries(0):
                    for holder in (anonymous, guest):
                        for include_inactive in (False, True):
                            rows = AuthorizedQuerySet(Note).authorized(holder, read, skip_is_active=include_inactive)
                            self.assertEqual(list(rows), [])
            compiled.assert_not_called()
            registry = RegistryFactory()
            grant = Ref(LocalUserGrant)
            registry.register(content=grant.note, user=grant.holder, permission=grant.action)
            self.assertEqual(_pks(built_catalog(registry).permissions_for(visible, note)), {read.pk})
            self.assertTrue(built_catalog(registry).has_perm(visible, '%s.%s' % (read.content_type.app_label, read.codename), note))
            scope_registry = RegistryFactory()
            scope_grant = Ref(FolderGrant)
            scope_registry.register(content=scope_grant.folder.identity_rows.note, user=scope_grant.holder, permission=scope_grant.permission)
            handle = scope_registry
            self.assertEqual(_pks(filter_by_permitted_content(Folder.objects.all(), visible, read, content=Note, registry=built_catalog(handle))), {folder.pk})
            backend = DocumentBackend()
            for holder in (anonymous, guest):
                with self.assertNumQueries(0):
                    for include_inactive in (False, True):
                        self.assertEqual(list(built_catalog(registry).permissions_for(holder, note, skip_is_active=include_inactive)), [])
                        self.assertFalse(built_catalog(registry).has_perm(holder, '%s.%s' % (read.content_type.app_label, read.codename), note, skip_is_active=include_inactive))
                        self.assertFalse(built_catalog(registry).filter_authorized(Note.objects.all(), holder, read, skip_is_active=include_inactive).exists())
                        self.assertFalse(filter_by_permitted_content(Folder.objects.all(), holder, read, content=Note, registry=built_catalog(handle), skip_is_active=include_inactive).exists())
                        self.assertFalse(backend.has_perm(holder, 'myapp.change_document', note, skip_is_active=include_inactive))
                        self.assertEqual(backend.get_all_permissions(holder, note, skip_is_active=include_inactive), set())
                        self.assertEqual(backend.get_group_permissions(holder, note, skip_is_active=include_inactive), set())
            if kernel_host_listed():
                change = _permission(Document, 'change_document')
                permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
                with self.assertNumQueries(0):
                    for holder in (anonymous, guest):
                        self.assertEqual(list(permitted.permitted(change, holder, skip_is_active=True)), [])
        finally:
            with connection.schema_editor() as editor:
                for model in reversed(models_):
                    editor.delete_model(model)

class _AcceptanceBackend(TrustModelBackendMixin, ModelBackend):
    """Installed only for the acceptance class below."""

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class DelegationAcceptanceInquiryTest(TransactionTestCase):
    """Permanent checks for delegation, expiry, and an explicit active filter.

    ``active_only`` is ``lambda user, permission, content: user.is_active == True``.
    ``unexpired`` is ``content.expires_on == content.as_of``. Both are named
    filters. The relationship condition stays
    ``allowed_permissions.contains(permission)``. ``filter_by_permitted_content``
    follows the ordinary cabinet grant and a one-level delegation of that grant.
    ``has_perm`` and ``get_permitted_users`` follow the same relationship.
    A named filter applies to those two inquiries. ``filter_by_permitted_content``
    receives the permission instance, so it follows the unfiltered grant.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Cabinet(models.Model):
            name = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Sheet(PermittedUsersMixin, models.Model):
            cabinet = models.ForeignKey(Cabinet, related_name='sheets', on_delete=models.CASCADE)
            title = models.CharField(max_length=40)
            expires_on = models.DateField()
            as_of = models.DateField()

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Relationship(models.Model):
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            delegate = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            allowed_permissions = models.ManyToManyField(Permission, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
        self.Cabinet = Cabinet
        self.Sheet = Sheet
        self.Grant = Grant
        self.Relationship = Relationship
        self._models = (Cabinet, Sheet, Grant, Relationship)
        with connection.schema_editor() as editor:
            for model in self._models:
                editor.create_model(model)
        allowed = Relationship._meta.get_field('allowed_permissions')
        if not hasattr(allowed, 'm2m_field_name'):
            allowed.contribute_to_related_class(Permission, allowed.remote_field)
        self._tables_ready = True
        try:
            self.live = datetime.date(2026, 10, 12)
            self.earlier = datetime.date(2026, 9, 1)
            self.sponsor = User.objects.create_user('sponsor-accept-284', password='x')
            self.delegate = User.objects.create_user('delegate-accept-284', password='x')
            self.nora = User.objects.create_user('nora-accept-284', password='x')
            self.cara = User.objects.create_user('cara-accept-284', password='x')
            self.read = _permission(Sheet, 'read_sheet')
            self.code = 'trusts_tests.read_sheet'
            self.filtered = self.code + ':active_only'
            self.cabinet = Cabinet.objects.create(name='cabinet')
            self.sheet = Sheet.objects.create(cabinet=self.cabinet, title='sheet', expires_on=self.live, as_of=self.live)
            for user in (self.sponsor, self.nora, self.cara):
                Grant.objects.create(cabinet=self.cabinet, user=user, permission=self.read)
            self.relationship = Relationship.objects.create(cabinet=self.cabinet, delegate=self.delegate, sponsor=self.sponsor)
            self.relationship.allowed_permissions.add(self.read)
            self.handle = RegistryFactory(path='tests.core.test_issue284._AcceptanceBackend')
            self.handle.register_public(trust=Grant, user='user', permission='permission', content='cabinet__sheets')
            self.handle.register_public(trust=Relationship, delegate='delegate', sponsor='sponsor', content='cabinet__sheets', condition=lambda relationship, permission: relationship.allowed_permissions.contains(permission))
            self.handle.register_permission_condition(Sheet, 'active_only', lambda user, permission, content: user.is_active == True)
            self.handle.register_permission_condition(Sheet, 'unexpired', lambda user, permission, content: content.expires_on == content.as_of)
            install_class_handle(_AcceptanceBackend, self.handle)
            from trusts.backends import catalogs
            factory = self.handle
            factory.path = '%s.%s' % (
                _AcceptanceBackend.__module__, _AcceptanceBackend.__qualname__,
            )
            factory.family = _AcceptanceBackend.family
            catalogs[_AcceptanceBackend] = built_catalog(factory)
            self.backend = _AcceptanceBackend()
            self._settings = override_settings(AUTHENTICATION_BACKENDS=('tests.core.test_issue284._AcceptanceBackend',))
            self._settings.enable()
            self._handles = None
        except Exception:
            self._drop_tables()
            raise

    def tearDown(self):
        install_class_handle(_AcceptanceBackend, None)
        from trusts.backends import catalogs
        catalogs.pop(_AcceptanceBackend, None)
        if getattr(self, '_settings', None) is not None:
            self._settings.disable()
        self._drop_tables()
        super().tearDown()

    def _drop_tables(self):
        if not getattr(self, '_tables_ready', False):
            return
        with connection.schema_editor() as editor:
            for model in reversed(self._models):
                editor.delete_model(model)
        self._tables_ready = False

    def _deactivate(self, user):
        user.is_active = False
        user.save(update_fields=['is_active'])

    def _user_pks(self, perm, **kwargs):
        return set(self.sheet.get_permitted_users(perm, **kwargs).values_list('pk', flat=True))

    def _scope_pks(self, user, **kwargs):
        return set(filter_by_permitted_content(self.Cabinet.objects.all(), user, self.read, content=self.Sheet, registry=built_catalog(self.handle), **kwargs).values_list('pk', flat=True))

    def test_both_inactive_delegate_and_sponsor_need_the_optional_keyword(self):
        self.assertTrue(self.backend.has_perm(self.delegate, self.code, self.sheet))
        self.assertIn(self.delegate.pk, self._user_pks(self.code))
        self.assertEqual(self._scope_pks(self.sponsor), {self.cabinet.pk})
        self._deactivate(self.delegate)
        self._deactivate(self.sponsor)
        self.assertFalse(self.backend.has_perm(self.delegate, self.code, self.sheet))
        self.assertFalse(self.backend.has_perm(self.sponsor, self.code, self.sheet))
        self.assertTrue(self.backend.has_perm(self.delegate, self.code, self.sheet, skip_is_active=True))
        self.assertTrue(self.backend.has_perm(self.sponsor, self.code, self.sheet, skip_is_active=True))
        self.assertNotIn(self.delegate.pk, self._user_pks(self.code))
        self.assertNotIn(self.sponsor.pk, self._user_pks(self.code))
        included = self._user_pks(self.code, skip_is_active=True)
        self.assertIn(self.delegate.pk, included)
        self.assertIn(self.sponsor.pk, included)
        self.assertEqual(self._scope_pks(self.delegate), set())
        self.assertEqual(self._scope_pks(self.delegate, skip_is_active=True), {self.cabinet.pk})
        self.assertEqual(self._scope_pks(self.sponsor), set())
        self.assertEqual(self._scope_pks(self.sponsor, skip_is_active=True), {self.cabinet.pk})

    def test_removing_the_allowed_permission_denies_the_delegate(self):
        self.relationship.allowed_permissions.remove(self.read)
        self.assertFalse(self.backend.has_perm(self.delegate, self.code, self.sheet))
        self.assertNotIn(self.delegate.pk, self._user_pks(self.code))
        self.assertIn(self.sponsor.pk, self._user_pks(self.code))
        self.assertEqual(self._scope_pks(self.delegate), set())
        self.assertEqual(self._scope_pks(self.sponsor), {self.cabinet.pk})
        self._deactivate(self.delegate)
        self._deactivate(self.sponsor)
        self.assertFalse(self.backend.has_perm(self.delegate, self.code, self.sheet, skip_is_active=True))
        included = self._user_pks(self.code, skip_is_active=True)
        self.assertNotIn(self.delegate.pk, included)
        self.assertIn(self.sponsor.pk, included)

    def test_revoking_the_sponsor_grant_denies_the_delegate(self):
        self.Grant.objects.filter(user=self.sponsor).delete()
        self.assertFalse(self.backend.has_perm(self.delegate, self.code, self.sheet))
        self.assertFalse(self.backend.has_perm(self.sponsor, self.code, self.sheet))
        users = self._user_pks(self.code)
        self.assertNotIn(self.delegate.pk, users)
        self.assertNotIn(self.sponsor.pk, users)
        self.assertEqual(self._scope_pks(self.delegate), set())
        self.assertEqual(self._scope_pks(self.sponsor), set())
        self._deactivate(self.delegate)
        self._deactivate(self.sponsor)
        for user in (self.delegate, self.sponsor):
            self.assertFalse(self.backend.has_perm(user, self.code, self.sheet, skip_is_active=True))
            self.assertNotIn(user.pk, self._user_pks(self.code, skip_is_active=True))

    def test_unexpired_named_filter_denies_when_the_dates_differ(self):
        filtered = self.code + ':unexpired'
        self.assertTrue(self.backend.has_perm(self.delegate, filtered, self.sheet))
        self.assertIn(self.delegate.pk, self._user_pks(filtered))
        self.assertEqual(self._scope_pks(self.sponsor), {self.cabinet.pk})
        self.assertTrue(self.backend.has_perm(self.delegate, filtered, self.sheet, skip_is_active=True))
        self.assertIn(self.delegate.pk, self._user_pks(filtered, skip_is_active=True))
        self.sheet.expires_on = self.earlier
        self.sheet.save(update_fields=['expires_on'])
        self.assertFalse(self.backend.has_perm(self.delegate, filtered, self.sheet))
        self.assertFalse(self.backend.has_perm(self.sponsor, filtered, self.sheet))
        expired_users = self._user_pks(filtered)
        self.assertNotIn(self.delegate.pk, expired_users)
        self.assertNotIn(self.sponsor.pk, expired_users)
        self.assertTrue(self.backend.has_perm(self.sponsor, self.code, self.sheet))
        self.assertTrue(self.backend.has_perm(self.delegate, self.code, self.sheet))
        self.assertIn(self.sponsor.pk, self._user_pks(self.code))
        self.assertIn(self.delegate.pk, self._user_pks(self.code))
        self.assertEqual(self._scope_pks(self.delegate), {self.cabinet.pk})
        self.assertEqual(self._scope_pks(self.sponsor), {self.cabinet.pk})
        self._deactivate(self.delegate)
        self._deactivate(self.sponsor)
        for user in (self.delegate, self.sponsor):
            self.assertFalse(self.backend.has_perm(user, filtered, self.sheet, skip_is_active=True))
            self.assertNotIn(user.pk, self._user_pks(filtered, skip_is_active=True))
        self.assertTrue(self.backend.has_perm(self.sponsor, self.code, self.sheet, skip_is_active=True))

    def test_active_only_named_filter_keeps_an_inactive_user_denied(self):
        self._deactivate(self.cara)
        self.assertFalse(self.backend.has_perm(self.cara, self.filtered, self.sheet))
        self.assertFalse(self.backend.has_perm(self.cara, self.filtered, self.sheet, skip_is_active=True))
        self.assertTrue(self.backend.has_perm(self.cara, self.code, self.sheet, skip_is_active=True))
        self.assertTrue(self.backend.has_perm(self.nora, self.filtered, self.sheet))
        self.assertNotIn(self.cara.pk, self._user_pks(self.filtered, skip_is_active=True))
        self.assertIn(self.nora.pk, self._user_pks(self.filtered))
        self.assertEqual(self._scope_pks(self.cara), set())
        self.assertEqual(self._scope_pks(self.cara, skip_is_active=True), {self.cabinet.pk})
        self.assertEqual(self._scope_pks(self.nora), {self.cabinet.pk})
