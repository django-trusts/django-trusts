"""Inactive users on Trusts inquiries (#284).

Default Trusts inquiries deny a user whose ``is_active`` is false.
``allow_inactive_user=True`` and ``allow_inactive=True`` skip only that
built-in check. Anonymous and unauthenticated users stay denied when
either keyword is true. Superuser shortcuts and explicit conditions stay
in place.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import Q
from django.test import TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin, kernel_host_listed
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentDelegation, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    filter_authorized_scopes,
)
from trusts.query import (
    AuthorizedQuerySet,
    PermittedQuerySet,
    PermittedUsersManagerMixin,
)


PERM = 'myapp.change_document'


def _permission(model, codename):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


class _Handle(object):
    def __init__(self, registry):
        self.registry = registry
        self.compiler = PlanQueryCompiler()


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
        self.superuser = User.objects.create_superuser(
            'super-284', email='super-284@example.com', password='x',
        )
        self.inactive_super = User.objects.create_superuser(
            'inactive-super-284', email='inactive-super-284@example.com',
            password='x',
        )
        self.inactive_super.is_active = False
        self.inactive_super.save(update_fields=['is_active'])
        self.change = _permission(Document, 'change_document')
        self.open_doc = Document.objects.create(title='open-284', confidential=False)
        self.secret = Document.objects.create(title='secret-284', confidential=True)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.sponsor, permission=self.change,
        )
        relationship = DocumentDelegation.objects.create(
            document=self.open_doc, delegate=self.delegate, sponsor=self.sponsor,
        )
        relationship.allowed_permissions.add(self.change)
        self.backend = DocumentBackend()

    def _deactivate(self, user):
        user.is_active = False
        user.save(update_fields=['is_active'])

    def test_content_enumeration_and_boolean_with_allow_inactive_user(self):
        self._deactivate(self.alice)
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertNumQueries(0):
            self.assertFalse(
                Document.objects.authorized(self.alice, self.change).exists()
            )
            self.assertEqual(
                _pks(permitted.permitted(self.change, self.alice)), set(),
            )
            self.assertFalse(self.alice.has_perm(PERM, self.open_doc))
            self.assertFalse(
                self.backend.has_perm(self.alice, PERM, self.open_doc)
            )
            self.assertEqual(
                self.backend.get_all_permissions(self.alice, self.open_doc),
                set(),
            )
            self.assertEqual(
                self.backend.get_group_permissions(self.alice, self.open_doc),
                set(),
            )
        self.assertEqual(
            _pks(Document.objects.authorized(
                self.alice, self.change, allow_inactive_user=True,
            )),
            {self.open_doc.pk, self.secret.pk},
        )
        self.assertEqual(
            _pks(permitted.permitted(
                self.change, self.alice, allow_inactive_user=True,
            )),
            {self.open_doc.pk, self.secret.pk},
        )
        self.assertEqual(
            _pks(permitted.permitted(
                PERM, self.alice, conditions=('non_confidential',),
                allow_inactive_user=True,
            )),
            {self.open_doc.pk},
        )
        self.assertTrue(self.backend.has_perm(
            self.alice, PERM, self.open_doc, allow_inactive_user=True,
        ))
        self.assertIn(
            PERM,
            self.backend.get_all_permissions(
                self.alice, self.open_doc, allow_inactive_user=True,
            ),
        )
        self.assertFalse(self.alice.has_perm(PERM, self.open_doc))
        with self.assertRaises(TypeError):
            self.alice.has_perm(PERM, self.open_doc, allow_inactive_user=True)

    def test_anonymous_stays_denied_with_allow_inactive_user(self):
        anonymous = AnonymousUser()
        permitted = PermittedQuerySet(model=Document, using=Document.objects.db)
        with self.assertNumQueries(0):
            self.assertEqual(
                _pks(permitted.permitted(
                    self.change, anonymous, allow_inactive_user=True,
                )),
                set(),
            )
            self.assertFalse(self.backend.has_perm(
                anonymous, PERM, self.open_doc, allow_inactive_user=True,
            ))
            with patch('trusts.core.granted') as compiled:
                denied = Document.objects.authorized(anonymous, self.change)
                audited = Document.objects.authorized(
                    anonymous, self.change, allow_inactive_user=True,
                )
                self.assertEqual(_pks(denied), set())
                self.assertEqual(_pks(audited), set())
            compiled.assert_not_called()

    def test_superuser_shortcut_is_unchanged(self):
        self.assertTrue(self.superuser.has_perm(PERM, self.open_doc))
        self.assertFalse(
            Document.objects.authorized(self.superuser, self.change).exists()
        )
        self.assertFalse(self.inactive_super.has_perm(PERM, self.open_doc))
        self.assertFalse(self.backend.has_perm(
            self.inactive_super, PERM, self.open_doc, allow_inactive_user=True,
        ))
        self.assertFalse(
            Document.objects.authorized(
                self.inactive_super, self.change, allow_inactive_user=True,
            ).exists()
        )

    def test_user_list_includes_inactive_grant_only_with_allow_inactive(self):
        self._deactivate(self.alice)

        class Listing(PermittedUsersManagerMixin, type(get_user_model().objects)):
            pass

        listing = Listing()
        listing.model = get_user_model()
        default_users = _pks(self.open_doc.get_permitted_users(self.change))
        audited_users = _pks(self.open_doc.get_permitted_users(
            self.change, allow_inactive=True,
        ))
        via_manager = _pks(listing.permitted(
            self.open_doc, self.change, allow_inactive=True,
        ))
        self.assertNotIn(self.alice.pk, default_users)
        self.assertIn(self.sponsor.pk, default_users)
        self.assertIn(self.alice.pk, audited_users)
        self.assertEqual(via_manager, audited_users)
        self.assertIn(self.superuser.pk, default_users)
        self.assertNotIn(self.inactive_super.pk, default_users)
        self.assertNotIn(self.inactive_super.pk, audited_users)

    def test_inactive_delegate_and_sponsor_fail_closed_unless_allow_inactive(self):
        self._deactivate(self.delegate)
        self.assertFalse(self.delegate.has_perm(PERM, self.open_doc))
        self.assertTrue(self.backend.has_perm(
            self.delegate, PERM, self.open_doc, allow_inactive_user=True,
        ))
        self.assertNotIn(
            self.delegate,
            set(self.open_doc.get_permitted_users(self.change)),
        )
        self.assertIn(
            self.delegate,
            set(self.open_doc.get_permitted_users(
                self.change, allow_inactive=True,
            )),
        )
        self.delegate.is_active = True
        self.delegate.save(update_fields=['is_active'])
        self._deactivate(self.sponsor)
        self.assertFalse(self.delegate.has_perm(PERM, self.open_doc))
        self.assertTrue(self.backend.has_perm(
            self.delegate, PERM, self.open_doc, allow_inactive_user=True,
        ))
        self.assertNotIn(
            self.delegate,
            set(self.open_doc.get_permitted_users(self.change)),
        )
        self.assertIn(
            self.delegate,
            set(self.open_doc.get_permitted_users(
                self.change, allow_inactive=True,
            )),
        )

    def test_allow_inactive_flag_must_be_a_bool_before_sql(self):
        with self.assertNumQueries(0):
            with self.assertRaises(TypeError):
                Document.objects.authorized(
                    self.alice, self.change, allow_inactive_user=1,
                )
            with self.assertRaises(TypeError):
                self.open_doc.get_permitted_users(self.change, allow_inactive=1)
            with self.assertRaises(TypeError):
                self.backend.has_perm(
                    self.alice, PERM, self.open_doc, allow_inactive_user='yes',
                )


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
            folder = models.ForeignKey(
                'Folder', related_name='rows', on_delete=models.CASCADE,
            )
            note = models.ForeignKey(
                'Note', related_name='rows', on_delete=models.CASCADE,
            )

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
            for model in (
                Note, Folder, Row, Account, NoteGrant, AccountGrant, FolderGrant,
            ):
                editor.create_model(model)
        try:
            alice = User.objects.create_user('alice-reg-284', password='x')
            inactive = User.objects.create_user('inactive-reg-284', password='x')
            inactive.is_active = False
            inactive.save(update_fields=['is_active'])
            ct = ContentType.objects.get_for_model(Note)
            read, _created = Permission.objects.get_or_create(
                content_type=ct, codename='read_note_284',
                defaults={'name': 'read note 284'},
            )
            note = Note.objects.create(title='n')
            folder = Folder.objects.create(title='f')
            Row.objects.create(folder=folder, note=note)
            NoteGrant.objects.create(note=note, user=alice, permission=read)
            NoteGrant.objects.create(note=note, user=inactive, permission=read)
            account = Account.objects.create(name='acct')
            AccountGrant.objects.create(note=note, account=account, action=read)
            FolderGrant.objects.create(
                folder=folder, user=alice, permission=read,
            )
            FolderGrant.objects.create(
                folder=folder, user=inactive, permission=read,
            )

            registry = TrustsRegistry()
            grant = Ref(NoteGrant)
            registry.register(
                content=grant.note, user=grant.user, permission=grant.permission,
            )
            self.assertEqual(
                _pks(registry.permissions_for(alice, note)), {read.pk},
            )
            self.assertTrue(registry.has_permission(alice, note, read))
            self.assertEqual(
                _pks(registry.filter_authorized(Note.objects.all(), alice, read)),
                {note.pk},
            )
            with self.assertNumQueries(0):
                self.assertEqual(
                    list(registry.permissions_for(inactive, note)), [],
                )
                self.assertFalse(registry.has_permission(inactive, note, read))
                self.assertFalse(
                    registry.filter_authorized(
                        Note.objects.all(), inactive, read,
                    ).exists()
                )
            self.assertEqual(
                _pks(registry.permissions_for(
                    inactive, note, allow_inactive_user=True,
                )),
                {read.pk},
            )
            self.assertTrue(registry.has_permission(
                inactive, note, read, allow_inactive_user=True,
            ))
            self.assertEqual(
                _pks(registry.filter_authorized(
                    Note.objects.all(), inactive, read,
                    allow_inactive_user=True,
                )),
                {note.pk},
            )

            account_registry = TrustsRegistry()
            account_grant = Ref(AccountGrant)
            account_registry.register(
                content=account_grant.note,
                user=account_grant.account,
                permission=account_grant.action,
            )
            self.assertEqual(
                _pks(account_registry.permissions_for(account, note)),
                {read.pk},
            )
            self.assertTrue(
                account_registry.has_permission(account, note, read)
            )

            scope_registry = TrustsRegistry()
            scope_grant = Ref(FolderGrant)
            scope_registry.register(
                content=scope_grant.folder.rows.note,
                user=scope_grant.user,
                permission=scope_grant.permission,
            )
            handle = _Handle(scope_registry)
            self.assertEqual(
                _pks(filter_authorized_scopes(
                    Folder.objects.all(), alice, read,
                    content=Note, handles=(handle,),
                )),
                {folder.pk},
            )
            with self.assertNumQueries(0):
                self.assertFalse(filter_authorized_scopes(
                    Folder.objects.all(), inactive, read,
                    content=Note, handles=(handle,),
                ).exists())
            self.assertEqual(
                _pks(filter_authorized_scopes(
                    Folder.objects.all(), inactive, read,
                    content=Note, handles=(handle,),
                    allow_inactive_user=True,
                )),
                {folder.pk},
            )
        finally:
            with connection.schema_editor() as editor:
                for model in (
                    FolderGrant, AccountGrant, NoteGrant, Account, Row, Folder, Note,
                ):
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
            folder = models.ForeignKey(
                'Folder', related_name='identity_rows', on_delete=models.CASCADE,
            )
            note = models.ForeignKey(
                'Note', related_name='identity_rows', on_delete=models.CASCADE,
            )

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

        models_ = (
            Note, Folder, Row, LocalUser, Bare, LocalUserGrant, FolderGrant,
        )
        with connection.schema_editor() as editor:
            for model in models_:
                editor.create_model(model)
        try:
            read = _permission(Note, 'read_note_identity_284')
            note = Note.objects.create(title='n')
            folder = Folder.objects.create(title='f')
            Row.objects.create(folder=folder, note=note)
            visible = LocalUser.objects.create(name='visible')
            anonymous = LocalUser.objects.create(
                name='anonymous', is_anonymous=True,
            )
            guest = LocalUser.objects.create(
                name='guest', is_authenticated=False,
            )
            bare = Bare.objects.create(name='bare')
            for holder in (visible, anonymous, guest):
                LocalUserGrant.objects.create(
                    note=note, holder=holder, action=read,
                )
                FolderGrant.objects.create(
                    folder=folder, holder=holder, permission=read,
                )

            with patch('trusts.core.granted', return_value=Q(pk=note.pk)) as compiled:
                kept = AuthorizedQuerySet(Note).authorized(bare, read)
                self.assertEqual(_pks(kept), {note.pk})
            compiled.assert_called()
            with patch('trusts.core.granted') as compiled:
                with self.assertNumQueries(0):
                    for holder in (anonymous, guest):
                        for include_inactive in (False, True):
                            rows = AuthorizedQuerySet(Note).authorized(
                                holder, read, allow_inactive_user=include_inactive,
                            )
                            self.assertEqual(list(rows), [])
            compiled.assert_not_called()

            registry = TrustsRegistry()
            grant = Ref(LocalUserGrant)
            registry.register(
                content=grant.note,
                user=grant.holder,
                permission=grant.action,
            )
            self.assertEqual(
                _pks(registry.permissions_for(visible, note)), {read.pk},
            )
            self.assertTrue(registry.has_permission(visible, note, read))
            scope_registry = TrustsRegistry()
            scope_grant = Ref(FolderGrant)
            scope_registry.register(
                content=scope_grant.folder.identity_rows.note,
                user=scope_grant.holder,
                permission=scope_grant.permission,
            )
            handle = _Handle(scope_registry)
            self.assertEqual(
                _pks(filter_authorized_scopes(
                    Folder.objects.all(), visible, read,
                    content=Note, handles=(handle,),
                )),
                {folder.pk},
            )
            backend = DocumentBackend()
            for holder in (anonymous, guest):
                with self.assertNumQueries(0):
                    for include_inactive in (False, True):
                        self.assertEqual(
                            list(registry.permissions_for(
                                holder, note, allow_inactive_user=include_inactive,
                            )),
                            [],
                        )
                        self.assertFalse(registry.has_permission(
                            holder, note, read, allow_inactive_user=include_inactive,
                        ))
                        self.assertFalse(registry.filter_authorized(
                            Note.objects.all(), holder, read,
                            allow_inactive_user=include_inactive,
                        ).exists())
                        self.assertFalse(filter_authorized_scopes(
                            Folder.objects.all(), holder, read,
                            content=Note, handles=(handle,),
                            allow_inactive_user=include_inactive,
                        ).exists())
                        self.assertFalse(backend.has_perm(
                            holder, 'myapp.change_document', note,
                            allow_inactive_user=include_inactive,
                        ))
                        self.assertEqual(
                            backend.get_all_permissions(
                                holder, note, allow_inactive_user=include_inactive,
                            ),
                            set(),
                        )
                        self.assertEqual(
                            backend.get_group_permissions(
                                holder, note, allow_inactive_user=include_inactive,
                            ),
                            set(),
                        )
            if kernel_host_listed():
                change = _permission(Document, 'change_document')
                permitted = PermittedQuerySet(
                    model=Document, using=Document.objects.db,
                )
                with self.assertNumQueries(0):
                    for holder in (anonymous, guest):
                        self.assertEqual(
                            list(permitted.permitted(
                                change, holder, allow_inactive_user=True,
                            )),
                            [],
                        )
        finally:
            with connection.schema_editor() as editor:
                for model in reversed(models_):
                    editor.delete_model(model)
