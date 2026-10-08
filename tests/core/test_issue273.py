"""#273: no implicit superuser authority on Trusts-owned inquiries.

``is_superuser`` is not a grant. A superuser is an ordinary principal
unless a registered path grants authority. Django's
``PermissionsMixin.has_perm`` shortcut and the stock admin stay
Django's. Core has no delegation compiler; the sponsor tests evaluate
the accepted ordinary-path ceiling that a delegated branch may pass on.
"""

from contextlib import contextmanager

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import Http404, HttpRequest
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps
from django.urls import path, reverse

from tests.core import KernelHostRequiredMixin
from tests.core.test_issue147.test_sql_export import (
    GOLDEN_SQLITE,
    _document_handle,
)
from tests.core.test_issue246 import _tables
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
from trusts.core import TrustsRegistry
from trusts.decorators import authorization_required
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import PermittedManager, PermittedUsersManagerMixin, is_active_principal


PERM = 'myapp.change_document'
OPEN_CODE = PERM + ':non_confidential'

urlpatterns = [
    path('admin/', admin.site.urls),
]


@authorization_required(Document, PERM)
def _edit(request, pk):
    return 'ok'


@authorization_required(Document, PERM, ('non_confidential',))
def _edit_open(request, pk):
    return 'ok'


class _UserManager(PermittedUsersManagerMixin, models.Manager):
    pass


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


def _view_status(view, user, pk):
    try:
        return view(_request(user), pk=pk)
    except PermissionDenied:
        return 403
    except Http404:
        return 404


@contextmanager
def _swapped_document_registry():
    config = implementation_for_path(DOCUMENT_BACKEND)
    saved = dict(config.registries)
    registry = TrustsRegistry()
    config.registries[DOCUMENT_BACKEND] = registry
    try:
        yield registry
    finally:
        config.registries.clear()
        config.registries.update(saved)


class Issue273SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue273', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue273', PAIR_KERNEL_SUITE)


class Issue273PolicyLockTest(SimpleTestCase):
    def test_lock_bytes_do_not_gain_an_outer_superuser_predicate(self):
        payload = render_policy_sql_bytes(handles=[_document_handle()])
        self.assertEqual(payload, GOLDEN_SQLITE)
        document = _load_policy_sql_document(payload)
        where = document['backends'][0]['contents'][0][
            'get_permitted_users'
        ]['sql'].split(' WHERE ', 1)[1]
        self.assertNotIn('is_superuser', where)


@override_settings(
    ROOT_URLCONF='tests.core.test_issue273',
    AUTHENTICATION_BACKENDS=('django.contrib.auth.backends.ModelBackend',),
)
class Issue273AdminBoundaryTest(TestCase):
    def test_stock_admin_index_and_changelist_stay_200(self):
        User = get_user_model()
        root = User.objects.create_superuser(
            username='root-admin-273',
            email='root-admin-273@example.com',
            password='x',
        )
        with self.assertNumQueries(0):
            self.assertTrue(root.has_perm('auth.view_user'))
            self.assertTrue(root.has_module_perms('auth'))
        self.client.force_login(root)
        index = self.client.get(reverse('admin:index'))
        changelist = self.client.get(reverse('admin:auth_user_changelist'))
        self.assertEqual(index.status_code, 200)
        self.assertEqual(changelist.status_code, 200)


class Issue273SuperuserMatrixTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.peer = User.objects.create_user('peer-273', password='x')
        self.actor = User.objects.create_user('actor-273', password='x')
        self.quiet = User.objects.create_user('quiet-273', password='x')
        self.quiet.is_active = False
        self.quiet.save(update_fields=['is_active'])
        self.root = User.objects.create_superuser(
            username='root-273',
            email='root-273@example.com',
            password='x',
        )
        self.dormant = User.objects.create_superuser(
            username='dormant-273',
            email='dormant-273@example.com',
            password='x',
        )
        self.dormant.is_active = False
        self.dormant.save(update_fields=['is_active'])
        self.sponsor = User.objects.create_superuser(
            username='sponsor-273',
            email='sponsor-273@example.com',
            password='x',
        )
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.open_doc = Document.objects.create(title='open-273', confidential=False)
        self.secret = Document.objects.create(title='secret-273', confidential=True)
        self.backend = DocumentBackend()
        self.docs = PermittedManager()
        self.docs.model = Document
        self.users = _UserManager()
        self.users.model = User
        self.users.name = 'objects'
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.quiet, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.dormant, permission=self.change,
        )

    def _grant(self, user, document):
        return DocumentGrant.objects.create(
            document=document, user=user, permission=self.change,
        )

    def _ordinary(self, user, document=None):
        document = self.open_doc if document is None else document
        return self.backend.has_perm(user, PERM, document)

    def _delegated(self, *, relationship, sponsor, document=None):
        """Sponsor ceiling from registered paths, not ``user.has_perm``.

        Core does not compile ``sponsor=``. This is the accepted algebra:
        a matching relationship can pass on only the sponsor's live
        ordinary authority, and only while that sponsor is active.
        """
        if not relationship or not is_active_principal(sponsor):
            return False
        return self._ordinary(sponsor, document)

    def test_active_superuser_without_a_path_is_absent_everywhere(self):
        self.assertTrue(self.root.is_active and self.root.is_superuser)
        with self.assertNumQueries(0):
            self.assertTrue(self.root.has_perm(PERM, self.open_doc))
        self.assertFalse(self._ordinary(self.root))
        self.assertNotIn(PERM, self.root.get_all_permissions(self.open_doc))
        self.assertEqual(
            _pks(Document.objects.authorized(self.root, self.change)),
            set(),
        )
        self.assertEqual(_pks(self.docs.permitted(PERM, self.root)), set())
        self.assertEqual(_view_status(_edit, self.root, self.open_doc.pk), 403)
        self.assertEqual(_view_status(_edit, self.root, self.open_doc.pk + 1000), 404)
        permitted_users = _pks(self.open_doc.get_permitted_users(self.change))
        self.assertNotIn(self.root.pk, permitted_users)
        self.assertEqual(
            _pks(self.users.permitted(self.open_doc, PERM)),
            permitted_users,
        )
        self.assertFalse(self._ordinary(self.peer))
        self.assertEqual(
            _view_status(_edit, self.peer, self.open_doc.pk),
            _view_status(_edit, self.root, self.open_doc.pk),
        )

    def test_registered_grant_authorizes_the_superuser_like_a_peer(self):
        self._grant(self.root, self.open_doc)
        self._grant(self.peer, self.open_doc)
        self.assertTrue(self._ordinary(self.root))
        self.assertTrue(self._ordinary(self.peer))
        self.assertIn(PERM, self.root.get_all_permissions(self.open_doc))
        self.assertIn(PERM, self.peer.get_all_permissions(self.open_doc))
        self.assertEqual(
            _pks(Document.objects.authorized(self.root, self.change)),
            {self.open_doc.pk},
        )
        self.assertEqual(
            _pks(self.docs.permitted(self.change, self.root)),
            _pks(self.docs.permitted(PERM, self.peer)),
        )
        self.assertEqual(_view_status(_edit, self.root, self.open_doc.pk), 'ok')
        self.assertEqual(_view_status(_edit, self.peer, self.open_doc.pk), 'ok')
        permitted_users = _pks(self.open_doc.get_permitted_users(PERM))
        self.assertIn(self.root.pk, permitted_users)
        self.assertIn(self.peer.pk, permitted_users)
        self.assertEqual(
            _pks(self.users.permitted(self.open_doc, self.change)),
            permitted_users,
        )

    def test_selected_condition_can_deny_a_superuser(self):
        self._grant(self.root, self.open_doc)
        self._grant(self.root, self.secret)
        self.assertEqual(_view_status(_edit, self.root, self.secret.pk), 'ok')
        self.assertEqual(_view_status(_edit_open, self.root, self.open_doc.pk), 'ok')
        self.assertEqual(
            _view_status(_edit_open, self.root, self.secret.pk),
            403,
        )
        self.assertEqual(
            _pks(self.docs.permitted(
                PERM, self.root, conditions=('non_confidential',),
            )),
            {self.open_doc.pk},
        )
        self.assertIn(
            self.root.pk,
            _pks(self.open_doc.get_permitted_users(OPEN_CODE)),
        )
        self.assertNotIn(
            self.root.pk,
            _pks(self.secret.get_permitted_users(OPEN_CODE)),
        )

    def test_superuser_sponsor_contributes_only_a_registered_path(self):
        handle = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        with self.assertRaises(TypeError):
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                sponsor='user',
            )
        self.assertTrue(self.sponsor.has_perm(PERM, self.open_doc))
        self.assertFalse(self._ordinary(self.actor))
        self.assertFalse(self._ordinary(self.sponsor))
        self.assertFalse(self._delegated(relationship=True, sponsor=self.sponsor))
        self.assertFalse(
            self._ordinary(self.root)
            or self._delegated(relationship=False, sponsor=self.sponsor)
        )

        self._grant(self.sponsor, self.open_doc)
        self.assertFalse(self._ordinary(self.actor))
        self.assertTrue(self._ordinary(self.sponsor))
        self.assertTrue(self._delegated(relationship=True, sponsor=self.sponsor))
        self.assertFalse(self._delegated(relationship=False, sponsor=self.sponsor))
        self.assertIn(
            self.sponsor.pk,
            _pks(self.open_doc.get_permitted_users(self.change)),
        )

        DocumentGrant.objects.filter(user=self.sponsor).delete()
        self.sponsor.refresh_from_db()
        self.assertTrue(self.sponsor.is_active and self.sponsor.is_superuser)
        self.assertFalse(self._ordinary(self.sponsor))
        self.assertFalse(self._delegated(relationship=True, sponsor=self.sponsor))
        self.assertNotIn(
            self.sponsor.pk,
            _pks(self.open_doc.get_permitted_users(self.change)),
        )

    def test_inactive_sponsor_contributes_no_delegated_authority(self):
        self.assertFalse(is_active_principal(self.dormant))
        self.assertTrue(self.dormant.is_superuser)
        self.assertFalse(self._ordinary(self.dormant))
        self.assertFalse(
            self._delegated(relationship=True, sponsor=self.dormant),
        )
        self.assertFalse(
            self._ordinary(self.actor)
            or self._delegated(relationship=True, sponsor=self.dormant)
        )

    def test_inactive_superuser_with_a_grant_is_denied(self):
        self.assertTrue(self.dormant.is_superuser)
        self.assertFalse(self.dormant.is_active)
        with self.assertNumQueries(0):
            self.assertEqual(
                _view_status(_edit, self.dormant, self.open_doc.pk),
                403,
            )
            dormant_rows = self.docs.permitted(PERM, self.dormant)
            quiet_rows = self.docs.permitted(PERM, self.quiet)
        self.assertEqual(list(dormant_rows), [])
        self.assertEqual(list(quiet_rows), [])
        self.assertFalse(self.backend.has_perm(self.dormant, PERM, self.open_doc))
        self.assertNotIn(PERM, self.dormant.get_all_permissions(self.open_doc))
        permitted_users = _pks(self.open_doc.get_permitted_users(self.change))
        self.assertNotIn(self.dormant.pk, permitted_users)
        self.assertNotIn(self.quiet.pk, permitted_users)
        self.assertEqual(
            _pks(Document.objects.authorized(self.dormant, self.change)),
            _pks(Document.objects.authorized(self.quiet, self.change)),
        )
        self.assertEqual(
            _pks(Document.objects.authorized(self.dormant, self.change)),
            {self.open_doc.pk},
        )

    @override_settings(
        AUTHENTICATION_BACKENDS=('django.contrib.auth.backends.ModelBackend',),
    )
    def test_no_contributing_backend_omits_the_superuser(self):
        with self.assertNumQueries(0):
            chosen = self.open_doc.get_permitted_users(PERM)
        self.assertEqual(list(chosen), [])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class Issue273CustomUserReverseTest(KernelHostRequiredMixin, TransactionTestCase):
    def test_reverse_inquiry_accepts_a_user_model_without_is_superuser(self):
        class PlainUser(models.Model):
            username = models.CharField(max_length=40, unique=True)
            is_active = models.BooleanField(default=True)
            is_anonymous = AbstractBaseUser.is_anonymous
            is_authenticated = AbstractBaseUser.is_authenticated

            class Meta:
                app_label = 'trusts_tests'

        class Note(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class NoteGrant(models.Model):
            user = models.ForeignKey(PlainUser, on_delete=models.CASCADE)
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        self.assertFalse(any(
            field.name == 'is_superuser'
            for field in PlainUser._meta.local_fields
        ))
        with _tables(PlainUser, Note, NoteGrant):
            with _swapped_document_registry() as registry:
                from trusts.core import BackendHandle, PlanQueryCompiler

                handle = BackendHandle(
                    path=DOCUMENT_BACKEND,
                    registry=registry,
                    compiler=PlanQueryCompiler(),
                )
                handle.register(
                    trust=NoteGrant,
                    user='user',
                    permission='permission',
                    content='note',
                )
                permission = _permission(Note, 'change_note', 'Can change note')
                note = Note.objects.create(title='plain-273')
                holder = PlainUser.objects.create(
                    username='holder-273', is_active=True,
                )
                outsider = PlainUser.objects.create(
                    username='outsider-273', is_active=True,
                )
                NoteGrant.objects.create(
                    user=holder, note=note, permission=permission,
                )
                manager = _UserManager()
                manager.model = PlainUser
                manager.name = 'objects'
                with self.assertNumQueries(0):
                    chosen = manager.permitted(note, permission)
                self.assertIs(chosen.model, PlainUser)
                found = _pks(chosen)
        self.assertEqual(found, {holder.pk})
        self.assertNotIn(outsider.pk, found)
