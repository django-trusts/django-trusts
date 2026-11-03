"""#268: string permission checks bind the exact codename on the content model."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from tests.core import KernelHostRequiredMixin
from tests.myapp.models import Document, DocumentGrant
from tests.support import configured_catalog
from tests.myapp.apps import DOCUMENT_BACKEND
from trusts.models import PermittedManager, PermittedUsersManagerMixin


class _Users(PermittedUsersManagerMixin):

    def __init__(self, model):
        self.model = model
        self.name = 'objects'

    def get_queryset(self):
        return self.model._default_manager.get_queryset()


def _permission(codename, name):
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct, codename=codename, defaults={'name': name},
    )
    return permission


def _code(permission):
    return '%s.%s' % (permission.content_type.app_label, permission.codename)


class ExactCodenameStringResolutionTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-268', password='x')
        self.bob = User.objects.create_user('bob-268', password='x')
        self.doc = Document.objects.create(title='doc-268', confidential=False)
        self.other = Document.objects.create(title='other-268', confidential=False)
        self.approve = _permission('approve', 'Approve document')
        self.publish = _permission('can_publish_report', 'Publish report')
        self.misleading = _permission(
            'change_organization', 'Misleading organization suffix',
        )
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.approve,
        )
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.publish,
        )
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.misleading,
        )
        self.docs = PermittedManager()
        self.docs.model = Document
        self.users = _Users(User)
        self.catalog = configured_catalog(DOCUMENT_BACKEND)

    def _assert_all_projections(self, permission, *, allowed=True):
        code = _code(permission)
        checks = (
            ('has_perm string', lambda: self.alice.has_perm(code, self.doc)),
            ('catalog string', lambda: self.catalog.has_perm(self.alice, code, self.doc)),
        )
        for label, check in checks:
            with self.subTest(label=label, codename=permission.codename):
                self.assertIs(check(), allowed)
        for label, perm in (('string', code), ('instance', permission)):
            with self.subTest(label=label, codename=permission.codename):
                reverse = set(
                    self.doc.get_permitted_users(perm).values_list('pk', flat=True),
                )
                if allowed:
                    self.assertEqual(reverse, {self.alice.pk})
                else:
                    self.assertNotIn(self.alice.pk, reverse)
                listed = set(
                    self.users.permitted(self.doc, perm).values_list('pk', flat=True),
                )
                if allowed:
                    self.assertEqual(listed, {self.alice.pk})
                else:
                    self.assertNotIn(self.alice.pk, listed)
                rows = set(
                    self.docs.permitted(perm, self.alice).values_list('pk', flat=True),
                )
                if allowed:
                    self.assertIn(self.doc.pk, rows)
                    self.assertNotIn(self.other.pk, rows)
                else:
                    self.assertEqual(rows, set())

    def test_non_action_model_codenames_match_every_projection(self):
        self._assert_all_projections(self.approve)
        self._assert_all_projections(self.publish)

    def test_misleading_suffix_uses_document_content_type(self):
        self._assert_all_projections(self.misleading)
        self.assertFalse(self.alice.has_perm(_code(self.misleading), self.other))
        self.assertFalse(
            self.catalog.has_perm(self.alice, _code(self.misleading), self.other),
        )
        self.assertNotIn(
            self.alice.pk,
            set(self.other.get_permitted_users(self.misleading).values_list('pk', flat=True)),
        )

    def test_bob_is_denied_on_every_projection(self):
        code = _code(self.approve)
        self.assertFalse(self.bob.has_perm(code, self.doc))
        self.assertFalse(self.catalog.has_perm(self.bob, code, self.doc))
        self.assertNotIn(
            self.bob.pk,
            set(self.doc.get_permitted_users(self.approve).values_list('pk', flat=True)),
        )
        self.assertNotIn(
            self.bob.pk,
            set(self.users.permitted(self.doc, self.approve).values_list('pk', flat=True)),
        )
        self.assertEqual(
            set(self.docs.permitted(self.approve, self.bob).values_list('pk', flat=True)),
            set(),
        )
