"""#181 / #137 C: named-filter QuerySet AND overlay.

Public mixin and ``user.has_perm`` only. A registered Document
relationship stays live. The documented ``non_confidential`` named
filter is an outer AND on that grant and compiles into the same
one-SQL evaluation. It cannot manufacture a path. Unsupported-content
zero-SQL denial stays on ``tests.core.test_issue132``. Private
overlay helpers and IR are not the assertion.

``user.has_perm`` with a named filter reaches every listed Trusts
backend until one returns True. Host looks up conditions on its own
registry, so a Document-owned filter is unknown there. The allow
path is asserted on ``user.has_perm`` when Document is first (True
short-circuits). The reject overlay is asserted on the public
Document mixin, which is the coordinator that compiles the AND.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from tests.backends import HostTrustModelBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant


PERM = 'myapp.change_document'
FILTERED = 'myapp.change_document:non_confidential'
MISSING = 'myapp.change_document:missing'
WRONG = 'myapp.add_document:non_confidential'


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


class NamedFilterQuerySetOverlayTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-181', password='x')
        self.bob = User.objects.create_user('bob-181', password='x')
        self.change = _permission(
            Document, 'change_document', 'Can change document',
        )
        _permission(Document, 'add_document', 'Can add document')
        self.open_doc = Document.objects.create(title='open')
        self.also_open = Document.objects.create(title='also-open')
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.open_doc,
            user=self.alice,
            permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.also_open,
            user=self.alice,
            permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret,
            user=self.alice,
            permission=self.change,
        )
        self.host = HostTrustModelBackend()
        self.document_backend = DocumentBackend()

    def _qs(self, *documents):
        return Document.objects.filter(
            pk__in=[document.pk for document in documents],
        )

    def test_granted_open_queryset_is_true_in_one_sql(self):
        one = self._qs(self.open_doc)
        many = self._qs(self.open_doc, self.also_open)
        with self.assertNumQueries(2):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, FILTERED, one),
            )
            self.assertTrue(
                self.document_backend.has_perm(self.alice, FILTERED, many),
            )
        with override_settings(AUTHENTICATION_BACKENDS=(
            DOCUMENT_BACKEND, HOST_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(FILTERED, many))

    def test_mixed_queryset_rejects_only_the_named_filter(self):
        mixed = self._qs(self.open_doc, self.secret)
        secret = self._qs(self.secret)
        with self.assertNumQueries(3):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, FILTERED, mixed),
            )
            self.assertFalse(
                self.document_backend.has_perm(self.alice, FILTERED, secret),
            )
            self.assertTrue(
                self.document_backend.has_perm(self.alice, PERM, mixed),
            )
        self.assertTrue(self.alice.has_perm(PERM, mixed))

    def test_named_filter_does_not_create_authorization(self):
        open_qs = self._qs(self.open_doc)
        with self.assertNumQueries(2):
            self.assertFalse(
                self.document_backend.has_perm(self.bob, FILTERED, open_qs),
            )
            self.assertFalse(
                self.document_backend.has_perm(self.alice, WRONG, open_qs),
            )
        with self.assertNumQueries(0):
            self.assertFalse(self.host.has_perm(self.alice, PERM, open_qs))

    def test_unknown_condition_fails_before_queryset_sql(self):
        open_qs = self._qs(self.open_doc)
        with self.assertNumQueries(0):
            with self.assertRaises(AttributeError) as missing:
                self.document_backend.has_perm(self.alice, MISSING, open_qs)
        self.assertIn('missing', str(missing.exception))
        self.assertTrue(
            self.document_backend.has_perm(self.alice, PERM, open_qs),
        )
