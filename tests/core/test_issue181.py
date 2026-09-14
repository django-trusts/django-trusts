"""#181 / #137 C: share-nothing authorization by exact path.

Public ``user.has_perm`` / mixin methods only. Each exact
``AUTHENTICATION_BACKENDS`` path evaluates ``self._own_handle()``.
Host does not preempt Document's ``non_confidential`` overlay on a
QuerySet or a model instance. A named filter cannot manufacture a
path or grant. Split-path grants do not OR per row before the
all-candidates projection. #132 already proves a registered true
filter cannot turn unsupported content into a plan. Private
overlay/lookup/compiler helpers are not the assertion.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from tests.backends import HostTrustModelBackend, MixinOnlyBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentAltGrant, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.core import BackendHandle, PlanQueryCompiler, TrustsRegistry


PERM = 'myapp.change_document'
FILTERED = 'myapp.change_document:non_confidential'
WRONG = 'myapp.add_document'
WRONG_FILTERED = 'myapp.add_document:non_confidential'
MISSING = 'myapp.change_document:missing'
MIXIN = 'tests.backends.MixinOnlyBackend'


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


class ShareNothingQuerySetAuthorizationTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-181', password='x')
        self.bob = User.objects.create_user('bob-181', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        _permission(Document, 'add_document', 'Can add document')
        self.open_one = Document.objects.create(title='open-one')
        self.open_two = Document.objects.create(title='open-two')
        self.secret = Document.objects.create(title='secret', confidential=True)
        for document in (self.open_one, self.open_two, self.secret):
            DocumentGrant.objects.create(
                document=document,
                user=self.alice,
                permission=self.change,
            )
        self.host = HostTrustModelBackend()
        self.document_backend = DocumentBackend()

    def _granted_qs(self, *documents):
        return Document.objects.filter(pk__in=[document.pk for document in documents])

    def test_named_filter_overlays_granted_queryset_at_one_sql(self):
        one = self._granted_qs(self.open_one)
        many = self._granted_qs(self.open_one, self.open_two)
        mixed = self._granted_qs(self.open_one, self.open_two, self.secret)

        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, FILTERED, one),
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, FILTERED, many),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, FILTERED, mixed),
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, PERM, mixed),
            )
        with self.assertNumQueries(0):
            self.assertFalse(self.host.has_perm(self.alice, FILTERED, mixed))
            self.assertFalse(self.host.has_perm(self.alice, PERM, mixed))
            self.assertEqual(self.host.get_all_permissions(self.alice, mixed), set())
            self.assertEqual(self.host.get_group_permissions(self.alice, mixed), set())

        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(FILTERED, one))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(FILTERED, many))
        with self.assertNumQueries(1):
            self.assertFalse(self.alice.has_perm(FILTERED, mixed))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(PERM, mixed))
        self.assertEqual(self.alice.get_all_permissions(mixed), {PERM})

        with override_settings(AUTHENTICATION_BACKENDS=(
            DOCUMENT_BACKEND, HOST_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(FILTERED, one))
            with self.assertNumQueries(1):
                self.assertFalse(self.alice.has_perm(FILTERED, mixed))
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(PERM, mixed))

    def test_named_filter_does_not_create_authorization(self):
        many = self._granted_qs(self.open_one, self.open_two)

        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(self.bob, FILTERED, many),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, WRONG_FILTERED, many),
            )
        with self.assertNumQueries(1):
            self.assertFalse(self.document_backend.has_perm(self.alice, WRONG, many))
        with self.assertNumQueries(0):
            self.assertFalse(self.host.has_perm(self.bob, FILTERED, many))
            self.assertFalse(self.host.has_perm(self.alice, WRONG_FILTERED, many))

        with self.assertNumQueries(1):
            self.assertFalse(self.bob.has_perm(FILTERED, many))
        with self.assertNumQueries(1):
            self.assertFalse(self.alice.has_perm(WRONG_FILTERED, many))
        self.assertFalse(self.alice.has_perm(WRONG, many))
        self.assertFalse(self.bob.has_perm(PERM, many))

    def test_unknown_local_filter_is_non_match_at_zero_sql(self):
        many = self._granted_qs(self.open_one, self.open_two)

        with self.assertNumQueries(0):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, MISSING, many),
            )
            self.assertFalse(self.host.has_perm(self.alice, MISSING, many))
            self.assertFalse(self.alice.has_perm(MISSING, many))
            self.assertFalse(
                self.document_backend.has_perm(self.alice, MISSING, self.open_one),
            )
            self.assertFalse(self.host.has_perm(self.alice, MISSING, self.open_one))
            self.assertFalse(self.alice.has_perm(MISSING, self.open_one))

        with self.assertNumQueries(1):
            self.assertTrue(self.document_backend.has_perm(self.alice, PERM, many))
        self.assertTrue(self.alice.has_perm(PERM, many))
        self.assertTrue(
            self.document_backend.has_perm(self.alice, PERM, self.open_one),
        )

    def test_split_path_grants_do_not_or_before_all_candidates(self):
        DocumentGrant.objects.filter(
            document=self.open_two, user=self.alice,
        ).delete()
        DocumentAltGrant.objects.create(
            document=self.open_two,
            user=self.alice,
            permission=self.change,
        )
        one = self._granted_qs(self.open_one)
        two = self._granted_qs(self.open_two)
        both = self._granted_qs(self.open_one, self.open_two)
        owner = implementation_for_path(DOCUMENT_BACKEND)
        saved = owner.trusts_backend_paths
        alt_registry = TrustsRegistry()
        BackendHandle(
            path=MIXIN,
            registry=alt_registry,
            compiler=PlanQueryCompiler(),
        ).register_relationship(
            DocumentAltGrant,
            user='user',
            permission='permission',
            content='document',
        )
        owner.registries[MIXIN] = alt_registry
        mixin = MixinOnlyBackend()
        try:
            owner.trusts_backend_paths = (DOCUMENT_BACKEND, MIXIN)
            with override_settings(AUTHENTICATION_BACKENDS=(
                HOST_BACKEND, DOCUMENT_BACKEND, MIXIN,
            )):
                with self.assertNumQueries(1):
                    self.assertTrue(
                        self.document_backend.has_perm(self.alice, PERM, one),
                    )
                with self.assertNumQueries(1):
                    self.assertTrue(mixin.has_perm(self.alice, PERM, two))
                with self.assertNumQueries(1):
                    self.assertFalse(
                        self.document_backend.has_perm(self.alice, PERM, both),
                    )
                with self.assertNumQueries(1):
                    self.assertFalse(mixin.has_perm(self.alice, PERM, both))
                with self.assertNumQueries(0):
                    self.assertFalse(self.host.has_perm(self.alice, PERM, both))
                with self.assertNumQueries(1):
                    self.assertEqual(
                        self.document_backend.get_all_permissions(self.alice, both),
                        set(),
                    )
                with self.assertNumQueries(1):
                    self.assertEqual(mixin.get_all_permissions(self.alice, both), set())
                with self.assertNumQueries(2):
                    self.assertFalse(self.alice.has_perm(PERM, both))
                self.assertEqual(self.alice.get_all_permissions(both), set())
                self.assertTrue(self.alice.has_perm(PERM, one))
                self.assertTrue(self.alice.has_perm(PERM, two))

            with override_settings(AUTHENTICATION_BACKENDS=(
                MIXIN, DOCUMENT_BACKEND, HOST_BACKEND,
            )):
                with self.assertNumQueries(2):
                    self.assertFalse(self.alice.has_perm(PERM, both))
                self.assertEqual(self.alice.get_all_permissions(both), set())
                self.assertTrue(self.alice.has_perm(PERM, one))
                self.assertTrue(self.alice.has_perm(PERM, two))
        finally:
            owner.trusts_backend_paths = saved
            owner.registries.pop(MIXIN, None)

    def test_duplicate_path_is_two_evaluations(self):
        qs = self._granted_qs(self.open_one)
        mixed = self._granted_qs(self.open_one, self.secret)
        with override_settings(AUTHENTICATION_BACKENDS=(
            HOST_BACKEND, DOCUMENT_BACKEND, DOCUMENT_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertTrue(
                    self.document_backend.has_perm(self.alice, FILTERED, qs),
                )
            with self.assertNumQueries(0):
                self.assertFalse(self.host.has_perm(self.alice, FILTERED, qs))
            # Django has_perm short-circuits on the first True. A False
            # overlay still runs every listed Document instance.
            with self.assertNumQueries(2):
                self.assertFalse(self.alice.has_perm(FILTERED, mixed))
            with self.assertNumQueries(2):
                self.assertEqual(self.alice.get_all_permissions(qs), {PERM})

    def test_instance_named_filter_does_not_preempt_siblings(self):
        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, FILTERED, self.open_one),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, FILTERED, self.secret),
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                self.document_backend.has_perm(self.alice, PERM, self.secret),
            )
        with self.assertNumQueries(0):
            self.assertFalse(self.host.has_perm(self.alice, FILTERED, self.open_one))
            self.assertFalse(self.host.has_perm(self.alice, PERM, self.open_one))
            self.assertFalse(self.host.has_perm(self.alice, MISSING, self.open_one))
            self.assertFalse(
                self.document_backend.has_perm(self.alice, MISSING, self.open_one),
            )

        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(FILTERED, self.open_one))
        with self.assertNumQueries(1):
            self.assertFalse(self.alice.has_perm(FILTERED, self.secret))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(PERM, self.secret))
        with self.assertNumQueries(0):
            self.assertFalse(self.alice.has_perm(MISSING, self.open_one))

        with override_settings(AUTHENTICATION_BACKENDS=(
            DOCUMENT_BACKEND, HOST_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertTrue(self.alice.has_perm(FILTERED, self.open_one))
            with self.assertNumQueries(1):
                self.assertFalse(self.alice.has_perm(FILTERED, self.secret))
            with self.assertNumQueries(0):
                self.assertFalse(self.alice.has_perm(MISSING, self.open_one))
