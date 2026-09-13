"""#178 / #137 B+D: kernel mixin enumeration and defensive boundaries.

Public ``user.*permission*`` and mixin methods only. A registered
Document relationship stays live. Enumeration comes from that same
plan as ``has_perm``. The first configured Trusts path is the sole
QuerySet coordinator. Cache compatibility is not a second
authorization source. Private helpers and ``_trust_perm_cache``
contents are not the assertion.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from tests.backends import HostTrustModelBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant


PERM = 'myapp.change_document'
WRONG = 'myapp.add_document'
MODEL_BACKEND = 'django.contrib.auth.backends.ModelBackend'


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


class KernelMixinEnumerationTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-178', password='x')
        self.bob = User.objects.create_user('bob-178', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        _permission(Document, 'add_document', 'Can add document')
        self.user_change = _permission(User, 'change_user', 'Can change user')
        self.alice.user_permissions.add(self.user_change)
        self.document = Document.objects.create(title='granted')
        self.other = Document.objects.create(title='other')
        DocumentGrant.objects.create(
            document=self.document,
            user=self.alice,
            permission=self.change,
        )
        self.host = HostTrustModelBackend()
        self.document_backend = DocumentBackend()

    def _granted_qs(self, *documents):
        return Document.objects.filter(pk__in=[document.pk for document in documents])

    def test_instance_enumeration_matches_has_perm(self):
        self.assertTrue(self.alice.has_perm(PERM, self.document))
        self.assertFalse(self.bob.has_perm(PERM, self.document))
        self.assertFalse(self.alice.has_perm(PERM, self.other))
        self.assertFalse(self.alice.has_perm(WRONG, self.document))

        with self.assertNumQueries(1):
            all_perms = self.alice.get_all_permissions(self.document)
        self.assertEqual(all_perms, {PERM})
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_group_permissions(self.document), set())
        with self.assertNumQueries(1):
            self.assertEqual(
                self.document_backend.get_all_permissions(self.alice, self.document),
                {PERM},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                self.document_backend.get_group_permissions(self.alice, self.document),
                set(),
            )
        with self.assertNumQueries(1):
            self.assertEqual(self.bob.get_all_permissions(self.document), set())
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_all_permissions(self.other), set())

    def test_queryset_coordinator_is_first_path_and_count_independent(self):
        extra = Document.objects.create(title='also-granted')
        DocumentGrant.objects.create(
            document=extra,
            user=self.alice,
            permission=self.change,
        )
        one = self._granted_qs(self.document)
        many = self._granted_qs(self.document, extra)
        mixed = self._granted_qs(self.document, extra, self.other)

        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_all_permissions(one), {PERM})
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_all_permissions(many), {PERM})
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_group_permissions(many), set())
        with self.assertNumQueries(1):
            self.assertTrue(self.host.has_perm(self.alice, PERM, many))
        with self.assertNumQueries(1):
            self.assertFalse(self.alice.has_perm(PERM, mixed))
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_all_permissions(mixed), set())

        with self.assertNumQueries(0):
            self.assertEqual(
                self.document_backend.get_all_permissions(self.alice, many),
                set(),
            )
            self.assertEqual(
                self.document_backend.get_group_permissions(self.alice, many),
                set(),
            )
            self.assertFalse(
                self.document_backend.has_perm(self.alice, PERM, many),
            )

        with override_settings(AUTHENTICATION_BACKENDS=(
            DOCUMENT_BACKEND, HOST_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertEqual(
                    self.document_backend.get_all_permissions(self.alice, many),
                    {PERM},
                )
            with self.assertNumQueries(0):
                self.assertEqual(self.host.get_all_permissions(self.alice, many), set())
                self.assertFalse(self.host.has_perm(self.alice, PERM, many))
            with self.assertNumQueries(1):
                self.assertEqual(self.alice.get_all_permissions(many), {PERM})

    def test_duplicate_exact_paths_do_not_add_a_coordinator(self):
        qs = self._granted_qs(self.document)
        with override_settings(AUTHENTICATION_BACKENDS=(
            HOST_BACKEND, DOCUMENT_BACKEND, HOST_BACKEND,
        )):
            with self.assertNumQueries(1):
                self.assertEqual(self.host.get_all_permissions(self.alice, qs), {PERM})
            with self.assertNumQueries(0):
                self.assertEqual(
                    self.document_backend.get_all_permissions(self.alice, qs),
                    set(),
                )
                self.assertFalse(
                    self.document_backend.has_perm(self.alice, PERM, qs),
                )

    def test_defensive_inputs_are_false_empty_with_zero_sql(self):
        self.alice.user_permissions.add(self.change)
        inactive = get_user_model().objects.get(pk=self.alice.pk)
        inactive.is_active = False
        qs = self._granted_qs(self.document)

        with self.assertNumQueries(0):
            self.assertFalse(self.host.has_perm(self.alice, PERM))
            self.assertFalse(self.document_backend.has_perm(self.alice, PERM))
            self.assertEqual(self.host.get_all_permissions(self.alice), set())
            self.assertEqual(self.document_backend.get_all_permissions(self.alice), set())
            self.assertEqual(self.host.get_group_permissions(self.alice), set())
            self.assertFalse(self.alice.has_perm(PERM))
            self.assertFalse(self.alice.has_perm('auth.change_user'))
            self.assertEqual(self.alice.get_all_permissions(), set())
            self.assertFalse(self.host.has_perm(self.alice, PERM, None))
            self.assertFalse(self.host.has_perm(self.alice, PERM, {}))
            self.assertFalse(self.document_backend.has_perm(self.alice, PERM, {}))
            self.assertEqual(self.host.get_all_permissions(self.alice, {}), set())
            self.assertEqual(
                self.document_backend.get_all_permissions(self.alice, {}),
                set(),
            )
            self.assertFalse(self.alice.has_perm(PERM, {}))
            self.assertEqual(self.alice.get_all_permissions({}), set())
            self.assertFalse(self.host.has_perm(inactive, PERM, self.document))
            self.assertFalse(self.document_backend.has_perm(inactive, PERM, qs))
            self.assertEqual(
                self.document_backend.get_all_permissions(inactive, self.document),
                set(),
            )
            self.assertFalse(inactive.has_perm(PERM, self.document))
            self.assertEqual(inactive.get_all_permissions(self.document), set())
            anon = AnonymousUser()
            self.assertFalse(self.host.has_perm(anon, PERM, self.document))
            self.assertFalse(self.document_backend.has_perm(anon, PERM, qs))
            self.assertEqual(
                self.document_backend.get_all_permissions(anon, self.document),
                set(),
            )
            self.assertFalse(anon.has_perm(PERM, self.document))
            self.assertEqual(anon.get_all_permissions(self.document), set())

        self.assertTrue(self.alice.has_perm(PERM, self.document))

    def test_modelbackend_restores_globals_not_object_grants(self):
        with override_settings(AUTHENTICATION_BACKENDS=(
            MODEL_BACKEND, HOST_BACKEND, DOCUMENT_BACKEND,
        )):
            self.assertTrue(self.alice.has_perm('auth.change_user'))
            self.assertIn('auth.change_user', self.alice.get_all_permissions())
            self.assertFalse(self.host.has_perm(self.alice, 'auth.change_user'))
            self.assertFalse(
                self.document_backend.has_perm(self.alice, 'auth.change_user'),
            )
            self.assertTrue(self.alice.has_perm(PERM, self.document))
            self.assertFalse(self.alice.has_perm('auth.change_user', self.document))
            self.assertNotIn(
                'auth.change_user',
                self.alice.get_all_permissions(self.document),
            )
            with self.assertNumQueries(0):
                self.assertFalse(self.alice.has_perm(PERM, {}))
                self.assertEqual(self.alice.get_all_permissions({}), set())
                self.assertFalse(self.host.has_perm(self.alice, PERM, {}))

    def test_enumeration_follows_the_live_grant_not_a_cache(self):
        self.assertEqual(self.alice.get_all_permissions(self.document), {PERM})
        DocumentGrant.objects.filter(
            document=self.document, user=self.alice,
        ).delete()
        with self.assertNumQueries(1):
            self.assertEqual(self.alice.get_all_permissions(self.document), set())
        with self.assertNumQueries(1):
            self.assertFalse(self.alice.has_perm(PERM, self.document))
        with self.assertNumQueries(1):
            self.assertFalse(
                self.document_backend.has_perm(self.alice, PERM, self.document),
            )
