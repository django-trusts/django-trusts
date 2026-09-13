"""#138: authorization_required Trusts-only pk guard."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.checks import Error, run_checks
from django.http import Http404, HttpRequest
from django.test import TestCase
from django.test.utils import override_settings

from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.myapp.settings import AUTHENTICATION_BACKENDS, INSTALLED_APPS
from trusts.core import TrustsConfigurationError
from trusts.decorators import (
    _declared_authorization_guards,
    authorization_required,
)
from trusts.apps import implementation_for_path


class AlwaysGrantBackend(object):
    """Unrelated Django backend that grants every has_perm question."""

    def authenticate(self, request, **credentials):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return True

    def has_module_perms(self, user_obj, app_label):
        return True


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _permission(codename, name):
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


@authorization_required(Document, 'myapp.change_document')
def _edit(request, pk):
    return 'ok'


@authorization_required(Document, 'myapp.change_document', ('non_confidential',))
def _edit_non_confidential(request, pk):
    return 'ok'


@authorization_required(Document, 'myapp.can_publish')
def _publish(request, pk):
    return 'ok'


@override_settings(
    AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS,
    INSTALLED_APPS=INSTALLED_APPS,
)
class AuthorizationRequiredTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-138', password='x')
        self.bob = User.objects.create_user(username='bob-138', password='x')
        self.superuser = User.objects.create_superuser(
            username='root-138', password='x', email='root@example.com',
        )
        self.inactive = User.objects.create_user(
            username='inactive-138', password='x',
        )
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.change = _permission('change_document', 'Can change document')
        self.publish = _permission('can_publish', 'Can publish document')
        self.open_doc = Document.objects.create(title='open', confidential=False)
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.publish,
        )

    def test_declaration_rejects_non_tuple_conditions_and_colon_permission(self):
        with self.assertRaises(TypeError):
            authorization_required(Document, 'myapp.change_document', 'non_confidential')
        with self.assertRaises(TypeError):
            authorization_required(Document, 'myapp.change_document', ['non_confidential'])
        with self.assertRaises(TypeError):
            authorization_required(object, 'myapp.change_document')
        with self.assertRaises(TrustsConfigurationError):
            authorization_required(Document, 'myapp.change_document:non_confidential')
        with self.assertRaises(TrustsConfigurationError):
            authorization_required(
                Document, 'myapp.change_document', ('non_confidential', 'non_confidential'),
            )
        with self.assertRaises(TrustsConfigurationError):
            authorization_required(Document, 'otherapp.change_document')

    def test_authorized_hit_is_one_combined_query(self):
        with self.assertNumQueries(1):
            self.assertEqual(_edit(_request(self.alice), pk=self.open_doc.pk), 'ok')

    def test_missing_and_malformed_pk_are_404_without_sql(self):
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                _edit(_request(self.alice))
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                _edit(_request(self.alice), pk='')
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                _edit(_request(self.alice), pk='not-a-pk')

    def test_absence_is_404_and_denial_is_403(self):
        with self.assertNumQueries(2):
            with self.assertRaises(Http404):
                _edit(_request(self.alice), pk=self.open_doc.pk + 1000)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                _edit(_request(self.bob), pk=self.open_doc.pk)

    def test_anonymous_and_inactive_are_denied_before_sql(self):
        anonymous = AnonymousUser()
        self.assertTrue(anonymous.is_anonymous)
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionDenied):
                _edit(_request(anonymous), pk=self.open_doc.pk)
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionDenied):
                _edit(_request(self.inactive), pk=self.open_doc.pk)

    def test_superuser_exists_in_one_existence_query(self):
        with self.assertNumQueries(1):
            self.assertEqual(_edit(_request(self.superuser), pk=self.open_doc.pk), 'ok')
        with self.assertNumQueries(1):
            self.assertEqual(
                _edit_non_confidential(_request(self.superuser), pk=self.secret.pk),
                'ok',
            )
        with self.assertNumQueries(1):
            with self.assertRaises(Http404):
                _edit(_request(self.superuser), pk=self.open_doc.pk + 1000)

    def test_named_condition_is_and_overlay_not_a_grant(self):
        self.assertEqual(
            _edit_non_confidential(_request(self.alice), pk=self.open_doc.pk),
            'ok',
        )
        with self.assertRaises(PermissionDenied):
            _edit_non_confidential(_request(self.alice), pk=self.secret.pk)
        with self.assertRaises(PermissionDenied):
            _edit_non_confidential(_request(self.bob), pk=self.open_doc.pk)

    def test_custom_codename_uses_explicit_model(self):
        with self.assertNumQueries(1):
            self.assertEqual(
                _publish(_request(self.alice), pk=self.open_doc.pk),
                'ok',
            )
        with self.assertRaises(PermissionDenied):
            _publish(_request(self.alice), pk=self.secret.pk)

    def _forget_guard(self, entry):
        try:
            _declared_authorization_guards.remove(entry)
        except ValueError:
            pass

    def test_unknown_condition_fails_closed_on_first_use(self):
        entry = (Document, 'myapp.change_document', ('missing_138',))
        self.addCleanup(self._forget_guard, entry)

        @authorization_required(Document, 'myapp.change_document', ('missing_138',))
        def _bad(request, pk):
            return 'no'

        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                _bad(_request(self.alice), pk=self.open_doc.pk)

    def test_system_check_reports_unknown_guard_condition(self):
        entry = (Document, 'myapp.change_document', ('missing_check_138',))
        self.addCleanup(self._forget_guard, entry)

        @authorization_required(Document, 'myapp.change_document', ('missing_check_138',))
        def _unused(request, pk):
            return 'no'

        self.assertIn(entry, _declared_authorization_guards)
        messages = [
            message for message in run_checks()
            if getattr(message, 'id', None) == 'trusts.E008'
            and 'missing_check_138' in message.msg
        ]
        self.assertTrue(messages)
        self.assertIsInstance(messages[0], Error)

    @override_settings(
        AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS + (
            'tests.core.test_issue138.AlwaysGrantBackend',
        ),
    )
    def test_unrelated_backend_cannot_override_a_trusts_denial(self):
        self.assertTrue(
            self.bob.has_perm('myapp.change_document', self.open_doc),
        )
        with self.assertRaises(PermissionDenied):
            _edit(_request(self.bob), pk=self.open_doc.pk)

    def test_ready_still_owns_the_document_plan(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        handle = owner.configured_backend()
        self.assertTrue(handle.registry.records)
        self.assertIsNotNone(
            handle.registry.get_permission_condition_record(
                Document, 'non_confidential',
            ),
        )
