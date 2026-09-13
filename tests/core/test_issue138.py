"""#138: Core ``authorization_required`` guard against the accepted #169 v2 map."""

import inspect
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.http import Http404, HttpRequest, QueryDict
from django.conf import settings
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext, isolate_apps, override_settings

from tests.apps import override_apps_ready
from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import configured_implementation_handles, implementation_for_path
from trusts.checks import (
    CHECK_ID_AUTHORIZATION_REQUIRED,
    check_authorization_required,
)
from trusts.conditions._ir import ConditionRecord
from trusts.core import Ref, TrustsConfigurationError, TrustsRegistry, granted
from trusts.decorators import (
    authorization_required,
    forget_authorization_required,
    iter_authorization_required_declarations,
    permission_required,
)
from trusts.utils import parse_perm_code


CHANGE = 'myapp.change_document'
PUBLISH = 'myapp.can_publish'


class GrantAllBackend(object):
    """Unrelated Django backend that would grant via ``user.has_perm`` OR."""

    def authenticate(self, request=None, **kwargs):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        return True

    def has_module_perms(self, user_obj, app_label):
        return True


def _request(user):
    request = HttpRequest()
    request.user = user
    request.GET = QueryDict('')
    request.POST = QueryDict('')
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _ok_view(request, pk):
    return 'ok'


def _guard(model, permission, conditions=()):
    declaration_before = iter_authorization_required_declarations()
    view = authorization_required(model, permission, conditions)(_ok_view)
    created = [
        item for item in iter_authorization_required_declarations()
        if item not in declaration_before
    ]
    return view, created


def _change_permission():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='change_document',
        defaults={'name': 'Can change document'},
    )
    return permission


def _publish_permission():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='can_publish',
        defaults={'name': 'Can publish document'},
    )
    return permission


class AuthorizationRequiredSignatureTest(SimpleTestCase):
    def test_frozen_signature_has_no_selector_or_colon_transport(self):
        parameters = list(inspect.signature(authorization_required).parameters)
        self.assertEqual(parameters, ['model', 'permission', 'conditions'])
        self.assertIs(
            inspect.signature(authorization_required).parameters['conditions'].default,
            (),
        )
        source = inspect.getsource(authorization_required)
        self.assertNotIn('pk_kwarg', source)
        self.assertNotIn('pk_selector', source)
        self.assertNotIn('fieldlookups', source)

    def test_permission_identity_does_not_use_codename_model_split(self):
        from trusts.decorators import _permission_identity

        names = _permission_identity.__code__.co_names
        self.assertNotIn('parse_perm_code', names)
        self.assertIn('codename', names)
        self.assertIn('model_name', names)

    def test_legacy_permission_required_is_still_importable(self):
        self.assertTrue(callable(permission_required))
        self.assertIsNot(authorization_required, permission_required)


class AuthorizationRequiredDeclarationTest(SimpleTestCase):
    def _assert_type_error(self, *args, **kwargs):
        before = iter_authorization_required_declarations()
        with self.assertRaises(TypeError):
            authorization_required(*args, **kwargs)
        self.assertEqual(iter_authorization_required_declarations(), before)

    def test_rejects_non_model_and_abstract_model(self):
        self._assert_type_error(object, CHANGE)
        self._assert_type_error(Document(), CHANGE)

        from django.db import models

        with isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes'):
            class AbstractNote(models.Model):
                class Meta:
                    app_label = 'trusts_tests'
                    abstract = True

            self._assert_type_error(AbstractNote, 'trusts_tests.change_abstractnote')

    def test_rejects_incomplete_or_colon_permission(self):
        self._assert_type_error(Document, 'change_document')
        self._assert_type_error(Document, 'myapp.')
        self._assert_type_error(Document, '.change_document')
        self._assert_type_error(Document, 'myapp.change_document:non_confidential')
        self._assert_type_error(Document, 'other.change_document')
        self._assert_type_error(Document, ['myapp.change_document'])

    def test_rejects_non_tuple_duplicate_and_malformed_conditions(self):
        self._assert_type_error(Document, CHANGE, 'non_confidential')
        self._assert_type_error(Document, CHANGE, ['non_confidential'])
        self._assert_type_error(Document, CHANGE, {'non_confidential'})
        self._assert_type_error(Document, CHANGE, ('non_confidential', 'non_confidential'))
        self._assert_type_error(Document, CHANGE, ('',))
        self._assert_type_error(Document, CHANGE, ('non confidential',))
        self._assert_type_error(Document, CHANGE, ('non_confidential:extra',))
        self._assert_type_error(Document, CHANGE, ('myapp.non_confidential',))
        self._assert_type_error(Document, CHANGE, (123,))

        def gen():
            yield 'non_confidential'

        self._assert_type_error(Document, CHANGE, gen())

    def test_does_not_resolve_registered_names_at_declaration(self):
        before = iter_authorization_required_declarations()
        with patch('trusts.apps.configured_implementation_handles') as handles:
            view = authorization_required(
                Document, CHANGE, ('not_registered_at_import',),
            )(_ok_view)
        handles.assert_not_called()
        created = [
            item for item in iter_authorization_required_declarations()
            if item not in before
        ]
        for item in created:
            forget_authorization_required(item)
        self.assertTrue(callable(view))


class AuthorizationRequiredCheckAndFirstUseTest(KernelHostRequiredMixin, SimpleTestCase):
    def _guarded(self, conditions):
        view, created = _guard(Document, CHANGE, conditions)
        for item in created:
            self.addCleanup(forget_authorization_required, item)
        return view

    def test_unknown_condition_is_system_check_and_first_use_fail_closed(self):
        sentinel = []

        def protected(request, pk):
            sentinel.append(pk)
            return 'ran'

        before = iter_authorization_required_declarations()
        view = authorization_required(
            Document, CHANGE, ('missing_condition_138',),
        )(protected)
        for item in iter_authorization_required_declarations():
            if item not in before:
                self.addCleanup(forget_authorization_required, item)

        messages = [
            message for message in check_authorization_required(None)
            if message.id == CHECK_ID_AUTHORIZATION_REQUIRED
        ]
        self.assertTrue(messages)
        self.assertIsInstance(messages[0], Error)
        self.assertIn('unknown', messages[0].msg)
        self.assertIn('missing_condition_138', messages[0].msg)
        self.assertEqual(messages[0].hint, (
            'Silencing this check ID suppresses only the early diagnostic. '
            'authorization_required still validates and fail-closes at first '
            'use; there is no fallback to the base grant.'
        ))

        with self.assertRaises(TrustsConfigurationError) as ctx:
            view(_request(AnonymousUser()), pk=1)
        self.assertIn('no fallback to the base grant', str(ctx.exception))
        self.assertEqual(sentinel, [])

    def test_silenced_check_still_fail_closes_at_first_use(self):
        from django.core.checks import run_checks

        view = self._guarded(('still_missing_138',))
        with override_settings(
            SILENCED_SYSTEM_CHECKS=['trusts.E008', 'fields.W342'],
        ):
            self.assertNotIn(
                CHECK_ID_AUTHORIZATION_REQUIRED,
                [message.id for message in run_checks()],
            )
            with self.assertRaises(TrustsConfigurationError):
                view(_request(AnonymousUser()), pk=1)

    def test_first_use_fail_closes_before_apps_ready(self):
        view = self._guarded(('non_confidential',))
        with override_apps_ready(False):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                view(_request(AnonymousUser()), pk=1)
        self.assertIn('before Django apps are ready', str(ctx.exception))


class AuthorizationRequiredLiveTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-138', password='x')
        self.bob = User.objects.create_user(username='bob-138', password='x')
        self.inactive = User.objects.create_user(
            username='inactive-138', password='x', is_active=False,
        )
        self.superuser = User.objects.create_superuser(
            username='super-138', password='x',
        )
        self.inactive_super = User.objects.create_user(
            username='inactive-super-138', password='x',
            is_active=False, is_superuser=True,
        )
        self.change = _change_permission()
        self.publish = _publish_permission()
        self.document = Document.objects.create(title='readme')
        self.other = Document.objects.create(title='other')
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.document, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.document, user=self.alice, permission=self.publish,
        )
        self._declarations = []

    def tearDown(self):
        for item in self._declarations:
            forget_authorization_required(item)
        super().tearDown()

    def _view(self, permission=CHANGE, conditions=()):
        view, created = _guard(Document, permission, conditions)
        self._declarations.extend(created)
        return view

    def test_custom_codename_authorizes_explicit_document(self):
        view = self._view(PUBLISH)
        with patch('trusts.utils.parse_perm_code', wraps=parse_perm_code) as parsed:
            with patch.object(self.alice, 'has_perm') as has_perm:
                with patch.object(Permission.objects, 'get') as getter:
                    with patch.object(Document, 'from_db', wraps=Document.from_db) as from_db:
                        with self.assertNumQueries(1):
                            self.assertEqual(
                                view(_request(self.alice), pk=self.document.pk),
                                'ok',
                            )
        parsed.assert_not_called()
        has_perm.assert_not_called()
        getter.assert_not_called()
        from_db.assert_not_called()
        with self.assertRaises(PermissionDenied):
            view(_request(self.alice), pk=self.other.pk)
        with self.assertRaises(PermissionDenied):
            view(_request(self.bob), pk=self.document.pk)

    def test_ordinary_hit_is_one_combined_query(self):
        view = self._view()
        with CaptureQueriesContext(connection) as captured:
            self.assertEqual(view(_request(self.alice), pk=self.document.pk), 'ok')
        self.assertEqual(len(captured.captured_queries), 1)
        sql = captured.captured_queries[0]['sql'].upper()
        self.assertIn('EXISTS', sql)
        self.assertTrue(
            'AUTH_PERMISSION' in sql or 'PERMISSION' in sql,
        )

    def test_ordinary_miss_distinguishes_404_and_403(self):
        view = self._view()
        missing = self.document.pk + self.other.pk + self.secret.pk + 99
        with self.assertNumQueries(2):
            with self.assertRaises(Http404):
                view(_request(self.alice), pk=missing)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(_request(self.bob), pk=self.document.pk)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(_request(self.alice), pk=self.other.pk)

    def test_condition_narrows_and_does_not_fall_back_to_base_grant(self):
        view = self._view(conditions=('non_confidential',))
        self.assertEqual(view(_request(self.alice), pk=self.document.pk), 'ok')
        with self.assertRaises(PermissionDenied):
            view(_request(self.alice), pk=self.secret.pk)
        self.assertTrue(
            self.alice.has_perm(CHANGE, self.secret),
        )

    def test_and_conditions_require_every_name(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        saved = owner.registries[DOCUMENT_BACKEND]
        registry = TrustsRegistry()
        junction = Ref(DocumentGrant)
        registry.register(
            content=junction.document,
            user=junction.user,
            permission=junction.permission,
        )
        registry.register_permission_condition(
            Document, 'non_confidential', lambda u, p, o: o.confidential != True,
        )
        registry.register_permission_condition(
            Document, 'named_readme', lambda u, p, o: o.title == 'readme',
        )
        owner.registries[DOCUMENT_BACKEND] = registry
        self.addCleanup(lambda: owner.registries.__setitem__(DOCUMENT_BACKEND, saved))

        view = self._view(conditions=('non_confidential', 'named_readme'))
        self.assertEqual(view(_request(self.alice), pk=self.document.pk), 'ok')
        with self.assertRaises(PermissionDenied):
            view(_request(self.alice), pk=self.secret.pk)
        renamed = Document.objects.create(title='renamed')
        DocumentGrant.objects.create(
            document=renamed, user=self.alice, permission=self.change,
        )
        with self.assertRaises(PermissionDenied):
            view(_request(self.alice), pk=renamed.pk)

    def test_unsupported_bound_condition_fail_closes_without_base_grant(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        saved = owner.registries[DOCUMENT_BACKEND]
        registry = TrustsRegistry()
        junction = Ref(DocumentGrant)
        registry.register(
            content=junction.document,
            user=junction.user,
            permission=junction.permission,
        )
        registry.conditions._records[
            (Document._meta.label, 'unbound_138')
        ] = ConditionRecord(expr=None, model=Document)
        owner.registries[DOCUMENT_BACKEND] = registry
        self.addCleanup(lambda: owner.registries.__setitem__(DOCUMENT_BACKEND, saved))

        view = self._view(conditions=('unbound_138',))
        messages = check_authorization_required(None)
        self.assertTrue(any(
            message.id == CHECK_ID_AUTHORIZATION_REQUIRED
            and 'unbound_138' in message.msg
            for message in messages
        ))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            view(_request(self.alice), pk=self.document.pk)
        self.assertIn('no fallback to the base grant', str(ctx.exception))

    def test_missing_empty_and_malformed_pk_reject_before_sql(self):
        view = self._view()
        request = _request(self.alice)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk='')
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk=None)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk='not-an-int')
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk=[self.document.pk])
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk='1 OR 1=1')

    def test_get_and_post_are_not_candidate_sources(self):
        view = self._view()
        request = _request(self.alice)
        request.GET = QueryDict('pk=%s' % self.document.pk)
        request.POST = QueryDict('pk=%s' % self.document.pk)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request)
        self.assertEqual(view(request, pk=self.document.pk), 'ok')

    def test_active_superuser_bypasses_grants_and_conditions_with_existence(self):
        view = self._view(conditions=('non_confidential',))
        with self.assertNumQueries(1):
            self.assertEqual(
                view(_request(self.superuser), pk=self.secret.pk),
                'ok',
            )
        missing = self.secret.pk + 99
        with self.assertNumQueries(1):
            with self.assertRaises(Http404):
                view(_request(self.superuser), pk=missing)

    def test_anonymous_and_inactive_principals_do_not_pass(self):
        view = self._view()
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionDenied):
                view(_request(AnonymousUser()), pk=self.document.pk)
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionDenied):
                view(_request(self.inactive), pk=self.document.pk)
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionDenied):
                view(_request(self.inactive_super), pk=self.document.pk)

    def test_does_not_consult_django_backend_or(self):
        view = self._view()
        listed = list(settings.AUTHENTICATION_BACKENDS)
        if 'tests.core.test_issue138.GrantAllBackend' not in listed:
            listed.append('tests.core.test_issue138.GrantAllBackend')
        with override_settings(AUTHENTICATION_BACKENDS=tuple(listed)):
            self.assertTrue(
                self.bob.has_perm(CHANGE, self.document),
            )
            with self.assertRaises(PermissionDenied):
                view(_request(self.bob), pk=self.document.pk)
            with patch.object(self.alice, 'has_perm') as has_perm:
                self.assertEqual(
                    view(_request(self.alice), pk=self.document.pk),
                    'ok',
                )
            has_perm.assert_not_called()

    def test_evaluates_configured_handles_in_settings_order(self):
        view = self._view()
        handles = configured_implementation_handles()
        self.assertGreaterEqual(len(handles), 2)
        with patch('trusts.core.granted', wraps=granted) as wrapped:
            self.assertEqual(view(_request(self.alice), pk=self.document.pk), 'ok')
        wrapped.assert_called()
        called = wrapped.call_args[0][0]
        self.assertEqual(
            tuple(handle.path for handle in called),
            tuple(handle.path for handle in handles),
        )
