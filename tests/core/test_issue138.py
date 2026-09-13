"""#138: authorization_required Trusts-only pk guard."""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.checks import Error, run_checks
from django.db import connection, models
from django.http import Http404, HttpRequest
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import override_settings

from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.myapp.settings import AUTHENTICATION_BACKENDS, INSTALLED_APPS
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
)
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


class AuthorizationRequiredDeclarationTest(SimpleTestCase):
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

    def test_system_check_skips_guards_when_model_app_is_absent(self):
        from django.apps import apps as django_apps

        real_get = django_apps.get_app_config

        def _missing(label):
            if label == Document._meta.app_label:
                raise LookupError(label)
            return real_get(label)

        with patch.object(django_apps, 'get_app_config', side_effect=_missing):
            messages = [
                message for message in run_checks()
                if getattr(message, 'id', None) == 'trusts.E008'
            ]
        self.assertFalse(messages)


@override_settings(
    AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS,
    INSTALLED_APPS=INSTALLED_APPS,
)
class AuthorizationRequiredTest(KernelHostRequiredMixin, TestCase):
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


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


def _document_backend():
    return implementation_for_path(DOCUMENT_BACKEND).configured_backend()


def _extra_handle(path='tests.core.issue138-extra'):
    return BackendHandle(
        path=path,
        registry=TrustsRegistry(),
        compiler=PlanQueryCompiler(),
    )


def _extra_grant_models():
    User = get_user_model()

    class ExtraDocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue138_extra_document_grant'

    class OtherPermission(models.Model):
        label = models.CharField(max_length=40, blank=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue138_other_permission'

    class OtherPermissionGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(
            OtherPermission, on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue138_other_permission_grant'

    return ExtraDocumentGrant, OtherPermission, OtherPermissionGrant


@override_settings(
    AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS,
    INSTALLED_APPS=INSTALLED_APPS,
)
class AuthorizationRequiredCompositionTest(KernelHostRequiredMixin, TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        (
            cls.ExtraDocumentGrant,
            cls.OtherPermission,
            cls.OtherPermissionGrant,
        ) = _extra_grant_models()

    @classmethod
    def tearDownClass(cls):
        from django.apps import apps as django_apps

        for model in (
            cls.ExtraDocumentGrant,
            cls.OtherPermissionGrant,
            cls.OtherPermission,
        ):
            django_apps.all_models[model._meta.app_label].pop(
                model._meta.model_name, None,
            )
        django_apps.clear_cache()
        super().tearDownClass()

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-138b', password='x')
        self.bob = User.objects.create_user(username='bob-138b', password='x')
        self.change = Permission.objects.get_or_create(
            content_type=ContentType.objects.get_for_model(Document),
            codename='change_document',
            defaults={'name': 'Can change document'},
        )[0]
        self.open_doc = Document.objects.create(title='open', confidential=False)
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )

    def _forget_guard(self, entry):
        try:
            _declared_authorization_guards.remove(entry)
        except ValueError:
            pass

    def _e008_messages(self, *needles):
        return [
            message for message in run_checks()
            if getattr(message, 'id', None) == 'trusts.E008'
            and all(needle in message.msg for needle in needles)
        ]

    def _assert_both_orders(self, primary, extra, view, pk, expect_ok):
        for handles in ((primary, extra), (extra, primary)):
            with patch(
                'trusts.apps.configured_implementation_handles',
                return_value=handles,
            ):
                if expect_ok:
                    self.assertEqual(view(_request(self.alice), pk=pk), 'ok')
                else:
                    with self.assertRaises(PermissionDenied):
                        view(_request(self.alice), pk=pk)

    def test_dual_backend_condition_order_does_not_broaden(self):
        primary = _document_backend()
        extra = _extra_handle()
        extra.register(
            self.ExtraDocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        extra.register_permission_condition(
            Document,
            'non_confidential',
            lambda u, p, o: o.title != 'nope',
        )
        with _tables(self.ExtraDocumentGrant):
            self._assert_both_orders(
                primary, extra, _edit_non_confidential, self.secret.pk, False,
            )
            self._assert_both_orders(
                primary, extra, _edit_non_confidential, self.open_doc.pk, True,
            )

    def test_incomplete_second_backend_grant_is_omitted(self):
        primary = _document_backend()
        extra = _extra_handle()
        extra.register(
            self.ExtraDocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with _tables(self.ExtraDocumentGrant):
            self.ExtraDocumentGrant.objects.create(
                document=self.secret, user=self.alice, permission=self.change,
            )
            self._assert_both_orders(
                primary, extra, _edit_non_confidential, self.secret.pk, False,
            )

    def test_incompatible_permission_terminal_cannot_collide(self):
        primary = _document_backend()
        extra = _extra_handle(path='tests.core.issue138-other-perm')
        extra.register(
            self.OtherPermissionGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with _tables(self.OtherPermission, self.OtherPermissionGrant):
            self.OtherPermission.objects.create(pk=self.change.pk, label='collide')
            self.OtherPermissionGrant.objects.create(
                document=self.open_doc,
                user=self.bob,
                permission_id=self.change.pk,
            )
            for handles in ((primary, extra), (extra, primary)):
                with patch(
                    'trusts.apps.configured_implementation_handles',
                    return_value=handles,
                ):
                    with self.assertRaises(PermissionDenied):
                        _edit(_request(self.bob), pk=self.open_doc.pk)
                    self.assertEqual(
                        _edit(_request(self.alice), pk=self.open_doc.pk),
                        'ok',
                    )

    def test_e008_split_names_across_backends_fail_closed(self):
        handle_a = _extra_handle(path='tests.core.issue138-split-a')
        handle_b = _extra_handle(path='tests.core.issue138-split-b')
        for handle in (handle_a, handle_b):
            handle.register(
                self.ExtraDocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        handle_a.register_permission_condition(
            Document, 'split_a_138', lambda u, p, o: o.confidential != True,
        )
        handle_b.register_permission_condition(
            Document, 'split_b_138', lambda u, p, o: o.confidential != True,
        )
        names = ('split_a_138', 'split_b_138')
        entry = (Document, 'myapp.change_document', names)
        self.addCleanup(self._forget_guard, entry)

        @authorization_required(Document, 'myapp.change_document', names)
        def _split(request, pk):
            return 'no'

        with patch(
            'trusts.apps.configured_implementation_handles',
            return_value=(handle_a, handle_b),
        ):
            messages = self._e008_messages('split_a_138', 'split_b_138')
            self.assertTrue(messages)
            self.assertIsInstance(messages[0], Error)
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    _split(_request(self.alice), pk=self.open_doc.pk)
            with override_settings(SILENCED_SYSTEM_CHECKS=['trusts.E008']):
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        _split(_request(self.alice), pk=self.open_doc.pk)

    def test_e008_name_only_on_incompatible_permission_terminal(self):
        primary = _document_backend()
        extra = _extra_handle(path='tests.core.issue138-other-e008')
        extra.register(
            self.OtherPermissionGrant,
            user='user',
            permission='permission',
            content='document',
        )
        extra.register_permission_condition(
            Document, 'only_other_138', lambda u, p, o: o.confidential != True,
        )
        entry = (Document, 'myapp.change_document', ('only_other_138',))
        self.addCleanup(self._forget_guard, entry)

        @authorization_required(Document, 'myapp.change_document', ('only_other_138',))
        def _other(request, pk):
            return 'no'

        with patch(
            'trusts.apps.configured_implementation_handles',
            return_value=(primary, extra),
        ):
            messages = self._e008_messages('only_other_138')
            self.assertTrue(messages)
            self.assertIsInstance(messages[0], Error)
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    _other(_request(self.alice), pk=self.open_doc.pk)
            with override_settings(SILENCED_SYSTEM_CHECKS=['trusts.E008']):
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        _other(_request(self.alice), pk=self.open_doc.pk)
