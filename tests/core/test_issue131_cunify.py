"""#131 C-unify: named path/request filters and trusts.check."""

from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps, override_settings

from tests.core.test_issue131 import _handle
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.myapp.settings import AUTHENTICATION_BACKENDS, INSTALLED_APPS
from trusts.apps import implementation_for_path
from trusts.core import (
    BackendHandle,
    Equal,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    check,
    granted,
    permission_in,
)
from trusts.path_filters import registration_fingerprint
from trusts.query import is_active_principal
from trusts.request_filters import (
    request_filter_query_identity,
    validate_request_filter,
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


def _grant_models():
    User = get_user_model()

    class Bundle(models.Model):
        permissions = models.ManyToManyField(Permission)

        class Meta:
            app_label = 'trusts_tests'

    class Item(models.Model):
        title = models.CharField(max_length=20)
        confidential = models.BooleanField(default=False)

        class Meta:
            app_label = 'trusts_tests'

    class ItemGrant(models.Model):
        item = models.ForeignKey(Item, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE, related_name='+',
        )
        other_permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE, related_name='+',
        )
        bundle = models.ForeignKey(Bundle, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Bundle, Item, ItemGrant


class RequestFilterTupleTest(SimpleTestCase):
    def test_rejects_str_list_set_before_iteration(self):
        for value in ('own', ['own'], {'own'}, {'own': True}):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    validate_request_filter(value)

    def test_empty_and_names(self):
        self.assertEqual(validate_request_filter(()), ())
        self.assertEqual(
            validate_request_filter(('non_confidential', 'editable')),
            ('non_confidential', 'editable'),
        )

    def test_duplicate_and_malformed(self):
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter(('own', 'own'))
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter(('1bad',))
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter(('',))

    def test_query_identity_sorts_after_validate(self):
        self.assertEqual(
            request_filter_query_identity(('editable', 'non_confidential')),
            ('editable', 'non_confidential'),
        )
        with self.assertRaises(TypeError):
            request_filter_query_identity('own')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PathFilterDeclarationTest(SimpleTestCase):
    def test_named_only_and_phase2_permission_bind(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()
        handle.register_path_filter(
            ItemGrant,
            'bundle_ceiling',
            lambda r: r.permission.in_(r.bundle.permissions),
        )
        with self.assertRaises(TypeError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter=lambda r: r.permission.in_(r.bundle.permissions),
            )
        with self.assertRaises(TypeError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter=('bundle_ceiling',),
            )
        record = handle.register(
            ItemGrant,
            user='user',
            permission='permission',
            content='item',
            filter='bundle_ceiling',
        )
        self.assertEqual(record.condition, permission_in(
            Ref(ItemGrant, ('bundle', 'permissions')),
        ))
        self.assertEqual(
            registration_fingerprint(record)[4],
            record.condition,
        )

    def test_phase2_rejects_wrong_permission_field(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()
        handle.register_path_filter(
            ItemGrant,
            'other_ceiling',
            lambda r: r.other_permission.in_(r.bundle.permissions),
        )
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter='other_ceiling',
            )
        self.assertFalse(handle.registry.records)

    def test_python_and_or_in_fail_loud(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()

        def bad_and(r):
            return r.permission.in_(r.bundle.permissions) and (
                r.permission.in_(r.bundle.permissions)
            )

        with self.assertRaises(TrustsConfigurationError):
            handle.register_path_filter(ItemGrant, 'bad_and', bad_and)

        def bad_in(r):
            return r.permission in r.bundle.permissions

        with self.assertRaises(TrustsConfigurationError):
            handle.register_path_filter(ItemGrant, 'bad_in', bad_in)

    def test_duplicate_and_unknown_and_condition_mutex(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()
        handle.register_path_filter(
            ItemGrant,
            'bundle_ceiling',
            lambda r: r.permission.in_(r.bundle.permissions),
        )
        with self.assertRaises(TrustsConfigurationError):
            handle.register_path_filter(
                ItemGrant,
                'bundle_ceiling',
                lambda r: r.permission.in_(r.bundle.permissions),
            )
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter='missing',
            )
        with self.assertRaises(TypeError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter='bundle_ceiling',
                condition=Equal('permission', 'other_permission'),
            )

    def test_same_ir_same_fingerprint_name_is_not_identity(self):
        Bundle, Item, ItemGrant = _grant_models()
        left = _handle(path='tests.core.handle-left')
        right = _handle(path='tests.core.handle-right')
        left.register_path_filter(
            ItemGrant, 'a',
            lambda r: r.permission.in_(r.bundle.permissions),
        )
        right.register_path_filter(
            ItemGrant, 'b',
            lambda r: r.permission.in_(r.bundle.permissions),
        )
        rec_a = left.register(
            ItemGrant, user='user', permission='permission',
            content='item', filter='a',
        )
        rec_b = right.register(
            ItemGrant, user='user', permission='permission',
            content='item', filter='b',
        )
        self.assertEqual(
            registration_fingerprint(rec_a)[4],
            registration_fingerprint(rec_b)[4],
        )

    def test_stores_do_not_cross_talk(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()
        handle.register_request_filter(
            Item, 'bundle_ceiling',
            lambda u, p, o: o.confidential != True,
        )
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                ItemGrant,
                user='user',
                permission='permission',
                content='item',
                filter='bundle_ceiling',
            )

    def test_frozen_raises_before_builder(self):
        Bundle, Item, ItemGrant = _grant_models()
        handle = _handle()
        handle.registry.freeze()
        calls = []

        def builder(r):
            calls.append(1)
            return r.permission.in_(r.bundle.permissions)

        with self.assertRaises(TrustsConfigurationError):
            handle.register_path_filter(ItemGrant, 'late', builder)
        with self.assertRaises(TrustsConfigurationError):
            handle.register_request_filter(
                Item, 'late', lambda u, p, o: o.confidential != True,
            )
        self.assertEqual(calls, [])


class CheckAndAuthorizedFilterTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._auth_override = override_settings(
            AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS,
        )
        cls._auth_override.enable()
        cls._apps_override = override_settings(INSTALLED_APPS=INSTALLED_APPS)
        cls._apps_override.enable()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls._apps_override.disable()
        cls._auth_override.disable()

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-cunify', password='x')
        self.superuser = User.objects.create_superuser(
            username='root-cunify', email='r@example.com', password='x',
        )
        ct = ContentType.objects.get_for_model(Document)
        self.perm, _ = Permission.objects.get_or_create(
            content_type=ct,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        self.document = Document.objects.create(title='open')
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.document, user=self.alice, permission=self.perm,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.perm,
        )

    def test_check_bare_and_filtered(self):
        self.assertTrue(check(self.alice, 'myapp.change_document', self.document))
        self.assertTrue(
            check(
                self.alice, 'myapp.change_document', self.document,
                filter=('non_confidential',),
            )
        )
        self.assertTrue(check(self.alice, 'myapp.change_document', self.secret))
        self.assertFalse(
            check(
                self.alice, 'myapp.change_document', self.secret,
                filter=('non_confidential',),
            )
        )
        self.assertFalse(
            check(self.superuser, 'myapp.change_document', self.document)
        )
        self.assertFalse(is_active_principal(None))

    def test_check_rejects_str_filter_before_sql(self):
        with self.assertRaises(TypeError):
            check(
                self.alice, 'myapp.change_document', self.document,
                filter='non_confidential',
            )

    def test_check_rejects_colon_permission_suffix(self):
        with self.assertRaises(TypeError):
            check(
                self.alice,
                'myapp.change_document:non_confidential',
                self.document,
            )

    def test_check_unknown_name_fails_closed(self):
        with self.assertRaises(AttributeError):
            check(
                self.alice, 'myapp.change_document', self.document,
                filter=('missing',),
            )

    def test_authorized_filter_and_granted_one_sql(self):
        qs = Document.objects.authorized(
            self.alice, self.perm, filter=('non_confidential',),
        )
        self.assertEqual(set(qs.values_list('pk', flat=True)), {self.document.pk})
        with self.assertNumQueries(1):
            check(
                self.alice, 'myapp.change_document',
                Document.objects.filter(
                    pk__in=(self.document.pk, self.secret.pk),
                ),
                filter=('non_confidential',),
            )

    def test_register_request_filter_is_public_alias(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        handle = owner.configured_backend()
        self.assertTrue(callable(handle.register_request_filter))
        self.assertTrue(callable(handle.register_path_filter))
        record = handle.registry.get_permission_condition_record(
            Document, 'non_confidential',
        )
        self.assertIsNotNone(record)
