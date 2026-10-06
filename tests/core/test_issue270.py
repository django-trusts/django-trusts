"""#270: queryset.permitted(permission, user, conditions=())."""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import connection, models
from django.http import Http404, HttpRequest
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
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
from trusts.query import (
    AuthorizedManager,
    AuthorizedQuerySet,
    PermittedManager,
    PermittedQuerySet,
    PermittedQuerySetMixin,
)
from trusts import query as query_mod


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


def _view_allows(view, user, pk):
    try:
        return view(_request(user), pk=pk) == 'ok'
    except (PermissionDenied, Http404):
        return False


@authorization_required(Document, 'myapp.change_document')
def _edit(request, pk):
    return 'ok'


@authorization_required(Document, 'myapp.change_document', ('non_confidential',))
def _edit_open(request, pk):
    return 'ok'


@authorization_required(Document, 'myapp.can_publish')
def _publish(request, pk):
    return 'ok'


class PermittedQuerySetSurfaceTest(SimpleTestCase):
    def test_public_attachment_is_the_queryset_mixin(self):
        self.assertTrue(issubclass(PermittedQuerySet, PermittedQuerySetMixin))
        self.assertIs(PermittedManager._queryset_class, PermittedQuerySet)
        self.assertFalse(hasattr(query_mod, 'PermittedManagerMixin'))
        self.assertFalse(hasattr(AuthorizedQuerySet, 'permitted'))
        self.assertFalse(hasattr(AuthorizedManager, 'permitted'))

        class OwnedQuerySet(PermittedQuerySetMixin, models.QuerySet):
            def application_method(self):
                return self.filter(title='owned')

        class OwnedManager(models.Manager.from_queryset(OwnedQuerySet)):
            def application_label(self):
                return 'owned'

        manager = OwnedQuerySet.as_manager()
        self.assertTrue(callable(manager.permitted))
        self.assertTrue(callable(manager.application_method))
        self.assertTrue(callable(OwnedManager.permitted))
        self.assertTrue(callable(OwnedManager.application_label))
        chained = OwnedQuerySet(model=Document).filter(title='owned')
        self.assertIsInstance(chained, OwnedQuerySet)
        self.assertTrue(callable(chained.permitted))

    def test_authorized_signature_stays_instance_projection(self):
        import inspect

        parameters = inspect.signature(AuthorizedQuerySet.authorized).parameters
        self.assertEqual(
            list(parameters),
            ['self', 'user', 'permission', 'extra_q'],
        )
        self.assertIsNone(parameters['extra_q'].default)


class PermittedQuerySetTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-270', password='x')
        self.bob = User.objects.create_user('bob-270', password='x')
        self.inactive = User.objects.create_user('inactive-270', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.superuser = User.objects.create_superuser(
            'root-270', password='x', email='root-270@example.com',
        )
        self.change = _permission('change_document', 'Can change document')
        self.publish = _permission('can_publish', 'Can publish document')
        self.open_doc = Document.objects.create(title='open', confidential=False)
        self.secret = Document.objects.create(title='secret', confidential=True)
        self.plain = Document.objects.create(title='plain', confidential=False)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.publish,
        )
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.inactive, permission=self.change,
        )
        self.docs = PermittedManager()
        self.docs.model = Document

    def test_string_and_instance_grant_before_pagination(self):
        expected = {self.open_doc.pk, self.secret.pk}
        for permission in ('myapp.change_document', self.change):
            with self.subTest(permission=permission):
                with self.assertNumQueries(0):
                    chosen = self.docs.permitted(permission, self.alice)
                self.assertIsInstance(chosen, PermittedQuerySet)
                self.assertIsNone(chosen._result_cache)
                with self.assertNumQueries(1):
                    self.assertEqual(_pks(chosen), expected)
                self.assertNotIn(self.plain.pk, _pks(chosen))
                self.assertEqual(_pks(self.docs.permitted(permission, self.bob)), set())

    def test_owned_condition_is_an_and_overlay(self):
        for permission in ('myapp.change_document', self.change):
            with self.subTest(permission=permission):
                with self.assertNumQueries(0):
                    chosen = self.docs.permitted(
                        permission, self.alice, conditions=('non_confidential',),
                    )
                with self.assertNumQueries(1):
                    self.assertEqual(_pks(chosen), {self.open_doc.pk})

    def test_instance_construction_does_not_read_content_type(self):
        fresh = Permission.objects.only('id', 'codename').get(pk=self.change.pk)
        self.assertNotIn('content_type', fresh._state.fields_cache)
        ContentType.objects.clear_cache()
        with self.assertNumQueries(0):
            chosen = self.docs.permitted(
                fresh, self.alice, conditions=('non_confidential',),
            )
        with self.assertNumQueries(1):
            self.assertEqual(_pks(chosen), {self.open_doc.pk})

    def test_same_codename_on_another_model_is_empty(self):
        foreign = Permission.objects.create(
            content_type=ContentType.objects.get_for_model(get_user_model()),
            codename='change_document',
            name='Foreign change document',
        )
        self.assertEqual(_pks(self.docs.permitted(foreign, self.alice)), set())
        self.assertEqual(
            _pks(self.docs.permitted(self.change, self.alice)),
            {self.open_doc.pk, self.secret.pk},
        )
        with self.assertNumQueries(0):
            other_app = self.docs.permitted('auth.change_document', self.alice)
        with self.assertNumQueries(1):
            self.assertEqual(list(other_app), [])
        grant_ct = ContentType.objects.get_for_model(DocumentGrant)
        Permission.objects.get_or_create(
            content_type=grant_ct,
            codename='change_documentgrant',
            defaults={'name': 'Can change document grant'},
        )
        self.assertEqual(
            list(self.docs.permitted('myapp.change_documentgrant', self.alice)),
            [],
        )

    def test_custom_codename_matches_the_decorator_not_has_perm(self):
        self.assertFalse(self.alice.has_perm('myapp.can_publish', self.open_doc))
        self.assertTrue(_view_allows(_publish, self.alice, self.open_doc.pk))
        self.assertFalse(_view_allows(_publish, self.alice, self.secret.pk))
        for permission in ('myapp.can_publish', self.publish):
            with self.subTest(permission=permission):
                self.assertEqual(
                    _pks(self.docs.permitted(permission, self.alice)),
                    {self.open_doc.pk},
                )

    def test_parity_with_authorization_required(self):
        cases = (
            (_edit, 'myapp.change_document', (), self.alice, self.open_doc, True),
            (_edit, 'myapp.change_document', (), self.bob, self.open_doc, False),
            (_edit, 'myapp.change_document', (), self.alice, self.secret, True),
            (_edit_open, 'myapp.change_document', ('non_confidential',), self.alice, self.open_doc, True),
            (_edit_open, 'myapp.change_document', ('non_confidential',), self.alice, self.secret, False),
            (_edit_open, 'myapp.change_document', ('non_confidential',), self.bob, self.open_doc, False),
            (_publish, 'myapp.can_publish', (), self.alice, self.open_doc, True),
            (_publish, 'myapp.can_publish', (), self.bob, self.open_doc, False),
        )
        for view, permission, conditions, user, document, allowed in cases:
            with self.subTest(permission=permission, user=user.username, document=document.title):
                self.assertIs(
                    _view_allows(view, user, document.pk),
                    allowed,
                )
                chosen = self.docs.permitted(
                    permission, user, conditions=conditions,
                )
                self.assertIs(document.pk in _pks(chosen), allowed)

    def test_anonymous_and_inactive_are_empty_after_validation(self):
        anonymous = AnonymousUser()
        with self.assertNumQueries(0):
            anonymous_qs = self.docs.permitted(self.change, anonymous)
            inactive_qs = self.docs.permitted(
                'myapp.change_document', self.inactive,
            )
        self.assertEqual(list(anonymous_qs), [])
        self.assertEqual(list(inactive_qs), [])
        self.assertEqual(
            _pks(Document.objects.authorized(self.inactive, self.change)),
            {self.open_doc.pk},
        )
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                Document.objects.authorized(self.inactive, 'myapp.change_document')

    def test_active_superuser_has_no_shortcut(self):
        self.assertTrue(
            self.superuser.has_perm('myapp.change_document', self.open_doc),
        )
        self.assertEqual(
            list(self.docs.permitted('myapp.change_document', self.superuser)),
            [],
        )
        self.assertEqual(
            list(self.docs.permitted(self.change, self.superuser)),
            [],
        )

    def test_malformed_input_raises_before_sql_and_before_the_principal(self):
        anonymous = AnonymousUser()
        cases = (
            (TypeError, None),
            (TypeError, 123),
            (TypeError, ['myapp.change_document']),
            (TypeError, self.open_doc),
            (TrustsConfigurationError, 'change_document'),
            (TrustsConfigurationError, 'myapp.change_document:non_confidential'),
            (TrustsConfigurationError, 'myapp.'),
            (TrustsConfigurationError, '.change_document'),
            (TrustsConfigurationError, '.'),
            (TrustsConfigurationError, 'myapp.change.document'),
            (TrustsConfigurationError, ''),
        )
        for expected, permission in cases:
            with self.subTest(permission=permission):
                with self.assertNumQueries(0):
                    with self.assertRaises(expected):
                        self.docs.permitted(permission, self.alice)
                    with self.assertRaises(expected):
                        self.docs.permitted(permission, anonymous)

    def test_unsaved_permission_instance_raises_at_zero_sql(self):
        unsaved = Permission(codename='change_document', name='unsaved')
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                self.docs.permitted(unsaved, self.alice)
            self.assertIn('saved', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                self.docs.permitted(unsaved, AnonymousUser())

    def test_condition_shape_and_missing_names_raise_at_zero_sql(self):
        anonymous = AnonymousUser()
        cases = (
            (TypeError, 'non_confidential'),
            (TypeError, ['non_confidential']),
            (TypeError, {'non_confidential'}),
            (TypeError, frozenset(('non_confidential',))),
            (TypeError, None),
            (TrustsConfigurationError, ('',)),
            (TrustsConfigurationError, (' padded ',)),
            (TrustsConfigurationError, ('has:colon',)),
            (TrustsConfigurationError, (None,)),
            (TrustsConfigurationError, ('non_confidential', 'non_confidential')),
            (TrustsConfigurationError, ('missing_270',)),
        )
        for expected, conditions in cases:
            with self.subTest(conditions=conditions):
                with self.assertNumQueries(0):
                    with self.assertRaises(expected):
                        self.docs.permitted(
                            'myapp.change_document', self.alice, conditions=conditions,
                        )
                    with self.assertRaises(expected):
                        self.docs.permitted(
                            self.change, anonymous, conditions=conditions,
                        )

    def test_runtime_call_is_not_an_e008_guard(self):
        from django.core.checks import run_checks

        before = list(_declared_authorization_guards)
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                self.docs.permitted(
                    self.change, AnonymousUser(), conditions=('missing_e008_270',),
                )
        self.assertEqual(_declared_authorization_guards, before)
        messages = [
            message for message in run_checks()
            if getattr(message, 'id', None) == 'trusts.E008'
            and 'missing_e008_270' in message.msg
        ]
        self.assertEqual(messages, [])

    def test_model_without_an_auth_permission_plan_raises(self):
        manager = PermittedManager()
        manager.model = DocumentGrant
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                manager.permitted('myapp.change_documentgrant', self.alice)
            self.assertIn('auth.Permission', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                manager.permitted(
                    'myapp.change_documentgrant', AnonymousUser(),
                )

    def test_unbound_condition_lookup_fails_before_the_principal(self):
        registry = implementation_for_path(
            DOCUMENT_BACKEND,
        ).configured_backend().registry
        previous = registry.condition_lookup
        try:
            registry.set_condition_lookup(None)
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted(
                        'myapp.change_document',
                        self.alice,
                        conditions=('non_confidential',),
                    )
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted(
                        self.change,
                        AnonymousUser(),
                        conditions=('non_confidential',),
                    )
        finally:
            registry.set_condition_lookup(previous)
        self.assertEqual(
            _pks(self.docs.permitted(
                'myapp.change_document', self.alice,
                conditions=('non_confidential',),
            )),
            {self.open_doc.pk},
        )

    def test_filter_permitted_filter_chains(self):
        class DocumentQuerySet(PermittedQuerySetMixin, models.QuerySet):
            def open_rows(self):
                return self.filter(confidential=False)

        class DocumentManager(models.Manager.from_queryset(DocumentQuerySet)):
            def application_label(self):
                return 'owned'

        manager = DocumentManager()
        manager.model = Document
        self.assertEqual(manager.application_label(), 'owned')
        chosen = manager.open_rows().permitted('myapp.change_document', self.alice)
        self.assertIsInstance(chosen, DocumentQuerySet)
        self.assertEqual(_pks(chosen), {self.open_doc.pk})
        narrowed = manager.permitted(self.change, self.alice).filter(
            title=self.secret.title,
        )
        self.assertEqual(_pks(narrowed), {self.secret.pk})

    def test_distinct_and_pagination_stay_in_sql(self):
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        for index in range(4):
            document = Document.objects.create(title='page-%s' % index)
            DocumentGrant.objects.create(
                document=document, user=self.alice, permission=self.change,
            )
        chosen = self.docs.permitted(
            'myapp.change_document', self.alice,
        ).order_by('pk')
        self.assertIn('DISTINCT', str(chosen.query).upper())
        window = chosen[1:3]
        self.assertIn('LIMIT', str(window.query).upper())
        with self.assertNumQueries(1):
            rows = list(window)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row.pk for row in rows}), 2)
        self.assertEqual(
            _pks(chosen.filter(pk=self.open_doc.pk)),
            {self.open_doc.pk},
        )
        page = Paginator(chosen, 2).page(1)
        self.assertEqual(len(page.object_list), 2)

    def test_private_compiler_takes_explicit_handles(self):
        from trusts._permitted import permitted_queryset

        handle = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(),
        ):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted('myapp.change_document', self.alice)
            chosen = permitted_queryset(
                PermittedQuerySet(model=Document),
                'myapp.change_document',
                self.alice,
                (),
                handles=(handle,),
            )
            self.assertEqual(
                _pks(chosen),
                {self.open_doc.pk, self.secret.pk},
            )


def _permission(codename, name):
    permission, _created = Permission.objects.get_or_create(
        content_type=ContentType.objects.get_for_model(Document),
        codename=codename,
        defaults={'name': name},
    )
    return permission


def _extra_models():
    User = get_user_model()

    class ExtraDocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue270_extra_document_grant'

    class OtherPermission(models.Model):
        label = models.CharField(max_length=40, blank=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue270_other_permission'

    class OtherPermissionGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(
            OtherPermission, on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue270_other_permission_grant'

    return ExtraDocumentGrant, OtherPermission, OtherPermissionGrant


def _handle(path):
    return BackendHandle(
        path=path,
        registry=TrustsRegistry(),
        compiler=PlanQueryCompiler(),
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


class PermittedQuerySetOwnershipTest(KernelHostRequiredMixin, TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        (
            cls.ExtraDocumentGrant,
            cls.OtherPermission,
            cls.OtherPermissionGrant,
        ) = _extra_models()

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
        self.alice = User.objects.create_user('alice-270b', password='x')
        self.bob = User.objects.create_user('bob-270b', password='x')
        self.change = _permission('change_document', 'Can change document')
        self.open_doc = Document.objects.create(title='open', confidential=False)
        self.secret = Document.objects.create(title='secret', confidential=True)
        self.plain = Document.objects.create(title='plain', confidential=False)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )
        self.docs = PermittedManager()
        self.docs.model = Document

    def test_split_and_foreign_terminal_conditions_raise(self):
        handle_a = _handle('tests.core.issue270-split-a')
        handle_b = _handle('tests.core.issue270-split-b')
        for handle in (handle_a, handle_b):
            handle.register(
                trust=self.ExtraDocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
        handle_a.add_named_filter(
            Document, 'split_a_270', lambda u, p, o: o.confidential != True,
        )
        handle_b.add_named_filter(
            Document, 'split_b_270', lambda u, p, o: o.confidential != True,
        )
        foreign = _handle('tests.core.issue270-other-name')
        foreign.register(
            trust=self.OtherPermissionGrant,
            user='user',
            permission='permission',
            content='document',
        )
        foreign.add_named_filter(
            Document, 'only_other_270', lambda u, p, o: o.confidential != True,
        )
        primary = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(handle_a, handle_b),
        ):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted(
                        'myapp.change_document',
                        self.alice,
                        conditions=('split_a_270', 'split_b_270'),
                    )
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted(
                        self.change,
                        AnonymousUser(),
                        conditions=('split_a_270', 'split_b_270'),
                    )
        with patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(primary, foreign),
        ):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError):
                    self.docs.permitted(
                        self.change, self.alice, conditions=('only_other_270',),
                    )

    def test_non_owner_grant_is_omitted_and_two_names_are_anded(self):
        primary = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        extra = _handle('tests.core.issue270-extra-grant')
        extra.register(
            trust=self.ExtraDocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        owned = _handle('tests.core.issue270-both-names')
        owned.register(
            trust=self.ExtraDocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        owned.add_named_filter(
            Document, 'open_title_270', lambda u, p, o: o.title == 'open',
        )
        owned.add_named_filter(
            Document, 'not_secret_270', lambda u, p, o: o.confidential != True,
        )
        with _tables(self.ExtraDocumentGrant):
            self.ExtraDocumentGrant.objects.create(
                document=self.secret, user=self.alice, permission=self.change,
            )
            self.ExtraDocumentGrant.objects.create(
                document=self.open_doc, user=self.alice, permission=self.change,
            )
            self.ExtraDocumentGrant.objects.create(
                document=self.plain, user=self.alice, permission=self.change,
            )
            with patch(
                'trusts.apps._relationship_implementation_handles',
                return_value=(primary, extra),
            ):
                self.assertEqual(
                    _pks(self.docs.permitted(
                        'myapp.change_document',
                        self.alice,
                        conditions=('non_confidential',),
                    )),
                    {self.open_doc.pk},
                )
            with patch(
                'trusts.apps._relationship_implementation_handles',
                return_value=(owned,),
            ):
                self.assertEqual(
                    _pks(self.docs.permitted(
                        self.change,
                        self.alice,
                        conditions=('open_title_270', 'not_secret_270'),
                    )),
                    {self.open_doc.pk},
                )

    def test_custom_terminal_pk_collision_does_not_grant(self):
        primary = implementation_for_path(DOCUMENT_BACKEND).configured_backend()
        extra = _handle('tests.core.issue270-other-perm')
        extra.register(
            trust=self.OtherPermissionGrant,
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
            for permission in ('myapp.change_document', self.change):
                for handles in ((primary, extra), (extra, primary)):
                    with self.subTest(permission=type(permission).__name__, order=handles[0].path):
                        with patch(
                            'trusts.apps._relationship_implementation_handles',
                            return_value=handles,
                        ):
                            denied = self.docs.permitted(permission, self.bob)
                            self.assertNotIn(
                                'issue270_other_permission', str(denied.query),
                            )
                            self.assertEqual(list(denied), [])
                            self.assertEqual(
                                _pks(self.docs.permitted(permission, self.alice)),
                                {self.open_doc.pk, self.secret.pk},
                            )


@isolate_apps('django.contrib.auth')
class PermittedPermissionExactnessTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-270c', password='x')
        self.change = _permission('change_document', 'Can change document')
        self.docs = PermittedManager()
        self.docs.model = Document

        class ExactnessProxy(Permission):
            class Meta:
                proxy = True
                app_label = 'auth'

        self.proxy_model = ExactnessProxy

    def test_proxy_permission_is_rejected_at_zero_sql(self):
        row = self.proxy_model(pk=self.change.pk, codename='change_document')
        with self.assertNumQueries(0):
            with self.assertRaises(TypeError):
                self.docs.permitted(row, self.alice)


class Issue270SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue270', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue270', PAIR_KERNEL_SUITE)
