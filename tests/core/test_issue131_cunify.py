"""#131 C-unify: path/request filter stores, named-only attach, trusts.check.

Covers separate typed stores, option B named-only path attach, r9
permission-path bind, tuple-only TypeError (including bare string),
fail-closed unknown request names, dual-handle isolation, freeze,
fingerprints/catalog, and the Trusts-only checker.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.core.test_issue100 import _direct_models
from tests.core.test_issue131 import _handle, _public_direct_fold
from tests.core.test_issue54 import _change_document
from tests.core.test_issue98 import _gh_models
from tests.myapp.models import Document, DocumentGrant
from trusts._filters import (
    PathFilterBooleanError,
    PathFilterUnsupported,
    ir_digest,
    query_filter_identity,
    validate_request_filter_tuple,
)
from trusts.core import (
    Equal,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    check,
    filter_authorized_scopes,
    granted,
    instance_match,
)


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


class RequestTupleBoundaryTest(SimpleTestCase):
    def test_outer_value_is_validated_before_any_coercion(self):
        with self.assertRaises(TypeError):
            validate_request_filter_tuple('editable')
        with self.assertRaises(TypeError):
            validate_request_filter_tuple(['editable'])
        with self.assertRaises(TypeError):
            validate_request_filter_tuple({'editable'})
        with self.assertRaises(TypeError):
            validate_request_filter_tuple({'editable': True})
        with self.assertRaises(TypeError):
            validate_request_filter_tuple(name for name in ('editable',))
        self.assertEqual(validate_request_filter_tuple(()), ())
        self.assertEqual(
            validate_request_filter_tuple(('non_confidential', 'editable')),
            ('non_confidential', 'editable'),
        )

    def test_bare_string_is_not_expanded_to_characters(self):
        with patch(
            'trusts._filters.validate_filter_name',
            side_effect=AssertionError('must not iterate a bare string'),
        ):
            with self.assertRaises(TypeError):
                validate_request_filter_tuple('editable')

    def test_duplicate_and_malformed_names_are_configuration_errors(self):
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter_tuple(('own', 'own'))
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter_tuple(('1bad',))
        with self.assertRaises(TrustsConfigurationError):
            validate_request_filter_tuple(('',))
        with self.assertRaises(TypeError):
            validate_request_filter_tuple((1,))

    def test_query_identity_validates_then_sorts(self):
        self.assertEqual(
            query_filter_identity(('editable', 'non_confidential')),
            ('editable', 'non_confidential'),
        )
        supplied = validate_request_filter_tuple(
            ('editable', 'non_confidential'),
        )
        self.assertEqual(supplied, ('editable', 'non_confidential'))


class NamedOnlyPathAttachTest(SimpleTestCase):
    def test_callable_tuple_list_mapping_are_type_error(self):
        handle = _handle()
        for value in (
            (lambda r: r),
            ('team_aligned',),
            ['team_aligned'],
            {'team_aligned': True},
        ):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    handle.register(
                        DocumentGrant,
                        user='user',
                        permission='permission',
                        content='document',
                        filter=value,
                    )
        self.assertEqual(handle.registry.records, ())

    def test_strategy_and_filter_is_type_error(self):
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                strategy=object(),
                filter='team_aligned',
            )
        self.assertEqual(handle.registry.records, ())

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_register_strategy_rejects_filter(self):
        Permission, DocumentModel, Ace = _direct_models()
        handle = _handle()
        with self.assertRaises(TypeError):
            handle.register_strategy(
                Ace,
                _public_direct_fold(Ace, Permission, DocumentModel),
                filter='bits',
            )
        self.assertEqual(handle.registry.strategies, ())


class SeparateStoresTest(SimpleTestCase):
    def test_path_lookup_never_reads_request_store(self):
        handle = _handle()
        handle.register_request_filter(
            Document, 'own', lambda u, p, o: o.confidential != True,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register(
                DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                filter='own',
            )
        self.assertIn('Unknown path filter', str(ctx.exception))
        self.assertEqual(handle.registry.records, ())
        self.assertIsNotNone(
            handle.registry.get_request_filter_record(Document, 'own'),
        )
        self.assertIsNone(handle.registry.get_path_filter_record(DocumentGrant, 'own'))

    def test_request_lookup_never_reads_path_store(self):
        handle = _handle()
        handle.register_path_filter(
            DocumentGrant,
            'own',
            lambda r: r.user == r.user,
        )
        self.assertIsNone(handle.registry.get_request_filter_record(Document, 'own'))
        self.assertIsNotNone(
            handle.registry.get_path_filter_record(DocumentGrant, 'own'),
        )

    def test_same_name_may_exist_in_both_stores(self):
        handle = _handle()
        path = handle.register_path_filter(
            DocumentGrant, 'own', lambda r: r.user == r.user,
        )
        request = handle.register_request_filter(
            Document, 'own', lambda u, p, o: o.confidential != True,
        )
        self.assertIsNot(path, request)
        self.assertIs(
            handle.registry.get_path_filter_record(DocumentGrant, 'own'), path,
        )
        self.assertIs(
            handle.registry.get_request_filter_record(Document, 'own'), request,
        )

    def test_permission_condition_forwards_onto_request_store(self):
        handle = _handle()
        record = handle.register_permission_condition(
            Document, 'non_confidential',
            lambda u, p, o: o.confidential != True,
        )
        self.assertIs(
            handle.registry.get_request_filter_record(Document, 'non_confidential'),
            record,
        )
        self.assertIsNone(
            handle.registry.get_path_filter_record(DocumentGrant, 'non_confidential'),
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PathFilterPhaseBindTest(SimpleTestCase):
    def test_r9_membership_left_must_equal_permission_path(self):
        models_ = _gh_models()
        _Account, _Owner, Team, Operation, _Bundle, Repository = models_[:6]

        class DualGrant(models.Model):
            team = models.ForeignKey(
                Team, related_name='dual_grants', on_delete=models.CASCADE,
            )
            repository = models.ForeignKey(
                Repository, related_name='dual_grants', on_delete=models.CASCADE,
            )
            operation = models.ForeignKey(
                Operation, related_name='dual_grants', on_delete=models.CASCADE,
            )
            also = models.ForeignKey(
                Operation, related_name='dual_also', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        handle = _handle()
        handle.register_path_filter(
            DualGrant,
            'wrong',
            lambda r: r.also.in_(r.team.permission_bundles.operations),
        )
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                DualGrant,
                user='team__members',
                permission='operation',
                content='repository',
                filter='wrong',
            )
        self.assertEqual(handle.registry.records, ())

    def test_matching_permission_path_binds(self):
        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        handle = _handle()
        handle.register_path_filter(
            TeamRepoGrant,
            'team_aligned',
            lambda r: (
                r.operation.in_(r.team.permission_bundles.operations)
                & (r.team.organization == r.repository.organization)
            ),
        )
        record = handle.register(
            TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            filter='team_aligned',
        )
        self.assertEqual(record.user_path, ('team', 'members'))
        self.assertEqual(record.permission_path, ('operation',))
        self.assertEqual(record.content_path, ('repository',))

    def test_equality_only_has_no_membership_left_to_prove(self):
        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        handle = _handle()
        handle.register_path_filter(
            TeamRepoGrant,
            'same_org',
            lambda r: r.team.organization == r.repository.organization,
        )
        record = handle.register(
            TeamRepoGrant,
            user='team__members',
            permission='operation',
            content='repository',
            filter='same_org',
        )
        self.assertEqual(len(handle.registry.records), 1)
        self.assertEqual(record.permission_path, ('operation',))

    def test_python_and_or_in_fail_loud(self):
        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        handle = _handle()
        with self.assertRaises(PathFilterBooleanError):
            handle.register_path_filter(
                TeamRepoGrant,
                'and_or',
                lambda r: (
                    (r.team.organization == r.repository.organization)
                    and (r.operation == r.operation)
                ),
            )
        with self.assertRaises(PathFilterUnsupported):
            handle.register_path_filter(
                TeamRepoGrant,
                'py_in',
                lambda r: r.operation in r.team.permission_bundles.operations,
            )
        self.assertEqual(handle.registry.filter_catalog(), ())

    def test_duplicate_path_filter_fails_before_builder(self):
        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        handle = _handle()
        calls = []

        def builder(r):
            calls.append(1)
            return r.team.organization == r.repository.organization

        handle.register_path_filter(TeamRepoGrant, 'same_org', builder)
        self.assertEqual(calls, [1])
        with self.assertRaises(TrustsConfigurationError):
            handle.register_path_filter(TeamRepoGrant, 'same_org', builder)
        self.assertEqual(calls, [1])

    def test_unknown_path_name_stores_nothing(self):
        models_ = _gh_models()
        TeamRepoGrant = models_[6]
        handle = _handle()
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                TeamRepoGrant,
                user='team__members',
                permission='operation',
                content='repository',
                filter='missing',
            )
        self.assertEqual(handle.registry.records, ())


class FilterCatalogFingerprintTest(SimpleTestCase):
    def test_unused_names_appear_and_fingerprint_ignores_name(self):
        handle = _handle()
        handle.register_path_filter(
            DocumentGrant, 'left', lambda r: r.user == r.user,
        )
        handle.register_path_filter(
            DocumentGrant, 'right', lambda r: r.user == r.user,
        )
        handle.register_request_filter(
            Document, 'editable', lambda u, p, o: o.confidential != True,
        )
        catalog = handle.filter_catalog()
        kinds = {(entry.kind, entry.name, entry.consumed) for entry in catalog}
        self.assertIn(('path', 'left', False), kinds)
        self.assertIn(('path', 'right', False), kinds)
        self.assertIn(('request', 'editable', False), kinds)
        first = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            filter='left',
        )
        second_handle = _handle(path='tests.core.handle-b')
        second_handle.register_path_filter(
            DocumentGrant, 'alias', lambda r: r.user == r.user,
        )
        second = second_handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            filter='alias',
        )
        self.assertEqual(
            handle.record_fingerprint(first),
            second_handle.record_fingerprint(second),
        )
        consumed = {
            (entry.name, entry.consumed)
            for entry in handle.filter_catalog()
            if entry.kind == 'path'
        }
        self.assertIn(('left', True), consumed)
        self.assertIn(('right', False), consumed)

    def test_changing_ir_changes_fingerprint(self):
        left = _handle(path='tests.core.fp-left')
        right = _handle(path='tests.core.fp-right')
        left.register_path_filter(
            DocumentGrant, 'same', lambda r: r.user == r.user,
        )
        right.register_path_filter(
            DocumentGrant, 'same',
            lambda r: r.permission == r.permission,
        )
        a = left.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            filter='same',
        )
        b = right.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            filter='same',
        )
        self.assertNotEqual(
            left.record_fingerprint(a), right.record_fingerprint(b),
        )
        self.assertNotEqual(ir_digest(a.condition), ir_digest(b.condition))


class FilterFreezeIsolationTest(SimpleTestCase):
    def test_freeze_raises_before_path_or_request_builder(self):
        registry = TrustsRegistry()
        handle = _handle(registry)
        registry.freeze()
        path_calls = []
        request_calls = []
        with self.assertRaises(TrustsConfigurationError) as ctx:
            handle.register_path_filter(
                DocumentGrant, 'same',
                lambda r: path_calls.append(1) or (r.user == r.user),
            )
        self.assertIn('frozen', str(ctx.exception).lower())
        with self.assertRaises(TrustsConfigurationError):
            handle.register_request_filter(
                Document, 'editable',
                lambda u, p, o: request_calls.append(1) or (o.confidential != True),
            )
        self.assertEqual(path_calls, [])
        self.assertEqual(request_calls, [])
        self.assertEqual(handle.filter_catalog(), ())

    def test_dual_handle_filters_do_not_leak(self):
        left = _handle(path='tests.core.filter-left')
        right = _handle(path='tests.core.filter-right')
        left.register_path_filter(
            DocumentGrant, 'same', lambda r: r.user == r.user,
        )
        left.register_request_filter(
            Document, 'editable', lambda u, p, o: o.confidential != True,
        )
        self.assertEqual(len(left.filter_catalog()), 2)
        self.assertEqual(right.filter_catalog(), ())
        self.assertIsNone(
            right.registry.get_path_filter_record(DocumentGrant, 'same'),
        )
        self.assertIsNone(
            right.registry.get_request_filter_record(Document, 'editable'),
        )


class CheckAndRequestFilterLiveTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-cunify', password='x')
        self.bob = User.objects.create_user('bob-cunify', password='x')
        self.change = _change_document()
        self.open_doc = Document.objects.create(title='open', confidential=False)
        self.secret = Document.objects.create(title='secret', confidential=True)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )

    def test_check_bare_grant_is_trusts_only(self):
        from trusts import check as imported_check

        self.assertIs(imported_check, check)
        self.assertTrue(check(self.alice, self.change, self.open_doc))
        self.assertTrue(check(self.alice, 'myapp.change_document', self.secret))
        self.assertFalse(check(self.bob, self.change, self.open_doc))
        self.assertFalse(check(AnonymousUser(), self.change, self.open_doc))
        self.alice.is_active = False
        self.alice.save()
        self.assertFalse(check(self.alice, self.change, self.open_doc))

    def test_check_request_filter_and_unknown_name(self):
        self.assertTrue(
            check(
                self.alice, self.change, self.open_doc,
                filter=('non_confidential',),
            )
        )
        self.assertFalse(
            check(
                self.alice, self.change, self.secret,
                filter=('non_confidential',),
            )
        )
        with self.assertRaises(AttributeError):
            check(
                self.alice, self.change, self.open_doc,
                filter=('missing',),
            )

    def test_check_does_not_parse_colon(self):
        self.assertFalse(
            check(self.alice, 'myapp.change_document:non_confidential', self.open_doc)
        )

    def test_authorized_and_granted_accept_filter_tuple_only(self):
        self.assertEqual(
            _pks(Document.objects.authorized(
                self.alice, self.change, filter=('non_confidential',),
            )),
            {self.open_doc.pk},
        )
        for bad in ('non_confidential', ['non_confidential'], {'non_confidential'}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    Document.objects.authorized(
                        self.alice, self.change, filter=bad,
                    )
                with self.assertRaises(TypeError):
                    granted(
                        (), Document.objects.all(), self.alice, self.change,
                        filter=bad,
                    )
                with self.assertRaises(TypeError):
                    all_match(
                        (), Document.objects.all(), self.alice, self.change,
                        filter=bad,
                    )
                with self.assertRaises(TypeError):
                    instance_match(
                        _handle(), self.open_doc, self.alice, self.change,
                        filter=bad,
                    )
                with self.assertRaises(TypeError):
                    filter_authorized_scopes(
                        Document.objects.all(), self.alice, self.change,
                        content=Document, filter=bad,
                    )
                with self.assertRaises(TypeError):
                    TrustsRegistry().filter_authorized(
                        Document.objects.all(), self.alice, self.change,
                        filter=bad,
                    )

    def test_instance_check_is_one_sql(self):
        with self.assertNumQueries(1):
            self.assertTrue(
                check(
                    self.alice, self.change, self.open_doc,
                    filter=('non_confidential',),
                )
            )

    def test_queryset_check_is_one_sql(self):
        qs = Document.objects.filter(pk__in=[self.open_doc.pk])
        with self.assertNumQueries(1):
            self.assertTrue(
                check(
                    self.alice, self.change, qs,
                    filter=('non_confidential',),
                )
            )
        secret_qs = Document.objects.filter(pk__in=[self.secret.pk])
        with self.assertNumQueries(1):
            self.assertFalse(
                check(
                    self.alice, self.change, secret_qs,
                    filter=('non_confidential',),
                )
            )


class LegacyConditionBaselineTest(SimpleTestCase):
    def test_closed_tree_condition_still_registers(self):
        handle = _handle()
        record = handle.register(
            DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            condition=Equal('user', 'user'),
        )
        self.assertIsNotNone(record.condition)
        self.assertEqual(handle.registry.records, (record,))
