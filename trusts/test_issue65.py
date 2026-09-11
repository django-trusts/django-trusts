"""Same-root registrations and trailing-reverse content paths (issue #65).

Isolated Folder / Document / FolderGrant mocks only. No historical Trusts
types, backends, managers, or queryset readers.
"""

import types
from contextlib import contextmanager
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import ForeignObject, Q
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from trusts.core import (
    Ref,
    RelationPlan,
    TrustsConfigurationError,
    TrustsRegistry,
)


def _folder_models():
    """FolderGrant.folder → Folder ← Document.folder (documents reverse)."""

    class Folder(models.Model):
        title = models.CharField(max_length=200)

        class Meta:
            app_label = 'trusts_tests'

    class Document(models.Model):
        folder = models.ForeignKey(
            Folder, related_name='documents', on_delete=models.CASCADE,
        )
        alt_folder = models.ForeignKey(
            Folder, related_name='alt_documents', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=200)

        class Meta:
            app_label = 'trusts_tests'

    User = get_user_model()

    class FolderGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentPermit(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Folder, Document, FolderGrant, DocumentPermit


def _register_folder_paths(registry, FolderGrant):
    j = Ref(FolderGrant)
    folder_rec = registry.register(
        content=j.folder, user=j.user, permission=j.permission,
    )
    document_rec = registry.register(
        content=j.folder.documents, user=j.user, permission=j.permission,
    )
    return folder_rec, document_rec


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


def _perm(codename):
    ct, _created = ContentType.objects.get_or_create(
        app_label='trusts_tests', model='document',
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _pks(rows):
    return {row.pk for row in rows}


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistrySameRootRegistrationTest(SimpleTestCase):
    def test_same_root_different_content_terminals_are_stored_in_order(self):
        Folder, Document, FolderGrant, _permit = _folder_models()
        registry = TrustsRegistry()
        folder_rec, document_rec = _register_folder_paths(registry, FolderGrant)

        self.assertEqual(folder_rec.content_path, ('folder',))
        self.assertEqual(folder_rec.content_field, 'folder')
        self.assertIs(folder_rec.content_model, Folder)
        self.assertEqual(folder_rec.content_target, Folder._meta.pk.attname)

        self.assertEqual(document_rec.content_path, ('folder', 'documents'))
        self.assertEqual(document_rec.content_field, 'folder__documents')
        self.assertIs(document_rec.content_model, Document)
        self.assertEqual(document_rec.content_target, Document._meta.pk.attname)

        self.assertEqual(registry.records, (folder_rec, document_rec))
        self.assertEqual(
            registry.records_for_root(FolderGrant),
            (folder_rec, document_rec),
        )
        plan_folder = registry.plan_for(Folder)
        plan_document = registry.plan_for(Document)
        self.assertEqual(plan_folder.records, (folder_rec,))
        self.assertEqual(plan_document.records, (document_rec,))

    def test_records_for_root_raises_when_absent(self):
        Folder, _document, FolderGrant, DocumentPermit = _folder_models()
        registry = TrustsRegistry()
        with self.assertRaisesRegex(TrustsConfigurationError, r'No registration'):
            registry.records_for_root(FolderGrant)
        j = Ref(FolderGrant)
        registry.register(content=j.folder, user=j.user, permission=j.permission)
        with self.assertRaisesRegex(TrustsConfigurationError, r'No registration'):
            registry.records_for_root(DocumentPermit)
        self.assertFalse(hasattr(registry, 'get'))

    def test_global_insertion_order_with_interleaved_roots(self):
        Folder, Document, FolderGrant, DocumentPermit = _folder_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        k = Ref(DocumentPermit)
        first = registry.register(
            content=j.folder, user=j.user, permission=j.permission,
        )
        second = registry.register(
            content=k.document, user=k.user, permission=k.permission,
        )
        third = registry.register(
            content=j.folder.documents, user=j.user, permission=j.permission,
        )
        self.assertEqual(registry.records, (first, second, third))
        self.assertEqual(registry.records_for_root(FolderGrant), (first, third))
        self.assertEqual(registry.records_for_root(DocumentPermit), (second,))
        self.assertEqual(registry.plan_for(Document).records, (second, third))

    def test_exact_duplicate_raises_without_mutating_records(self):
        _folder, _document, FolderGrant, _permit = _folder_models()
        registry = TrustsRegistry()
        first, second = _register_folder_paths(registry, FolderGrant)
        stored = registry.records
        j = Ref(FolderGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            registry.register(
                content=j.folder, user=j.user, permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            registry.register(
                content=j.folder.documents, user=j.user, permission=j.permission,
            )
        self.assertEqual(registry.records, stored)
        self.assertEqual(registry.records, (first, second))

    def test_same_root_same_content_terminal_is_conflict(self):
        _folder, _document, FolderGrant, _permit = _folder_models()
        registry = TrustsRegistry()
        first, second = _register_folder_paths(registry, FolderGrant)
        j = Ref(FolderGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            registry.register(
                content=j.folder.alt_documents,
                user=j.user,
                permission=j.permission,
            )
        self.assertEqual(registry.records, (first, second))
        self.assertEqual(second.content_path, ('folder', 'documents'))

    def test_unsupported_shapes_fail_during_registration_without_sql(self):
        Folder, Document, FolderGrant, _permit = _folder_models()

        class Tag(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class Owner(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'

        class FolderExtra(models.Model):
            title = models.CharField(max_length=40)
            owner = models.ForeignKey(Owner, on_delete=models.CASCADE)
            tags = models.ManyToManyField(Tag)

            class Meta:
                app_label = 'trusts_tests'

        class Profile(models.Model):
            folder = models.OneToOneField(
                FolderExtra, related_name='profile', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class ExtraGrant(models.Model):
            folder = models.ForeignKey(FolderExtra, on_delete=models.CASCADE)
            user = models.ForeignKey(
                settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
            tags = models.ManyToManyField(Tag)
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            target = GenericForeignKey('content_type', 'object_id')

            class Meta:
                app_label = 'trusts_tests'

        class ExtraNote(models.Model):
            grant = models.ForeignKey(
                ExtraGrant, related_name='notes', on_delete=models.CASCADE,
            )
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Pair(models.Model):
            left = models.IntegerField()
            right = models.IntegerField()

            class Meta:
                app_label = 'trusts_tests'
                unique_together = ('left', 'right')

        class PairGrant(models.Model):
            left = models.IntegerField()
            right = models.IntegerField()
            pair = ForeignObject(
                Pair,
                on_delete=models.CASCADE,
                from_fields=('left', 'right'),
                to_fields=('left', 'right'),
                related_name='grants',
            )
            user = models.ForeignKey(
                settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        extra = Ref(ExtraGrant)
        pair = Ref(PairGrant)

        with self.assertRaisesRegex(TrustsConfigurationError, r'reverse'):
            registry.register(
                content=extra.notes,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'reverse one-to-one',
        ):
            registry.register(
                content=extra.folder.profile,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'multi-valued'):
            registry.register(
                content=extra.tags,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'multi-valued'):
            registry.register(
                content=extra.folder.tags,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'generic foreign key',
        ):
            registry.register(
                content=extra.target,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'scalar'):
            registry.register(
                content=j.folder.documents.title,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'forward path ending',
        ):
            registry.register(
                content=extra.folder.owner,
                user=extra.user,
                permission=extra.permission,
            )
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'composite|target fields',
        ):
            registry.register(
                content=pair.pair,
                user=pair.user,
                permission=pair.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct'):
            registry.register(
                content=extra.folder,
                user=extra.folder.owner,
                permission=extra.permission,
            )
        self.assertEqual(registry.records, ())

    def test_user_and_permission_remain_direct_single_valued(self):
        _folder, _document, FolderGrant, _permit = _folder_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct|reverse'):
            registry.register(
                content=j.folder,
                user=j.folder.documents,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct|reverse'):
            registry.register(
                content=j.folder,
                user=j.user,
                permission=j.folder.documents,
            )
        self.assertEqual(registry.records, ())

    def test_no_historical_model_is_required(self):
        Folder, Document, FolderGrant, DocumentPermit = _folder_models()
        for model in (Folder, Document, FolderGrant, DocumentPermit):
            names = {cls.__name__ for cls in model.__mro__}
            self.assertNotIn('Trust', names)
            self.assertNotIn('Content', names)
            self.assertNotIn('Junction', names)
        self.assertEqual(FolderGrant.__module__, __name__)
        self.assertEqual(Document.__module__, __name__)

    def test_package_surface_does_not_reexport_registry(self):
        import trusts
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RelationPlan', None))

    def test_core_module_has_no_historical_import_or_global(self):
        import trusts.core as core

        forbidden = {
            'Trust',
            'Content',
            'Junction',
            'TrustUserPermission',
            'TrustGroupPermission',
            'Group',
            'Role',
        }
        self.assertFalse(forbidden.intersection(vars(core)))

        imported = {
            value.__name__
            for value in vars(core).values()
            if isinstance(value, types.ModuleType)
        }
        self.assertTrue(
            all(
                name == 'trusts.core' or not name.startswith('trusts.')
                for name in imported
            ),
            imported,
        )
        for value in vars(core).values():
            module = getattr(value, '__module__', None)
            if isinstance(module, str):
                self.assertFalse(
                    module.startswith('trusts.') and module != 'trusts.core',
                    module,
                )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryTrailingReverseProjectionTest(TransactionTestCase):
    def setUp(self):
        (
            self.Folder,
            self.Document,
            self.FolderGrant,
            self.DocumentPermit,
        ) = _folder_models()
        self._table_cm = _tables(
            self.Folder,
            self.Document,
            self.FolderGrant,
            self.DocumentPermit,
        )
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice', password='x')
        self.bob = User.objects.create_user(username='bob', password='x')
        self.read = _perm('read_document')
        self.write = _perm('write_document')
        self.folder_a = self.Folder.objects.create(title='A')
        self.folder_b = self.Folder.objects.create(title='B')
        self.doc_a1 = self.Document.objects.create(
            folder=self.folder_a, alt_folder=self.folder_b, title='A1',
        )
        self.doc_a2 = self.Document.objects.create(
            folder=self.folder_a, alt_folder=self.folder_b, title='A2',
        )
        self.doc_b1 = self.Document.objects.create(
            folder=self.folder_b, alt_folder=self.folder_a, title='B1',
        )
        self.registry = TrustsRegistry()
        self.folder_rec, self.document_rec = _register_folder_paths(
            self.registry, self.FolderGrant,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_grant_authorizes_matching_documents_and_denies_unrelated(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_b, user=self.bob, permission=self.write,
        )

        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.folder_a)),
            {self.read.pk},
        )
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.doc_a1)),
            {self.read.pk},
        )
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.doc_a2)),
            {self.read.pk},
        )
        self.assertEqual(
            list(self.registry.permissions_for(self.alice, self.doc_b1)),
            [],
        )
        self.assertEqual(
            list(self.registry.permissions_for(self.alice, self.folder_b)),
            [],
        )
        self.assertTrue(
            self.registry.has_permission(self.alice, self.folder_a, self.read),
        )
        self.assertTrue(
            self.registry.has_permission(self.alice, self.doc_a1, self.read),
        )
        self.assertTrue(
            self.registry.has_permission(self.alice, self.doc_a2, self.read),
        )
        self.assertFalse(
            self.registry.has_permission(self.alice, self.doc_b1, self.read),
        )
        self.assertFalse(
            self.registry.has_permission(self.alice, self.doc_a1, self.write),
        )
        self.assertFalse(
            self.registry.has_permission(self.bob, self.doc_a1, self.read),
        )
        self.assertFalse(
            self.registry.has_permission(self.bob, self.folder_a, self.read),
        )
        self.assertTrue(
            self.registry.has_permission(self.bob, self.doc_b1, self.write),
        )

    def test_three_projections_agree_for_folder_and_document(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_b, user=self.alice, permission=self.write,
        )

        expected_folders = [
            folder for folder in self.Folder.objects.order_by('pk')
            if self.registry.has_permission(self.alice, folder, self.read)
        ]
        expected_docs = [
            document for document in self.Document.objects.order_by('pk')
            if self.registry.has_permission(self.alice, document, self.read)
        ]
        folder_qs = self.registry.filter_authorized(
            self.Folder.objects.order_by('pk'), self.alice, self.read,
        )
        document_qs = self.registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )
        self.assertEqual(expected_folders, [self.folder_a])
        self.assertEqual(expected_docs, [self.doc_a1, self.doc_a2])
        with self.assertNumQueries(1):
            self.assertEqual(list(folder_qs), expected_folders)
        with self.assertNumQueries(1):
            self.assertEqual(list(document_qs), expected_docs)
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.folder_a)),
            {self.read.pk},
        )
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.doc_a1)),
            {self.read.pk},
        )
        self.assertNotIn(
            self.write.pk,
            _pks(self.registry.permissions_for(self.alice, self.doc_a1)),
        )

    def test_authorized_content_is_lazy_set_based_and_one_query(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        with self.assertNumQueries(0):
            qs = self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )
            plan = self.registry.plan_for(
                self.Document.objects.all(),
                user=self.alice,
                permission=self.read,
            )
            enumerated = self.registry.permissions_for(self.alice, self.doc_a1)
            exists = plan.content_exists(self.alice, self.read)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsInstance(plan, RelationPlan)
        self.assertIsInstance(enumerated, QuerySet)
        self.assertIsNotNone(exists)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.doc_a1.pk, self.doc_a2.pk})
        page = self.registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )[:1]
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.doc_a1])

    def test_filter_authorized_consumes_content_exists(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        plan = self.registry.plan_for(
            self.Document.objects.all(),
            user=self.alice,
            permission=self.read,
        )
        with patch.object(RelationPlan, 'content_exists', wraps=plan.content_exists) as exists:
            list(plan.filter_content(
                self.Document.objects.all(), self.alice, self.read,
            ))
        self.assertEqual(exists.call_count, 1)

        terminals = []
        original = RelationPlan._correlated_exists

        def spy(self, terminal_field_attr, **bindings):
            terminals.append(terminal_field_attr)
            return original(self, terminal_field_attr, **bindings)

        with patch.object(RelationPlan, '_correlated_exists', spy):
            list(plan.permissions(self.alice, self.doc_a1))
            plan.has_permission(self.alice, self.doc_a1, self.read)
            list(plan.filter_content(
                self.Document.objects.all(), self.alice, self.read,
            ))
        self.assertEqual(
            terminals,
            ['permission_field', 'permission_field', 'content_field'],
        )

    def test_content_exists_ors_on_the_original_candidate_queryset(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        plan = self.registry.plan_for(
            self.Document, user=self.alice, permission=self.read,
        )
        exists = plan.content_exists(self.alice, self.read)
        # Stand-in for a later reader OR-ing another predicate on the
        # original candidate queryset (must not filter-then-OR).
        combined = self.Document.objects.order_by('pk').filter(
            Q(exists) | Q(pk=self.doc_b1.pk),
        )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(combined),
                [self.doc_a1, self.doc_a2, self.doc_b1],
            )
        trustee_only = self.registry.filter_authorized(
            self.Document.objects.order_by('pk'), self.alice, self.read,
        )
        self.assertEqual(list(trustee_only), [self.doc_a1, self.doc_a2])

    def test_second_root_ors_for_the_same_document_terminal(self):
        j = Ref(self.DocumentPermit)
        self.registry.register(
            content=j.document, user=j.user, permission=j.permission,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.DocumentPermit.objects.create(
            document=self.doc_b1, user=self.alice, permission=self.write,
        )

        self.assertTrue(
            self.registry.has_permission(self.alice, self.doc_a1, self.read),
        )
        self.assertTrue(
            self.registry.has_permission(self.alice, self.doc_b1, self.write),
        )
        self.assertFalse(
            self.registry.has_permission(self.alice, self.doc_a1, self.write),
        )
        self.assertEqual(
            _pks(self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )),
            {self.doc_a1.pk, self.doc_a2.pk},
        )
        self.assertEqual(
            _pks(self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.write,
            )),
            {self.doc_b1.pk},
        )
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.doc_a1)),
            {self.read.pk},
        )
        self.assertEqual(
            _pks(self.registry.permissions_for(self.alice, self.doc_b1)),
            {self.write.pk},
        )
        sql = str(self.registry.filter_authorized(
            self.Document.objects.all(), self.alice, self.read,
        ).query).upper()
        self.assertIn('EXISTS', sql)
        self.assertIn(' OR ', sql)

    def test_shared_row_correlation_does_not_combine_split_facts(self):
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_b, user=self.alice, permission=self.write,
        )
        self.assertFalse(
            self.registry.has_permission(self.alice, self.doc_a1, self.write),
        )
        self.assertFalse(
            self.registry.has_permission(self.alice, self.doc_b1, self.read),
        )
        self.assertEqual(
            _pks(self.registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.write,
            )),
            {self.doc_b1.pk},
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryToFieldHopTest(TransactionTestCase):
    def test_to_field_on_forward_hop_retains_correlation(self):
        User = get_user_model()

        class CodedFolder(models.Model):
            code = models.SlugField(unique=True)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CodedDocument(models.Model):
            folder = models.ForeignKey(
                CodedFolder, related_name='documents', on_delete=models.CASCADE,
            )
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CodedGrant(models.Model):
            folder = models.ForeignKey(
                CodedFolder, to_field='code', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(CodedFolder, CodedDocument, CodedGrant):
            registry = TrustsRegistry()
            j = Ref(CodedGrant)
            folder_rec = registry.register(
                content=j.folder, user=j.user, permission=j.permission,
            )
            document_rec = registry.register(
                content=j.folder.documents, user=j.user, permission=j.permission,
            )
            self.assertEqual(folder_rec.content_target, 'code')
            self.assertEqual(document_rec.content_field, 'folder__documents')
            self.assertEqual(
                document_rec.content_target, CodedDocument._meta.pk.attname,
            )
            self.assertNotEqual(document_rec.content_target, 'code')

            alice = User.objects.create_user(username='alice-tf', password='x')
            bob = User.objects.create_user(username='bob-tf', password='x')
            read = _perm('read_coded')
            write = _perm('write_coded')
            folder_alpha = CodedFolder.objects.create(code='alpha', title='A')
            folder_beta = CodedFolder.objects.create(code='beta', title='B')
            self.assertNotEqual(folder_alpha.pk, 'alpha')
            doc_a1 = CodedDocument.objects.create(folder=folder_alpha, title='A1')
            doc_a2 = CodedDocument.objects.create(folder=folder_alpha, title='A2')
            doc_b1 = CodedDocument.objects.create(folder=folder_beta, title='B1')
            CodedGrant.objects.create(
                folder=folder_alpha, user=alice, permission=read,
            )

            self.assertEqual(
                _pks(registry.permissions_for(alice, folder_alpha)),
                {read.pk},
            )
            self.assertEqual(
                list(registry.permissions_for(alice, folder_beta)),
                [],
            )
            self.assertTrue(registry.has_permission(alice, folder_alpha, read))
            self.assertFalse(registry.has_permission(alice, folder_beta, read))
            self.assertTrue(registry.has_permission(alice, doc_a1, read))
            self.assertTrue(registry.has_permission(alice, doc_a2, read))
            self.assertFalse(registry.has_permission(alice, doc_b1, read))
            self.assertFalse(registry.has_permission(bob, doc_a1, read))
            self.assertFalse(registry.has_permission(alice, doc_a1, write))

            folder_sql = str(registry.filter_authorized(
                CodedFolder.objects.order_by('pk'), alice, read,
            ).query).lower()
            self.assertIn('exists', folder_sql)
            self.assertIn('code', folder_sql)
            document_sql = str(registry.filter_authorized(
                CodedDocument.objects.order_by('pk'), alice, read,
            ).query).lower()
            self.assertIn('exists', document_sql)
            self.assertIn('folder', document_sql)

            with self.assertNumQueries(1):
                self.assertEqual(
                    list(registry.filter_authorized(
                        CodedFolder.objects.order_by('pk'), alice, read,
                    )),
                    [folder_alpha],
                )
            with self.assertNumQueries(1):
                self.assertEqual(
                    list(registry.filter_authorized(
                        CodedDocument.objects.order_by('pk'), alice, read,
                    )),
                    [doc_a1, doc_a2],
                )
