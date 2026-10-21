"""Isolated Compiler registration tests (issue #57).

Registration only. Does not exercise object authorization, authorized-content
filtering, permission enumeration, backends, conditions, or compatibility.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.compile.factory import RegisteredRelation
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from tests.support import compiler


def _mock_models():
    """Test-only ordinary models equivalent to the accepted #56 mock."""

    class Document(models.Model):
        title = models.CharField(max_length=200)

        class Meta:
            app_label = 'trusts_tests'

    class Tag(models.Model):
        name = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentGrant(models.Model):
        document = models.ForeignKey(
            Document, related_name='grants', on_delete=models.CASCADE,
        )
        alt_document = models.ForeignKey(
            Document, related_name='alt_grants', on_delete=models.CASCADE,
        )
        user = models.ForeignKey(
            get_user_model(), on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE,
        )
        tags = models.ManyToManyField(Tag)
        content_type = models.ForeignKey(
            ContentType, on_delete=models.CASCADE,
        )
        object_id = models.PositiveIntegerField()
        target = GenericForeignKey('content_type', 'object_id')

        class Meta:
            app_label = 'trusts_tests'

    class OtherGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(
            get_user_model(), on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Document, DocumentGrant, OtherGrant


def _register(registry, grant, content_attr='document'):
    j = Ref(grant)
    return registry.register_relation(
        content=getattr(j, content_attr),
        user=j.user,
        permission=j.permission,
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryTest(SimpleTestCase):
    def test_successful_direct_registration_infers_root_and_terminals(self):
        Document, DocumentGrant, _other = _mock_models()
        User = get_user_model()
        registry = compiler()
        j = Ref(DocumentGrant)

        record = registry.register_relation(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )

        self.assertIsInstance(record, RegisteredRelation)
        self.assertIs(record.root, DocumentGrant)
        self.assertEqual(record.content_path, ('document',))
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.content_field, 'document')
        self.assertEqual(record.user_path, ('user',))
        self.assertIs(record.user_model, User)
        self.assertEqual(record.user_field, 'user')
        self.assertEqual(record.permission_path, ('permission',))
        self.assertIs(record.permission_model, Permission)
        self.assertEqual(record.permission_field, 'permission')
        self.assertIsNone(record.condition)
        self.assertEqual(record.content_target, Document._meta.pk.attname)
        self.assertEqual(record.user_target, User._meta.pk.attname)
        self.assertEqual(record.permission_target, Permission._meta.pk.attname)
        self.assertEqual(
            tuple(row for row in registry.records if row.root is DocumentGrant),
            (record,),
        )
        self.assertEqual(registry.records, (record,))

    def test_all_refs_share_the_same_root(self):
        _document, DocumentGrant, _other = _mock_models()
        record = _register(compiler(), DocumentGrant)
        self.assertIs(record.root, DocumentGrant)
        self.assertEqual(record.content_path[0], 'document')
        self.assertEqual(record.user_path[0], 'user')
        self.assertEqual(record.permission_path[0], 'permission')

    def test_mixed_roots_rejected(self):
        _document, DocumentGrant, OtherGrant = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        k = Ref(OtherGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'same root'):
            registry.register_relation(
                content=j.document,
                user=k.user,
                permission=j.permission,
            )
        self.assertEqual(registry.records, ())

    def test_missing_field_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'missing field'):
            registry.register_relation(
                content=j.missing,
                user=j.user,
                permission=j.permission,
            )

    def test_scalar_intermediate_traversal_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'scalar'):
            registry.register_relation(
                content=j.document.title,
                user=j.user,
                permission=j.permission,
            )

    def test_multi_valued_traversal_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'multi-valued',
        ):
            registry.register_relation(
                content=j.tags,
                user=j.user,
                permission=j.permission,
            )

    def test_reverse_traversal_rejected(self):
        Document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(Document)
        with self.assertRaisesRegex(TrustsConfigurationError, r'reverse'):
            registry.register_relation(
                content=j.grants,
                user=j.grants,
                permission=j.grants,
            )
        self.assertFalse(hasattr(DocumentGrant, 'trust'))

    def test_generic_foreign_key_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'generic foreign key',
        ):
            registry.register_relation(
                content=j.target,
                user=j.user,
                permission=j.permission,
            )

    def test_root_and_path_field_names_build_refs(self):
        Document, _grant, _other = _mock_models()

        class CollisionGrant(models.Model):
            root = models.ForeignKey(
                Document, related_name='collision_root_grants',
                on_delete=models.CASCADE,
            )
            path = models.ForeignKey(
                get_user_model(), related_name='collision_path_grants',
                on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        User = get_user_model()
        j = Ref(CollisionGrant)
        self.assertIsInstance(j.root, Ref)
        self.assertIsInstance(j.path, Ref)
        self.assertEqual(j.root, Ref(CollisionGrant, ('root',)))
        self.assertEqual(j.path, Ref(CollisionGrant, ('path',)))

        registry = compiler()
        record = registry.register_relation(
            content=j.root,
            user=j.path,
            permission=j.permission,
        )
        self.assertIs(record.root, CollisionGrant)
        self.assertEqual(record.content_path, ('root',))
        self.assertEqual(record.content_field, 'root')
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.user_path, ('path',))
        self.assertEqual(record.user_field, 'path')
        self.assertIs(record.user_model, User)

        alt = compiler()
        via_path_content = alt.register_relation(
            content=Ref(CollisionGrant).path,
            user=Ref(CollisionGrant).root,
            permission=Ref(CollisionGrant).permission,
        )
        self.assertEqual(via_path_content.content_path, ('path',))
        self.assertIs(via_path_content.content_model, User)
        self.assertEqual(via_path_content.user_path, ('root',))
        self.assertIs(via_path_content.user_model, Document)

    def test_non_model_root_rejected(self):
        with self.assertRaisesRegex(TrustsConfigurationError, r'model class'):
            Ref(object)
        with self.assertRaisesRegex(TrustsConfigurationError, r'model class'):
            Ref('DocumentGrant')
        _document, DocumentGrant, _other = _mock_models()
        with self.assertRaisesRegex(TrustsConfigurationError, r'model class'):
            Ref(object())

    def test_malformed_arguments_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'must be a root-relative Ref'):
            registry.register_relation(
                content='document',
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'non-empty'):
            registry.register_relation(
                content=j,
                user=j.user,
                permission=j.permission,
            )

    def test_non_none_condition_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'not supported'):
            registry.register_relation(
                content=j.document,
                user=j.user,
                permission=j.permission,
                condition=object(),
            )
        record = registry.register_relation(
            content=j.document,
            user=j.user,
            permission=j.permission,
            condition=None,
        )
        self.assertIsNone(record.condition)

    def test_duplicate_and_conflicting_registration_are_deterministic(self):
        _document, DocumentGrant, OtherGrant = _mock_models()
        registry = compiler()
        first = _register(registry, DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            _register(registry, DocumentGrant)
        self.assertEqual(registry.records, (first,))
        self.assertEqual(
            tuple(row for row in registry.records if row.root is DocumentGrant),
            (first,),
        )

        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            _register(registry, DocumentGrant, content_attr='alt_document')
        self.assertEqual(registry.records, (first,))
        self.assertEqual(first.content_path, ('document',))

        other = _register(registry, OtherGrant)
        self.assertEqual(registry.records, (first, other))

        twin = compiler()
        again = _register(twin, DocumentGrant)
        self.assertEqual(first, again)
        self.assertIsNot(first, again)
        self.assertEqual(twin.records, (again,))
        self.assertEqual(registry.records, (first, other))

    def test_normalized_records_are_immutable(self):
        _document, DocumentGrant, _other = _mock_models()
        record = _register(compiler(), DocumentGrant)
        with self.assertRaises((AttributeError, TrustsConfigurationError, TypeError)):
            record.root = object
        j = Ref(DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            j.path = ('document',)

    def test_registration_executes_zero_queries(self):
        # SimpleTestCase forbids database connections. Completing register
        # here is the zero-SQL proof; a query would raise
        # DatabaseOperationForbidden.
        _document, DocumentGrant, _other = _mock_models()
        registry = compiler()
        _register(registry, DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            _register(registry, DocumentGrant)
        j = Ref(DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register_relation(
                content=j.missing,
                user=j.user,
                permission=j.permission,
            )


    def test_instances_are_isolated(self):
        _document, DocumentGrant, _other = _mock_models()
        left = compiler()
        right = compiler()
        _register(left, DocumentGrant)
        self.assertEqual(len(left.records), 1)
        self.assertEqual(right.records, ())

